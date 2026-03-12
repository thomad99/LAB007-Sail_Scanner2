const express = require('express');
const { Pool } = require('pg');
const axios = require('axios');
const cheerio = require('cheerio');
const fs = require('fs');
const path = require('path');

// Note: Playwright/Puppeteer is no longer needed. Clubspot scraping uses the Parse Server REST API directly.

const app = express();
const port = process.env.PORT || 3001;

app.use(express.json());

// Database connection - lazy initialization (don't connect until needed)
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    },
    // Don't connect immediately - wait until first query
    connectionTimeoutMillis: 10000,
    idleTimeoutMillis: 30000
});

// Initialize regattas table if needed
async function ensureRegattasTable() {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS regattas (
                id SERIAL PRIMARY KEY,
                regatta_date DATE NOT NULL,
                regatta_name TEXT NOT NULL,
                location TEXT,
                event_website_url TEXT,
                registrants_url TEXT,
                registrant_count INTEGER,
                source TEXT NOT NULL,
                source_id TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(regatta_name, regatta_date, source)
            )
        `);

        await pool.query(`CREATE INDEX IF NOT EXISTS idx_regattas_date ON regattas(regatta_date);`);
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_regattas_name ON regattas(regatta_name);`);
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_regattas_location ON regattas(location);`);
        await pool.query(`ALTER TABLE regattas ADD COLUMN IF NOT EXISTS registrant_count INTEGER;`);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS scrape_log (
                id SERIAL PRIMARY KEY,
                source TEXT NOT NULL,
                regattas_found INTEGER DEFAULT 0,
                regattas_added INTEGER DEFAULT 0,
                scrape_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        console.log('Regattas table verified');
    } catch (err) {
        console.error('Error ensuring regattas table:', err);
    }
}

function normalizeText(text) {
    return text ? text.replace(/\s+/g, ' ').trim() : '';
}

function parseHSSailingDate(dateText, fallbackYear, fallbackMonth) {
    const months = {
        jan: '01', feb: '02', mar: '03', apr: '04',
        may: '05', jun: '06', jul: '07', aug: '08',
        sep: '09', sept: '09', oct: '10', nov: '11', dec: '12'
    };

    const normalized = normalizeText(dateText);
    if (!normalized) return null;

    // e.g. "Jan 3-4", "Sep 6-25 Sat-Sat"
    const monthDayMatch = normalized.match(/(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)[a-z]*\s+(\d{1,2})/i);
    if (monthDayMatch) {
        const month = months[monthDayMatch[1].toLowerCase().slice(0, 4)];
        const day = monthDayMatch[2].padStart(2, '0');
        const year = fallbackYear || new Date().getFullYear();
        if (month && day && year) {
            return `${year}-${month}-${day}`;
        }
    }

    // If month name missing, try using month from the current header row
    if (fallbackMonth) {
        const dayOnlyMatch = normalized.match(/(\d{1,2})/);
        const month = months[fallbackMonth.toLowerCase().slice(0, 4)];
        if (dayOnlyMatch && month) {
            const day = dayOnlyMatch[1].padStart(2, '0');
            const year = fallbackYear || new Date().getFullYear();
            return `${year}-${month}-${day}`;
        }
    }

    // Numeric formats like YYYY-MM-DD or MM/DD/YYYY
    const isoMatch = normalized.match(/(\d{4})-(\d{1,2})-(\d{1,2})/);
    if (isoMatch) {
        return `${isoMatch[1]}-${isoMatch[2].padStart(2, '0')}-${isoMatch[3].padStart(2, '0')}`;
    }

    const slashMatch = normalized.match(/(\d{1,2})\/(\d{1,2})\/(\d{4})/);
    if (slashMatch) {
        return `${slashMatch[3]}-${slashMatch[1].padStart(2, '0')}-${slashMatch[2].padStart(2, '0')}`;
    }

    return null;
}

function parseHighSchoolSailingPage(html, defaultYear) {
    const $ = cheerio.load(html);
    const regattas = [];
    let currentYear = defaultYear || new Date().getFullYear();
    let currentMonthName = null;

    $('table tr').each((index, row) => {
        const cells = $(row).find('td, th');
        if (cells.length === 0) return;

        const headerText = normalizeText(cells.eq(0).text());

        // Month/year header rows (e.g., "January 2026")
        const monthHeaderMatch = headerText.match(/(January|February|March|April|May|June|July|August|September|October|November|December)\s+(\d{4})/i);
        if (monthHeaderMatch) {
            currentMonthName = monthHeaderMatch[1];
            currentYear = parseInt(monthHeaderMatch[2], 10) || currentYear;
            return;
        }

        // Skip column header rows
        if (headerText.toLowerCase().startsWith('date')) {
            return;
        }

        // Expect at least Date + Event + Host + Venue columns
        if (cells.length < 4) return;

        const dateText = normalizeText(cells.eq(0).text());
        const eventCell = cells.eq(1);
        const regattaName = normalizeText(eventCell.text());
        const venueText = normalizeText(cells.eq(3).text());
        const hostText = normalizeText(cells.eq(2).text());

        const regattaDate = parseHSSailingDate(dateText, currentYear, currentMonthName);
        if (!regattaDate || !regattaName || regattaName.length < 3) {
            return;
        }

        let eventWebsiteUrl = null;
        const linkHref = eventCell.find('a').first().attr('href');
        if (linkHref) {
            eventWebsiteUrl = linkHref.startsWith('http') ? linkHref : `https://hssailing.org${linkHref}`;
        }

        // Prefer venue as location, fall back to host if venue is missing
        const location = venueText || hostText || null;
        const sourceIdBase = eventWebsiteUrl || regattaName;

        regattas.push({
            regatta_date: regattaDate,
            regatta_name: regattaName,
            location,
            event_website_url: eventWebsiteUrl,
            source_id: `${regattaDate}-${sourceIdBase.replace(/\s+/g, '-').toLowerCase().substring(0, 120)}`
        });
    });

    return regattas;
}

/** Fetch event page and extract "Entry List" link href. Returns absolute URL or null. */
async function fetchHSSailingEntryListUrl(eventPageUrl) {
    if (!eventPageUrl) return null;
    try {
        const response = await axios.get(eventPageUrl, {
            headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' },
            timeout: 15000
        });
        const $ = cheerio.load(response.data);
        let href = null;
        $('a').each((i, el) => {
            const text = $(el).text().trim();
            if (/^Entry\s*List$/i.test(text)) {
                const h = $(el).attr('href');
                if (h) {
                    href = h.startsWith('http') ? h : `https://hssailing.org${h.startsWith('/') ? h : '/' + h}`;
                    return false;
                }
            }
        });
        return href;
    } catch (err) {
        console.error(`Error fetching HS Sailing entry list for ${eventPageUrl}:`, err.message);
        return null;
    }
}

// Scrape Regatta Network
async function scrapeRegattaNetwork() {
    try {
        const url = 'https://www.regattanetwork.com/html/calendar.php';
        const response = await axios.get(url, {
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            },
            timeout: 30000
        });

        const $ = cheerio.load(response.data);
        const regattas = [];

        $('table tr').each((index, element) => {
            const $row = $(element);
            const $cells = $row.find('td');

            if ($cells.length >= 3) {
                const dateText = $cells.eq(0).text().trim();
                const eventCell = $cells.eq(1);
                const linksCell = $cells.eq(2);

                let regattaDate = null;
                if (dateText) {
                    const dateMatch = dateText.match(/(\d{2})\/(\d{2})\/(\d{2})/);
                    if (dateMatch) {
                        const [, month, day, year] = dateMatch;
                        const fullYear = parseInt(year) < 50 ? 2000 + parseInt(year) : 1900 + parseInt(year);
                        regattaDate = `${fullYear}-${month}-${day}`;
                    }
                }

                const fullText = eventCell.text();
                const lines = fullText.split('\n').map(l => l.trim()).filter(l => l);
                const line0 = lines[0] || '';
                const locationLinePattern = /^.*,\s*[A-Z]{2}$/;
                const locationLike = lines.filter(l => l.length > 3 && locationLinePattern.test(l));
                const lastLocationLine = locationLike.length > 0 ? locationLike[locationLike.length - 1].trim() : null;

                let location = '';
                const allMatches = fullText.match(/[^,\n]+(?:,\s*[^,\n]+)*,\s*[A-Z]{2}/g);
                let lastMatch = allMatches && allMatches.length > 0 ? allMatches[allMatches.length - 1].trim() : null;
                if (lines.length === 1 && lastMatch === line0) {
                    const parts = line0.split(/,\s*/);
                    if (parts.length >= 2 && /^[A-Z]{2}$/.test(parts[parts.length - 1])) {
                        const citySt = parts.slice(-2).join(', ');
                        location = (parts.length >= 3 ? parts.slice(-3).join(', ') : citySt);
                        lastMatch = null;
                    }
                }
                if (lastLocationLine && (lines.length > 1 || lastLocationLine !== line0)) {
                    location = lastLocationLine;
                } else if (lastMatch) {
                    location = lastMatch;
                } else if (!location && lines.length > 1 && locationLinePattern.test(lines[1])) {
                    location = lines[1];
                }

                let eventName = eventCell.clone().children().remove().end().text().trim();
                if (!eventName) {
                    eventName = line0;
                } else {
                    const firstLine = eventName.split('\n').map(l => l.trim()).filter(l => l)[0] || eventName;
                    if (firstLine && firstLine.length > 2) eventName = firstLine;
                }
                if (lines.length === 1 && location && fullText.includes(location)) {
                    const before = fullText.replace(location, '').replace(/,+\s*$/, '').trim();
                    if (before.length >= 3) eventName = before;
                }
                if (eventName && location && (location.startsWith(eventName) || location.includes('\n'))) {
                    location = location.replace(eventName, '').replace(/^[\s,\-]+/, '').trim();
                }
                if (location && eventName && location.includes(eventName)) {
                    location = location.replace(eventName, '').replace(/^[\s,\-]+/, '').trim();
                }

                let eventWebsiteUrl = '';
                eventCell.find('a').each((i, link) => {
                    const href = $(link).attr('href');
                    const text = $(link).text().trim();
                    if (text.includes('Event Website') || (href && href.includes('event'))) {
                        eventWebsiteUrl = href.startsWith('http') ? href : `https://www.regattanetwork.com${href}`;
                        return false;
                    }
                });

                let registrantsUrl = '';
                linksCell.find('a').each((i, link) => {
                    const href = $(link).attr('href');
                    const text = $(link).text().trim();
                    if (text.includes('View Registrants') || text.includes('Registrants') || (href && href.includes('registrant'))) {
                        registrantsUrl = href.startsWith('http') ? href : `https://www.regattanetwork.com${href}`;
                        return false;
                    }
                });

                if (eventName && location && eventName.includes(location)) {
                    eventName = eventName.replace(location, '').trim();
                }

                if (regattaDate && eventName && eventName.length > 3) {
                    const sourceId = `${regattaDate}-${eventName.replace(/\s+/g, '-').toLowerCase().substring(0, 100)}`;

                    regattas.push({
                        regatta_date: regattaDate,
                        regatta_name: eventName,
                        location: location || null,
                        event_website_url: eventWebsiteUrl || null,
                        registrants_url: registrantsUrl || null,
                        source: 'regattanetwork',
                        source_id: sourceId
                    });
                }
            }
        });

        console.log(`Found ${regattas.length} regattas from Regatta Network`);

        let added = 0;
        for (const regatta of regattas) {
            try {
                // Try to compute registrant count for Regatta Network events when we have a registrants URL
                let registrantCount = null;
                if (regatta.source === 'regattanetwork' && (regatta.registrants_url || regatta.event_website_url)) {
                    try {
                        // Prefer explicit registrants_url, otherwise construct from event_website_url
                        let registrantsUrl = regatta.registrants_url;
                        if (!registrantsUrl && regatta.event_website_url && regatta.event_website_url.includes('regattanetwork.com/event')) {
                            const baseUrl = regatta.event_website_url.split('#')[0];
                            registrantsUrl = `${baseUrl}#_registration+current`;
                            regatta.registrants_url = registrantsUrl;
                        }

                        if (registrantsUrl) {
                            const registrantsResponse = await axios.get(registrantsUrl, {
                                headers: {
                                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                                },
                                timeout: 20000
                            });
                            const $r = cheerio.load(registrantsResponse.data);

                            // Heuristic: count data rows in tables on the page (excluding header rows)
                            let count = 0;
                            $r('table').each((i, table) => {
                                const $table = $r(table);
                                const headerRows = $table.find('thead tr').length;
                                const bodyRows = $table.find('tbody tr').length;
                                if (bodyRows > 0) {
                                    count = Math.max(count, bodyRows);
                                } else {
                                    // Fallback: count all tr that have data cells
                                    const dataRows = $table.find('tr').filter((idx, row) => {
                                        return $r(row).find('td').length > 1;
                                    }).length;
                                    count = Math.max(count, dataRows);
                                }
                            });

                            if (count > 0) {
                                registrantCount = count;
                            }
                        }
                    } catch (registrantError) {
                        console.error('Error fetching registrant count:', registrantError.message);
                    }
                }

                await pool.query(`
                    INSERT INTO regattas (regatta_date, regatta_name, location, event_website_url, registrants_url, registrant_count, source, source_id)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                    ON CONFLICT (regatta_name, regatta_date, source) 
                    DO UPDATE SET 
                        location = EXCLUDED.location,
                        event_website_url = EXCLUDED.event_website_url,
                        registrants_url = EXCLUDED.registrants_url,
                        registrant_count = COALESCE(EXCLUDED.registrant_count, regattas.registrant_count),
                        source_id = EXCLUDED.source_id,
                        last_updated = CURRENT_TIMESTAMP
                `, [
                    regatta.regatta_date,
                    regatta.regatta_name,
                    regatta.location,
                    regatta.event_website_url,
                    regatta.registrants_url,
                    registrantCount,
                    regatta.source,
                    regatta.source_id
                ]);
                added++;
            } catch (err) {
                if (!err.message.includes('duplicate')) {
                    console.error('Error inserting regatta:', err);
                }
            }
        }

        await pool.query(`
            INSERT INTO scrape_log (source, regattas_found, regattas_added)
            VALUES ('regattanetwork', $1, $2)
        `, [regattas.length, added]);

        return { found: regattas.length, added };
    } catch (error) {
        console.error('Error scraping Regatta Network:', error);
        throw error;
    }
}

// Scrape Clubspot using the Parse Server REST API (no headless browser needed)
async function scrapeClubspot() {
    console.log('🌐 Starting Clubspot scrape via Parse Server API...');

    // ClubSpot uses Parse Server. Query it directly - no headless browser needed.
    const PARSE_API_URL = 'https://theclubspot.com/parse/classes/regattas';
    const PARSE_APP_ID = 'myclubspot2017';
    const BATCH_SIZE = 100;

    try {
        // Fetch upcoming regattas (from 30 days ago to catch events already started)
        const fromDate = new Date();
        fromDate.setDate(fromDate.getDate() - 30);

        const where = {
            archived: { $ne: true },
            startDate: { $gte: { __type: 'Date', iso: fromDate.toISOString() } }
        };

        const baseParams = new URLSearchParams({
            order: 'startDate',
            include: 'clubObject',
            keys: 'name,startDate,endDate,city,state,country,zipOrPostalCode,clubObject,objectId',
            where: JSON.stringify(where)
        });

        // First, get total count
        const countParams = new URLSearchParams(baseParams);
        countParams.set('count', '1');
        countParams.set('limit', '0');

        const countResponse = await axios.get(`${PARSE_API_URL}?${countParams}`, {
            headers: { 'X-Parse-Application-Id': PARSE_APP_ID },
            timeout: 30000
        });

        const totalCount = countResponse.data.count || 0;
        console.log(`📊 Total upcoming Clubspot regattas: ${totalCount}`);

        // Paginate through all results
        const allRegattas = [];
        const totalPages = Math.ceil(totalCount / BATCH_SIZE);

        for (let page = 0; page < totalPages; page++) {
            const pageParams = new URLSearchParams(baseParams);
            pageParams.set('limit', BATCH_SIZE.toString());
            pageParams.set('skip', (page * BATCH_SIZE).toString());

            console.log(`📄 Fetching page ${page + 1}/${totalPages} (skip=${page * BATCH_SIZE})...`);

            const response = await axios.get(`${PARSE_API_URL}?${pageParams}`, {
                headers: { 'X-Parse-Application-Id': PARSE_APP_ID },
                timeout: 30000
            });

            const results = response.data.results || [];
            allRegattas.push(...results);

            // Brief pause between pages to be polite
            if (page < totalPages - 1) {
                await new Promise(r => setTimeout(r, 200));
            }
        }

        console.log(`✅ Fetched ${allRegattas.length} regattas from Clubspot API`);

        // Map Parse objects to our DB schema
        const extractedRegattas = allRegattas.map(r => {
            // Extract date from Parse Date object (ISO string → YYYY-MM-DD)
            const startDateIso = r.startDate && r.startDate.iso ? r.startDate.iso : r.startDate;
            const regattaDate = startDateIso ? startDateIso.substring(0, 10) : null;

            // Build location string
            let location = null;
            if (r.city && r.state) {
                location = `${r.city}, ${r.state}`;
            } else if (r.city) {
                location = r.city;
            } else if (r.clubObject && r.clubObject.name) {
                location = r.clubObject.name;
            }

            // Build event URL using club subdomain + regatta objectId
            let eventWebsiteUrl = null;
            if (r.clubObject && r.clubObject.subdomain && r.objectId) {
                // Subdomains may contain special chars; encode them safely
                const subdomain = r.clubObject.subdomain.replace(/[^a-zA-Z0-9-]/g, '');
                if (subdomain) {
                    eventWebsiteUrl = `https://${subdomain}.theclubspot.com/regatta/${r.objectId}`;
                }
            }
            // Fallback to main racing site
            if (!eventWebsiteUrl && r.objectId) {
                eventWebsiteUrl = `https://racing.theclubspot.com/`;
            }

            return {
                regatta_date: regattaDate,
                regatta_name: r.name || null,
                location,
                event_website_url: eventWebsiteUrl,
                source_id: r.objectId
            };
        }).filter(r => r.regatta_date && r.regatta_name && r.regatta_name.length > 2);

        console.log(`📋 Valid regattas after filtering: ${extractedRegattas.length}`);

        // Insert into database
        let added = 0;
        for (const regatta of extractedRegattas) {
            try {
                await pool.query(`
                    INSERT INTO regattas (regatta_date, regatta_name, location, event_website_url, registrants_url, registrant_count, source, source_id)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                    ON CONFLICT (regatta_name, regatta_date, source)
                    DO UPDATE SET
                        location = EXCLUDED.location,
                        event_website_url = EXCLUDED.event_website_url,
                        registrants_url = EXCLUDED.registrants_url,
                        registrant_count = COALESCE(EXCLUDED.registrant_count, regattas.registrant_count),
                        source_id = EXCLUDED.source_id,
                        last_updated = CURRENT_TIMESTAMP
                `, [
                    regatta.regatta_date,
                    regatta.regatta_name,
                    regatta.location,
                    regatta.event_website_url,
                    null,
                    null,
                    'clubspot',
                    regatta.source_id
                ]);
                added++;
            } catch (err) {
                if (!err.message.includes('duplicate')) {
                    console.error('Error inserting regatta:', err.message);
                }
            }
        }

        await pool.query(`
            INSERT INTO scrape_log (source, regattas_found, regattas_added)
            VALUES ('clubspot', $1, $2)
        `, [extractedRegattas.length, added]);

        console.log(`✅ Clubspot scrape complete: ${extractedRegattas.length} found, ${added} added/updated`);
        return { found: extractedRegattas.length, added };

    } catch (error) {
        console.error('Error scraping Clubspot via API:', error.message);
        if (error.response) {
            console.error('API response status:', error.response.status);
            console.error('API response data:', JSON.stringify(error.response.data));
        }
        throw error;
    }
}

async function scrapeHighSchoolSailing() {
    try {
        const now = new Date();
        const currentYear = now.getFullYear();
        const seasons = [
            { start: currentYear - 1, end: currentYear },
            { start: currentYear - 2, end: currentYear - 1 }
        ];

        const targetUrls = [];
        seasons.forEach(season => {
            targetUrls.push({
                url: `https://hssailing.org/schedule-results/current/${season.start}/${season.end}`,
                season
            });
            targetUrls.push({
                url: `https://hssailing.org/schedule-results/${season.start}/${season.end}`,
                season
            });
        });

        const regattas = [];
        const seen = new Set();

        for (const { url, season } of targetUrls) {
            try {
                console.log(`Fetching High School Sailing schedule: ${url}`);
                const response = await axios.get(url, {
                    headers: {
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                    },
                    timeout: 45000
                });

                const pageRegattas = parseHighSchoolSailingPage(response.data, season.end);
                pageRegattas.forEach(regatta => {
                    const key = `${regatta.regatta_date}-${regatta.regatta_name}`.toLowerCase();
                    if (!seen.has(key)) {
                        seen.add(key);
                        regattas.push(regatta);
                    }
                });
            } catch (err) {
                console.error(`High School Sailing fetch failed for ${url}:`, err.message);
            }
        }

        console.log(`Found ${regattas.length} regattas from High School Sailing`);

        console.log('Fetching Entry List links from event pages...');
        for (const regatta of regattas) {
            if (regatta.event_website_url) {
                const entryListUrl = await fetchHSSailingEntryListUrl(regatta.event_website_url);
                if (entryListUrl) {
                    regatta.registrants_url = entryListUrl;
                    console.log(`  Entry List: ${regatta.regatta_name} -> ${entryListUrl}`);
                }
                await new Promise(r => setTimeout(r, 350));
            }
        }

        let added = 0;
        for (const regatta of regattas) {
            try {
                const sourceId = regatta.source_id || `${regatta.regatta_date}-${regatta.regatta_name.replace(/\s+/g, '-').toLowerCase().substring(0, 120)}`;
                await pool.query(`
                    INSERT INTO regattas (regatta_date, regatta_name, location, event_website_url, registrants_url, registrant_count, source, source_id)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                    ON CONFLICT (regatta_name, regatta_date, source) 
                    DO UPDATE SET 
                        location = EXCLUDED.location,
                        event_website_url = EXCLUDED.event_website_url,
                        registrants_url = EXCLUDED.registrants_url,
                        registrant_count = COALESCE(EXCLUDED.registrant_count, regattas.registrant_count),
                        source_id = EXCLUDED.source_id,
                        last_updated = CURRENT_TIMESTAMP
                `, [
                    regatta.regatta_date,
                    regatta.regatta_name,
                    regatta.location,
                    regatta.event_website_url,
                    regatta.registrants_url || null,
                    null,
                    'hssailing',
                    sourceId
                ]);
                added++;
            } catch (err) {
                if (!err.message.includes('duplicate')) {
                    console.error('Error inserting High School Sailing regatta:', err);
                }
            }
        }

        await pool.query(`
            INSERT INTO scrape_log (source, regattas_found, regattas_added)
            VALUES ('hssailing', $1, $2)
        `, [regattas.length, added]);

        return { found: regattas.length, added };
    } catch (error) {
        console.error('Error scraping High School Sailing:', error);
        throw error;
    }
}

// Scraping endpoint
app.post('/api/scrape-regattas', async (req, res) => {
    console.log('=== Regatta Scraping Request Received ===');

    try {
        const { source } = req.body; // 'regattanetwork', 'clubspot', 'hssailing', or 'all'
        let totalFound = 0;
        let totalAdded = 0;
        const results = {
            regattanetwork: { found: 0, added: 0 },
            clubspot: { found: 0, added: 0 },
            hssailing: { found: 0, added: 0 }
        };

        if (!source || source === 'all' || source === 'regattanetwork') {
            console.log('Scraping Regatta Network...');
            const rnResult = await scrapeRegattaNetwork();
            results.regattanetwork = rnResult;
            totalFound += rnResult.found;
            totalAdded += rnResult.added;
        }

        if (!source || source === 'all' || source === 'hssailing') {
            console.log('Scraping High School Sailing...');
            const hsResult = await scrapeHighSchoolSailing();
            results.hssailing = hsResult;
            totalFound += hsResult.found;
            totalAdded += hsResult.added;
        }

        if (!source || source === 'all' || source === 'clubspot') {
            console.log('Scraping Clubspot...');
            try {
                const csResult = await scrapeClubspot();
                results.clubspot = csResult;
                totalFound += csResult.found;
                totalAdded += csResult.added;
            } catch (csError) {
                console.error('Clubspot scraping error:', csError);
                results.clubspot = {
                    found: 0,
                    added: 0,
                    error: csError.message || 'Failed to scrape Clubspot'
                };
            }
        }

        console.log(`=== Scraping Complete: ${totalFound} found, ${totalAdded} added ===`);
        res.json({
            success: true,
            totalFound,
            totalAdded,
            results
        });
    } catch (error) {
        console.error('=== Scraping Error ===', error);
        res.status(500).json({
            error: 'Failed to scrape regattas',
            details: error.message
        });
    }
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({ status: 'ok', service: 'regatta-scraper' });
});

// Start server - minimal synchronous startup
const server = app.listen(port, () => {
    console.log(`Regatta Scraper Service running on port ${port}`);
    console.log('Server is ready to accept requests');
});

// Initialize database asynchronously in background (don't await)
setTimeout(() => {
    initializeDatabase().catch(err => {
        console.error('Database initialization error:', err.message);
    });
}, 1000); // Wait 1 second after server starts

// Separate function for database initialization
async function initializeDatabase() {
    try {
        // Test database connection
        await pool.query('SELECT 1');
        console.log('✓ Database connected');

        // Ensure tables exist
        await ensureRegattasTable();

        console.log('✓ Service ready to accept scraping requests');
        console.log('  - Regatta Network scraping: Available');
        console.log('  - Clubspot scraping: Available (Parse Server API)');
    } catch (err) {
        console.error('✗ Database initialization failed:', err.message);
        if (err.code === 'ENOTFOUND') {
            console.error('  DNS lookup failed - check DATABASE_URL');
        }
        if (!process.env.DATABASE_URL) {
            console.error('  DATABASE_URL environment variable is not set!');
        }
        console.error('  Service will continue but database operations may fail');
    }
}

// Handle unhandled promise rejections to prevent crashes
process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
    // Don't exit - log and continue
});

process.on('uncaughtException', (error) => {
    console.error('Uncaught Exception:', error);
    console.error('Stack:', error.stack);
    // Don't exit - log and continue (or exit if critical)
    // For now, let it continue to see what happens
});

