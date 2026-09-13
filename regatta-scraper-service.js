const express = require('express');
const { Pool } = require('pg');
const axios = require('axios');
const cheerio = require('cheerio');
const fs = require('fs');
const path = require('path');
const { PARSE_APP_ID, clubspotGet, clubspotConfigSummary } = require('./clubspot-http');
const {
    isoDateFromParse,
    extractBoatTypesFromText,
    mergeBoatTypes,
    expandInclusiveDates,
    resolveClubspotBoatTypes,
    ensureRegattaExtraColumns,
    upsertRegatta,
    clubspotLocationText
} = require('./regatta-scrape-helpers');
const {
    scrapeRegattaNetworkCalendar,
    scrapeHighSchoolSailingCalendar
} = require('./regatta-calendar-scraper');

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

/**
 * Upserts report every touched row. Use RETURNING (xmax = 0) AS was_inserted
 * so scrape_log.regattas_added counts only true inserts, not updates.
 */
function countTrueInserts(upsertResult) {
    if (!upsertResult?.rows?.length) return 0;
    return upsertResult.rows.filter((row) => row.was_inserted === true).length;
}

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
        await ensureRegattaExtraColumns(pool);

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

async function scrapeRegattaNetwork() {
    return scrapeRegattaNetworkCalendar({ axios, cheerio, pool });
}

// Scrape Clubspot using the Parse Server REST API (no headless browser needed)
async function scrapeClubspot() {
    const pace = clubspotConfigSummary();
    console.log(
        `🌐 Starting Clubspot scrape via Parse Server API ` +
        `(pacing ${pace.delayMinMs}-${pace.delayMaxMs}ms, retry on 429/5xx up to ${pace.maxRetries})...`
    );

    // ClubSpot uses Parse Server. Query it directly - no headless browser needed.
    const PARSE_API_URL = 'https://theclubspot.com/parse/classes/regattas';
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
            include: 'clubObject,boatClassesArray',
            keys: 'name,startDate,endDate,city,state,country,zipOrPostalCode,clubObject,objectId,boatClassesArray',
            where: JSON.stringify(where)
        });

        // First, get total count
        const countParams = new URLSearchParams(baseParams);
        countParams.set('count', '1');
        countParams.set('limit', '0');

        const countResponse = await clubspotGet(axios, `${PARSE_API_URL}?${countParams}`, {
            headers: { 'X-Parse-Application-Id': PARSE_APP_ID }
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

            const response = await clubspotGet(axios, `${PARSE_API_URL}?${pageParams}`, {
                headers: { 'X-Parse-Application-Id': PARSE_APP_ID }
            });

            const results = response.data.results || [];
            allRegattas.push(...results);
        }

        console.log(`✅ Fetched ${allRegattas.length} regattas from Clubspot API`);

        const extractedRegattas = [];
        for (const r of allRegattas) {
            const startDate = isoDateFromParse(r.startDate);
            const endDate = isoDateFromParse(r.endDate);
            const eventDates = expandInclusiveDates(startDate, endDate);
            const regattaDate = eventDates[0] || startDate;
            if (!regattaDate || !r.name || r.name.length <= 2) continue;

            const location = clubspotLocationText(r);

            let eventWebsiteUrl = null;
            if (r.clubObject && r.clubObject.subdomain && r.objectId) {
                const subdomain = r.clubObject.subdomain.replace(/[^a-zA-Z0-9-]/g, '');
                if (subdomain) {
                    eventWebsiteUrl = `https://${subdomain}.theclubspot.com/regatta/${r.objectId}`;
                }
            }
            if (!eventWebsiteUrl && r.objectId) {
                eventWebsiteUrl = `https://racing.theclubspot.com/`;
            }

            const apiBoatTypes = await resolveClubspotBoatTypes(axios, r.boatClassesArray);
            extractedRegattas.push({
                regatta_date: regattaDate,
                event_dates: eventDates.length ? eventDates : [regattaDate],
                boat_types: mergeBoatTypes(apiBoatTypes, extractBoatTypesFromText(r.name)),
                regatta_name: r.name,
                location,
                event_website_url: eventWebsiteUrl,
                source_id: r.objectId
            });
        }

        console.log(`📋 Valid regattas after filtering: ${extractedRegattas.length}`);

        let added = 0;
        let updated = 0;
        for (const regatta of extractedRegattas) {
            try {
                await upsertRegatta(pool, {
                    ...regatta,
                    source: 'clubspot'
                });
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

        console.log(`✅ Clubspot scrape complete: ${extractedRegattas.length} found, ${added} newly added, ${updated} updated`);
        return { found: extractedRegattas.length, added, updated };

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
    return scrapeHighSchoolSailingCalendar({ axios, cheerio, pool });
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

        console.log(`=== Scraping Complete: ${totalFound} found, ${totalAdded} newly added ===`);
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

