/**
 * Race-results scraper for ClubSpot and Regatta Network.
 * Stores rows in scraped_race_results (separate from the existing
 * regattanetworkdata table used by the public chatbot).
 *
 * Test cap: last LOOKBACK_DAYS (default 60) of events only.
 */

const LOOKBACK_DAYS = 60;
const TABLE = 'scraped_race_results';
const PARSE_APP_ID = 'myclubspot2017';
const PARSE_REGATTAS_URL = 'https://theclubspot.com/parse/classes/regattas';
const CLUBSPOT_RESULTS_API = 'https://results.theclubspot.com/clubspot-results-v4';
const RN_ARCHIVE_URL = 'https://www.regattanetwork.com/html/results.php';
const HTTP_HEADERS = {
    'User-Agent': 'LoveSailing/1.0 (race-results indexer; https://lovesailing.ai)'
};

const job = {
    running: false,
    startedAt: null,
    finishedAt: null,
    source: null,
    lookbackDays: LOOKBACK_DAYS,
    log: [],
    stats: emptyStats(),
    error: null
};

function emptyStats() {
    return {
        regattanetwork: { eventsFound: 0, eventsScraped: 0, rowsUpserted: 0, errors: 0 },
        clubspot: { eventsFound: 0, eventsScraped: 0, rowsUpserted: 0, errors: 0 }
    };
}

function snapshotJob() {
    return {
        running: job.running,
        startedAt: job.startedAt,
        finishedAt: job.finishedAt,
        source: job.source,
        lookbackDays: job.lookbackDays,
        stats: job.stats,
        error: job.error,
        log: job.log.slice(-40)
    };
}

function logLine(message) {
    const line = `[${new Date().toISOString()}] ${message}`;
    console.log('[race-results]', message);
    job.log.push(line);
    if (job.log.length > 80) job.log.splice(0, job.log.length - 80);
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function lookbackCutoff(days) {
    const d = new Date();
    d.setUTCHours(0, 0, 0, 0);
    d.setUTCDate(d.getUTCDate() - days);
    return d;
}

function parseRnDate(text) {
    const m = String(text || '').trim().match(/(\d{1,2})\/(\d{1,2})\/(\d{2})/);
    if (!m) return null;
    const month = parseInt(m[1], 10);
    const day = parseInt(m[2], 10);
    const yy = parseInt(m[3], 10);
    const year = yy < 50 ? 2000 + yy : 1900 + yy;
    const dt = new Date(Date.UTC(year, month - 1, day));
    if (isNaN(dt.getTime())) return null;
    return dt.toISOString().slice(0, 10);
}

function isoDate(val) {
    if (!val) return null;
    if (typeof val === 'object' && val.iso) return String(val.iso).slice(0, 10);
    const s = String(val);
    return s.length >= 10 ? s.slice(0, 10) : null;
}

function cellText($, el) {
    return $(el).text().replace(/\u00a0/g, ' ').replace(/\s+/g, ' ').trim();
}

function normalizeHeader(text) {
    return String(text || '').replace(/\u00a0/g, ' ').replace(/\s+/g, ' ').trim().toLowerCase();
}

async function ensureScrapedResultsTable(pool) {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS ${TABLE} (
            id SERIAL PRIMARY KEY,
            source TEXT NOT NULL,
            source_event_id TEXT NOT NULL,
            source_url TEXT,
            regatta_name TEXT,
            regatta_date DATE,
            category TEXT NOT NULL DEFAULT '',
            position TEXT,
            sail_number TEXT NOT NULL DEFAULT '',
            boat_name TEXT,
            skipper TEXT NOT NULL DEFAULT '',
            yacht_club TEXT,
            results TEXT,
            total_points TEXT,
            scraped_at TIMESTAMP NOT NULL DEFAULT NOW(),
            UNIQUE (source, source_event_id, category, sail_number, skipper)
        )
    `);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_srr_date ON ${TABLE}(regatta_date)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_srr_skipper ON ${TABLE}(skipper)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_srr_regatta ON ${TABLE}(regatta_name)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_srr_source ON ${TABLE}(source)`);
}

async function upsertRows(pool, rows) {
    if (!rows.length) return 0;
    let upserted = 0;
    const BATCH = 40;
    for (let i = 0; i < rows.length; i += BATCH) {
        const batch = rows.slice(i, i + BATCH);
        const values = [];
        const placeholders = batch.map((r, idx) => {
            const b = idx * 13;
            values.push(
                r.source,
                r.source_event_id,
                r.source_url || null,
                r.regatta_name || null,
                r.regatta_date || null,
                r.category || '',
                r.position || null,
                r.sail_number || '',
                r.boat_name || null,
                r.skipper || '',
                r.yacht_club || null,
                r.results || null,
                r.total_points || null
            );
            return `($${b + 1},$${b + 2},$${b + 3},$${b + 4},$${b + 5},$${b + 6},$${b + 7},$${b + 8},$${b + 9},$${b + 10},$${b + 11},$${b + 12},$${b + 13})`;
        });
        const result = await pool.query(`
            INSERT INTO ${TABLE} (
                source, source_event_id, source_url, regatta_name, regatta_date,
                category, position, sail_number, boat_name, skipper, yacht_club,
                results, total_points
            )
            VALUES ${placeholders.join(',')}
            ON CONFLICT (source, source_event_id, category, sail_number, skipper)
            DO UPDATE SET
                source_url = EXCLUDED.source_url,
                regatta_name = EXCLUDED.regatta_name,
                regatta_date = EXCLUDED.regatta_date,
                position = EXCLUDED.position,
                boat_name = EXCLUDED.boat_name,
                yacht_club = EXCLUDED.yacht_club,
                results = EXCLUDED.results,
                total_points = EXCLUDED.total_points,
                scraped_at = NOW()
        `, values);
        upserted += result.rowCount || batch.length;
    }
    return upserted;
}

function parseRnListing($, lookbackDays) {
    const cutoff = lookbackCutoff(lookbackDays).toISOString().slice(0, 10);
    const today = new Date().toISOString().slice(0, 10);
    const events = [];
    const seen = new Set();

    $('tr').each((_, tr) => {
        const $tr = $(tr);
        const $cells = $tr.children('td');
        if ($cells.length < 3) return;

        const dateStr = parseRnDate(cellText($, $cells.eq(0)));
        if (!dateStr || dateStr < cutoff || dateStr > today) return;

        const resultsHref = $cells.eq(2).find('a[href*="applet_regatta_results.php"]').attr('href')
            || $cells.eq(2).find('a[href*="regatta_id="]').attr('href');
        if (!resultsHref) return;

        const idMatch = resultsHref.match(/regatta_id=(\d+)/);
        if (!idMatch) return;
        const sourceEventId = idMatch[1];
        if (seen.has(sourceEventId)) return;
        seen.add(sourceEventId);

        const $eventCell = $cells.eq(1);
        const parts = ($eventCell.clone().find('a').remove().end().html() || '')
            .split(/<br\s*\/?>/i)
            .map(p => cheerioLoadText(p))
            .filter(Boolean);
        const name = parts[0] || cellText($, $eventCell).split('[')[0].trim();
        const yachtClub = parts[1] || null;

        const absUrl = resultsHref.startsWith('http')
            ? resultsHref
            : `https://www.regattanetwork.com${resultsHref.startsWith('/') ? '' : '/clubmgmt/'}${resultsHref.replace(/^(\.\/)?/, '')}`;
        const resultsUrl = absUrl.includes('show_divisions=')
            ? absUrl
            : `${absUrl}${absUrl.includes('?') ? '&' : '?'}show_divisions=1`;

        if (name && name.length > 2) {
            events.push({
                source_event_id: sourceEventId,
                regatta_name: name.replace(/\[Event Website\]/i, '').trim(),
                regatta_date: dateStr,
                host_club: yachtClub || null,
                results_url: resultsUrl.split('#')[0]
            });
        }
    });

    return events;
}

function cheerioLoadText(fragment) {
    return String(fragment || '').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
}

function parseRnResultsPage($, event) {
    const rows = [];
    $('tbody.results').each((_, tbody) => {
        const $tbody = $(tbody);
        const category = ($tbody.attr('data-fleet') || '').trim();
        const $table = $tbody.closest('table');
        const headerCells = $table.find('thead tr').first().children('td, th');
        const headers = [];
        headerCells.each((i, td) => {
            const text = normalizeHeader($(td));
            headers.push({ i, text });
        });

        const col = (name) => {
            const hit = headers.find(h => h.text === name || h.text.startsWith(name));
            return hit ? hit.i : -1;
        };
        const posIdx = col('pos');
        const sailIdx = col('sail');
        const boatIdx = col('boat');
        const skipperIdx = col('skipper');
        const clubIdx = headers.findIndex(h => h.text.includes('yacht') && h.text.includes('club')) >= 0
            ? headers.findIndex(h => h.text.includes('yacht') && h.text.includes('club'))
            : col('club');
        const totalIdx = col('total');
        const raceIdxs = headers.filter(h => /^\d+$/.test(h.text)).map(h => h.i);

        $tbody.children('tr').each((__, tr) => {
            const $tds = $(tr).children('td');
            if (!$tds.length) return;
            const val = (idx) => (idx >= 0 && idx < $tds.length) ? cellText($, $tds.eq(idx)) : '';
            const skipper = val(skipperIdx);
            const sail = val(sailIdx);
            if (!skipper && !sail) return;

            const raceBits = raceIdxs.map(i => val(i)).filter(Boolean);
            rows.push({
                source: 'regattanetwork',
                source_event_id: event.source_event_id,
                source_url: event.results_url,
                regatta_name: event.regatta_name,
                regatta_date: event.regatta_date,
                category,
                position: val(posIdx).replace(/[^\d.]/g, '') || val(posIdx),
                sail_number: sail,
                boat_name: val(boatIdx) || null,
                skipper,
                yacht_club: val(clubIdx) || event.host_club || null,
                results: raceBits.join(',') || null,
                total_points: val(totalIdx) || null
            });
        });
    });
    return rows;
}

function formatClubspotRaceCells(scoringData) {
    if (!Array.isArray(scoringData) || !scoringData.length) return null;
    const sorted = [...scoringData].sort((a, b) => (a.race_number || 0) - (b.race_number || 0));
    return sorted.map(s => {
        let cell;
        if (s.letterScore && s.points != null && s.points !== '') {
            cell = `${s.points}/${s.letterScore}`;
        } else if (s.letterScore) {
            cell = String(s.letterScore);
        } else if (s.points != null && s.points !== '') {
            cell = String(s.points);
        } else {
            cell = '';
        }
        if (s.throwout && cell) cell = `[${cell}]`;
        return cell;
    }).filter(Boolean).join(',') || null;
}

function rowsFromClubspotPayload(payload, event, classId) {
    const regs = (payload && payload.scoresByRegistration) || [];
    if (!regs.length) return [];

    const ranked = regs.map((entry, idx) => {
        const net = Number(entry.net);
        const total = Number(entry.total);
        return {
            entry,
            idx,
            net: Number.isFinite(net) ? net : Number.POSITIVE_INFINITY,
            total: Number.isFinite(total) ? total : Number.POSITIVE_INFINITY
        };
    }).sort((a, b) => a.net - b.net || a.total - b.total || a.idx - b.idx);

    return ranked.map((item, place) => {
        const ro = item.entry.registrationObject || {};
        const className = (ro.boatClassObject && ro.boatClassObject.name) || classId || '';
        const skipper = `${ro.firstName || ''} ${ro.lastName || ''}`.trim()
            || (Array.isArray(ro.participantNames) ? ro.participantNames[0] : '')
            || '';
        const net = item.entry.net;
        const total = item.entry.total;
        const points = (net != null && net !== '') ? String(net) : (total != null ? String(total) : null);
        return {
            source: 'clubspot',
            source_event_id: event.source_event_id,
            source_url: event.results_url,
            regatta_name: event.regatta_name,
            regatta_date: event.regatta_date,
            category: className,
            position: String(place + 1),
            sail_number: ro.sailNumber != null ? String(ro.sailNumber) : '',
            boat_name: ro.boatName || null,
            skipper,
            yacht_club: ro.clubName || event.host_club || null,
            results: formatClubspotRaceCells(item.entry.scoring_data),
            total_points: points
        };
    }).filter(r => r.skipper || r.sail_number);
}

async function scrapeRegattaNetwork(axios, cheerio, pool, lookbackDays) {
    logLine('Regatta Network: loading results archive');
    const response = await axios.get(RN_ARCHIVE_URL, { headers: HTTP_HEADERS, timeout: 45000 });
    const $ = cheerio.load(response.data);
    const events = parseRnListing($, lookbackDays);
    job.stats.regattanetwork.eventsFound = events.length;
    logLine(`Regatta Network: ${events.length} events in last ${lookbackDays} days`);

    for (const event of events) {
        if (!job.running) break;
        try {
            const page = await axios.get(event.results_url, { headers: HTTP_HEADERS, timeout: 45000 });
            const rows = parseRnResultsPage(cheerio.load(page.data), event);
            const n = await upsertRows(pool, rows);
            job.stats.regattanetwork.eventsScraped += 1;
            job.stats.regattanetwork.rowsUpserted += n;
            logLine(`RN ${event.source_event_id}: ${event.regatta_name} → ${rows.length} rows`);
        } catch (err) {
            job.stats.regattanetwork.errors += 1;
            logLine(`RN ${event.source_event_id} error: ${err.message}`);
        }
        await sleep(120);
    }
}

async function listClubspotEvents(axios, lookbackDays) {
    const now = new Date();
    const from = lookbackCutoff(lookbackDays);
    const where = {
        archived: { $ne: true },
        public: { $ne: false },
        endDate: {
            $gte: { __type: 'Date', iso: from.toISOString() },
            $lte: { __type: 'Date', iso: now.toISOString() }
        }
    };
    const base = {
        order: '-endDate',
        include: 'clubObject',
        keys: 'name,startDate,endDate,city,state,clubObject,objectId,boatClassesArray',
        where: JSON.stringify(where)
    };

    const countParams = new URLSearchParams({ ...base, count: '1', limit: '0' });
    const countRes = await axios.get(`${PARSE_REGATTAS_URL}?${countParams}`, {
        headers: { ...HTTP_HEADERS, 'X-Parse-Application-Id': PARSE_APP_ID },
        timeout: 30000
    });
    const total = countRes.data.count || 0;
    const BATCH = 100;
    const pages = Math.ceil(total / BATCH);
    const all = [];

    for (let page = 0; page < pages; page++) {
        const params = new URLSearchParams({
            ...base,
            limit: String(BATCH),
            skip: String(page * BATCH)
        });
        const res = await axios.get(`${PARSE_REGATTAS_URL}?${params}`, {
            headers: { ...HTTP_HEADERS, 'X-Parse-Application-Id': PARSE_APP_ID },
            timeout: 30000
        });
        all.push(...(res.data.results || []));
        if (page < pages - 1) await sleep(150);
    }

    return all.map(r => {
        const club = r.clubObject || {};
        const classes = (r.boatClassesArray || [])
            .map(c => (c && c.objectId) || null)
            .filter(Boolean);
        const start = isoDate(r.startDate);
        const end = isoDate(r.endDate);
        let location = null;
        if (r.city && r.state) location = `${r.city}, ${r.state}`;
        else if (r.city) location = r.city;
        else if (club.name) location = club.name;
        const subdomain = (club.subdomain || '').replace(/[^a-zA-Z0-9-]/g, '');
        const resultsUrl = subdomain
            ? `https://${subdomain}.theclubspot.com/regatta/${r.objectId}/results`
            : `https://www.theclubspot.com/regatta/${r.objectId}/results`;
        return {
            source_event_id: r.objectId,
            regatta_name: r.name,
            regatta_date: start || end,
            host_club: club.name || null,
            location,
            class_ids: classes,
            results_url: resultsUrl
        };
    }).filter(e => e.source_event_id && e.regatta_name && e.class_ids.length);
}

async function scrapeClubspot(axios, pool, lookbackDays) {
    logLine('ClubSpot: listing events via Parse API');
    const events = await listClubspotEvents(axios, lookbackDays);
    job.stats.clubspot.eventsFound = events.length;
    logLine(`ClubSpot: ${events.length} events in last ${lookbackDays} days`);

    for (const event of events) {
        if (!job.running) break;
        try {
            const eventRows = [];
            for (const classId of event.class_ids) {
                const url = `${CLUBSPOT_RESULTS_API}/${event.source_event_id}`;
                const res = await axios.get(url, {
                    params: { boatClassIDs: classId },
                    headers: HTTP_HEADERS,
                    timeout: 30000
                });
                eventRows.push(...rowsFromClubspotPayload(res.data, event, classId));
                await sleep(80);
            }
            const n = await upsertRows(pool, eventRows);
            job.stats.clubspot.eventsScraped += 1;
            job.stats.clubspot.rowsUpserted += n;
            logLine(`CS ${event.source_event_id}: ${event.regatta_name} → ${eventRows.length} rows`);
        } catch (err) {
            job.stats.clubspot.errors += 1;
            logLine(`CS ${event.source_event_id} error: ${err.message}`);
        }
    }
}

async function runScrape({ axios, cheerio, pool, source, lookbackDays }) {
    logLine(`Starting scrape source=${source} lookbackDays=${lookbackDays}`);

    try {
        await ensureScrapedResultsTable(pool);
        if (source === 'all' || source === 'regattanetwork') {
            await scrapeRegattaNetwork(axios, cheerio, pool, lookbackDays);
        }
        if (source === 'all' || source === 'clubspot') {
            await scrapeClubspot(axios, pool, lookbackDays);
        }
        logLine('Scrape complete');
    } catch (err) {
        job.error = err.message;
        logLine(`Scrape failed: ${err.message}`);
    } finally {
        job.running = false;
        job.finishedAt = new Date().toISOString();
    }
}

const CHAT_SYSTEM = `You are a sailing results assistant querying a NEW test table of recently scraped race results (last ~2 months from Regatta Network and ClubSpot).

Interpret the user's question and output ONLY a JSON object with:
- "intent": one of sailor_search, boat_search, club_search, regatta_search, club_sailors, top_sailors, top_clubs, clubs_in_region, data_summary, sample
- "skipper": sailor name when searching a person
- "boat_name": when searching by boat
- "yacht_club": club name
- "regatta_name": when searching a regatta / who won an event
- "year": optional integer
- "region": location/state for "clubs in X"
- "source": optional "regattanetwork" or "clubspot"

Rules:
- Overview / "what's in the data" / counts → intent "data_summary"
- "show me some rows" / "sample" → intent "sample"
- Message contains "regatta" or "who won" plus a name → intent "regatta_search"
- Person name only → intent "sailor_search"
- Reply with ONLY valid JSON.`;

function attachRaceResultsScraper(app, { pool, openai, axios, cheerio }) {
    app.get('/api/race-results/status', (req, res) => {
        res.json({
            success: true,
            tableName: TABLE,
            lookbackDaysDefault: LOOKBACK_DAYS,
            ...snapshotJob()
        });
    });

    app.get('/api/race-results/stats', async (req, res) => {
        try {
            await ensureScrapedResultsTable(pool);
            const r = await pool.query(`
                SELECT
                    COUNT(*)::int AS total_records,
                    COUNT(DISTINCT TRIM(skipper)) FILTER (WHERE skipper IS NOT NULL AND TRIM(skipper) <> '')::int AS total_sailors,
                    COUNT(DISTINCT TRIM(regatta_name)) FILTER (WHERE regatta_name IS NOT NULL AND TRIM(regatta_name) <> '')::int AS total_regattas,
                    MIN(regatta_date)::text AS earliest_date,
                    MAX(regatta_date)::text AS latest_date
                FROM ${TABLE}
            `);
            const bySource = await pool.query(`
                SELECT source, COUNT(*)::int AS count,
                    COUNT(DISTINCT source_event_id)::int AS events
                FROM ${TABLE}
                GROUP BY source
                ORDER BY source
            `);
            const recent = await pool.query(`
                SELECT source, regatta_name, regatta_date::text, category, position, sail_number, skipper, yacht_club, total_points
                FROM ${TABLE}
                ORDER BY scraped_at DESC, id DESC
                LIMIT 12
            `);
            res.json({
                success: true,
                tableName: TABLE,
                ...r.rows[0],
                bySource: bySource.rows,
                recent: recent.rows
            });
        } catch (e) {
            console.error('race-results stats error:', e);
            res.status(500).json({ success: false, error: e.message });
        }
    });

    app.post('/api/race-results/scrape', async (req, res) => {
        if (job.running) {
            return res.status(409).json({ success: false, error: 'A results scrape is already running', status: snapshotJob() });
        }
        const source = (req.body && req.body.source) || 'all';
        if (!['all', 'regattanetwork', 'clubspot'].includes(source)) {
            return res.status(400).json({ success: false, error: 'source must be all, regattanetwork, or clubspot' });
        }
        const lookbackDays = Math.min(60, Math.max(1, parseInt((req.body && req.body.lookbackDays) || LOOKBACK_DAYS, 10) || LOOKBACK_DAYS));
        job.running = true;
        job.startedAt = new Date().toISOString();
        job.finishedAt = null;
        job.source = source;
        job.lookbackDays = lookbackDays;
        job.error = null;
        job.stats = emptyStats();
        job.log = [];
        logLine(`Queued scrape source=${source} lookbackDays=${lookbackDays}`);
        res.json({
            success: true,
            status: 'started',
            message: `Race-results scrape started (${source}, last ${lookbackDays} days). Poll /api/race-results/status.`,
            lookbackDays
        });
        runScrape({ axios, cheerio, pool, source, lookbackDays }).catch(err => {
            job.running = false;
            job.finishedAt = new Date().toISOString();
            job.error = err.message;
            logLine(`Background scrape crash: ${err.message}`);
        });
    });

    app.post('/api/race-results/clear', async (req, res) => {
        try {
            await ensureScrapedResultsTable(pool);
            const r = await pool.query(`DELETE FROM ${TABLE}`);
            res.json({ success: true, deleted: r.rowCount });
        } catch (e) {
            res.status(500).json({ success: false, error: e.message });
        }
    });

    app.post('/api/race-results/chat', async (req, res) => {
        try {
            const message = req.body && req.body.message;
            if (!message || !String(message).trim()) {
                return res.status(400).json({ success: false, error: 'Message required' });
            }
            if (!openai) {
                return res.status(503).json({ success: false, error: 'OpenAI not configured (OPENAI_API_KEY)' });
            }
            await ensureScrapedResultsTable(pool);

            const completion = await openai.chat.completions.create({
                model: 'gpt-4o-mini',
                messages: [
                    { role: 'system', content: CHAT_SYSTEM },
                    { role: 'user', content: String(message).trim() }
                ],
                max_tokens: 256,
                temperature: 0
            });
            const raw = completion.choices?.[0]?.message?.content?.trim() || '{}';
            let parsed = {};
            try {
                parsed = JSON.parse(raw.replace(/^```(?:json)?\s*|\s*```$/g, '').trim());
            } catch (_) {
                parsed = { intent: 'sailor_search', skipper: String(message).trim() };
            }

            const intent = (parsed.intent || '').toLowerCase();
            const criteria = {
                skipper: parsed.skipper,
                boat_name: parsed.boat_name,
                yacht_club: parsed.yacht_club,
                regatta_name: parsed.regatta_name,
                year: parsed.year,
                source: parsed.source
            };

            if (intent === 'data_summary') {
                const r = await pool.query(`
                    SELECT COUNT(*)::int AS total_records,
                        COUNT(DISTINCT TRIM(skipper)) FILTER (WHERE skipper IS NOT NULL AND TRIM(skipper) <> '')::int AS sailors,
                        COUNT(DISTINCT TRIM(regatta_name)) FILTER (WHERE regatta_name IS NOT NULL AND TRIM(regatta_name) <> '')::int AS regattas,
                        MIN(regatta_date)::text AS earliest_date,
                        MAX(regatta_date)::text AS latest_date
                    FROM ${TABLE}
                `);
                const by = await pool.query(`SELECT source, COUNT(*)::int AS count FROM ${TABLE} GROUP BY source`);
                const row = r.rows[0];
                const src = by.rows.map(x => `${x.source}: ${x.count}`).join(', ') || 'none';
                return res.json({
                    success: true,
                    reply: `Scraped results table **${TABLE}** has **${row.total_records}** rows, **${row.sailors}** sailors, **${row.regattas}** regattas. Dates ${row.earliest_date || '—'} to ${row.latest_date || '—'}. By source: ${src}.`,
                    data: { resultType: 'summary', ...row, bySource: by.rows }
                });
            }

            if (intent === 'sample') {
                const r = await pool.query(`
                    SELECT source, regatta_name, regatta_date::text, category, position, sail_number, boat_name, skipper, yacht_club, results, total_points, source_url
                    FROM ${TABLE}
                    ORDER BY regatta_date DESC NULLS LAST, position ASC NULLS LAST
                    LIMIT 25
                `);
                return res.json({
                    success: true,
                    reply: r.rows.length ? `Here are ${r.rows.length} recent scraped result rows.` : 'The scraped table is empty. Run a results scrape first.',
                    data: { resultType: 'rows', rows: r.rows }
                });
            }

            const params = [];
            let n = 0;
            let where = '1=1';
            const add = (col, val) => {
                if (!val || String(val).trim() === '') return;
                n++;
                where += ` AND ${col} ILIKE $${n}`;
                params.push(`%${String(val).trim()}%`);
            };
            add('skipper', criteria.skipper);
            add('boat_name', criteria.boat_name);
            add('yacht_club', criteria.yacht_club);
            add('regatta_name', criteria.regatta_name);
            if (criteria.source) add('source', criteria.source);
            if (criteria.year) {
                n++;
                where += ` AND EXTRACT(YEAR FROM regatta_date) = $${n}`;
                params.push(parseInt(String(criteria.year), 10));
            }

            if (intent === 'top_sailors') {
                const r = await pool.query(`
                    SELECT skipper AS name, COUNT(*)::int AS count
                    FROM ${TABLE}
                    WHERE skipper IS NOT NULL AND TRIM(skipper) <> ''
                    GROUP BY skipper ORDER BY count DESC, skipper ASC LIMIT 15
                `);
                return res.json({
                    success: true,
                    reply: r.rows.length ? 'Top sailors in the scraped table (by result rows):' : 'No sailor data yet.',
                    data: { resultType: 'list', rows: r.rows }
                });
            }
            if (intent === 'top_clubs') {
                const r = await pool.query(`
                    SELECT yacht_club AS name, COUNT(*)::int AS count
                    FROM ${TABLE}
                    WHERE yacht_club IS NOT NULL AND TRIM(yacht_club) <> ''
                    GROUP BY yacht_club ORDER BY count DESC, yacht_club ASC LIMIT 15
                `);
                return res.json({
                    success: true,
                    reply: r.rows.length ? 'Top clubs in the scraped table:' : 'No club data yet.',
                    data: { resultType: 'list', rows: r.rows }
                });
            }
            if (intent === 'club_sailors' && criteria.yacht_club) {
                const r = await pool.query(`
                    SELECT skipper AS name, COUNT(*)::int AS count
                    FROM ${TABLE}
                    WHERE yacht_club ILIKE $1 AND skipper IS NOT NULL AND TRIM(skipper) <> ''
                    GROUP BY skipper ORDER BY count DESC LIMIT 40
                `, ['%' + String(criteria.yacht_club).trim() + '%']);
                return res.json({
                    success: true,
                    reply: r.rows.length ? `Sailors at ${criteria.yacht_club}:` : `No sailors found for ${criteria.yacht_club}.`,
                    data: { resultType: 'list', rows: r.rows }
                });
            }

            if (n === 0 && !['regatta_search', 'sailor_search', 'boat_search', 'club_search'].includes(intent)) {
                return res.json({
                    success: true,
                    reply: 'Try a sailor name, boat, club, regatta, "who won [event]", "top sailors", or "what\'s in the data".',
                    data: null
                });
            }

            n++;
            params.push(80);
            const result = await pool.query(`
                SELECT source, regatta_name, regatta_date::text, category, position, sail_number, boat_name, skipper, yacht_club, results, total_points, source_url
                FROM ${TABLE}
                WHERE ${where}
                ORDER BY regatta_date DESC NULLS LAST, position ASC NULLS LAST
                LIMIT $${n}
            `, params);

            let reply;
            if (!result.rows.length) {
                reply = 'No matching rows in the scraped results table yet. If you just started a scrape, wait for it to finish.';
            } else if (intent === 'regatta_search') {
                const winners = result.rows.filter(r => String(r.position) === '1');
                reply = `Found **${result.rows.length}** result rows for that regatta. ${winners.length ? 'First-place boats are listed first where position = 1.' : ''}`;
            } else {
                reply = `Found **${result.rows.length}** matching result row(s) in the scraped table.`;
            }

            res.json({
                success: true,
                reply,
                data: { resultType: 'rows', rows: result.rows }
            });
        } catch (e) {
            console.error('race-results chat error:', e);
            res.status(500).json({ success: false, error: e.message });
        }
    });
}

module.exports = {
    LOOKBACK_DAYS,
    TABLE,
    ensureScrapedResultsTable,
    attachRaceResultsScraper,
    parseRnListing,
    parseRnResultsPage,
    rowsFromClubspotPayload
};
