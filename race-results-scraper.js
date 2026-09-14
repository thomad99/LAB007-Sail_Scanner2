/**
 * Race-results scraper for ClubSpot and Regatta Network.
 * Stores rows in scraped_race_results (separate from the existing
 * regattanetworkdata table used by the public chatbot).
 *
 * Lookback window is chosen in the admin UI (default 60 days, max 365).
 */

const { parseChatIntent } = require('./chat-intent');
const { PARSE_APP_ID, clubspotGet, clubspotConfigSummary } = require('./clubspot-http');
const { parseRnListingRows, withRnShowDivisions } = require('./regatta-scrape-helpers');

const LOOKBACK_DAYS = 60;
const LOOKBACK_MAX_DAYS = 365;
const TABLE = 'scraped_race_results';
const PARSE_REGATTAS_URL = 'https://theclubspot.com/parse/classes/regattas';
const PARSE_BOAT_CLASSES_URL = 'https://theclubspot.com/parse/classes/boatClasses';
const CLUBSPOT_RESULTS_API = 'https://results.theclubspot.com/clubspot-results-v4';
const RN_ARCHIVE_URL = 'https://www.regattanetwork.com/html/results.php';
const HTTP_HEADERS = {
    'User-Agent': 'LoveSailing/1.0 (race-results indexer; https://lovesailing.ai)'
};

const SCRAPE_LOG_TABLE = 'race_results_scrape_log';
const STATS_SNAPSHOT_TABLE = 'race_results_stats';
const STATS_MAX_AGE_MS = 24 * 60 * 60 * 1000;
const STATS_REFRESH_TIMEOUT_MS = 180000;

const job = {
    running: false,
    startedAt: null,
    finishedAt: null,
    source: null,
    mode: 'lookback',
    year: null,
    lookbackDays: LOOKBACK_DAYS,
    fromDate: null,
    toDate: null,
    windowLabel: null,
    trigger: 'manual',
    log: [],
    stats: emptyStats(),
    error: null
};

let schemaReadyPromise = null;

function emptySourceStats() {
    return {
        eventsFound: 0,
        eventsScraped: 0,
        rowsInserted: 0,
        rowsUpdated: 0,
        errors: 0,
        regattas: 0,
        sailors: 0
    };
}

function emptyStats() {
    return {
        regattanetwork: emptySourceStats(),
        clubspot: emptySourceStats()
    };
}

function emptyCollected() {
    return {
        regattanetwork: { regattas: new Set(), sailors: new Set() },
        clubspot: { regattas: new Set(), sailors: new Set() }
    };
}

let collected = emptyCollected();

function noteCollected(sourceKey, rows) {
    const bucket = collected[sourceKey];
    if (!bucket) return;
    for (const row of rows || []) {
        const regattaName = normalizeSpace(row.regatta_name);
        const skipper = normalizeSpace(row.skipper);
        if (regattaName) bucket.regattas.add(regattaName.toLowerCase());
        if (skipper) bucket.sailors.add(skipper.toLowerCase());
    }
    job.stats[sourceKey].regattas = bucket.regattas.size;
    job.stats[sourceKey].sailors = bucket.sailors.size;
}

function normalizeSpace(s) {
    return String(s == null ? '' : s).replace(/\u00a0/g, ' ').replace(/\s+/g, ' ').trim();
}

function normalizeSail(s) {
    return normalizeSpace(s).replace(/[\s-]/g, '').toUpperCase();
}

function resultDedupeKey(row) {
    return [
        normalizeSpace(row.source).toLowerCase(),
        normalizeSpace(row.source_event_id).toLowerCase(),
        normalizeSpace(row.category).toLowerCase(),
        normalizeSail(row.sail_number),
        normalizeSpace(row.skipper).toLowerCase()
    ].join('|');
}

function normalizeResultRow(row) {
    return {
        ...row,
        category: normalizeSpace(row.category),
        sail_number: normalizeSpace(row.sail_number),
        skipper: normalizeSpace(row.skipper),
        boat_name: normalizeSpace(row.boat_name) || null,
        yacht_club: normalizeSpace(row.yacht_club) || null,
        position: normalizeSpace(row.position) || null,
        results: normalizeSpace(row.results) || null,
        total_points: normalizeSpace(row.total_points) || null,
        dedupe_key: resultDedupeKey(row)
    };
}

function dedupeResultRows(rows) {
    const byKey = new Map();
    for (const raw of rows) {
        const row = normalizeResultRow(raw);
        if (!row.dedupe_key || (!row.skipper && !row.sail_number)) continue;
        byKey.set(row.dedupe_key, row);
    }
    return Array.from(byKey.values());
}

function snapshotJob() {
    return {
        running: job.running,
        startedAt: job.startedAt,
        finishedAt: job.finishedAt,
        source: job.source,
        mode: job.mode,
        year: job.year,
        lookbackDays: job.lookbackDays,
        fromDate: job.fromDate,
        toDate: job.toDate,
        windowLabel: job.windowLabel,
        trigger: job.trigger,
        stats: job.stats,
        error: job.error,
        log: job.log.slice(-40)
    };
}

/** Resolve a rolling lookback or a full calendar year into an inclusive UTC date window. */
function resolveScrapeWindow({ lookbackDays, year } = {}) {
    const now = new Date();
    now.setUTCHours(0, 0, 0, 0);
    const today = now.toISOString().slice(0, 10);
    const y = year != null && String(year).trim() !== '' ? parseInt(year, 10) : NaN;
    if (Number.isFinite(y) && y >= 2000 && y <= now.getUTCFullYear() + 1) {
        const fromDate = `${y}-01-01`;
        let toDate = `${y}-12-31`;
        if (toDate > today) toDate = today;
        return {
            mode: 'year',
            year: y,
            lookbackDays: null,
            fromDate,
            toDate,
            label: `Year ${y}`
        };
    }
    const days = Math.min(
        LOOKBACK_MAX_DAYS,
        Math.max(1, parseInt(lookbackDays || LOOKBACK_DAYS, 10) || LOOKBACK_DAYS)
    );
    const from = lookbackCutoff(days);
    return {
        mode: 'lookback',
        year: null,
        lookbackDays: days,
        fromDate: from.toISOString().slice(0, 10),
        toDate: today,
        label: `Last ${days} days`
    };
}

function normalizeListingWindow(lookbackOrWindow) {
    if (lookbackOrWindow && typeof lookbackOrWindow === 'object') {
        return {
            fromDate: lookbackOrWindow.fromDate,
            toDate: lookbackOrWindow.toDate,
            label: lookbackOrWindow.label || null
        };
    }
    const days = lookbackOrWindow || LOOKBACK_DAYS;
    return {
        fromDate: lookbackCutoff(days).toISOString().slice(0, 10),
        toDate: new Date().toISOString().slice(0, 10),
        label: `Last ${days} days`
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

async function ensureResultsScrapeLogTable(pool) {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS ${SCRAPE_LOG_TABLE} (
            id SERIAL PRIMARY KEY,
            source TEXT NOT NULL,
            mode TEXT NOT NULL,
            lookback_days INTEGER,
            year INTEGER,
            from_date DATE,
            to_date DATE,
            events_found INTEGER DEFAULT 0,
            events_scraped INTEGER DEFAULT 0,
            rows_inserted INTEGER DEFAULT 0,
            rows_updated INTEGER DEFAULT 0,
            errors INTEGER DEFAULT 0,
            started_at TIMESTAMPTZ,
            finished_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
            status TEXT NOT NULL DEFAULT 'success',
            triggered_by TEXT NOT NULL DEFAULT 'manual'
        )
    `);
    await pool.query(`ALTER TABLE ${SCRAPE_LOG_TABLE} ADD COLUMN IF NOT EXISTS triggered_by TEXT NOT NULL DEFAULT 'manual'`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_rrsl_source_year ON ${SCRAPE_LOG_TABLE}(source, year)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_rrsl_finished ON ${SCRAPE_LOG_TABLE}(finished_at DESC)`);
}

async function logResultsScrape(pool, { source, window, stats, startedAt, status, triggeredBy }) {
    try {
        await ensureResultsScrapeLogTable(pool);
        await pool.query(
            `
            INSERT INTO ${SCRAPE_LOG_TABLE} (
                source, mode, lookback_days, year, from_date, to_date,
                events_found, events_scraped, rows_inserted, rows_updated, errors,
                started_at, finished_at, status, triggered_by
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,CURRENT_TIMESTAMP,$13,$14)
            `,
            [
                source,
                window.mode,
                window.lookbackDays,
                window.year,
                window.fromDate,
                window.toDate,
                stats.eventsFound || 0,
                stats.eventsScraped || 0,
                stats.rowsInserted || 0,
                stats.rowsUpdated || 0,
                stats.errors || 0,
                startedAt || null,
                status || 'success',
                triggeredBy || job.trigger || 'manual'
            ]
        );
    } catch (err) {
        console.error('[race-results] scrape log write failed:', err.message);
    }
}

async function ensureScrapedResultsTable(pool) {
    // Table/columns only — no index builds on read/startup (those can lock & timeout).
    if (schemaReadyPromise) return schemaReadyPromise;
    schemaReadyPromise = (async () => {
        await ensureResultsScrapeLogTable(pool);
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
                dedupe_key TEXT
            )
        `);
        await pool.query(`ALTER TABLE ${TABLE} ADD COLUMN IF NOT EXISTS dedupe_key TEXT`);
    })().catch((err) => {
        schemaReadyPromise = null;
        throw err;
    });
    return schemaReadyPromise;
}

async function withStatementTimeout(pool, timeoutMs, fn) {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        await client.query(`SET LOCAL statement_timeout = ${Math.max(1000, Number(timeoutMs) || 8000)}`);
        const result = await fn(client);
        await client.query('COMMIT');
        return result;
    } catch (err) {
        try { await client.query('ROLLBACK'); } catch (_) { /* ignore */ }
        throw err;
    } finally {
        client.release();
    }
}

/** Session-level timeout, no transaction — for long background scans and CONCURRENTLY. */
async function withSessionTimeout(pool, timeoutMs, fn) {
    const client = await pool.connect();
    try {
        await client.query(`SET statement_timeout = ${Math.max(1000, Number(timeoutMs) || 8000)}`);
        return await fn(client);
    } finally {
        try { await client.query('RESET statement_timeout'); } catch (_) { /* ignore */ }
        client.release();
    }
}

function parseJsonArray(value) {
    let parsed = value;
    if (typeof parsed === 'string') {
        try { parsed = JSON.parse(parsed); } catch (_) { return []; }
    }
    return Array.isArray(parsed) ? parsed : [];
}

function emptyStatsSnapshot() {
    return {
        success: true,
        tableName: TABLE,
        total_records: 0,
        total_sailors: 0,
        total_regattas: 0,
        earliest_date: null,
        latest_date: null,
        earliest_year: null,
        latest_year: null,
        bySource: [],
        dataYears: [],
        recent: [],
        computed_at: null,
        snapshot: true
    };
}

function formatStatsSnapshot(row) {
    if (!row) return emptyStatsSnapshot();
    const earliest = row.earliest_date ? String(row.earliest_date).slice(0, 10) : null;
    const latest = row.latest_date ? String(row.latest_date).slice(0, 10) : null;
    const earliestYear = earliest ? parseInt(earliest.slice(0, 4), 10) : null;
    const latestYear = latest ? parseInt(latest.slice(0, 4), 10) : null;
    const bySource = parseJsonArray(row.by_source != null ? row.by_source : row.bySource);
    const dataYears = parseJsonArray(row.data_years != null ? row.data_years : row.dataYears);
    return {
        success: true,
        tableName: TABLE,
        total_records: Number(row.total_records) || 0,
        total_sailors: Number(row.total_sailors) || 0,
        total_regattas: Number(row.total_regattas) || 0,
        earliest_date: earliest,
        latest_date: latest,
        earliest_year: Number.isFinite(earliestYear) ? earliestYear : null,
        latest_year: Number.isFinite(latestYear) ? latestYear : null,
        bySource,
        dataYears,
        recent: [],
        computed_at: row.computed_at || null,
        snapshot: true
    };
}

function snapshotIsFresh(snapshot) {
    if (!snapshot || !snapshot.computed_at) return false;
    const age = Date.now() - new Date(snapshot.computed_at).getTime();
    return Number.isFinite(age) && age >= 0 && age < STATS_MAX_AGE_MS;
}

async function ensureStatsSnapshotTable(pool) {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS ${STATS_SNAPSHOT_TABLE} (
            id INTEGER PRIMARY KEY DEFAULT 1,
            total_records INTEGER NOT NULL DEFAULT 0,
            total_sailors INTEGER NOT NULL DEFAULT 0,
            total_regattas INTEGER NOT NULL DEFAULT 0,
            earliest_date DATE,
            latest_date DATE,
            by_source JSONB NOT NULL DEFAULT '[]'::jsonb,
            data_years JSONB NOT NULL DEFAULT '[]'::jsonb,
            computed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            CONSTRAINT race_results_stats_singleton CHECK (id = 1)
        )
    `);
    await pool.query(`
        ALTER TABLE ${STATS_SNAPSHOT_TABLE}
        ADD COLUMN IF NOT EXISTS data_years JSONB NOT NULL DEFAULT '[]'::jsonb
    `);
}

async function readRaceResultsStatsSnapshot(pool) {
    await ensureStatsSnapshotTable(pool);
    const r = await pool.query(`SELECT * FROM ${STATS_SNAPSHOT_TABLE} WHERE id = 1`);
    return r.rows[0] ? formatStatsSnapshot(r.rows[0]) : null;
}

let statsRefreshPromise = null;
let statsIndexPromise = null;

async function ensureRaceResultsStatsIndexes(pool) {
    if (statsIndexPromise) return statsIndexPromise;
    statsIndexPromise = (async () => {
        const statements = [
            `CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_srr_skipper ON ${TABLE}(skipper)`,
            `CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_srr_skipper_trim ON ${TABLE}(TRIM(skipper)) WHERE skipper IS NOT NULL AND TRIM(skipper) <> ''`,
            `CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_srr_regatta ON ${TABLE}(regatta_name)`,
            `CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_srr_date ON ${TABLE}(regatta_date)`,
            `CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_srr_source ON ${TABLE}(source)`
        ];
        const client = await pool.connect();
        try {
            await client.query('SET statement_timeout = 0');
            for (const sql of statements) {
                try {
                    await client.query(sql);
                    console.log('[race-results] index ready:', sql.replace(/\s+/g, ' ').slice(0, 90));
                } catch (err) {
                    console.warn('[race-results] index skipped:', err.message);
                }
            }
        } finally {
            try { await client.query('RESET statement_timeout'); } catch (_) { /* ignore */ }
            client.release();
        }
    })().catch((err) => {
        console.error('[race-results] background index create failed:', err.message);
        statsIndexPromise = null;
        return null;
    });
    return statsIndexPromise;
}

async function refreshRaceResultsStatsSnapshot(pool) {
    if (statsRefreshPromise) return statsRefreshPromise;
    statsRefreshPromise = (async () => {
        await ensureScrapedResultsTable(pool);
        await ensureStatsSnapshotTable(pool);
        console.log(`[race-results] computing stats snapshot (statement_timeout=${STATS_REFRESH_TIMEOUT_MS}ms)...`);
        const computed = await withSessionTimeout(pool, STATS_REFRESH_TIMEOUT_MS, async (client) => {
            const totals = await client.query(`SELECT COUNT(*)::int AS total_records FROM ${TABLE}`);
            const sailors = await client.query(`
                SELECT COUNT(*)::int AS total_sailors FROM (
                    SELECT DISTINCT TRIM(skipper) AS skipper
                    FROM ${TABLE}
                    WHERE skipper IS NOT NULL AND TRIM(skipper) <> ''
                ) s
            `);
            const regattas = await client.query(`
                SELECT COUNT(*)::int AS total_regattas FROM (
                    SELECT DISTINCT TRIM(regatta_name) AS regatta_name
                    FROM ${TABLE}
                    WHERE regatta_name IS NOT NULL AND TRIM(regatta_name) <> ''
                ) r
            `);
            const dates = await client.query(`
                SELECT MIN(regatta_date)::text AS earliest_date,
                    MAX(regatta_date)::text AS latest_date
                FROM ${TABLE}
            `);
            const bySource = await client.query(`
                SELECT source, COUNT(*)::int AS count,
                    COUNT(DISTINCT source_event_id)::int AS events
                FROM ${TABLE}
                GROUP BY source
                ORDER BY source
            `);
            const dataYears = await client.query(`
                SELECT source, EXTRACT(YEAR FROM regatta_date)::int AS year,
                    COUNT(*)::int AS rows,
                    COUNT(DISTINCT source_event_id)::int AS events
                FROM ${TABLE}
                WHERE regatta_date IS NOT NULL
                GROUP BY source, EXTRACT(YEAR FROM regatta_date)
                ORDER BY source, year DESC
            `);
            return {
                total_records: totals.rows[0] && totals.rows[0].total_records || 0,
                total_sailors: sailors.rows[0] && sailors.rows[0].total_sailors || 0,
                total_regattas: regattas.rows[0] && regattas.rows[0].total_regattas || 0,
                earliest_date: dates.rows[0] && dates.rows[0].earliest_date || null,
                latest_date: dates.rows[0] && dates.rows[0].latest_date || null,
                bySource: bySource.rows || [],
                dataYears: dataYears.rows || []
            };
        });
        await pool.query(
            `
            INSERT INTO ${STATS_SNAPSHOT_TABLE} (
                id, total_records, total_sailors, total_regattas,
                earliest_date, latest_date, by_source, data_years, computed_at
            ) VALUES (1, $1, $2, $3, $4, $5, $6::jsonb, $7::jsonb, NOW())
            ON CONFLICT (id) DO UPDATE SET
                total_records = EXCLUDED.total_records,
                total_sailors = EXCLUDED.total_sailors,
                total_regattas = EXCLUDED.total_regattas,
                earliest_date = EXCLUDED.earliest_date,
                latest_date = EXCLUDED.latest_date,
                by_source = EXCLUDED.by_source,
                data_years = EXCLUDED.data_years,
                computed_at = EXCLUDED.computed_at
            `,
            [
                computed.total_records || 0,
                computed.total_sailors || 0,
                computed.total_regattas || 0,
                computed.earliest_date || null,
                computed.latest_date || null,
                JSON.stringify(computed.bySource || []),
                JSON.stringify(computed.dataYears || [])
            ]
        );
        const snapshot = await readRaceResultsStatsSnapshot(pool);
        console.log(
            '[race-results] stats snapshot stored:',
            snapshot.total_sailors, 'sailors,',
            snapshot.total_regattas, 'regattas,',
            (snapshot.dataYears || []).length, 'dataYear rows,',
            'computed_at=', snapshot.computed_at
        );
        return snapshot;
    })().catch((err) => {
        console.error('[race-results] background stats snapshot failed:', err.message);
        throw err;
    }).finally(() => {
        statsRefreshPromise = null;
    });
    return statsRefreshPromise;
}

async function refreshRaceResultsStatsIfStale(pool) {
    try {
        const snapshot = await readRaceResultsStatsSnapshot(pool);
        if (snapshotIsFresh(snapshot)) {
            console.log('[race-results] serving stored stats snapshot computed_at=', snapshot.computed_at);
            return snapshot;
        }
        return await refreshRaceResultsStatsSnapshot(pool);
    } catch (err) {
        console.error('[race-results] stats snapshot refresh failed:', err.message);
        return null;
    }
}

function kickStaleStatsRefresh(pool, snapshot) {
    if (snapshotIsFresh(snapshot)) return;
    if (!snapshot || !snapshot.computed_at) {
        console.warn('[race-results] stats snapshot missing — serving zeros and starting background refresh');
    } else {
        console.log('[race-results] stats snapshot stale (computed_at=', snapshot.computed_at, ') — serving stored snapshot and starting background refresh');
    }
    refreshRaceResultsStatsSnapshot(pool).catch((err) => {
        console.error('[race-results] background stats snapshot failed:', err.message);
    });
}

/** Optional heavy cleanup — only after scrapes, never on dashboard reads. */
async function cleanupScrapedResultsData(pool) {
    await ensureScrapedResultsTable(pool);
    await pool.query(`
        UPDATE ${TABLE} SET
            category = TRIM(REGEXP_REPLACE(COALESCE(category, ''), '\\s+', ' ', 'g')),
            skipper = TRIM(REGEXP_REPLACE(COALESCE(skipper, ''), '\\s+', ' ', 'g')),
            sail_number = TRIM(REGEXP_REPLACE(COALESCE(sail_number, ''), '\\s+', ' ', 'g')),
            boat_name = NULLIF(TRIM(REGEXP_REPLACE(COALESCE(boat_name, ''), '\\s+', ' ', 'g')), ''),
            yacht_club = NULLIF(TRIM(REGEXP_REPLACE(COALESCE(yacht_club, ''), '\\s+', ' ', 'g')), '')
        WHERE category IS DISTINCT FROM TRIM(REGEXP_REPLACE(COALESCE(category, ''), '\\s+', ' ', 'g'))
           OR skipper IS DISTINCT FROM TRIM(REGEXP_REPLACE(COALESCE(skipper, ''), '\\s+', ' ', 'g'))
           OR sail_number IS DISTINCT FROM TRIM(REGEXP_REPLACE(COALESCE(sail_number, ''), '\\s+', ' ', 'g'))
    `);
    await pool.query(`
        UPDATE ${TABLE} SET dedupe_key =
            LOWER(TRIM(source)) || '|' ||
            LOWER(TRIM(source_event_id)) || '|' ||
            LOWER(TRIM(COALESCE(category, ''))) || '|' ||
            UPPER(REGEXP_REPLACE(TRIM(COALESCE(sail_number, '')), '[\\s-]+', '', 'g')) || '|' ||
            LOWER(TRIM(COALESCE(skipper, '')))
        WHERE dedupe_key IS NULL OR TRIM(dedupe_key) = ''
    `);
    const cleaned = await pool.query(`
        DELETE FROM ${TABLE} a
        USING ${TABLE} b
        WHERE a.dedupe_key = b.dedupe_key
          AND a.dedupe_key IS NOT NULL
          AND a.id > b.id
    `);
    if (cleaned.rowCount) {
        console.log(`[race-results] Removed ${cleaned.rowCount} duplicate row(s)`);
    }
    // Indexes after scrape only (never on dashboard reads).
    try {
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_srr_date ON ${TABLE}(regatta_date)`);
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_srr_skipper ON ${TABLE}(skipper)`);
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_srr_regatta ON ${TABLE}(regatta_name)`);
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_srr_source ON ${TABLE}(source)`);
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_srr_scraped_at ON ${TABLE}(scraped_at DESC)`);
        await pool.query(`
            DO $$
            DECLARE r RECORD;
            BEGIN
                FOR r IN
                    SELECT c.conname
                    FROM pg_constraint c
                    JOIN pg_class t ON c.conrelid = t.oid
                    WHERE t.relname = '${TABLE}'
                      AND c.contype = 'u'
                LOOP
                    EXECUTE format('ALTER TABLE ${TABLE} DROP CONSTRAINT IF EXISTS %I', r.conname);
                END LOOP;
            END $$;
        `);
        await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS idx_srr_dedupe_key ON ${TABLE}(dedupe_key)`);
    } catch (err) {
        console.error('[race-results] post-scrape index maintenance skipped:', err.message);
    }
}


async function upsertRows(pool, rows) {
    const uniqueRows = dedupeResultRows(rows);
    if (!uniqueRows.length) return { inserted: 0, updated: 0, total: 0 };
    let inserted = 0;
    let updated = 0;
    const BATCH = 40;
    for (let i = 0; i < uniqueRows.length; i += BATCH) {
        const batch = uniqueRows.slice(i, i + BATCH);
        const values = [];
        const placeholders = batch.map((r, idx) => {
            const b = idx * 14;
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
                r.total_points || null,
                r.dedupe_key
            );
            return `($${b + 1},$${b + 2},$${b + 3},$${b + 4},$${b + 5},$${b + 6},$${b + 7},$${b + 8},$${b + 9},$${b + 10},$${b + 11},$${b + 12},$${b + 13},$${b + 14})`;
        });
        const result = await pool.query(`
            INSERT INTO ${TABLE} (
                source, source_event_id, source_url, regatta_name, regatta_date,
                category, position, sail_number, boat_name, skipper, yacht_club,
                results, total_points, dedupe_key
            )
            VALUES ${placeholders.join(',')}
            ON CONFLICT (dedupe_key)
            DO UPDATE SET
                source_url = EXCLUDED.source_url,
                regatta_name = EXCLUDED.regatta_name,
                regatta_date = EXCLUDED.regatta_date,
                category = EXCLUDED.category,
                position = EXCLUDED.position,
                sail_number = EXCLUDED.sail_number,
                boat_name = EXCLUDED.boat_name,
                skipper = EXCLUDED.skipper,
                yacht_club = EXCLUDED.yacht_club,
                results = EXCLUDED.results,
                total_points = EXCLUDED.total_points,
                scraped_at = NOW()
            RETURNING (xmax = 0) AS inserted
        `, values);
        for (const row of result.rows) {
            if (row.inserted) inserted += 1;
            else updated += 1;
        }
    }
    return { inserted, updated, total: inserted + updated };
}

function parseRnListing($, lookbackOrWindow) {
    const { fromDate, toDate } = normalizeListingWindow(lookbackOrWindow);
    return parseRnListingRows($, {
        fromDate,
        toDate,
        requireResults: true
    }).map((row) => ({
        source_event_id: row.source_event_id,
        regatta_name: row.regatta_name,
        regatta_date: row.regatta_date,
        host_club: row.host_club || null,
        results_url: withRnShowDivisions(row.results_url)
    }));
}

function cheerioLoadText(fragment) {
    return String(fragment || '')
        .replace(/<[^>]+>/g, ' ')
        .replace(/&nbsp;/gi, ' ')
        .replace(/&amp;/gi, '&')
        .replace(/&lt;/gi, '<')
        .replace(/&gt;/gi, '>')
        .replace(/\s+/g, ' ')
        .trim();
}

function cleanRnCategory(text) {
    return normalizeSpace(text)
        .replace(/\(top\)/ig, ' ')
        .replace(/Series Standing.*/i, ' ')
        .replace(/\(\s*\d+\s*boats?\)/ig, ' ')
        .replace(/\s+/g, ' ')
        .trim();
}

function nearestRnCategory($, $el) {
    const $tbody = $el.closest('tbody');
    const fleet = ($tbody.attr('data-fleet') || '').trim();
    if (fleet) return fleet;
    const $h2 = $el.closest('table').prevAll('h2').first();
    if ($h2.length) {
        const named = cellText($, $h2.find('a[name]').first()) || cellText($, $h2.find('a').first());
        if (named) return cleanRnCategory(named);
        return cleanRnCategory(cellText($, $h2));
    }
    return '';
}

const RN_LETTER_SCORES = 'DNC|DNS|DNF|DSQ|DNE|DGM|OCS|UFD|BFD|SCP|ZFP|TLE|NSC|RET|RAF|RDG|DPI|DCT|STP';
const RN_RACE_SCORE_RE = new RegExp(
    `^(?:\\d+(?:\\.\\d+)?(?:\\/(?:${RN_LETTER_SCORES}))?|(?:${RN_LETTER_SCORES})(?:\\/\\d+(?:\\.\\d+)?)?)$`,
    'i'
);
const RN_SKIP_CELL_CLASS_RE = /pos|sail-num|boatname|handicap|country|corrected-time|elapsed-time|finish-time/;

function isRnClockTime(text) {
    const t = normalizeSpace(text);
    if (/^NO\s*TIME$/i.test(t)) return true;
    return /^\d{1,2}:\d{2}(?::\d{2})?(?:\.\d+)?$/.test(t.replace(/\s+/g, ''));
}

function unwrapRnScore(text) {
    const t = normalizeSpace(text).replace(/\s+/g, '');
    const m = t.match(/^\[(.+)\]$/) || t.match(/^\((.+)\)$/);
    return m ? m[1] : t;
}

function isRnRaceScore(text) {
    const inner = unwrapRnScore(text);
    if (!inner || isRnClockTime(inner)) return false;
    if (RN_RACE_SCORE_RE.test(inner)) return true;
    return /^\d+(?:\.\d+)?\/[A-Z]{2,8}(?:-[A-Z0-9]{1,8})?$/i.test(inner);
}

function hrefMatchesRnFleet(href, fleet) {
    if (!fleet) return true;
    const decoded = decodeURIComponent(String(href || '').replace(/\+/g, '%20')).replace(/\s+/g, ' ');
    const want = String(fleet).replace(/\s+/g, ' ');
    return decoded.toLowerCase().includes(want.toLowerCase());
}

function getRnRaceColumnIndexes($, $tbody) {
    const fleet = (($tbody && $tbody.attr && $tbody.attr('data-fleet')) || '').trim();
    const findHeader = (scope, matchFleet) => {
        let $header = null;
        if (!scope || !scope.length) return null;
        scope.find('tr').each((_, tr) => {
            const $tr = $(tr);
            const $link = $tr.find('a[href*="race_num="]').first();
            if (!$link.length) return;
            if (matchFleet && !hrefMatchesRnFleet($link.attr('href'), fleet)) return;
            $header = $tr;
            return false;
        });
        return $header;
    };

    const $table = $tbody && $tbody.closest ? $tbody.closest('table') : null;
    let $header = $table && $table.length ? findHeader($table, false) : null;
    if (!$header) {
        $('tr').each((_, tr) => {
            const $tr = $(tr);
            const $link = $tr.find('a[href*="race_num="]').first();
            if (!$link.length) return;
            if (fleet && !hrefMatchesRnFleet($link.attr('href'), fleet)) return;
            $header = $tr;
            return false;
        });
    }
    if (!$header || !$header.length) return [];
    const idxs = [];
    $header.children('td, th').each((i, cell) => {
        if ($(cell).find('a[href*="race_num="]').length) idxs.push(i);
    });
    return idxs;
}

function firstNumericRnPos($, $tr) {
    let pos = '';
    $tr.find('td.pos').each((_, td) => {
        if (pos) return;
        const t = cellText($, $(td));
        const n = t.replace(/[^\d.]/g, '');
        if (n) pos = n;
    });
    return pos;
}

function extractRnRaceBits($, $tr, raceIdxs) {
    if (raceIdxs && raceIdxs.length) {
        const $cells = $tr.children('td');
        return raceIdxs.map((i) => cellText($, $cells.eq(i)).replace(/\s+/g, ''));
    }
    const raceBits = [];
    $tr.children('td').each((_, td) => {
        const $td = $(td);
        const cls = $td.attr('class') || '';
        if (RN_SKIP_CELL_CLASS_RE.test(cls)) return;
        if ($td.find('.the-score').length) return;
        const bg = ($td.attr('bgcolor') || '').toUpperCase();
        if (bg === '#999999') return;
        const t = cellText($, $td);
        if (isRnRaceScore(t)) raceBits.push(t.replace(/\s+/g, ''));
    });
    return raceBits;
}

function extractRnResultRow($, $tr, category, raceIdxs) {
    const $score = $tr.find('.the-score').first();
    const rawSkipper = normalizeSpace($score.attr('data-skipper') || cellText($, $tr.find('td.country').first()));
    const sail = normalizeSpace($score.attr('data-sail') || cellText($, $tr.find('td.sail-num').first()));
    const boat = normalizeSpace($score.attr('data-boat') || cellText($, $tr.find('td.boatname').first()));
    if (!rawSkipper && !sail) return [];

    const cat = category || nearestRnCategory($, $tr);
    const pos = firstNumericRnPos($, $tr);
    const total = normalizeSpace(cellText($, $score));

    let yachtClub = '';
    const $country = $tr.find('td.country').first();
    if ($country.length) {
        let $n = $country.next();
        while ($n.length) {
            const cls = ($n.attr('class') || '');
            const bg = ($n.attr('bgcolor') || '').toUpperCase();
            const t = cellText($, $n);
            if (bg === '#999999' || RN_SKIP_CELL_CLASS_RE.test(cls) || $n.find('.the-score').length) {
                $n = $n.next();
                continue;
            }
            if (t && !isRnClockTime(t) && !isRnRaceScore(t)) {
                yachtClub = t;
                break;
            }
            $n = $n.next();
        }
    }

    const raceBits = extractRnRaceBits($, $tr, raceIdxs);
    const sailors = splitSailorNames(rawSkipper, cat);
    const names = sailors.length ? sailors : [rawSkipper || ''];
    return names.map((skipper) => ({
        category: cat,
        position: pos || null,
        sail_number: sail,
        boat_name: boat || null,
        skipper,
        yacht_club: yachtClub || null,
        results: raceBits.join(',') || null,
        total_points: total || null
    })).filter(r => r.skipper || r.sail_number);
}

function parseRnResultsPage($, event) {
    const rows = [];
    const seen = new Set();
    const add = (parsedList) => {
        const list = Array.isArray(parsedList) ? parsedList : (parsedList ? [parsedList] : []);
        list.forEach((parsed) => {
            if (!parsed) return;
            const key = `${parsed.category}|${parsed.sail_number}|${parsed.skipper}`.toLowerCase();
            if (seen.has(key)) return;
            seen.add(key);
            rows.push({
                source: 'regattanetwork',
                source_event_id: event.source_event_id,
                source_url: event.results_url,
                regatta_name: event.regatta_name,
                regatta_date: event.regatta_date,
                ...parsed
            });
        });
    };

    $('tbody.results, tbody[data-fleet]').each((_, tbody) => {
        const $tbody = $(tbody);
        const category = ($tbody.attr('data-fleet') || '').trim();
        const raceIdxs = getRnRaceColumnIndexes($, $tbody);
        $tbody.find('tr').each((__, tr) => add(extractRnResultRow($, $(tr), category, raceIdxs)));
    });

    if (!rows.length) {
        $('tr').each((_, tr) => {
            const $tr = $(tr);
            if (!$tr.find('.the-score, td.sail-num, td.boatname').length) return;
            const raceIdxs = getRnRaceColumnIndexes($, $tr.closest('tbody, table'));
            add(extractRnResultRow($, $tr, nearestRnCategory($, $tr), raceIdxs));
        });
    }
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

/** Classes that are almost always one sailor (don't pair-split long names). */
const SINGLEHANDED_CLASS_RE = /\b(optimist|opti|green|red|white|blue|rwb|ilca(?:\s*[467])?|laser(?:\s*(?:radial|4\.7|standard))?|sunfish|byte|finn|ok\s*dinghy|rs\s*aero|waszp)\b/i;

function isLikelySinglehandedClass(category) {
    return SINGLEHANDED_CLASS_RE.test(String(category || ''));
}

/**
 * Expand a skipper/crew cell into one or more person names.
 * Prefer explicit separators; for doublehanded fleets, also pair "First Last First Last".
 */
function splitSailorNames(raw, category) {
    const text = normalizeSpace(raw);
    if (!text) return [];

    const separated = text
        .split(/\s*(?:\/|&|\+|•|\band\b|;|\n|\r|,)\s*/i)
        .map(normalizeSpace)
        .filter(Boolean);
    if (separated.length > 1) return separated;

    if (isLikelySinglehandedClass(category)) return [text];

    const words = text.split(/\s+/).filter(Boolean);
    // "Coco Claypoole Dominic Thomas" → two First+Last names
    if (words.length >= 4 && words.length % 2 === 0) {
        const names = [];
        for (let i = 0; i < words.length; i += 2) {
            names.push(`${words[i]} ${words[i + 1]}`);
        }
        return names;
    }
    return [text];
}

function sailorNamesFromClubspotRegistration(ro, category) {
    if (Array.isArray(ro.participantNames) && ro.participantNames.length) {
        const named = ro.participantNames.map(normalizeSpace).filter(Boolean);
        if (named.length) return named;
    }
    const combined = `${ro.firstName || ''} ${ro.lastName || ''}`.trim();
    return splitSailorNames(combined, category);
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

    const rows = [];
    ranked.forEach((item, place) => {
        const ro = item.entry.registrationObject || {};
        const className = (ro.boatClassObject && ro.boatClassObject.name) || classId || '';
        const sailors = sailorNamesFromClubspotRegistration(ro, className);
        const net = item.entry.net;
        const total = item.entry.total;
        const points = (net != null && net !== '') ? String(net) : (total != null ? String(total) : null);
        const base = {
            source: 'clubspot',
            source_event_id: event.source_event_id,
            source_url: event.results_url,
            regatta_name: event.regatta_name,
            regatta_date: event.regatta_date,
            category: className,
            position: String(place + 1),
            sail_number: ro.sailNumber != null ? String(ro.sailNumber) : '',
            boat_name: ro.boatName || null,
            yacht_club: ro.clubName || event.host_club || null,
            results: formatClubspotRaceCells(item.entry.scoring_data),
            total_points: points
        };
        if (!sailors.length) {
            if (base.sail_number) rows.push({ ...base, skipper: '' });
            return;
        }
        sailors.forEach((name) => {
            rows.push({ ...base, skipper: name });
        });
    });
    return rows.filter(r => r.skipper || r.sail_number);
}

async function scrapeRegattaNetwork(axios, cheerio, pool, window) {
    logLine(`Regatta Network: loading results archive (${window.label})`);
    const fromYear = parseInt(window.fromDate.slice(0, 4), 10);
    const toYear = parseInt(window.toDate.slice(0, 4), 10);
    const urls = [];
    // Year scrapes only need that year's past-results page; rolling windows may span years.
    if (window.mode !== 'year') urls.push(RN_ARCHIVE_URL);
    for (let y = fromYear; y <= toYear; y++) {
        urls.push(`https://www.regattanetwork.com/clubmgmt/applet_past_results.php?year=${y}`);
    }

    const byId = new Map();
    for (const url of urls) {
        const response = await axios.get(url, { headers: HTTP_HEADERS, timeout: 45000 });
        const events = parseRnListing(cheerio.load(response.data), window);
        events.forEach(e => byId.set(e.source_event_id, e));
        await sleep(150);
    }
    const events = Array.from(byId.values());
    job.stats.regattanetwork.eventsFound = events.length;
    logLine(`Regatta Network: ${events.length} events for ${window.label}`);

    for (const event of events) {
        if (!job.running) break;
        try {
            const page = await axios.get(event.results_url, { headers: HTTP_HEADERS, timeout: 45000 });
            const rows = parseRnResultsPage(cheerio.load(page.data), event);
            const n = await upsertRows(pool, rows);
            job.stats.regattanetwork.eventsScraped += 1;
            job.stats.regattanetwork.rowsInserted += n.inserted;
            job.stats.regattanetwork.rowsUpdated += n.updated;
            noteCollected('regattanetwork', rows);
            if (!rows.length) {
                logLine(`RN ${event.source_event_id}: ${event.regatta_name} → no standing rows parsed`);
            } else {
                logLine(`RN ${event.source_event_id}: ${event.regatta_name} → ${job.stats.regattanetwork.regattas} regattas, ${job.stats.regattanetwork.sailors} sailors (${rows.length} parsed)`);
            }
        } catch (err) {
            job.stats.regattanetwork.errors += 1;
            logLine(`RN ${event.source_event_id} error: ${err.message}`);
        }
        await sleep(120);
    }
}

async function fetchClubspotClassIds(axios, regattaId) {
    const where = JSON.stringify({
        regattaObject: { __type: 'Pointer', className: 'regattas', objectId: regattaId }
    });
    try {
        const res = await clubspotGet(axios, PARSE_BOAT_CLASSES_URL, {
            params: { where, limit: '100', keys: 'objectId,name' },
            headers: { 'X-Parse-Application-Id': PARSE_APP_ID }
        }, { log: logLine });
        const ids = (res.data.results || []).map(c => c.objectId).filter(Boolean);
        if (ids.length) return [...new Set(ids)];
    } catch (err) {
        logLine(`ClubSpot class lookup failed for ${regattaId}: ${err.message}`);
    }
    return [];
}

async function listClubspotEvents(axios, window) {
    const fromIso = `${window.fromDate}T00:00:00.000Z`;
    const toIso = `${window.toDate}T23:59:59.999Z`;
    const where = {
        archived: { $ne: true },
        public: { $ne: false },
        endDate: {
            $gte: { __type: 'Date', iso: fromIso },
            $lte: { __type: 'Date', iso: toIso }
        }
    };
    const base = {
        order: '-endDate',
        include: 'clubObject',
        keys: 'name,startDate,endDate,city,state,clubObject,objectId,boatClassesArray',
        where: JSON.stringify(where)
    };

    const countParams = new URLSearchParams({ ...base, count: '1', limit: '0' });
    const countRes = await clubspotGet(axios, `${PARSE_REGATTAS_URL}?${countParams}`, {
        headers: { 'X-Parse-Application-Id': PARSE_APP_ID }
    }, { log: logLine });
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
        const res = await clubspotGet(axios, `${PARSE_REGATTAS_URL}?${params}`, {
            headers: { 'X-Parse-Application-Id': PARSE_APP_ID }
        }, { log: logLine });
        all.push(...(res.data.results || []));
    }

    const events = [];
    let classLookups = 0;
    for (const r of all) {
        if (!r.objectId || !r.name) continue;
        const club = r.clubObject || {};
        let classes = (r.boatClassesArray || [])
            .map(c => (c && c.objectId) || null)
            .filter(Boolean);
        // Some ClubSpot events leave boatClassesArray empty but still have
        // classes under parse/classes/boatClasses (e.g. Sarasota Labor Day).
        if (!classes.length) {
            classLookups += 1;
            classes = await fetchClubspotClassIds(axios, r.objectId);
        }
        if (!classes.length) continue;

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
        events.push({
            source_event_id: r.objectId,
            regatta_name: r.name,
            regatta_date: start || end,
            host_club: club.name || null,
            location,
            class_ids: classes,
            results_url: resultsUrl
        });
    }
    if (classLookups) {
        logLine(`ClubSpot: resolved classes via boatClasses lookup for ${classLookups} event(s)`);
    }
    return events;
}

async function scrapeClubspot(axios, pool, window) {
    const pace = clubspotConfigSummary();
    logLine(
        `ClubSpot: listing events via Parse API (${window.label}); ` +
        `pacing ${pace.delayMinMs}-${pace.delayMaxMs}ms, retry on 429/5xx up to ${pace.maxRetries}`
    );
    const events = await listClubspotEvents(axios, window);
    job.stats.clubspot.eventsFound = events.length;
    logLine(`ClubSpot: ${events.length} events for ${window.label}`);

    for (const event of events) {
        if (!job.running) break;
        try {
            const eventRows = [];
            for (const classId of event.class_ids) {
                const url = `${CLUBSPOT_RESULTS_API}/${event.source_event_id}`;
                const res = await clubspotGet(axios, url, {
                    params: { boatClassIDs: classId }
                }, { log: logLine });
                eventRows.push(...rowsFromClubspotPayload(res.data, event, classId));
            }
            const n = await upsertRows(pool, eventRows);
            job.stats.clubspot.eventsScraped += 1;
            job.stats.clubspot.rowsInserted += n.inserted;
            job.stats.clubspot.rowsUpdated += n.updated;
            noteCollected('clubspot', eventRows);
            logLine(`CS ${event.source_event_id}: ${event.regatta_name} → ${job.stats.clubspot.regattas} regattas, ${job.stats.clubspot.sailors} sailors`);
        } catch (err) {
            job.stats.clubspot.errors += 1;
            logLine(`CS ${event.source_event_id} error: ${err.message}`);
        }
    }
}

async function runScrape({ axios, cheerio, pool, source, window }) {
    logLine(`Starting scrape source=${source} window=${window.label} (${window.fromDate} → ${window.toDate})`);
    const startedAt = job.startedAt;

    try {
        await ensureScrapedResultsTable(pool);
        if (source === 'all' || source === 'regattanetwork') {
            await scrapeRegattaNetwork(axios, cheerio, pool, window);
        }
        if (source === 'all' || source === 'clubspot') {
            await scrapeClubspot(axios, pool, window);
        }
        logLine('Scrape complete');
        try {
            await cleanupScrapedResultsData(pool);
        } catch (cleanupErr) {
            console.error('[race-results] post-scrape cleanup failed:', cleanupErr.message);
        }
        const status = job.error ? 'error' : 'success';
        if (source === 'all' || source === 'regattanetwork') {
            await logResultsScrape(pool, {
                source: 'regattanetwork',
                window,
                stats: job.stats.regattanetwork,
                startedAt,
                status
            });
        }
        if (source === 'all' || source === 'clubspot') {
            await logResultsScrape(pool, {
                source: 'clubspot',
                window,
                stats: job.stats.clubspot,
                startedAt,
                status
            });
        }
    } catch (err) {
        job.error = err.message;
        logLine(`Scrape failed: ${err.message}`);
        const sources = source === 'all' ? ['regattanetwork', 'clubspot'] : [source];
        for (const src of sources) {
            await logResultsScrape(pool, {
                source: src,
                window,
                stats: job.stats[src] || emptyStats()[src],
                startedAt,
                status: 'error'
            });
        }
    } finally {
        job.running = false;
        job.finishedAt = new Date().toISOString();
    }
}

function formatChatDate(isoOrText) {
    if (!isoOrText) return '—';
    const s = String(isoOrText).slice(0, 10);
    const m = s.match(/^(\d{4})-(\d{2})-(\d{2})$/);
    if (!m) return String(isoOrText);
    const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    const month = months[parseInt(m[2], 10) - 1] || m[2];
    return `${parseInt(m[3], 10)} ${month} ${m[1]}`;
}

function parseNumericPlace(value) {
    if (value == null) return null;
    const m = String(value).trim().match(/^(\d+)/);
    if (!m) return null;
    const n = parseInt(m[1], 10);
    return Number.isFinite(n) && n > 0 ? n : null;
}

/** Parse per-race score cells from scraped `results` text into numeric places when possible. */
function parseRaceCells(resultsText) {
    if (!resultsText) return [];
    return String(resultsText)
        .split(',')
        .map((raw, index) => {
            const cell = String(raw || '').trim();
            if (!cell) return null;
            const throwout = cell.includes('[') && cell.includes(']');
            const cleaned = cell.replace(/[\[\]]/g, '').trim();
            // ClubSpot style: "2/DNF" or plain "3"
            const leading = cleaned.match(/^(\d+)(?:\s*\/.*)?$/);
            const place = leading ? parseInt(leading[1], 10) : null;
            return {
                index: index + 1,
                raw: cell,
                place: Number.isFinite(place) && place > 0 ? place : null,
                throwout
            };
        })
        .filter(Boolean);
}

function pickBestKnownClub(rows) {
    const counts = new Map();
    for (const row of rows) {
        const club = normalizeSpace(row.yacht_club);
        if (!club) continue;
        const key = club.toLowerCase();
        const prev = counts.get(key) || { club, count: 0, latest: null };
        prev.count += 1;
        const d = row.regatta_date || '';
        if (!prev.latest || d > prev.latest) prev.latest = d;
        counts.set(key, prev);
    }
    const ranked = Array.from(counts.values()).sort((a, b) => {
        if (b.count !== a.count) return b.count - a.count;
        return String(b.latest || '').localeCompare(String(a.latest || ''));
    });
    return ranked.length ? ranked[0].club : 'Unknown';
}

function buildSailorCard(rows, preferredName) {
    if (!rows || !rows.length) return null;
    const bySkipper = new Map();
    for (const row of rows) {
        const name = normalizeSpace(row.skipper);
        if (!name) continue;
        const key = name.toLowerCase();
        if (!bySkipper.has(key)) bySkipper.set(key, { name, rows: [] });
        bySkipper.get(key).rows.push(row);
    }
    if (!bySkipper.size) return null;

    let chosen = null;
    const preferred = preferredName ? normalizeSpace(preferredName).toLowerCase() : '';
    if (preferred && bySkipper.has(preferred)) {
        chosen = bySkipper.get(preferred);
    } else if (bySkipper.size === 1) {
        chosen = Array.from(bySkipper.values())[0];
    } else if (preferred) {
        const partial = Array.from(bySkipper.values()).filter(s =>
            s.name.toLowerCase().includes(preferred) || preferred.includes(s.name.toLowerCase())
        );
        if (partial.length === 1) chosen = partial[0];
        else {
            return {
                resultType: 'sailors_list',
                subtitle: 'Multiple sailors matched — pick one:',
                list: Array.from(bySkipper.values())
                    .sort((a, b) => b.rows.length - a.rows.length)
                    .map(s => ({ name: s.name, count: s.rows.length }))
            };
        }
    } else {
        return {
            resultType: 'sailors_list',
            subtitle: 'Multiple sailors matched — pick one:',
            list: Array.from(bySkipper.values())
                .sort((a, b) => b.rows.length - a.rows.length)
                .map(s => ({ name: s.name, count: s.rows.length }))
        };
    }
    if (!chosen) {
        chosen = Array.from(bySkipper.values()).sort((a, b) => b.rows.length - a.rows.length)[0];
    }

    const sailorRows = chosen.rows.slice().sort((a, b) => String(b.regatta_date || '').localeCompare(String(a.regatta_date || '')));
    const club = pickBestKnownClub(sailorRows);
    const details = {};
    const history = [];
    const racePlaces = [];

    sailorRows.forEach((row, idx) => {
        const detailId = `r${idx}`;
        const cells = parseRaceCells(row.results);
        details[detailId] = {
            source: row.source || null,
            source_url: row.source_url || null,
            regatta_name: row.regatta_name || null,
            regatta_date: row.regatta_date || null,
            category: row.category || null,
            position: row.position || null,
            sail_number: row.sail_number || null,
            boat_name: row.boat_name || null,
            yacht_club: row.yacht_club || null,
            results: row.results || null,
            resultsCells: cells,
            total_points: row.total_points || null
        };
        history.push({
            detailId,
            position: row.position || null,
            regatta_name: row.regatta_name || null,
            regatta_date: formatChatDate(row.regatta_date),
            regatta_date_raw: row.regatta_date || null,
            category: row.category || null
        });
        cells.forEach((cell) => {
            if (cell.place == null) return;
            racePlaces.push({
                detailId,
                racePlace: cell.place,
                raceIndex: cell.index,
                throwout: cell.throwout,
                regatta_name: row.regatta_name || null,
                regatta_date: formatChatDate(row.regatta_date),
                category: row.category || null
            });
        });
    });

    const regattaAchievements = history
        .filter(r => parseNumericPlace(r.position) != null)
        .slice()
        .sort((a, b) => parseNumericPlace(a.position) - parseNumericPlace(b.position))
        .slice(0, 8);

    const raceAchievements = racePlaces
        .slice()
        .sort((a, b) => a.racePlace - b.racePlace || String(b.regatta_date || '').localeCompare(String(a.regatta_date || '')))
        .slice(0, 8);

    const bestRegattaPlace = regattaAchievements.length ? parseNumericPlace(regattaAchievements[0].position) : null;
    const bestRacePlace = raceAchievements.length ? raceAchievements[0].racePlace : null;
    const uniqueRegattas = new Set(
        sailorRows.map(r => `${normalizeSpace(r.regatta_name).toLowerCase()}|${r.regatta_date || ''}`)
    ).size;
    const dates = sailorRows.map(r => r.regatta_date).filter(Boolean).sort();
    const sources = Array.from(new Set(sailorRows.map(r => r.source).filter(Boolean)));

    return {
        resultType: 'sailor_card',
        sailor: { name: chosen.name, club },
        summary: {
            totalRegattas: uniqueRegattas,
            bestRegattaPlace,
            bestRacePlace,
            resultRows: sailorRows.length,
            firstDate: dates.length ? formatChatDate(dates[0]) : null,
            lastDate: dates.length ? formatChatDate(dates[dates.length - 1]) : null,
            sources
        },
        regattaAchievements,
        raceAchievements,
        history,
        details
    };
}

/**
 * Start a results scrape in the background. Used by the manual API and the weekly scheduler.
 * @returns {{ success: true, window: object, status: object }}
 * @throws Error with code SCRAPE_BUSY or VALIDATION
 */
function startResultsScrapeJob({ axios, cheerio, pool, source = 'all', lookbackDays, year, trigger = 'manual', onComplete } = {}) {
    if (job.running) {
        const err = new Error('A results scrape is already running');
        err.code = 'SCRAPE_BUSY';
        err.status = snapshotJob();
        throw err;
    }
    if (!['all', 'regattanetwork', 'clubspot'].includes(source)) {
        const err = new Error('source must be all, regattanetwork, or clubspot');
        err.code = 'VALIDATION';
        throw err;
    }
    const window = resolveScrapeWindow({ lookbackDays, year });
    job.running = true;
    job.startedAt = new Date().toISOString();
    job.finishedAt = null;
    job.source = source;
    job.mode = window.mode;
    job.year = window.year;
    job.lookbackDays = window.lookbackDays;
    job.fromDate = window.fromDate;
    job.toDate = window.toDate;
    job.windowLabel = window.label;
    job.trigger = trigger || 'manual';
    job.error = null;
    job.stats = emptyStats();
    collected = emptyCollected();
    job.log = [];
    logLine(`Queued scrape trigger=${job.trigger} source=${source} ${window.label} (${window.fromDate} → ${window.toDate})`);

    const finish = (report) => {
        if (typeof onComplete === 'function') {
            Promise.resolve(onComplete(report)).catch((err) => {
                console.error('[race-results] onComplete failed:', err.message);
            });
        }
    };

    runScrape({ axios, cheerio, pool, source, window }).then(() => {
        finish({
            success: !job.error,
            status: job.error ? 'error' : 'success',
            error: job.error,
            trigger: job.trigger,
            source: job.source,
            mode: job.mode,
            lookbackDays: job.lookbackDays,
            year: job.year,
            fromDate: job.fromDate,
            toDate: job.toDate,
            windowLabel: job.windowLabel,
            startedAt: job.startedAt,
            finishedAt: job.finishedAt,
            stats: job.stats
        });
    }).catch(err => {
        job.running = false;
        job.finishedAt = new Date().toISOString();
        job.error = err.message;
        logLine(`Background scrape crash: ${err.message}`);
        finish({
            success: false,
            status: 'error',
            error: err.message,
            trigger: job.trigger,
            source: job.source,
            mode: job.mode,
            lookbackDays: job.lookbackDays,
            year: job.year,
            fromDate: job.fromDate,
            toDate: job.toDate,
            windowLabel: job.windowLabel,
            startedAt: job.startedAt,
            finishedAt: job.finishedAt,
            stats: job.stats
        });
    });

    return {
        success: true,
        window,
        status: snapshotJob()
    };
}


function attachRaceResultsScraper(app, { pool, openai, axios, cheerio }) {
    app.get('/api/race-results/status', (req, res) => {
        res.json({
            success: true,
            tableName: TABLE,
            lookbackDaysDefault: LOOKBACK_DAYS,
            lookbackDaysMax: LOOKBACK_MAX_DAYS,
            ...snapshotJob()
        });
    });

    app.get('/api/race-results/stats', async (req, res) => {
        try {
            const snapshot = await readRaceResultsStatsSnapshot(pool);
            if (snapshot && snapshot.computed_at) {
                console.log(
                    '[race-results] /stats serving snapshot computed_at=',
                    snapshot.computed_at,
                    'sailors=', snapshot.total_sailors,
                    'regattas=', snapshot.total_regattas
                );
            }
            kickStaleStatsRefresh(pool, snapshot);
            res.json(snapshot || emptyStatsSnapshot());
        } catch (e) {
            console.error('race-results stats error:', e);
            res.json(emptyStatsSnapshot());
        }
    });

    app.get('/api/race-results/export', async (req, res) => {
        try {
            await ensureScrapedResultsTable(pool);
            const type = String((req.query && req.query.type) || 'rows').toLowerCase();
            const source = String((req.query && req.query.source) || '').toLowerCase();
            const params = [];
            const sourceClause = ['regattanetwork', 'clubspot'].includes(source)
                ? (() => { params.push(source); return `source = $${params.length}`; })()
                : '';

            let rows;
            let filename;
            if (type === 'sailors') {
                const where = [sourceClause, `skipper IS NOT NULL AND TRIM(skipper) <> ''`].filter(Boolean).join(' AND ');
                const r = await pool.query(`
                    SELECT TRIM(skipper) AS skipper,
                        COUNT(*)::int AS result_rows,
                        COUNT(DISTINCT TRIM(regatta_name))::int AS regattas,
                        COUNT(DISTINCT TRIM(yacht_club)) FILTER (WHERE yacht_club IS NOT NULL AND TRIM(yacht_club) <> '')::int AS clubs,
                        MIN(regatta_date)::text AS first_date,
                        MAX(regatta_date)::text AS last_date,
                        STRING_AGG(DISTINCT source, ',') AS sources
                    FROM ${TABLE}
                    WHERE ${where}
                    GROUP BY TRIM(skipper)
                    ORDER BY result_rows DESC, skipper ASC
                `, params);
                rows = r.rows;
                filename = `scraped-sailors-${Date.now()}.csv`;
            } else if (type === 'regattas') {
                const where = [sourceClause, `regatta_name IS NOT NULL AND TRIM(regatta_name) <> ''`].filter(Boolean).join(' AND ');
                const r = await pool.query(`
                    SELECT source,
                        source_event_id,
                        TRIM(regatta_name) AS regatta_name,
                        MIN(regatta_date)::text AS regatta_date,
                        COUNT(*)::int AS result_rows,
                        COUNT(DISTINCT TRIM(skipper)) FILTER (WHERE skipper IS NOT NULL AND TRIM(skipper) <> '')::int AS sailors,
                        COUNT(DISTINCT TRIM(category)) FILTER (WHERE category IS NOT NULL AND TRIM(category) <> '')::int AS classes,
                        MIN(source_url) AS source_url
                    FROM ${TABLE}
                    WHERE ${where}
                    GROUP BY source, source_event_id, TRIM(regatta_name)
                    ORDER BY regatta_date DESC NULLS LAST, regatta_name ASC
                `, params);
                rows = r.rows;
                filename = `scraped-regattas-${Date.now()}.csv`;
            } else {
                const where = sourceClause ? `WHERE ${sourceClause}` : '';
                const r = await pool.query(`
                    SELECT source, source_event_id, regatta_name, regatta_date::text AS regatta_date,
                        category, position, sail_number, boat_name, skipper, yacht_club,
                        results, total_points, source_url, scraped_at::text AS scraped_at
                    FROM ${TABLE}
                    ${where}
                    ORDER BY regatta_date DESC NULLS LAST, category ASC, position ASC NULLS LAST, skipper ASC
                `, params);
                rows = r.rows;
                filename = `scraped-rows-${Date.now()}.csv`;
            }

            const cols = rows.length
                ? Object.keys(rows[0])
                : (type === 'sailors'
                    ? ['skipper', 'result_rows', 'regattas', 'clubs', 'first_date', 'last_date', 'sources']
                    : type === 'regattas'
                        ? ['source', 'source_event_id', 'regatta_name', 'regatta_date', 'result_rows', 'sailors', 'classes', 'source_url']
                        : ['source', 'source_event_id', 'regatta_name', 'regatta_date', 'category', 'position', 'sail_number', 'boat_name', 'skipper', 'yacht_club', 'results', 'total_points', 'source_url', 'scraped_at']);

            const escapeCsv = (v) => {
                if (v == null) return '';
                const s = String(v);
                return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
            };
            const lines = [cols.join(',')];
            for (const row of rows) {
                lines.push(cols.map(c => escapeCsv(row[c])).join(','));
            }

            res.setHeader('Content-Type', 'text/csv; charset=utf-8');
            res.setHeader('Content-Disposition', `attachment; filename=${filename}`);
            res.send(lines.join('\n'));
        } catch (e) {
            console.error('race-results export error:', e);
            res.status(500).json({ success: false, error: e.message });
        }
    });

    app.get('/api/race-results/scrape-history', async (req, res) => {
        try {
            // Log table first so history UI works even if results-table scans are slow.
            await ensureResultsScrapeLogTable(pool);
            await ensureScrapedResultsTable(pool);

            const yearsDone = await pool.query(`
                SELECT source, year,
                    MAX(finished_at) AS last_finished,
                    SUM(events_scraped)::int AS events_scraped,
                    SUM(rows_inserted)::int AS rows_inserted,
                    SUM(rows_updated)::int AS rows_updated
                FROM ${SCRAPE_LOG_TABLE}
                WHERE mode = 'year' AND year IS NOT NULL AND status = 'success'
                GROUP BY source, year
                ORDER BY source, year DESC
            `);
            const recent = await pool.query(`
                SELECT source, mode, year, lookback_days, from_date::text, to_date::text,
                    events_found, events_scraped, rows_inserted, rows_updated, errors,
                    started_at, finished_at, status
                FROM ${SCRAPE_LOG_TABLE}
                ORDER BY finished_at DESC
                LIMIT 40
            `);

            const snapshot = await readRaceResultsStatsSnapshot(pool);
            kickStaleStatsRefresh(pool, snapshot);
            const dataYearsRows = (snapshot && snapshot.dataYears) || [];
            if (snapshot && snapshot.computed_at) {
                console.log(
                    '[race-results] scrape-history dataYears from snapshot:',
                    dataYearsRows.length, 'year-source rows, computed_at=', snapshot.computed_at
                );
            } else {
                console.warn('[race-results] scrape-history dataYears empty — snapshot not ready yet');
            }

            const bySource = { clubspot: { yearsDone: [], dataYears: [] }, regattanetwork: { yearsDone: [], dataYears: [] } };
            for (const row of yearsDone.rows) {
                if (!bySource[row.source]) bySource[row.source] = { yearsDone: [], dataYears: [] };
                bySource[row.source].yearsDone.push({
                    year: row.year,
                    lastFinished: row.last_finished,
                    eventsScraped: row.events_scraped,
                    rowsInserted: row.rows_inserted,
                    rowsUpdated: row.rows_updated
                });
            }
            for (const row of dataYearsRows) {
                if (!bySource[row.source]) bySource[row.source] = { yearsDone: [], dataYears: [] };
                bySource[row.source].dataYears.push({
                    year: row.year,
                    rows: row.rows,
                    events: row.events
                });
            }
            const currentYear = new Date().getUTCFullYear();
            res.json({
                success: true,
                yearOptions: Array.from({ length: 8 }, (_, i) => currentYear - i),
                bySource,
                recent: recent.rows
            });
        } catch (e) {
            console.error('race-results scrape-history error:', e);
            res.status(500).json({ success: false, error: e.message });
        }
    });

    app.post('/api/race-results/scrape', async (req, res) => {
        try {
            const source = (req.body && req.body.source) || 'all';
            const yearRaw = req.body && (req.body.year != null && req.body.year !== '' ? req.body.year : null);
            const started = startResultsScrapeJob({
                axios,
                cheerio,
                pool,
                source,
                lookbackDays: req.body && req.body.lookbackDays,
                year: yearRaw,
                trigger: 'manual'
            });
            res.json({
                success: true,
                status: 'started',
                message: `Race-results scrape started (${source}, ${started.window.label}). Poll /api/race-results/status.`,
                lookbackDays: started.window.lookbackDays,
                year: started.window.year,
                mode: started.window.mode,
                fromDate: started.window.fromDate,
                toDate: started.window.toDate,
                windowLabel: started.window.label
            });
        } catch (err) {
            if (err.code === 'SCRAPE_BUSY') {
                return res.status(409).json({ success: false, error: err.message, status: err.status || snapshotJob() });
            }
            if (err.code === 'VALIDATION') {
                return res.status(400).json({ success: false, error: err.message });
            }
            console.error('race-results scrape start error:', err);
            res.status(500).json({ success: false, error: err.message });
        }
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
            await ensureScrapedResultsTable(pool);

            const parsed = await parseChatIntent(message, openai);
            const intent = (parsed.intent || '').toLowerCase();
            const parser = parsed.parser || 'rules';
            const ok = (body) => res.json({ parser, ...body });
            const criteria = {
                skipper: parsed.skipper,
                boat_name: parsed.boat_name,
                yacht_club: parsed.yacht_club,
                regatta_name: parsed.regatta_name,
                sail_number: parsed.sail_number,
                position: parsed.position,
                category: parsed.category,
                limit: parsed.limit,
                year: parsed.year,
                source: parsed.source
            };

            if (intent === 'data_summary') {
                const snapshot = await readRaceResultsStatsSnapshot(pool);
                kickStaleStatsRefresh(pool, snapshot);
                const row = snapshot || emptyStatsSnapshot();
                const src = (row.bySource || []).map(x => `${x.source}: ${x.count}`).join(', ') || 'none';
                return ok({
                    success: true,
                    reply: `Scraped results table **${TABLE}** has **${row.total_records}** rows, **${row.total_sailors}** sailors, **${row.total_regattas}** regattas. Dates ${row.earliest_date || '—'} to ${row.latest_date || '—'}. By source: ${src}.`,
                    data: {
                        resultType: 'summary',
                        total_records: row.total_records,
                        sailors: row.total_sailors,
                        regattas: row.total_regattas,
                        earliest_date: row.earliest_date,
                        latest_date: row.latest_date,
                        bySource: row.bySource,
                        computed_at: row.computed_at
                    }
                });
            }

            if (intent === 'sample') {
                const r = await pool.query(`
                    SELECT source, regatta_name, regatta_date::text, category, position, sail_number, boat_name, skipper, yacht_club, results, total_points, source_url
                    FROM ${TABLE}
                    ORDER BY regatta_date DESC NULLS LAST, position ASC NULLS LAST
                    LIMIT 25
                `);
                return ok({
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
            if (criteria.sail_number) {
                n++;
                where += ` AND REPLACE(UPPER(COALESCE(sail_number,'')), ' ', '') ILIKE $${n}`;
                params.push('%' + String(criteria.sail_number).replace(/\s+/g, '').toUpperCase() + '%');
            }
            if (criteria.position) {
                n++;
                where += ` AND TRIM(COALESCE(position,'')) = $${n}`;
                params.push(String(criteria.position).trim());
            }
            if (criteria.source) add('source', criteria.source);
            if (criteria.year) {
                n++;
                where += ` AND EXTRACT(YEAR FROM regatta_date) = $${n}`;
                params.push(parseInt(String(criteria.year), 10));
            }

            if (intent === 'top_sailors') {
                const limit = Math.min(50, Math.max(1, parseInt(String(criteria.limit || 10), 10) || 10));
                const paramsTop = [];
                let whereTop = `skipper IS NOT NULL AND TRIM(skipper) <> ''`;
                if (criteria.category) {
                    paramsTop.push('%' + String(criteria.category).trim() + '%');
                    whereTop += ` AND category ILIKE $${paramsTop.length}`;
                }
                if (criteria.year) {
                    paramsTop.push(parseInt(String(criteria.year), 10));
                    whereTop += ` AND EXTRACT(YEAR FROM regatta_date) = $${paramsTop.length}`;
                }
                paramsTop.push(limit);
                const r = await pool.query(`
                    SELECT skipper AS name, COUNT(*)::int AS count
                    FROM ${TABLE}
                    WHERE ${whereTop}
                    GROUP BY skipper ORDER BY count DESC, skipper ASC
                    LIMIT $${paramsTop.length}
                `, paramsTop);
                const scope = criteria.category ? ` in **${criteria.category}**` : '';
                return ok({
                    success: true,
                    reply: r.rows.length
                        ? `Top ${r.rows.length} sailor${r.rows.length === 1 ? '' : 's'}${scope} (by result rows):`
                        : `No sailor data yet${scope}.`,
                    data: { resultType: 'list', rows: r.rows }
                });
            }
            if (intent === 'top_clubs') {
                const limit = Math.min(50, Math.max(1, parseInt(String(criteria.limit || 10), 10) || 10));
                const paramsTop = [];
                let whereTop = `yacht_club IS NOT NULL AND TRIM(yacht_club) <> ''`;
                if (criteria.category) {
                    paramsTop.push('%' + String(criteria.category).trim() + '%');
                    whereTop += ` AND category ILIKE $${paramsTop.length}`;
                }
                if (criteria.year) {
                    paramsTop.push(parseInt(String(criteria.year), 10));
                    whereTop += ` AND EXTRACT(YEAR FROM regatta_date) = $${paramsTop.length}`;
                }
                paramsTop.push(limit);
                const r = await pool.query(`
                    SELECT yacht_club AS name, COUNT(*)::int AS count
                    FROM ${TABLE}
                    WHERE ${whereTop}
                    GROUP BY yacht_club ORDER BY count DESC, yacht_club ASC
                    LIMIT $${paramsTop.length}
                `, paramsTop);
                const scope = criteria.category ? ` in **${criteria.category}**` : '';
                return ok({
                    success: true,
                    reply: r.rows.length
                        ? `Top ${r.rows.length} club${r.rows.length === 1 ? '' : 's'}${scope}:`
                        : `No club data yet${scope}.`,
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
                return ok({
                    success: true,
                    reply: r.rows.length ? `Sailors at ${criteria.yacht_club}:` : `No sailors found for ${criteria.yacht_club}.`,
                    data: { resultType: 'list', rows: r.rows }
                });
            }

            if (n === 0 && !['regatta_search', 'sailor_search', 'boat_search', 'club_search', 'sail_search'].includes(intent)) {
                return ok({
                    success: true,
                    reply: 'Try a sailor/person name, boat, club, regatta/race, sail number, "who won [event]", "top sailors", or "what\'s in the data".',
                    data: null
                });
            }

            const selectSql = `
                SELECT source, regatta_name, regatta_date::text, category, position, sail_number, boat_name, skipper, yacht_club, results, total_points, source_url
                FROM ${TABLE}
            `;
            n++;
            params.push(80);
            let result = await pool.query(`
                ${selectSql}
                WHERE ${where}
                ORDER BY regatta_date DESC NULLS LAST, position ASC NULLS LAST
                LIMIT $${n}
            `, params);

            // If the narrow intent missed (e.g. "Labor Day" parsed as a sailor),
            // broaden across sailor / boat / club / regatta / sail / class.
            if (!result.rows.length) {
                const needle = String(message).trim();
                const broad = await pool.query(`
                    ${selectSql}
                    WHERE skipper ILIKE $1
                       OR boat_name ILIKE $1
                       OR yacht_club ILIKE $1
                       OR regatta_name ILIKE $1
                       OR sail_number ILIKE $1
                       OR category ILIKE $1
                    ORDER BY regatta_date DESC NULLS LAST, position ASC NULLS LAST
                    LIMIT 80
                `, ['%' + needle + '%']);
                if (broad.rows.length) {
                    result = broad;
                } else {
                    // try significant tokens (drop tiny filler words)
                    const tokens = needle.split(/\s+/).filter(t =>
                        t.length > 2
                        && !/^(the|and|for|from|with|who|what|when|where|show|find|get|top|best|sail|sailor|sailors|person|boat|club|race|regatta|place|date|number|named|called|results?)$/i.test(t)
                    );
                    if (tokens.length) {
                        const ors = [];
                        const bparams = [];
                        tokens.forEach((t) => {
                            bparams.push('%' + t + '%');
                            const i = bparams.length;
                            ors.push(`(skipper ILIKE $${i} OR boat_name ILIKE $${i} OR yacht_club ILIKE $${i} OR regatta_name ILIKE $${i} OR sail_number ILIKE $${i} OR category ILIKE $${i})`);
                        });
                        bparams.push(80);
                        const tokened = await pool.query(`
                            ${selectSql}
                            WHERE ${ors.join(' AND ')}
                            ORDER BY regatta_date DESC NULLS LAST, position ASC NULLS LAST
                            LIMIT $${bparams.length}
                        `, bparams);
                        if (tokened.rows.length) result = tokened;
                    }
                }
            }

            let reply;
            if (!result.rows.length) {
                const total = await pool.query(`SELECT COUNT(*)::int AS c FROM ${TABLE}`);
                const count = total.rows[0].c;
                if (!count) {
                    reply = 'The scraped results table is empty. Run a results scrape first.';
                } else {
                    const bits = [
                        criteria.skipper && `sailor "${criteria.skipper}"`,
                        criteria.boat_name && `boat "${criteria.boat_name}"`,
                        criteria.yacht_club && `club "${criteria.yacht_club}"`,
                        criteria.regatta_name && `regatta "${criteria.regatta_name}"`,
                        criteria.sail_number && `sail "${criteria.sail_number}"`,
                        criteria.category && `class "${criteria.category}"`,
                        criteria.position && `place ${criteria.position}`,
                        criteria.year && `year ${criteria.year}`
                    ].filter(Boolean);
                    reply = bits.length
                        ? `No rows matched ${bits.join(', ')}. The table has **${count}** scraped rows — try a different spelling, a sail number, or ask "sample" / "what's in the data".`
                        : `No rows matched "${String(message).trim()}". The table has **${count}** scraped rows — try "sample", a sailor name from the data, or a regatta name.`;
                }
                return ok({ success: true, reply, data: null });
            }

            const sailorIntent = intent === 'sailor_search'
                || (criteria.skipper && !criteria.regatta_name && !criteria.boat_name && !criteria.yacht_club && !criteria.sail_number && !criteria.position);
            if (sailorIntent) {
                const card = buildSailorCard(result.rows, criteria.skipper || String(message).trim());
                if (card && card.resultType === 'sailors_list') {
                    return ok({
                        success: true,
                        reply: 'I found several sailors with that name. Pick one:',
                        data: card
                    });
                }
                if (card && card.resultType === 'sailor_card') {
                    const s = card.summary || {};
                    const bits = [
                        s.totalRegattas != null && `**Total number of regattas:** ${s.totalRegattas}`,
                        s.bestRegattaPlace != null && `**Best regatta place:** ${s.bestRegattaPlace}`,
                        s.bestRacePlace != null && `**Best race place:** ${s.bestRacePlace}`
                    ].filter(Boolean);
                    reply = `I found the following information:\n\n${bits.join('\n')}\n\nSee the tables below for achievements and race history.`;
                    return ok({
                        success: true,
                        reply,
                        data: card
                    });
                }
            }

            if (intent === 'regatta_search') {
                const winners = result.rows.filter(r => String(r.position) === '1');
                reply = `Found **${result.rows.length}** result rows for that regatta. ${winners.length ? 'First-place boats are included where position = 1.' : ''}`;
            } else if (intent === 'sail_search') {
                reply = `Found **${result.rows.length}** row(s) for that sail number.`;
            } else if (criteria.position) {
                reply = `Found **${result.rows.length}** row(s) at place **${criteria.position}**.`;
            } else {
                reply = `Found **${result.rows.length}** matching result row(s) in the scraped table.`;
            }

            return ok({
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
    LOOKBACK_MAX_DAYS,
    TABLE,
    SCRAPE_LOG_TABLE,
    STATS_SNAPSHOT_TABLE,
    resolveScrapeWindow,
    ensureScrapedResultsTable,
    ensureStatsSnapshotTable,
    ensureRaceResultsStatsIndexes,
    readRaceResultsStatsSnapshot,
    refreshRaceResultsStatsSnapshot,
    refreshRaceResultsStatsIfStale,
    startResultsScrapeJob,
    attachRaceResultsScraper,
    parseRnListing,
    parseRnResultsPage,
    rowsFromClubspotPayload,
    buildSailorCard,
    parseRaceCells
};
