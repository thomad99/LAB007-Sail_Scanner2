/**
 * Weekly automated race-results scraper.
 * Default: Mondays 09:00 America/New_York, lookback 7 days, both sources.
 * Settings + last-run report persist in Postgres; cron is rebuilt when settings change.
 */

const cron = require('node-cron');
const { startResultsScrapeJob } = require('./race-results-scraper');

const SETTINGS_TABLE = 'race_results_scheduler_settings';

const DEFAULTS = {
    enabled: true,
    dayOfWeek: 1, // Monday (0=Sun … 6=Sat)
    hour: 9,
    minute: 0,
    timezone: 'America/New_York',
    lookbackDays: 7,
    source: 'all'
};

const DAY_NAMES = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];

let cronTask = null;
let deps = null; // { pool, axios, cheerio }

function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

function clampInt(value, min, max, fallback) {
    const n = parseInt(value, 10);
    if (!Number.isFinite(n)) return fallback;
    return Math.min(max, Math.max(min, n));
}

function normalizeSettings(input = {}) {
    const dayOfWeek = clampInt(input.dayOfWeek ?? input.day_of_week, 0, 6, DEFAULTS.dayOfWeek);
    const hour = clampInt(input.hour, 0, 23, DEFAULTS.hour);
    const minute = clampInt(input.minute, 0, 59, DEFAULTS.minute);
    const lookbackDays = clampInt(input.lookbackDays ?? input.lookback_days, 1, 365, DEFAULTS.lookbackDays);
    let source = String(input.source || DEFAULTS.source).toLowerCase();
    if (!['all', 'regattanetwork', 'clubspot'].includes(source)) source = DEFAULTS.source;
    let timezone = String(input.timezone || DEFAULTS.timezone).trim() || DEFAULTS.timezone;
    try {
        // Validate IANA timezone
        Intl.DateTimeFormat('en-US', { timeZone: timezone }).format(new Date());
    } catch (_) {
        timezone = DEFAULTS.timezone;
    }
    const enabled = input.enabled === undefined && input.paused === undefined
        ? DEFAULTS.enabled
        : input.enabled !== undefined
            ? !!input.enabled
            : !input.paused;
    return { enabled, dayOfWeek, hour, minute, timezone, lookbackDays, source };
}

function cronExpression({ minute, hour, dayOfWeek }) {
    return `${minute} ${hour} * * ${dayOfWeek}`;
}

function scheduleDescription(settings) {
    const day = DAY_NAMES[settings.dayOfWeek] || `day ${settings.dayOfWeek}`;
    const hh = String(settings.hour).padStart(2, '0');
    const mm = String(settings.minute).padStart(2, '0');
    return `Every ${day} at ${hh}:${mm} (${settings.timezone}), last ${settings.lookbackDays} day(s), source=${settings.source}`;
}

/** Zoned calendar parts for a Date using Intl (no extra deps). */
function zonedParts(date, timeZone) {
    const fmt = new Intl.DateTimeFormat('en-US', {
        timeZone,
        weekday: 'short',
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hourCycle: 'h23'
    });
    const parts = Object.fromEntries(fmt.formatToParts(date).filter((p) => p.type !== 'literal').map((p) => [p.type, p.value]));
    const weekdayMap = { Sun: 0, Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6 };
    return {
        dayOfWeek: weekdayMap[parts.weekday],
        year: parseInt(parts.year, 10),
        month: parseInt(parts.month, 10),
        day: parseInt(parts.day, 10),
        hour: parseInt(parts.hour, 10),
        minute: parseInt(parts.minute, 10),
        second: parseInt(parts.second, 10)
    };
}

function computeNextRun(settings, from = new Date()) {
    if (!settings.enabled) return null;
    const startMs = from.getTime();
    // Scan minute-by-minute up to 8 days ahead in the target timezone.
    for (let i = 1; i <= 8 * 24 * 60; i++) {
        const t = new Date(startMs + i * 60 * 1000);
        const z = zonedParts(t, settings.timezone);
        if (
            z.dayOfWeek === settings.dayOfWeek &&
            z.hour === settings.hour &&
            z.minute === settings.minute
        ) {
            return t.toISOString();
        }
    }
    return null;
}

async function ensureSchedulerTable(pool) {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS ${SETTINGS_TABLE} (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            enabled BOOLEAN NOT NULL DEFAULT TRUE,
            day_of_week INTEGER NOT NULL DEFAULT 1,
            hour INTEGER NOT NULL DEFAULT 9,
            minute INTEGER NOT NULL DEFAULT 0,
            timezone TEXT NOT NULL DEFAULT 'America/New_York',
            lookback_days INTEGER NOT NULL DEFAULT 7,
            source TEXT NOT NULL DEFAULT 'all',
            last_run_at TIMESTAMPTZ,
            last_run_status TEXT,
            last_run_report JSONB,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    `);
    await pool.query(`
        INSERT INTO ${SETTINGS_TABLE} (id)
        VALUES (1)
        ON CONFLICT (id) DO NOTHING
    `);
}

function rowToSettings(row) {
    if (!row) return { ...DEFAULTS };
    return normalizeSettings({
        enabled: row.enabled,
        dayOfWeek: row.day_of_week,
        hour: row.hour,
        minute: row.minute,
        timezone: row.timezone,
        lookbackDays: row.lookback_days,
        source: row.source
    });
}

async function readSettingsRow(pool) {
    await ensureSchedulerTable(pool);
    const r = await pool.query(`SELECT * FROM ${SETTINGS_TABLE} WHERE id = 1`);
    return r.rows[0] || null;
}

async function getSettings(pool) {
    const row = await readSettingsRow(pool);
    return {
        ...rowToSettings(row),
        lastRunAt: row && row.last_run_at ? new Date(row.last_run_at).toISOString() : null,
        lastRunStatus: row ? row.last_run_status : null,
        lastRunReport: row ? row.last_run_report : null,
        updatedAt: row && row.updated_at ? new Date(row.updated_at).toISOString() : null
    };
}

async function saveSettings(pool, patch) {
    const current = await getSettings(pool);
    const next = normalizeSettings({ ...current, ...patch });
    await pool.query(
        `
        UPDATE ${SETTINGS_TABLE}
        SET enabled = $1,
            day_of_week = $2,
            hour = $3,
            minute = $4,
            timezone = $5,
            lookback_days = $6,
            source = $7,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = 1
        `,
        [next.enabled, next.dayOfWeek, next.hour, next.minute, next.timezone, next.lookbackDays, next.source]
    );
    return getSettings(pool);
}

async function recordLastRun(pool, report) {
    await ensureSchedulerTable(pool);
    await pool.query(
        `
        UPDATE ${SETTINGS_TABLE}
        SET last_run_at = CURRENT_TIMESTAMP,
            last_run_status = $1,
            last_run_report = $2::jsonb,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = 1
        `,
        [report.status || (report.success ? 'success' : 'error'), JSON.stringify(report || {})]
    );
}

function stopCron() {
    if (cronTask) {
        cronTask.stop();
        cronTask = null;
    }
}

function rebuildCron(settings) {
    stopCron();
    if (!settings.enabled) {
        console.log('[results-scheduler] paused — cron not scheduled');
        return;
    }
    const expr = cronExpression(settings);
    if (!cron.validate(expr)) {
        console.error('[results-scheduler] invalid cron expression:', expr);
        return;
    }
    cronTask = cron.schedule(
        expr,
        () => {
            fireScheduledScrape().catch((err) => {
                console.error('[results-scheduler] fire failed:', err.message);
            });
        },
        { timezone: settings.timezone }
    );
    console.log(`[results-scheduler] scheduled: ${scheduleDescription(settings)} (cron "${expr}")`);
}

async function fireScheduledScrape() {
    if (!deps || !deps.pool) {
        console.warn('[results-scheduler] no deps — skip');
        return;
    }
    const settings = await getSettings(deps.pool);
    if (!settings.enabled) {
        console.log('[results-scheduler] skipped (paused)');
        return;
    }
    console.log(
        `[results-scheduler] starting weekly scrape lookback=${settings.lookbackDays}d source=${settings.source}`
    );
    try {
        startResultsScrapeJob({
            axios: deps.axios,
            cheerio: deps.cheerio,
            pool: deps.pool,
            source: settings.source,
            lookbackDays: settings.lookbackDays,
            trigger: 'scheduled',
            onComplete: async (report) => {
                await recordLastRun(deps.pool, {
                    ...report,
                    schedule: {
                        lookbackDays: settings.lookbackDays,
                        source: settings.source,
                        timezone: settings.timezone
                    }
                });
                console.log('[results-scheduler] completed:', report.status, report.windowLabel);
            }
        });
    } catch (err) {
        if (err.code === 'SCRAPE_BUSY') {
            await recordLastRun(deps.pool, {
                success: false,
                status: 'skipped_busy',
                error: err.message,
                trigger: 'scheduled',
                finishedAt: new Date().toISOString()
            });
            console.warn('[results-scheduler] skipped — scrape already running');
            return;
        }
        await recordLastRun(deps.pool, {
            success: false,
            status: 'error',
            error: err.message,
            trigger: 'scheduled',
            finishedAt: new Date().toISOString()
        });
        throw err;
    }
}

async function buildStatus(pool) {
    const settings = await getSettings(pool);
    const nextRunAt = computeNextRun(settings);
    return {
        success: true,
        enabled: settings.enabled,
        paused: !settings.enabled,
        dayOfWeek: settings.dayOfWeek,
        dayName: DAY_NAMES[settings.dayOfWeek],
        hour: settings.hour,
        minute: settings.minute,
        timezone: settings.timezone,
        lookbackDays: settings.lookbackDays,
        source: settings.source,
        cronExpression: cronExpression(settings),
        scheduleDescription: scheduleDescription(settings),
        lastRunAt: settings.lastRunAt,
        lastRunStatus: settings.lastRunStatus,
        lastRunReport: settings.lastRunReport,
        nextRunAt,
        updatedAt: settings.updatedAt,
        defaults: { ...DEFAULTS, dayName: DAY_NAMES[DEFAULTS.dayOfWeek] }
    };
}

function attachRaceResultsScheduler(app, { pool, axios, cheerio }) {
    deps = { pool, axios, cheerio };

    // Boot: load settings and start cron (non-blocking)
    getSettings(pool)
        .then((settings) => {
            rebuildCron(settings);
        })
        .catch((err) => {
            console.error('[results-scheduler] init failed:', err.message);
            // Fall back to defaults in-memory so a DB blip doesn't kill the process
            rebuildCron(DEFAULTS);
        });

    app.get('/api/race-results/schedule', async (req, res) => {
        try {
            const status = await buildStatus(pool);
            res.json(status);
        } catch (err) {
            console.error('[results-scheduler] status error:', err);
            res.status(500).json({ success: false, error: err.message });
        }
    });

    app.put('/api/race-results/schedule', async (req, res) => {
        try {
            const body = req.body || {};
            const saved = await saveSettings(pool, {
                enabled: body.enabled !== undefined ? body.enabled : body.paused !== undefined ? !body.paused : undefined,
                dayOfWeek: body.dayOfWeek,
                hour: body.hour,
                minute: body.minute,
                timezone: body.timezone,
                lookbackDays: body.lookbackDays,
                source: body.source
            });
            rebuildCron(saved);
            const status = await buildStatus(pool);
            res.json({ success: true, message: 'Schedule updated', ...status });
        } catch (err) {
            console.error('[results-scheduler] update error:', err);
            res.status(500).json({ success: false, error: err.message });
        }
    });

    app.post('/api/race-results/schedule/pause', async (req, res) => {
        try {
            await saveSettings(pool, { enabled: false });
            rebuildCron({ ...(await getSettings(pool)) });
            res.json({ success: true, message: 'Scheduler paused', ...(await buildStatus(pool)) });
        } catch (err) {
            res.status(500).json({ success: false, error: err.message });
        }
    });

    app.post('/api/race-results/schedule/resume', async (req, res) => {
        try {
            await saveSettings(pool, { enabled: true });
            rebuildCron({ ...(await getSettings(pool)) });
            res.json({ success: true, message: 'Scheduler resumed', ...(await buildStatus(pool)) });
        } catch (err) {
            res.status(500).json({ success: false, error: err.message });
        }
    });

    app.post('/api/race-results/schedule/run-now', async (req, res) => {
        try {
            const settings = await getSettings(pool);
            const lookbackDays = clampInt(req.body && req.body.lookbackDays, 1, 365, settings.lookbackDays);
            const source = (req.body && req.body.source) || settings.source;
            startResultsScrapeJob({
                axios,
                cheerio,
                pool,
                source,
                lookbackDays,
                trigger: 'scheduled_manual',
                onComplete: async (report) => {
                    await recordLastRun(pool, {
                        ...report,
                        schedule: { lookbackDays, source, timezone: settings.timezone, runNow: true }
                    });
                }
            });
            res.json({
                success: true,
                message: `Scheduled-style scrape started (last ${lookbackDays} days, ${source})`,
                ...(await buildStatus(pool))
            });
        } catch (err) {
            if (err.code === 'SCRAPE_BUSY') {
                return res.status(409).json({ success: false, error: err.message, status: err.status });
            }
            if (err.code === 'VALIDATION') {
                return res.status(400).json({ success: false, error: err.message });
            }
            res.status(500).json({ success: false, error: err.message });
        }
    });
}

module.exports = {
    SETTINGS_TABLE,
    DEFAULTS,
    attachRaceResultsScheduler,
    computeNextRun,
    scheduleDescription,
    normalizeSettings,
    // exported for tests
    _zonedParts: zonedParts,
    _cronExpression: cronExpression,
    _rebuildCron: rebuildCron,
    _stopCron: stopCron,
    _fireScheduledScrape: fireScheduledScrape
};
