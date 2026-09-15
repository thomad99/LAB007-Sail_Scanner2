/**
 * Weekly automated upcoming-regatta calendar scraper.
 * Default: Sundays 10:00 America/New_York, all sources.
 * Settings + last-run report persist in Postgres; cron is rebuilt when settings change.
 */

const cron = require('node-cron');

const SETTINGS_TABLE = 'regatta_dates_scheduler_settings';
const VALID_SOURCES = ['all', 'regattanetwork', 'clubspot', 'hssailing'];

const DEFAULTS = {
    enabled: true,
    dayOfWeek: 0, // Sunday
    hour: 10,
    minute: 0,
    timezone: 'America/New_York',
    source: 'all'
};

const DAY_NAMES = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
const SOURCE_LABELS = {
    all: 'All sources',
    regattanetwork: 'Regatta Network',
    clubspot: 'ClubSpot',
    hssailing: 'High School Sailing'
};

let cronTask = null;
let deps = null; // { pool, runScrape }
let scrapeBusy = false;

function clampInt(value, min, max, fallback) {
    const n = parseInt(value, 10);
    if (!Number.isFinite(n)) return fallback;
    return Math.min(max, Math.max(min, n));
}

function normalizeSource(value) {
    const src = String(value || '').trim().toLowerCase();
    return VALID_SOURCES.includes(src) ? src : DEFAULTS.source;
}

function normalizeSettings(input = {}) {
    const dayOfWeek = clampInt(input.dayOfWeek ?? input.day_of_week, 0, 6, DEFAULTS.dayOfWeek);
    const hour = clampInt(input.hour, 0, 23, DEFAULTS.hour);
    const minute = clampInt(input.minute, 0, 59, DEFAULTS.minute);
    const source = normalizeSource(input.source);
    const timezone = DEFAULTS.timezone;
    const enabled = input.enabled === undefined && input.paused === undefined
        ? DEFAULTS.enabled
        : input.enabled !== undefined
            ? !!input.enabled
            : !input.paused;
    return { enabled, dayOfWeek, hour, minute, timezone, source };
}

function cronExpression({ minute, hour, dayOfWeek }) {
    return `${minute} ${hour} * * ${dayOfWeek}`;
}

function formatClock(hour, minute) {
    const hh = String(hour).padStart(2, '0');
    const mm = String(minute).padStart(2, '0');
    return `${hh}:${mm}`;
}

function scheduleDescription(settings) {
    const day = DAY_NAMES[settings.dayOfWeek] || `day ${settings.dayOfWeek}`;
    const time = formatClock(settings.hour, settings.minute);
    const source = SOURCE_LABELS[settings.source] || settings.source;
    return `${day} · ${time} · ${source}`;
}

function scheduleSummary(settings) {
    return {
        dayName: DAY_NAMES[settings.dayOfWeek] || `day ${settings.dayOfWeek}`,
        timeLabel: formatClock(settings.hour, settings.minute),
        frequencyLabel: SOURCE_LABELS[settings.source] || settings.source
    };
}

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
            day_of_week INTEGER NOT NULL DEFAULT 0,
            hour INTEGER NOT NULL DEFAULT 10,
            minute INTEGER NOT NULL DEFAULT 0,
            timezone TEXT NOT NULL DEFAULT 'America/New_York',
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
            source = $6,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = 1
        `,
        [next.enabled, next.dayOfWeek, next.hour, next.minute, next.timezone, next.source]
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
        console.log('[dates-scheduler] paused — cron not scheduled');
        return;
    }
    const expr = cronExpression(settings);
    if (!cron.validate(expr)) {
        console.error('[dates-scheduler] invalid cron expression:', expr);
        return;
    }
    cronTask = cron.schedule(
        expr,
        () => {
            fireScheduledScrape().catch((err) => {
                console.error('[dates-scheduler] fire failed:', err.message);
            });
        },
        { timezone: settings.timezone }
    );
    console.log(`[dates-scheduler] scheduled: ${scheduleDescription(settings)} (cron "${expr}")`);
}

function summarizeResults(results = {}) {
    const sources = ['regattanetwork', 'clubspot', 'hssailing'];
    let found = 0;
    let added = 0;
    const stats = {};
    sources.forEach((src) => {
        const row = results[src] || {};
        stats[src] = {
            found: Number(row.found || 0),
            added: Number(row.added || 0),
            updated: Number(row.updated || 0),
            status: row.status || null
        };
        found += stats[src].found;
        added += stats[src].added;
    });
    return { found, added, stats };
}

async function fireScheduledScrape(trigger = 'scheduled', sourceOverride) {
    if (!deps || !deps.pool || !deps.runScrape) {
        console.warn('[dates-scheduler] no deps — skip');
        return;
    }
    if (scrapeBusy) {
        await recordLastRun(deps.pool, {
            success: false,
            status: 'skipped_busy',
            error: 'A calendar scrape is already running',
            trigger,
            finishedAt: new Date().toISOString()
        });
        console.warn('[dates-scheduler] skipped — scrape already running');
        return;
    }
    const settings = await getSettings(deps.pool);
    if (trigger === 'scheduled' && !settings.enabled) {
        console.log('[dates-scheduler] skipped (paused)');
        return;
    }
    const source = normalizeSource(sourceOverride || settings.source);
    scrapeBusy = true;
    console.log(`[dates-scheduler] starting scrape source=${source} trigger=${trigger}`);
    try {
        const outcome = await deps.runScrape(source);
        const summary = summarizeResults(outcome && outcome.results);
        await recordLastRun(deps.pool, {
            success: true,
            status: 'success',
            source,
            trigger,
            totalFound: outcome.totalFound != null ? outcome.totalFound : summary.found,
            totalAdded: outcome.totalAdded != null ? outcome.totalAdded : summary.added,
            stats: summary.stats,
            finishedAt: new Date().toISOString()
        });
        console.log('[dates-scheduler] completed:', summary.found, 'found,', summary.added, 'added');
    } catch (err) {
        await recordLastRun(deps.pool, {
            success: false,
            status: 'error',
            error: err.message,
            trigger,
            finishedAt: new Date().toISOString()
        });
        console.error('[dates-scheduler] scrape failed:', err.message);
        throw err;
    } finally {
        scrapeBusy = false;
    }
}

async function buildStatus(pool) {
    const settings = await getSettings(pool);
    const nextRunAt = computeNextRun(settings);
    const summary = scheduleSummary(settings);
    return {
        success: true,
        enabled: settings.enabled,
        paused: !settings.enabled,
        dayOfWeek: settings.dayOfWeek,
        dayName: summary.dayName,
        hour: settings.hour,
        minute: settings.minute,
        timezone: settings.timezone,
        source: settings.source,
        sourceLabel: SOURCE_LABELS[settings.source] || settings.source,
        cronExpression: cronExpression(settings),
        scheduleDescription: scheduleDescription(settings),
        timeLabel: summary.timeLabel,
        frequencyLabel: summary.frequencyLabel,
        lastRunAt: settings.lastRunAt,
        lastRunStatus: settings.lastRunStatus,
        lastRunReport: settings.lastRunReport,
        nextRunAt,
        busy: scrapeBusy,
        updatedAt: settings.updatedAt,
        defaults: { ...DEFAULTS, dayName: DAY_NAMES[DEFAULTS.dayOfWeek] }
    };
}

function attachRegattaDatesScheduler(app, { pool, runScrape }) {
    deps = { pool, runScrape };

    getSettings(pool)
        .then((settings) => {
            rebuildCron(settings);
        })
        .catch((err) => {
            console.error('[dates-scheduler] init failed:', err.message);
            rebuildCron(DEFAULTS);
        });

    app.get('/api/regatta-dates/schedule', async (req, res) => {
        try {
            res.json(await buildStatus(pool));
        } catch (err) {
            console.error('[dates-scheduler] status error:', err);
            res.status(500).json({ success: false, error: err.message });
        }
    });

    app.put('/api/regatta-dates/schedule', async (req, res) => {
        try {
            const body = req.body || {};
            const saved = await saveSettings(pool, {
                enabled: body.enabled !== undefined ? body.enabled : body.paused !== undefined ? !body.paused : undefined,
                dayOfWeek: body.dayOfWeek,
                hour: body.hour,
                minute: body.minute,
                source: body.source,
                timezone: DEFAULTS.timezone
            });
            rebuildCron(saved);
            res.json({ success: true, message: 'Schedule updated', ...(await buildStatus(pool)) });
        } catch (err) {
            console.error('[dates-scheduler] update error:', err);
            res.status(500).json({ success: false, error: err.message });
        }
    });

    app.post('/api/regatta-dates/schedule/pause', async (req, res) => {
        try {
            await saveSettings(pool, { enabled: false });
            rebuildCron(await getSettings(pool));
            res.json({ success: true, message: 'Scheduler paused', ...(await buildStatus(pool)) });
        } catch (err) {
            res.status(500).json({ success: false, error: err.message });
        }
    });

    app.post('/api/regatta-dates/schedule/resume', async (req, res) => {
        try {
            await saveSettings(pool, { enabled: true });
            rebuildCron(await getSettings(pool));
            res.json({ success: true, message: 'Scheduler resumed', ...(await buildStatus(pool)) });
        } catch (err) {
            res.status(500).json({ success: false, error: err.message });
        }
    });

    app.post('/api/regatta-dates/schedule/run-now', async (req, res) => {
        try {
            if (scrapeBusy) {
                return res.status(409).json({
                    success: false,
                    error: 'A calendar scrape is already running',
                    ...(await buildStatus(pool))
                });
            }
            const requested = normalizeSource(req.body && req.body.source);
            fireScheduledScrape('scheduled_manual', requested).catch((err) => {
                console.error('[dates-scheduler] run-now failed:', err.message);
            });
            res.json({
                success: true,
                message: `Calendar scrape started (${SOURCE_LABELS[requested] || requested})`,
                ...(await buildStatus(pool))
            });
        } catch (err) {
            res.status(500).json({ success: false, error: err.message });
        }
    });
}

async function getDatesScheduleStatus(pool) {
    return buildStatus(pool);
}

module.exports = {
    SETTINGS_TABLE,
    DEFAULTS,
    attachRegattaDatesScheduler,
    getDatesScheduleStatus
};
