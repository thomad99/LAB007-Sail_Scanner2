const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

    const WATCH_POLL_CRON = '*/15 * * * *';
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MAX_URL_LEN = 2000;

let pollDeps = null;

function publicBaseUrl() {
    return (process.env.PUBLIC_BASE_URL || 'https://lovesailing.ai').replace(/\/$/, '');
}

function mailFrom() {
    return process.env.SMTP_FROM || process.env.SMTP_USER || 'noreply@lovesailing.ai';
}

function normalizeEmail(email) {
    return String(email || '').trim().toLowerCase();
}

function normalizeUrl(url) {
    return String(url || '').trim();
}

function normalizeRegattaDate(value) {
    const s = String(value || '').trim().slice(0, 10);
    return /^\d{4}-\d{2}-\d{2}$/.test(s) ? s : null;
}

function parseTokens(raw) {
    const list = Array.isArray(raw) ? raw : (raw ? [raw] : []);
    const tokens = [...new Set(list.map(value => String(value || '').trim()).filter(value => value && value.length <= 128))];
    return tokens.slice(0, 50);
}

function isValidHttpUrl(url) {
    try {
        const parsed = new URL(url);
        return parsed.protocol === 'http:' || parsed.protocol === 'https:';
    } catch (_err) {
        return false;
    }
}

function newWatchToken() {
    return crypto.randomBytes(24).toString('hex');
}

function fingerprintHtml(cheerio, html) {
    const $ = cheerio.load(html || '');
    $('script, style, noscript, iframe, svg, canvas, link, meta').remove();
    const chunks = [];
    const tables = $('table');
    if (tables.length) {
        tables.each((_, table) => {
            chunks.push($(table).text());
        });
    } else {
        chunks.push($('main').text() || $('body').text() || $.root().text());
    }
    const text = chunks.join('\n')
        .replace(/\b\d{1,2}:\d{2}(?::\d{2})?\s*(?:am|pm)?\b/gi, ' ')
        .replace(/\b(?:last updated|updated|as of|generated)\b[^\n]{0,80}/gi, ' ')
        .replace(/\s+/g, ' ')
        .trim()
        .toLowerCase();
    return crypto.createHash('sha256').update(text).digest('hex');
}

async function ensureResultsWatchersTable(pool) {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS results_watchers (
            id SERIAL PRIMARY KEY,
            token TEXT UNIQUE NOT NULL,
            email TEXT NOT NULL,
            results_url TEXT NOT NULL,
            regatta_name TEXT,
            content_hash TEXT,
            last_checked TIMESTAMP,
            last_changed TIMESTAMP,
            last_error TEXT,
            active BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP DEFAULT (CURRENT_TIMESTAMP + INTERVAL '48 hours'),
            UNIQUE (email, results_url)
        )
    `);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_results_watchers_active ON results_watchers(active) WHERE active = TRUE;`);
    await pool.query(`ALTER TABLE results_watchers ADD COLUMN IF NOT EXISTS notify_count INTEGER DEFAULT 0`);
    await pool.query(`ALTER TABLE results_watchers ADD COLUMN IF NOT EXISTS stopped_at TIMESTAMP`);
    await pool.query(`ALTER TABLE results_watchers ADD COLUMN IF NOT EXISTS regatta_date DATE`);
    await pool.query(`ALTER TABLE results_watchers ALTER COLUMN expires_at SET DEFAULT (CURRENT_TIMESTAMP + INTERVAL '48 hours')`);
    await pool.query(`
        CREATE TABLE IF NOT EXISTS results_watch_events (
            id SERIAL PRIMARY KEY,
            watch_id INTEGER,
            event_type TEXT NOT NULL,
            detail TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    `);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_results_watch_events_created ON results_watch_events(created_at DESC)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_results_watch_events_type ON results_watch_events(event_type)`);
}

async function logWatchEvent(pool, watchId, eventType, detail) {
    try {
        await pool.query(
            `INSERT INTO results_watch_events (watch_id, event_type, detail) VALUES ($1, $2, $3)`,
            [watchId || null, eventType, detail ? String(detail).slice(0, 500) : null]
        );
    } catch (err) {
        console.error('[Results Watcher] Event log failed:', err.message);
    }
}

function escapeHtml(value) {
    return String(value || '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

const LOGO_FILE = path.join(__dirname, 'public', 'Images', 'Sail_Logo_Trans.PNG');

function watchLogoUrl() {
    return `${publicBaseUrl()}/Images/Sail_Logo_Trans.PNG`;
}

function watchLogoAttachment() {
    try {
        if (fs.existsSync(LOGO_FILE)) {
            return {
                filename: 'Sail_Logo_Trans.PNG',
                path: LOGO_FILE,
                cid: 'lovesailing-logo',
                contentType: 'image/png'
            };
        }
    } catch (_err) {}
    return null;
}

function emailCopy(kind) {
    if (kind === 'updated') {
        return {
            badge: 'RESULTS UPDATED',
            heading: 'New results are in.',
            extraTitle: 'Still watching'
        };
    }
    if (kind === 'email') {
        return {
            badge: 'ALERT EMAIL UPDATED',
            heading: "We'll use this inbox.",
            extraTitle: 'Your alerts'
        };
    }
    return {
        badge: 'RESULTS ALERTS \u2022 ON',
        heading: "You're on the list.",
        extraTitle: 'Following for 48 hours'
    };
}

function formatAlertTime(value) {
    const d = value instanceof Date ? value : new Date(value || Date.now());
    if (Number.isNaN(d.getTime())) return '';
    return d.toLocaleString('en-US', {
        timeZone: 'America/New_York',
        weekday: 'short',
        month: 'short',
        day: 'numeric',
        year: 'numeric',
        hour: 'numeric',
        minute: '2-digit',
        timeZoneName: 'short'
    });
}

function watchEmailBodies({ title, intro, resultsUrl, stopUrl, extra, changedAt, kind, logoSrc }) {
    const name = title || 'regatta results';
    const copy = emailCopy(kind);
    const extraText = extra ? `\n${extra}\n` : '';
    const changedLine = changedAt ? `Updated: ${formatAlertTime(changedAt)}` : '';
    const logo = escapeHtml(logoSrc || watchLogoUrl());
    const extraTitle = extra ? (copy.extraTitle || 'Note') : '';
    const text = [
        copy.heading,
        intro,
        '',
        `Regatta: ${name}`,
        changedLine,
        `Results: ${resultsUrl}`,
        extraText,
        `STOP ALERTS: ${stopUrl}`,
        '',
        'Love Sailing'
    ].filter(Boolean).join('\n');

    const extraBlock = extra ? `
        <tr>
            <td style="padding:0 32px 28px;font-family:Arial,Helvetica,sans-serif;">
                <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
                    <tr>
                        <td width="4" bgcolor="#148c8c" style="width:4px;background:#148c8c;font-size:0;line-height:0;">&nbsp;</td>
                        <td bgcolor="#eef6f5" style="padding:16px 18px;background:#eef6f5;">
                            <p style="margin:0 0 6px;font-size:14px;font-weight:700;color:#0b2e3f;">${escapeHtml(extraTitle)}</p>
                            <p style="margin:0;font-size:14px;line-height:1.5;color:#5b7380;">${escapeHtml(extra)}</p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>` : '';

    const html = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Love Sailing</title>
</head>
<body style="margin:0;padding:0;background:#f3f5f6;">
    <div style="display:none;max-height:0;overflow:hidden;mso-hide:all;">${escapeHtml(intro)}</div>
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f3f5f6;">
        <tr>
            <td align="center" style="padding:16px 12px;">
                <table role="presentation" width="560" cellpadding="0" cellspacing="0" style="max-width:560px;width:100%;background:#ffffff;border:1px solid #e4ecee;">
                    <tr>
                        <td style="height:6px;background:#148c8c;font-size:0;line-height:0;">&nbsp;</td>
                    </tr>
                    <tr>
                        <td style="background:#0b2e3f;padding:28px 32px 36px;font-family:Arial,Helvetica,sans-serif;">
                            <table role="presentation" cellpadding="0" cellspacing="0" style="margin-bottom:22px;">
                                <tr>
                                    <td style="vertical-align:middle;padding:0;">
                                        <img src="${logo}" alt="Love Sailing" width="48" height="52" style="display:block;border:0;width:48px;height:52px;">
                                    </td>
                                    <td style="padding-left:12px;vertical-align:middle;font-family:Arial,Helvetica,sans-serif;font-size:16px;font-weight:700;color:#ffffff;letter-spacing:0.04em;">Love Sailing</td>
                                </tr>
                            </table>
                            <table role="presentation" cellpadding="0" cellspacing="0">
                                <tr>
                                    <td style="background:#1e4a56;color:#b7d9d6;font-size:11px;font-weight:700;letter-spacing:0.08em;padding:6px 10px;font-family:Arial,Helvetica,sans-serif;">${escapeHtml(copy.badge)}</td>
                                </tr>
                            </table>
                            <h1 style="margin:18px 0 10px;color:#ffffff;font-size:30px;line-height:1.15;font-weight:700;letter-spacing:-0.02em;">${escapeHtml(copy.heading)}</h1>
                            <p style="margin:0;color:#c5d4dc;font-size:16px;line-height:1.5;">${escapeHtml(intro)}</p>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding:28px 32px 22px;font-family:Arial,Helvetica,sans-serif;">
                            <p style="margin:0 0 8px;font-size:11px;font-weight:700;letter-spacing:0.12em;color:#8a9aa3;">YOUR REGATTA</p>
                            <h2 style="margin:0 0 18px;font-size:26px;line-height:1.2;font-weight:700;color:#0b2e3f;">${escapeHtml(name)}</h2>
                            ${changedAt ? `<p style="margin:0 0 16px;font-size:14px;color:#5b7380;">Updated: <strong style="color:#0b2e3f;">${escapeHtml(formatAlertTime(changedAt))}</strong></p>` : ''}
                            <a href="${escapeHtml(resultsUrl)}" style="background:#148c8c;color:#ffffff;padding:12px 20px;border-radius:8px;text-decoration:none;display:inline-block;font-weight:700;font-size:15px;font-family:Arial,Helvetica,sans-serif;">View results &rarr;</a>
                        </td>
                    </tr>
                    ${extraBlock}
                    <tr>
                        <td style="padding:22px 32px 28px;border-top:1px solid #e8eef0;font-family:Arial,Helvetica,sans-serif;">
                            <a href="${escapeHtml(stopUrl)}" style="color:#5b6b75;padding:10px 18px;border:1px solid #c9d3d8;border-radius:8px;text-decoration:none;display:inline-block;font-weight:700;font-size:13px;letter-spacing:0.06em;font-family:Arial,Helvetica,sans-serif;">STOP ALERTS</a>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>`;
    return { text, html };
}

async function sendWatchEmail(emailTransporter, { to, title, intro, resultsUrl, stopUrl, extra, subject, changedAt, kind }) {
    if (!emailTransporter) throw new Error('Email is not configured');
    const attachment = watchLogoAttachment();
    const bodies = watchEmailBodies({
        title,
        intro,
        resultsUrl,
        stopUrl,
        extra,
        changedAt,
        kind,
        logoSrc: attachment ? 'cid:lovesailing-logo' : watchLogoUrl()
    });
    await emailTransporter.sendMail({
        from: mailFrom(),
        to,
        subject: subject || 'Love Sailing - Alerts',
        text: bodies.text,
        html: bodies.html,
        attachments: attachment ? [attachment] : []
    });
}

function stopUrlForToken(token) {
    return `${publicBaseUrl()}/stop-alerts.html?token=${encodeURIComponent(token)}`;
}

function clubspotEventIdFromUrl(url) {
    const match = String(url || '').match(/theclubspot\.com\/regatta\/([^/?#]+)/i);
    return match ? match[1] : null;
}

function regattaNetworkEventIdFromUrl(url) {
    const match = String(url || '').match(/regattanetwork\.com\/event\/(\d+)/i);
    return match ? match[1] : null;
}

function splitStoredHash(stored) {
    const text = String(stored || '');
    const idx = text.indexOf('|');
    if (idx < 0) return { local: text, remote: '' };
    return { local: text.slice(0, idx), remote: text.slice(idx + 1) };
}

async function fingerprintLocalResults(pool, regattaName) {
    const name = String(regattaName || '').trim();
    if (!name) return 'local:none';
    try {
        const result = await pool.query(`
            SELECT
                COUNT(*)::int AS n,
                COALESCE(md5(string_agg(payload, E'\\n' ORDER BY payload)), 'empty') AS digest
            FROM (
                SELECT CONCAT_WS('|',
                    COALESCE(category, ''),
                    COALESCE(position, ''),
                    COALESCE(sail_number, ''),
                    COALESCE(skipper, ''),
                    COALESCE(results, ''),
                    COALESCE(total_points, '')
                ) AS payload
                FROM scraped_race_results
                WHERE LOWER(TRIM(regatta_name)) = LOWER(TRIM($1))
                   OR LOWER(TRIM(regatta_name)) LIKE LOWER(TRIM($1)) || ' %'
                   OR LOWER(TRIM($1)) LIKE LOWER(TRIM(regatta_name)) || ' %'
            ) scores
        `, [name]);
        const row = result.rows[0] || {};
        return `local:${row.n || 0}:${row.digest || 'empty'}`;
    } catch (err) {
        console.error('[Results Watcher] Local fingerprint failed:', err.message);
        return 'local:unavailable';
    }
}

async function fingerprintRemoteResults(axios, cheerio, url) {
    const clean = String(url || '').split('#')[0];
    const csId = clubspotEventIdFromUrl(clean);
    if (csId) {
        const response = await axios.get(`https://results.theclubspot.com/clubspot-results-v4/${encodeURIComponent(csId)}`, {
            headers: {
                'User-Agent': 'Mozilla/5.0 LoveSailing Results Watcher',
                'Accept': 'application/json,text/plain,*/*'
            },
            timeout: 25000,
            validateStatus: status => status >= 200 && status < 400
        });
        const body = typeof response.data === 'string' ? response.data : JSON.stringify(response.data || {});
        return 'cs:' + crypto.createHash('sha256').update(body).digest('hex');
    }

    const rnId = regattaNetworkEventIdFromUrl(clean);
    const fetchUrl = rnId ? `https://www.regattanetwork.com/event/${rnId}` : clean;
    const response = await axios.get(fetchUrl, {
        headers: {
            'User-Agent': 'Mozilla/5.0 LoveSailing Results Watcher',
            'Accept': 'text/html,application/xhtml+xml'
        },
        timeout: 25000,
        maxRedirects: 5,
        validateStatus: status => status >= 200 && status < 400
    });
    const html = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
    return 'html:' + fingerprintHtml(cheerio, html);
}

async function combinedWatchHash({ pool, axios, cheerio, watch }) {
    const previous = splitStoredHash(watch.content_hash);
    const localHash = await fingerprintLocalResults(pool, watch.regatta_name);
    let remoteHash = previous.remote || 'remote:none';
    try {
        remoteHash = await fingerprintRemoteResults(axios, cheerio, watch.results_url);
    } catch (err) {
        console.warn(`[Results Watcher] Remote check failed for ${watch.results_url}: ${err.message}`);
        remoteHash = previous.remote || 'remote:none';
    }
    return `${localHash}|${remoteHash}`;
}

let pollRunning = false;

async function expireDueWatchers(pool) {
    const expired = await pool.query(`
        UPDATE results_watchers
        SET active = FALSE,
            stopped_at = COALESCE(stopped_at, CURRENT_TIMESTAMP)
        WHERE active = TRUE
          AND expires_at IS NOT NULL
          AND expires_at <= CURRENT_TIMESTAMP
        RETURNING id, regatta_name
    `);
    for (const row of expired.rows) {
        await logWatchEvent(pool, row.id, 'expired', row.regatta_name);
    }
    return expired.rowCount || 0;
}

async function pollActiveWatchers({ pool, axios, cheerio, emailTransporter }) {
    if (pollRunning) {
        console.log('[Results Watcher] Previous poll still running, skipping');
        return;
    }
    pollRunning = true;
    try {
        await ensureResultsWatchersTable(pool);
        await expireDueWatchers(pool);
        const result = await pool.query(`
            SELECT id, token, email, results_url, regatta_name, content_hash
            FROM results_watchers
            WHERE active = TRUE
              AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
            ORDER BY last_checked NULLS FIRST, id ASC
            LIMIT 200
        `);

        for (const watch of result.rows) {
            try {
                const hash = await combinedWatchHash({ pool, axios, cheerio, watch });
                const stored = String(watch.content_hash || '');
                const comparable = stored.includes('|');
                const changed = comparable && stored !== hash;
                const changedAt = new Date();

                if (changed) {
                    await sendWatchEmail(emailTransporter, {
                        to: watch.email,
                        title: watch.regatta_name || 'Regatta results',
                        intro: 'Results were updated. Open the results page to see the latest standings.',
                        resultsUrl: watch.results_url,
                        stopUrl: stopUrlForToken(watch.token),
                        subject: 'LOVE SAILING - Results updated',
                        changedAt,
                        kind: 'updated',
                        extra: 'Alerts stop automatically after 48 hours. You can also stop them anytime below.'
                    });
                    await logWatchEvent(pool, watch.id, 'notified', watch.regatta_name);
                }

                await pool.query(`
                    UPDATE results_watchers
                    SET content_hash = $2,
                        last_checked = CURRENT_TIMESTAMP,
                        last_changed = CASE WHEN $3 THEN CURRENT_TIMESTAMP ELSE last_changed END,
                        notify_count = CASE WHEN $3 THEN COALESCE(notify_count, 0) + 1 ELSE notify_count END,
                        last_error = NULL
                    WHERE id = $1
                `, [watch.id, hash, changed]);
            } catch (err) {
                await pool.query(`
                    UPDATE results_watchers
                    SET last_checked = CURRENT_TIMESTAMP, last_error = $2
                    WHERE id = $1
                `, [watch.id, String(err.message || err).slice(0, 500)]);
                console.error(`[Results Watcher] ${watch.results_url}:`, err.message);
            }
            await new Promise(r => setTimeout(r, 250));
        }
    } catch (err) {
        console.error('[Results Watcher] Poll failed:', err.message);
    } finally {
        pollRunning = false;
    }
}

async function notifyWatchersAfterScrape() {
    if (!pollDeps) return;
    await pollActiveWatchers(pollDeps);
}

function attachResultsWatcher(app, { pool, axios, cheerio, emailTransporter, cron }) {
    pollDeps = { pool, axios, cheerio, emailTransporter };
    app.post('/api/results-watch', async (req, res) => {
        try {
            await ensureResultsWatchersTable(pool);
            const email = normalizeEmail(req.body && req.body.email);
            const resultsUrl = normalizeUrl(req.body && (req.body.resultsUrl || req.body.websiteUrl));
            const regattaName = String((req.body && req.body.regattaName) || '').trim().slice(0, 200) || null;
            const regattaDate = normalizeRegattaDate(req.body && (req.body.regattaDate || req.body.regatta_date));

            if (!EMAIL_RE.test(email)) {
                return res.status(400).json({ success: false, error: 'Please enter a valid email address.' });
            }
            if (!resultsUrl || resultsUrl.length > MAX_URL_LEN || !isValidHttpUrl(resultsUrl)) {
                return res.status(400).json({ success: false, error: 'A valid results page URL is required.' });
            }
            if (!process.env.SMTP_USER && !process.env.SMTP_FROM) {
                return res.status(503).json({ success: false, error: 'Email alerts are not configured on the server yet.' });
            }

            const existing = await pool.query(
                `SELECT id, token, active FROM results_watchers WHERE email = $1 AND results_url = $2`,
                [email, resultsUrl]
            );

            let token;
            let created = false;
            let watchId;
            if (existing.rows.length) {
                watchId = existing.rows[0].id;
                token = existing.rows[0].token;
                const wasActive = existing.rows[0].active;
                await pool.query(`
                    UPDATE results_watchers
                    SET active = TRUE,
                        regatta_name = COALESCE($3, regatta_name),
                        regatta_date = COALESCE($4::date, regatta_date),
                        expires_at = CURRENT_TIMESTAMP + INTERVAL '48 hours',
                        last_error = NULL,
                        stopped_at = NULL
                    WHERE email = $1 AND results_url = $2
                `, [email, resultsUrl, regattaName, regattaDate]);
                await logWatchEvent(pool, watchId, wasActive ? 'renewed' : 'reactivated', regattaName);
            } else {
                token = newWatchToken();
                created = true;
                const inserted = await pool.query(`
                    INSERT INTO results_watchers (token, email, results_url, regatta_name, regatta_date)
                    VALUES ($1, $2, $3, $4, $5::date)
                    RETURNING id
                `, [token, email, resultsUrl, regattaName, regattaDate]);
                watchId = inserted.rows[0].id;
                await logWatchEvent(pool, watchId, 'created', regattaName);
            }

            const stopUrl = stopUrlForToken(token);
            try {
                await sendWatchEmail(emailTransporter, {
                    to: email,
                    title: regattaName || 'Regatta results',
                    intro: created
                        ? "We'll email you when results are posted or scores change for this regatta."
                        : 'Your results alerts are active again for this regatta.',
                    resultsUrl,
                    stopUrl,
                    subject: created ? 'LOVE SAILING - Alerts started' : 'LOVE SAILING - Alerts active',
                    extra: 'Alerts stop automatically after 48 hours. You can also stop them anytime below.',
                    kind: created ? 'started' : 'active'
                });
            } catch (mailErr) {
                console.error('[Results Watcher] Confirmation email failed:', mailErr.message);
                return res.status(502).json({
                    success: false,
                    error: 'Saved the watcher, but the confirmation email could not be sent. Check SMTP settings.'
                });
            }

            res.json({
                success: true,
                token,
                stopUrl,
                created,
                message: created ? 'Alerts are on for 48 hours. Check your email for a STOP ALERTS button.' : 'Alerts are on again for 48 hours.'
            });
        } catch (err) {
            console.error('[Results Watcher] Create failed:', err);
            res.status(500).json({ success: false, error: 'Could not set up alerts.' });
        }
    });

    async function stopByToken(token) {
        const current = await pool.query(
            `SELECT id, email, results_url, regatta_name, active FROM results_watchers WHERE token = $1`,
            [token]
        );
        if (!current.rows.length) return null;
        const watch = current.rows[0];
        if (watch.active) {
            await pool.query(`
                UPDATE results_watchers
                SET active = FALSE, stopped_at = CURRENT_TIMESTAMP
                WHERE id = $1
            `, [watch.id]);
            await logWatchEvent(pool, watch.id, 'stopped', watch.regatta_name);
        }
        return {
            email: watch.email,
            results_url: watch.results_url,
            regatta_name: watch.regatta_name
        };
    }

    app.get('/api/results-watch/stop', async (req, res) => {
        try {
            await ensureResultsWatchersTable(pool);
            const token = String(req.query.token || '').trim();
            if (!token) {
                return res.status(400).json({ success: false, error: 'Missing stop token.' });
            }
            const stopped = await stopByToken(token);
            if (!stopped) {
                return res.status(404).json({ success: false, error: 'This alert was not found or was already stopped.' });
            }
            res.json({ success: true, message: 'Alerts stopped.', watch: stopped });
        } catch (err) {
            console.error('[Results Watcher] Stop failed:', err);
            res.status(500).json({ success: false, error: 'Could not stop alerts.' });
        }
    });

    app.post('/api/results-watch/stop', async (req, res) => {
        try {
            await ensureResultsWatchersTable(pool);
            const token = String((req.body && req.body.token) || req.query.token || '').trim();
            const tokens = parseTokens(req.body && req.body.tokens);

            if (token) {
                const stopped = await stopByToken(token);
                if (!stopped) {
                    return res.status(404).json({ success: false, error: 'This alert was not found or was already stopped.' });
                }
                return res.json({ success: true, message: 'Alerts stopped.', watch: stopped });
            }

            if (tokens.length) {
                const result = await pool.query(`
                    UPDATE results_watchers
                    SET active = FALSE, stopped_at = COALESCE(stopped_at, CURRENT_TIMESTAMP)
                    WHERE token = ANY($1::text[]) AND active = TRUE
                    RETURNING id, results_url, regatta_name
                `, [tokens]);
                for (const row of result.rows) {
                    await logWatchEvent(pool, row.id, 'stopped', row.regatta_name);
                }
                return res.json({
                    success: true,
                    message: result.rowCount ? `Stopped ${result.rowCount} alert(s).` : 'No matching alerts to stop.',
                    count: result.rowCount
                });
            }

            return res.status(400).json({ success: false, error: 'Provide a stop token.' });
        } catch (err) {
            console.error('[Results Watcher] Stop failed:', err);
            res.status(500).json({ success: false, error: 'Could not stop alerts.' });
        }
    });

    app.post('/api/results-watch/mine', async (req, res) => {
        try {
            await ensureResultsWatchersTable(pool);
            const tokens = parseTokens(req.body && req.body.tokens);
            if (!tokens.length) {
                return res.json({ success: true, watches: [] });
            }
            const result = await pool.query(`
                SELECT token, active, email, regatta_name, regatta_date::text AS regatta_date,
                    results_url, created_at, last_checked, last_changed, expires_at, notify_count
                FROM results_watchers
                WHERE token = ANY($1::text[])
                ORDER BY created_at DESC
            `, [tokens]);
            const watches = result.rows || [];
            const missingNames = [...new Set(
                watches
                    .filter((row) => !normalizeRegattaDate(row.regatta_date) && row.regatta_name)
                    .map((row) => String(row.regatta_name).trim().toLowerCase())
            )];
            if (missingNames.length) {
                try {
                    const found = await pool.query(`
                        SELECT LOWER(TRIM(regatta_name)) AS key,
                            MIN(regatta_date)::text AS regatta_date
                        FROM regattas
                        WHERE LOWER(TRIM(regatta_name)) = ANY($1::text[])
                        GROUP BY LOWER(TRIM(regatta_name))
                    `, [missingNames]);
                    const byName = new Map((found.rows || []).map((row) => [row.key, row.regatta_date]));
                    watches.forEach((row) => {
                        if (normalizeRegattaDate(row.regatta_date)) return;
                        const lookedUp = byName.get(String(row.regatta_name || '').trim().toLowerCase());
                        if (lookedUp) row.regatta_date = lookedUp;
                    });
                } catch (lookupErr) {
                    console.warn('[Results Watcher] Date lookup failed:', lookupErr.message);
                }
            }
            res.json({ success: true, watches });
        } catch (err) {
            console.error('[Results Watcher] Mine failed:', err);
            res.status(500).json({ success: false, error: 'Could not load alerts.' });
        }
    });

    app.post('/api/results-watch/email', async (req, res) => {
        try {
            await ensureResultsWatchersTable(pool);
            const email = normalizeEmail(req.body && req.body.email);
            const tokens = parseTokens(req.body && req.body.tokens);
            if (!EMAIL_RE.test(email)) {
                return res.status(400).json({ success: false, error: 'Please enter a valid email address.' });
            }
            if (!tokens.length) {
                return res.status(400).json({ success: false, error: 'No alerts to update on this device.' });
            }

            const existing = await pool.query(`
                SELECT id, token, results_url, regatta_name, active
                FROM results_watchers
                WHERE token = ANY($1::text[])
            `, [tokens]);
            if (!existing.rows.length) {
                return res.status(404).json({ success: false, error: 'No matching alerts were found for this device.' });
            }

            let updated = 0;
            for (const watch of existing.rows) {
                if (!watch.active) continue;
                const conflict = await pool.query(
                    `SELECT id FROM results_watchers WHERE email = $1 AND results_url = $2 AND token <> $3`,
                    [email, watch.results_url, watch.token]
                );
                if (conflict.rows.length) {
                    await pool.query(`UPDATE results_watchers SET active = FALSE WHERE id = $1`, [conflict.rows[0].id]);
                }
                await pool.query(`UPDATE results_watchers SET email = $1 WHERE id = $2`, [email, watch.id]);
                updated += 1;
            }

            const sample = existing.rows.find(row => row.active) || existing.rows[0];
            try {
                await sendWatchEmail(emailTransporter, {
                    to: email,
                    title: sample && sample.regatta_name ? sample.regatta_name : 'Regatta results',
                    intro: `Future results alerts will be sent to ${email}.`,
                    resultsUrl: (sample && sample.results_url) || publicBaseUrl() + '/Find-regatta.html#alerts',
                    stopUrl: sample ? stopUrlForToken(sample.token) : publicBaseUrl() + '/Find-regatta.html#alerts',
                    extra: updated > 1 ? `${updated} alerts on this device now use this email.` : 'This alert on this device now uses this email.',
                    kind: 'email'
                });
            } catch (mailErr) {
                console.error('[Results Watcher] Email update notice failed:', mailErr.message);
            }

            res.json({
                success: true,
                email,
                updated,
                message: updated
                    ? `Alert email updated to ${email}.`
                    : 'No active alerts to update.'
            });
        } catch (err) {
            console.error('[Results Watcher] Email update failed:', err);
            res.status(500).json({ success: false, error: 'Could not update alert email.' });
        }
    });

    app.get('/api/results-watch/status', async (req, res) => {
        try {
            await ensureResultsWatchersTable(pool);
            const token = String(req.query.token || '').trim();
            if (token) {
                const result = await pool.query(`
                    SELECT active, regatta_name, results_url, created_at, last_checked, last_changed, expires_at
                    FROM results_watchers WHERE token = $1
                `, [token]);
                if (!result.rows.length) return res.status(404).json({ success: false, error: 'Alert not found.' });
                return res.json({ success: true, watch: result.rows[0] });
            }
            return res.status(400).json({ success: false, error: 'Provide a stop token.' });
        } catch (err) {
            console.error('[Results Watcher] Status failed:', err);
            res.status(500).json({ success: false, error: 'Could not load alerts.' });
        }
    });

    app.get('/api/results-watch/admin-stats', async (req, res) => {
        try {
            await ensureResultsWatchersTable(pool);
            const stillActive = `active = TRUE AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)`;
            const [totals, events7d, events30d, byRegatta, byDay, recent] = await Promise.all([
                pool.query(`
                    SELECT
                        COUNT(*) FILTER (WHERE ${stillActive})::int AS active,
                        COUNT(*)::int AS total_ever,
                        COUNT(*) FILTER (WHERE active = FALSE)::int AS stopped,
                        COUNT(*) FILTER (
                            WHERE active = TRUE AND expires_at IS NOT NULL AND expires_at <= CURRENT_TIMESTAMP
                        )::int AS expired,
                        COUNT(DISTINCT email)::int AS emails_ever,
                        COUNT(DISTINCT email) FILTER (WHERE ${stillActive})::int AS emails_active,
                        COUNT(*) FILTER (WHERE created_at >= CURRENT_TIMESTAMP - INTERVAL '7 days')::int AS created_7d,
                        COUNT(*) FILTER (WHERE created_at >= CURRENT_TIMESTAMP - INTERVAL '30 days')::int AS created_30d,
                        COUNT(*) FILTER (WHERE last_changed IS NOT NULL)::int AS ever_fired,
                        COALESCE(SUM(notify_count), 0)::int AS notifications_sent,
                        COUNT(*) FILTER (WHERE ${stillActive} AND last_error IS NOT NULL)::int AS with_errors,
                        COUNT(*) FILTER (
                            WHERE ${stillActive}
                              AND expires_at IS NOT NULL
                              AND expires_at <= CURRENT_TIMESTAMP + INTERVAL '7 days'
                        )::int AS expiring_7d
                    FROM results_watchers
                `),
                pool.query(`
                    SELECT event_type, COUNT(*)::int AS count
                    FROM results_watch_events
                    WHERE created_at >= CURRENT_TIMESTAMP - INTERVAL '7 days'
                    GROUP BY event_type
                    ORDER BY count DESC
                `),
                pool.query(`
                    SELECT event_type, COUNT(*)::int AS count
                    FROM results_watch_events
                    WHERE created_at >= CURRENT_TIMESTAMP - INTERVAL '30 days'
                    GROUP BY event_type
                    ORDER BY count DESC
                `),
                pool.query(`
                    SELECT
                        COALESCE(NULLIF(BTRIM(regatta_name), ''), '(unnamed)') AS name,
                        COUNT(*)::int AS total,
                        COUNT(*) FILTER (WHERE ${stillActive})::int AS active
                    FROM results_watchers
                    GROUP BY 1
                    ORDER BY total DESC, name ASC
                    LIMIT 12
                `),
                pool.query(`
                    SELECT created_at::date::text AS day, COUNT(*)::int AS count
                    FROM results_watchers
                    WHERE created_at >= CURRENT_DATE - 13
                    GROUP BY 1
                    ORDER BY 1
                `),
                pool.query(`
                    SELECT
                        email, regatta_name, results_url, active, created_at, last_checked,
                        last_changed, expires_at, last_error, notify_count, stopped_at
                    FROM results_watchers
                    ORDER BY created_at DESC
                    LIMIT 80
                `)
            ]);

            res.json({
                success: true,
                stats: totals.rows[0] || {},
                events7d: events7d.rows,
                events30d: events30d.rows,
                byRegatta: byRegatta.rows,
                signupsByDay: byDay.rows,
                recent: recent.rows
            });
        } catch (err) {
            console.error('[Results Watcher] Admin stats failed:', err);
            res.status(500).json({ success: false, error: 'Could not load alert stats.' });
        }
    });

    if (cron) {
        cron.schedule(WATCH_POLL_CRON, () => {
            pollActiveWatchers({ pool, axios, cheerio, emailTransporter }).catch(err => {
                console.error('[Results Watcher] Cron error:', err.message);
            });
        });
        console.log('[Results Watcher] Polling every 15 minutes');
    }
}

module.exports = {
    attachResultsWatcher,
    ensureResultsWatchersTable,
    fingerprintHtml,
    pollActiveWatchers,
    notifyWatchersAfterScrape
};
