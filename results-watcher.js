const crypto = require('crypto');

const WATCH_POLL_CRON = '*/15 * * * *';
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MAX_URL_LEN = 2000;

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
            expires_at TIMESTAMP DEFAULT (CURRENT_TIMESTAMP + INTERVAL '21 days'),
            UNIQUE (email, results_url)
        )
    `);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_results_watchers_active ON results_watchers(active) WHERE active = TRUE;`);
}

function escapeHtml(value) {
    return String(value || '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

function watchEmailBodies({ title, intro, resultsUrl, stopUrl, extra }) {
    const name = title || 'regatta results';
    const extraText = extra ? `\n${extra}\n` : '';
    const text = [
        intro,
        '',
        `Regatta: ${name}`,
        `Results: ${resultsUrl}`,
        extraText,
        `Stop these alerts: ${stopUrl}`,
        '',
        'Love Sailing'
    ].join('\n');

    const html = `
        <div style="font-family:Arial,sans-serif;color:#111;line-height:1.5">
            <p>${escapeHtml(intro)}</p>
            <p><strong>${escapeHtml(name)}</strong></p>
            <p><a href="${escapeHtml(resultsUrl)}" style="background:#0066cc;color:#fff;padding:10px 16px;border-radius:6px;text-decoration:none;display:inline-block">View results</a></p>
            ${extra ? `<p>${escapeHtml(extra)}</p>` : ''}
            <p style="margin-top:24px;font-size:13px;color:#555">
                <a href="${escapeHtml(stopUrl)}">Stop these alerts</a>
            </p>
        </div>
    `;
    return { text, html };
}

async function sendWatchEmail(emailTransporter, { to, subject, title, intro, resultsUrl, stopUrl, extra }) {
    if (!emailTransporter) throw new Error('Email is not configured');
    const bodies = watchEmailBodies({ title, intro, resultsUrl, stopUrl, extra });
    await emailTransporter.sendMail({
        from: mailFrom(),
        to,
        subject,
        text: bodies.text,
        html: bodies.html
    });
}

function stopUrlForToken(token) {
    return `${publicBaseUrl()}/stop-alerts.html?token=${encodeURIComponent(token)}`;
}

let pollRunning = false;

async function pollActiveWatchers({ pool, axios, cheerio, emailTransporter }) {
    if (pollRunning) {
        console.log('[Results Watcher] Previous poll still running, skipping');
        return;
    }
    pollRunning = true;
    try {
        await ensureResultsWatchersTable(pool);
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
                const response = await axios.get(watch.results_url, {
                    headers: {
                        'User-Agent': 'Mozilla/5.0 LoveSailing Results Watcher',
                        'Accept': 'text/html,application/xhtml+xml'
                    },
                    timeout: 25000,
                    maxRedirects: 5,
                    validateStatus: status => status >= 200 && status < 400
                });
                const html = typeof response.data === 'string'
                    ? response.data
                    : JSON.stringify(response.data);
                const hash = fingerprintHtml(cheerio, html);
                const changed = Boolean(watch.content_hash) && watch.content_hash !== hash;

                if (changed) {
                    await sendWatchEmail(emailTransporter, {
                        to: watch.email,
                        subject: `Results updated: ${watch.regatta_name || 'regatta'}`,
                        title: watch.regatta_name || 'Regatta results',
                        intro: 'Scores look like they were updated. Open the results page to see the latest standings.',
                        resultsUrl: watch.results_url,
                        stopUrl: stopUrlForToken(watch.token)
                    });
                }

                await pool.query(`
                    UPDATE results_watchers
                    SET content_hash = $2,
                        last_checked = CURRENT_TIMESTAMP,
                        last_changed = CASE WHEN $3 THEN CURRENT_TIMESTAMP ELSE last_changed END,
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

function attachResultsWatcher(app, { pool, axios, cheerio, emailTransporter, cron }) {
    app.post('/api/results-watch', async (req, res) => {
        try {
            await ensureResultsWatchersTable(pool);
            const email = normalizeEmail(req.body && req.body.email);
            const resultsUrl = normalizeUrl(req.body && (req.body.resultsUrl || req.body.websiteUrl));
            const regattaName = String((req.body && req.body.regattaName) || '').trim().slice(0, 200) || null;

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
                `SELECT token, active FROM results_watchers WHERE email = $1 AND results_url = $2`,
                [email, resultsUrl]
            );

            let token;
            let created = false;
            if (existing.rows.length) {
                token = existing.rows[0].token;
                await pool.query(`
                    UPDATE results_watchers
                    SET active = TRUE,
                        regatta_name = COALESCE($3, regatta_name),
                        expires_at = CURRENT_TIMESTAMP + INTERVAL '21 days',
                        last_error = NULL
                    WHERE email = $1 AND results_url = $2
                `, [email, resultsUrl, regattaName]);
            } else {
                token = newWatchToken();
                created = true;
                await pool.query(`
                    INSERT INTO results_watchers (token, email, results_url, regatta_name)
                    VALUES ($1, $2, $3, $4)
                `, [token, email, resultsUrl, regattaName]);
            }

            const stopUrl = stopUrlForToken(token);
            try {
                await sendWatchEmail(emailTransporter, {
                    to: email,
                    subject: created
                        ? `Results alerts on: ${regattaName || 'regatta'}`
                        : `Results alerts restarted: ${regattaName || 'regatta'}`,
                    title: regattaName || 'Regatta results',
                    intro: created
                        ? 'We will email you when this results page changes. Checks run about every 15 minutes.'
                        : 'Your results alerts are active again. Checks run about every 15 minutes.',
                    resultsUrl,
                    stopUrl,
                    extra: 'You can stop alerts from this email or from the Love Sailing website.'
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
                message: created ? 'Alerts are on. Check your email for a stop link.' : 'Alerts are on again.'
            });
        } catch (err) {
            console.error('[Results Watcher] Create failed:', err);
            res.status(500).json({ success: false, error: 'Could not set up alerts.' });
        }
    });

    async function stopByToken(token) {
        const result = await pool.query(`
            UPDATE results_watchers
            SET active = FALSE
            WHERE token = $1
            RETURNING email, results_url, regatta_name
        `, [token]);
        return result.rows[0] || null;
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
                    SET active = FALSE
                    WHERE token = ANY($1::text[]) AND active = TRUE
                    RETURNING results_url, regatta_name
                `, [tokens]);
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
                SELECT token, active, email, regatta_name, results_url, created_at, last_checked, last_changed, expires_at
                FROM results_watchers
                WHERE token = ANY($1::text[])
                ORDER BY created_at DESC
            `, [tokens]);
            res.json({ success: true, watches: result.rows });
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
                    subject: 'Results alert email updated',
                    title: sample && sample.regatta_name ? sample.regatta_name : 'Regatta results',
                    intro: `Future results alerts will be sent to ${email}.`,
                    resultsUrl: (sample && sample.results_url) || publicBaseUrl() + '/Find-regatta.html#alerts',
                    stopUrl: sample ? stopUrlForToken(sample.token) : publicBaseUrl() + '/Find-regatta.html#alerts',
                    extra: updated > 1 ? `${updated} alerts on this device now use this email.` : 'This alert on this device now uses this email.'
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
    fingerprintHtml
};
