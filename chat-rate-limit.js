/**
 * Per-browser chat cap so SailBot cannot run up an OpenAI bill.
 * The session id lives in an HttpOnly cookie and survives "New chat".
 * Each session gets CHAT_DAILY_LIMIT messages per Eastern calendar day.
 */

const crypto = require('crypto');

const CHAT_DAILY_LIMIT = 10;
const CHAT_USAGE_TABLE = 'chatbot_daily_usage';
const CHAT_SESSION_COOKIE = 'sailbot_sid';
const USAGE_TZ = 'America/New_York';

let chatUsageReady = null;

function usageDay(now = new Date()) {
    const parts = new Intl.DateTimeFormat('en-US', {
        timeZone: USAGE_TZ,
        year: 'numeric',
        month: '2-digit',
        day: '2-digit'
    }).formatToParts(now);
    const get = (type) => parts.find((p) => p.type === type).value;
    return `${get('year')}-${get('month')}-${get('day')}`;
}

function readCookie(req, name) {
    const raw = req.headers && req.headers.cookie;
    if (!raw) return null;
    for (const part of String(raw).split(';')) {
        const idx = part.indexOf('=');
        if (idx === -1) continue;
        if (part.slice(0, idx).trim() === name) {
            try {
                return decodeURIComponent(part.slice(idx + 1).trim());
            } catch (_err) {
                return null;
            }
        }
    }
    return null;
}

function cookieSecure(req) {
    const proto = String((req.headers && req.headers['x-forwarded-proto']) || '').split(',')[0].trim();
    return proto === 'https' || req.secure === true;
}

function chatSessionId(req, res) {
    let id = readCookie(req, CHAT_SESSION_COOKIE);
    if (!id || !/^[a-f0-9]{32}$/i.test(id)) {
        id = crypto.randomBytes(16).toString('hex');
        const secure = cookieSecure(req) ? '; Secure' : '';
        res.append(
            'Set-Cookie',
            `${CHAT_SESSION_COOKIE}=${id}; Path=/; Max-Age=31536000; HttpOnly; SameSite=Lax${secure}`
        );
    }
    return id;
}

async function ensureChatUsageTable(pool) {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS ${CHAT_USAGE_TABLE} (
            session_id TEXT NOT NULL,
            usage_day DATE NOT NULL,
            message_count INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (session_id, usage_day)
        )
    `);
    await pool.query(
        `DELETE FROM ${CHAT_USAGE_TABLE} WHERE usage_day < ($1::date - 14)`,
        [usageDay()]
    );
}

function ensureChatUsageOnce(pool) {
    if (!chatUsageReady) {
        chatUsageReady = ensureChatUsageTable(pool).catch((err) => {
            chatUsageReady = null;
            throw err;
        });
    }
    return chatUsageReady;
}

async function readChatQuota(pool, sessionId) {
    await ensureChatUsageOnce(pool);
    const r = await pool.query(
        `SELECT message_count FROM ${CHAT_USAGE_TABLE} WHERE session_id = $1 AND usage_day = $2::date`,
        [sessionId, usageDay()]
    );
    const used = r.rows.length ? r.rows[0].message_count : 0;
    return {
        limit: CHAT_DAILY_LIMIT,
        used,
        remaining: Math.max(0, CHAT_DAILY_LIMIT - used)
    };
}

/** Counts one chat. Returns allowed:false once the daily cap is already used. */
async function consumeChatMessage(pool, sessionId) {
    await ensureChatUsageOnce(pool);
    const r = await pool.query(
        `
        INSERT INTO ${CHAT_USAGE_TABLE} (session_id, usage_day, message_count)
        VALUES ($1, $2::date, 1)
        ON CONFLICT (session_id, usage_day)
        DO UPDATE SET message_count = ${CHAT_USAGE_TABLE}.message_count + 1
        WHERE ${CHAT_USAGE_TABLE}.message_count < $3
        RETURNING message_count
        `,
        [sessionId, usageDay(), CHAT_DAILY_LIMIT]
    );
    if (!r.rows.length) {
        return { allowed: false, limit: CHAT_DAILY_LIMIT, used: CHAT_DAILY_LIMIT, remaining: 0 };
    }
    const used = r.rows[0].message_count;
    return {
        allowed: true,
        limit: CHAT_DAILY_LIMIT,
        used,
        remaining: Math.max(0, CHAT_DAILY_LIMIT - used)
    };
}

module.exports = {
    CHAT_DAILY_LIMIT,
    usageDay,
    chatSessionId,
    readChatQuota,
    consumeChatMessage
};
