/**
 * Shared ClubSpot HTTP helper: polite pacing + retry/backoff on 429/5xx.
 *
 * Env knobs (optional):
 *   CLUBSPOT_REQUEST_DELAY_MS      min delay between requests (default 300)
 *   CLUBSPOT_REQUEST_DELAY_MAX_MS  max delay / jitter ceiling (default 600)
 *   CLUBSPOT_MAX_RETRIES           retries on 429/5xx (default 4)
 *   CLUBSPOT_BACKOFF_BASE_MS       first backoff wait (default 5000)
 *   CLUBSPOT_BACKOFF_MAX_MS        cap on backoff wait (default 30000)
 */

const PARSE_APP_ID = 'myclubspot2017';

function envInt(name, fallback) {
    const n = parseInt(process.env[name], 10);
    return Number.isFinite(n) && n >= 0 ? n : fallback;
}

const DELAY_MIN_MS = envInt('CLUBSPOT_REQUEST_DELAY_MS', 300);
const DELAY_MAX_MS = Math.max(DELAY_MIN_MS, envInt('CLUBSPOT_REQUEST_DELAY_MAX_MS', 600));
const MAX_RETRIES = envInt('CLUBSPOT_MAX_RETRIES', 4);
const BACKOFF_BASE_MS = envInt('CLUBSPOT_BACKOFF_BASE_MS', 5000);
const BACKOFF_MAX_MS = envInt('CLUBSPOT_BACKOFF_MAX_MS', 30000);

let lastRequestAt = 0;
let throttleChain = Promise.resolve();

function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

function jitter(minMs, maxMs) {
    if (maxMs <= minMs) return minMs;
    return minMs + Math.floor(Math.random() * (maxMs - minMs + 1));
}

function isRetryableStatus(status) {
    return status === 429 || (status >= 500 && status <= 599);
}

/**
 * Serialize ClubSpot calls and wait a jittered gap since the previous one.
 * Shared across all callers in this process so list + class + results stay polite.
 */
async function paceClubspotRequest() {
    const run = throttleChain.then(async () => {
        const gap = jitter(DELAY_MIN_MS, DELAY_MAX_MS);
        const elapsed = Date.now() - lastRequestAt;
        if (lastRequestAt && elapsed < gap) {
            await sleep(gap - elapsed);
        }
        lastRequestAt = Date.now();
    });
    // Keep the chain alive even if a waiter rejects (should not happen here).
    throttleChain = run.catch(() => {});
    await run;
}

/**
 * GET a ClubSpot URL with pacing and exponential backoff on 429/5xx.
 * @param {import('axios').AxiosInstance|Function} axios
 * @param {string} url
 * @param {object} [config] axios request config
 * @param {{ log?: (msg: string) => void }} [opts]
 */
async function clubspotGet(axios, url, config = {}, opts = {}) {
    const log = typeof opts.log === 'function' ? opts.log : (msg) => console.log('[clubspot-http]', msg);
    const headers = {
        'User-Agent': 'LoveSailing/1.0 (race-results indexer; https://lovesailing.ai)',
        ...(config.headers || {})
    };

    let lastErr;
    for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
        await paceClubspotRequest();
        try {
            return await axios.get(url, {
                timeout: 30000,
                ...config,
                headers
            });
        } catch (err) {
            lastErr = err;
            const status = err.response && err.response.status;
            if (isRetryableStatus(status) && attempt < MAX_RETRIES) {
                const backoff = Math.min(
                    BACKOFF_MAX_MS,
                    BACKOFF_BASE_MS * Math.pow(2, attempt) + jitter(0, 1000)
                );
                log(`ClubSpot ${status} on ${url} — backing off ${backoff}ms (attempt ${attempt + 1}/${MAX_RETRIES})`);
                await sleep(backoff);
                continue;
            }
            throw err;
        }
    }
    throw lastErr;
}

function clubspotConfigSummary() {
    return {
        delayMinMs: DELAY_MIN_MS,
        delayMaxMs: DELAY_MAX_MS,
        maxRetries: MAX_RETRIES,
        backoffBaseMs: BACKOFF_BASE_MS,
        backoffMaxMs: BACKOFF_MAX_MS
    };
}

module.exports = {
    PARSE_APP_ID,
    clubspotGet,
    paceClubspotRequest,
    clubspotConfigSummary,
    sleep
};
