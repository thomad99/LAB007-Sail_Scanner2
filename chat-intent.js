/**
 * Cheap intent parsing for sailing-results chat.
 * High-confidence rules skip OpenAI. Unclear questions use gpt-4o-mini.
 * If the key is missing or the API fails, rules are used as fallback.
 */

const INTENT_CACHE_TTL_MS = 15 * 60 * 1000;
const INTENT_CACHE_MAX = 80;
const intentCache = new Map();

const OPENAI_INTENT_PROMPT = `Extract a sailing-results search as JSON only:
{"intent":"sailor_search|boat_search|club_search|regatta_search|club_sailors|top_sailors|top_clubs|clubs_in_region|data_summary|sample","skipper":null,"boat_name":null,"yacht_club":null,"regatta_name":null,"year":null,"region":null,"source":null}
source is clubspot, regattanetwork, or null. Omit unused fields as null.`;

function blankCriteria(year, source) {
    return {
        intent: 'sailor_search',
        skipper: null,
        boat_name: null,
        yacht_club: null,
        regatta_name: null,
        year: year || null,
        region: null,
        source: source || null
    };
}

function extractYearAndSource(text) {
    const yearMatch = String(text).match(/\b(20\d{2})\b/);
    let source = null;
    if (/\bclubspot\b/i.test(text)) source = 'clubspot';
    if (/\bregatta\s*network\b/i.test(text)) source = 'regattanetwork';
    return {
        year: yearMatch ? parseInt(yearMatch[1], 10) : null,
        source
    };
}

function stripJunk(s) {
    return String(s || '')
        .replace(/[?.!]+$/g, '')
        .replace(/\s+/g, ' ')
        .trim();
}

function parseIntentRules(message) {
    const q = stripJunk(message);
    const lower = q.toLowerCase();
    const { year, source } = extractYearAndSource(q);
    const base = blankCriteria(year, source);

    if (
        /^(summary|stats|status|overview)$/i.test(q)
        || /\b(what'?s in the data|data summary|how many rows|how many records|table stats)\b/i.test(lower)
    ) {
        return { ...base, intent: 'data_summary', confidence: 'high' };
    }
    if (/\b(sample|show (me )?(some )?rows|preview data|show (me )?data)\b/i.test(lower)) {
        return { ...base, intent: 'sample', confidence: 'high' };
    }
    if (/\btop\s*\d*\s*sailors\b|\bbest sailors\b|\bmost active sailors\b/i.test(lower)) {
        return { ...base, intent: 'top_sailors', confidence: 'high' };
    }
    if (/\btop\s*\d*\s*clubs\b|\bmost active clubs\b/i.test(lower)) {
        return { ...base, intent: 'top_clubs', confidence: 'high' };
    }

    const clubsIn = q.match(/\bclubs in\s+(.+)/i);
    if (clubsIn) {
        return { ...base, intent: 'clubs_in_region', region: stripJunk(clubsIn[1]), confidence: 'high' };
    }

    const sailorsAt = q.match(/\bsailors?\s+(?:at|for|from)\s+(.+)/i)
        || q.match(/\bwho races for\s+(.+)/i);
    if (sailorsAt) {
        return { ...base, intent: 'club_sailors', yacht_club: stripJunk(sailorsAt[1]), confidence: 'high' };
    }

    const won = q.match(/\b(?:who won|winner of|winners of|results for|result for)\s+(.+)/i);
    if (won) {
        const name = stripJunk(won[1].replace(/\bregatta\b/ig, ' '));
        return { ...base, intent: 'regatta_search', regatta_name: name || stripJunk(won[1]), confidence: 'high' };
    }

    if (/\bregatta\b/i.test(q)) {
        const name = stripJunk(
            q.replace(/\b(the|a|an|show|me|for|please|what|are|is|results?)\b/gi, ' ')
                .replace(/\bregatta\b/ig, ' ')
        );
        if (name.length > 1) {
            return { ...base, intent: 'regatta_search', regatta_name: name, confidence: 'high' };
        }
    }

    const boat = q.match(/\bboat(?:\s+named)?\s+["']?(.+?)["']?$/i);
    if (boat && boat[1] && !/\bwho\b/i.test(q)) {
        return { ...base, intent: 'boat_search', boat_name: stripJunk(boat[1]), confidence: 'high' };
    }

    const words = q.split(/\s+/).filter(Boolean);
    const nameLike = words.length >= 1 && words.length <= 4
        && words.every(w => /^[A-Za-z][A-Za-z.'-]*$/.test(w))
        && !/^(who|what|when|where|how|show|list|top|find|get|the|a|an)$/i.test(words[0]);
    if (nameLike && !/\b(club|yacht|regatta|race|won|results?)\b/i.test(q)) {
        return { ...base, intent: 'sailor_search', skipper: q, confidence: 'high' };
    }

    return { ...base, intent: 'sailor_search', skipper: q, confidence: 'low' };
}

function cacheGet(key) {
    const hit = intentCache.get(key);
    if (!hit) return null;
    if (Date.now() - hit.at > INTENT_CACHE_TTL_MS) {
        intentCache.delete(key);
        return null;
    }
    return hit.value;
}

function cacheSet(key, value) {
    intentCache.set(key, { at: Date.now(), value });
    if (intentCache.size > INTENT_CACHE_MAX) {
        const first = intentCache.keys().next().value;
        intentCache.delete(first);
    }
}

function normalizeParsed(parsed, fallbackMessage) {
    const rules = parseIntentRules(fallbackMessage);
    const intent = String(parsed.intent || rules.intent || 'sailor_search').toLowerCase();
    const yearRaw = parsed.year != null && parsed.year !== '' ? parseInt(String(parsed.year), 10) : rules.year;
    return {
        intent,
        skipper: parsed.skipper || null,
        boat_name: parsed.boat_name || null,
        yacht_club: parsed.yacht_club || null,
        regatta_name: parsed.regatta_name || null,
        year: Number.isFinite(yearRaw) ? yearRaw : null,
        region: parsed.region || null,
        source: parsed.source || rules.source || null,
        confidence: 'high',
        parser: 'openai'
    };
}

async function parseChatIntent(message, openai) {
    const text = String(message || '').trim();
    const rules = parseIntentRules(text);

    if (rules.confidence === 'high') {
        return { ...rules, parser: 'rules' };
    }

    const cacheKey = text.toLowerCase();
    const cached = cacheGet(cacheKey);
    if (cached) return { ...cached, parser: 'cache' };

    if (!openai) {
        return { ...rules, parser: 'fallback' };
    }

    try {
        const completion = await openai.chat.completions.create({
            model: process.env.OPENAI_CHAT_MODEL || 'gpt-4o-mini',
            messages: [
                { role: 'system', content: OPENAI_INTENT_PROMPT },
                { role: 'user', content: text.slice(0, 400) }
            ],
            max_tokens: 80,
            temperature: 0,
            response_format: { type: 'json_object' }
        });
        const raw = completion.choices?.[0]?.message?.content?.trim() || '{}';
        const json = raw.replace(/^```(?:json)?\s*|\s*```$/g, '').trim();
        const parsed = JSON.parse(json);
        const out = normalizeParsed(parsed, text);
        cacheSet(cacheKey, out);
        return out;
    } catch (err) {
        console.warn('[chat-intent] OpenAI failed, using rules:', err.message);
        return { ...rules, parser: 'fallback' };
    }
}

module.exports = {
    parseIntentRules,
    parseChatIntent
};
