/**
 * Cheap intent parsing for sailing-results chat.
 * High-confidence rules skip OpenAI. Unclear questions use gpt-4o-mini.
 * If the key is missing or the API fails, rules are used as fallback.
 *
 * Synonyms people use:
 *   sailor/person/skipper/racer → skipper
 *   boat/yacht → boat_name
 *   race/regatta/event → regatta_name
 *   place/position/finish → position
 *   date/year → year
 *   sail number/sail # → sail_number
 *   club/yacht club/YC → yacht_club
 */

const INTENT_CACHE_TTL_MS = 15 * 60 * 1000;
const INTENT_CACHE_MAX = 80;
const intentCache = new Map();

const OPENAI_INTENT_PROMPT = `You map sailing questions to a JSON search against race-results data.

Vocabulary:
- sailor / person / skipper / racer / competitor → skipper
- boat / yacht / vessel → boat_name
- race / regatta / event / series → regatta_name
- place / position / finish / standing / ranked → position (overall series place, e.g. "1")
- date / year / in 2026 → year
- sail number / sail # / sail → sail_number
- club / yacht club / YC / sailing club → yacht_club
- "who won X" / winners → regatta_search + that event name
- "sailors at/for [club]" → club_sailors
- "best/top sailor(s)" → top_sailors; "best/top club(s)" → top_clubs
- "top 10 sailors" / "top 5 sailors in C420" → top_sailors with limit and optional category (boat class)

Return JSON only:
{"intent":"sailor_search|boat_search|club_search|regatta_search|sail_search|club_sailors|top_sailors|top_clubs|clubs_in_region|data_summary|sample","skipper":null,"boat_name":null,"yacht_club":null,"regatta_name":null,"sail_number":null,"position":null,"category":null,"limit":null,"year":null,"region":null,"source":null}
source is clubspot, regattanetwork, or null. limit is an integer when the user asks for top N. category is a boat class like C420, Laser, Sunfish. Unused fields null.`;

const FILLER_RE = /\b(the|a|an|show|me|for|please|what|are|is|was|were|find|get|list|about|of|from|to|in|on|at|named|called|number|#|results?|info|information|lookup|search)\b/gi;

function blankCriteria(year, source) {
    return {
        intent: 'sailor_search',
        skipper: null,
        boat_name: null,
        yacht_club: null,
        regatta_name: null,
        sail_number: null,
        position: null,
        category: null,
        limit: null,
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
        .replace(/[?.!,;:]+$/g, '')
        .replace(/^["'\s]+|["'\s]+$/g, '')
        .replace(/\s+/g, ' ')
        .trim();
}

function cleanValue(s) {
    return stripJunk(String(s || '').replace(FILLER_RE, ' ').replace(/\s+/g, ' '));
}

function parseOrdinalPosition(text) {
    const lower = String(text || '').toLowerCase();
    const words = {
        first: '1', second: '2', third: '3', fourth: '4', fifth: '5',
        sixth: '6', seventh: '7', eighth: '8', ninth: '9', tenth: '10'
    };
    for (const [w, n] of Object.entries(words)) {
        if (new RegExp(`\\b${w}\\s+(?:place|position|finish|spot)\\b`).test(lower)
            || new RegExp(`\\b(?:place|position|finish|finished)\\s+${w}\\b`).test(lower)
            || new RegExp(`\\b${w}\\b`).test(lower) && /\b(place|position|finish|winner|won)\b/.test(lower) && w === 'first') {
            return n;
        }
    }
    const m = String(text).match(/\b(?:place|position|finish(?:ed)?|pos)\s*(?:#|no\.?|number)?\s*(\d{1,3})\b/i)
        || String(text).match(/\b(\d{1,3})(?:st|nd|rd|th)\s+(?:place|position|finish)\b/i);
    return m ? m[1] : null;
}

function labeledCapture(q, labels) {
    const label = labels.join('|');
    const re = new RegExp(`\\b(?:${label})\\s*(?:is|=|:)?\\s+["']?(.+?)["']?$`, 'i');
    const m = q.match(re);
    return m ? cleanValue(m[1]) : null;
}

function extractTopLimit(text) {
    const m = String(text).match(/\b(?:top|best)\s+(\d{1,3})\b/i)
        || String(text).match(/\b(\d{1,3})\s+(?:top|best)\b/i);
    if (m) {
        const n = parseInt(m[1], 10);
        if (Number.isFinite(n) && n > 0) return Math.min(n, 50);
    }
    if (/\b(?:top|best)\s+(?:sailor|skipper|racer|person|club)\b/i.test(text)) return 1;
    return null;
}

function extractClassCategory(text) {
    const m = String(text).match(/\b(?:in|for|class|fleet)\s+([A-Za-z0-9][A-Za-z0-9+\/\- ]{0,30})$/i)
        || String(text).match(/\b(?:in|for)\s+(?:the\s+)?([A-Za-z0-9][A-Za-z0-9+\/\-]{1,20})\s+class\b/i);
    if (!m) return null;
    const raw = stripJunk(m[1]).replace(/\b(?:class|fleet|sailors?|clubs?|people|skippers?|racers?)\b/ig, ' ').replace(/\s+/g, ' ').trim();
    if (!raw || /^(top|best|\d+)$/i.test(raw)) return null;
    return raw;
}

function parseIntentRules(message) {
    const q = stripJunk(message);
    const lower = q.toLowerCase();
    const { year, source } = extractYearAndSource(q);
    const base = blankCriteria(year, source);
    const position = parseOrdinalPosition(q);
    if (position) base.position = position;

    if (
        /^(summary|stats|status|overview)$/i.test(q)
        || /\b(what'?s in the data|data summary|how many rows|how many records|table stats)\b/i.test(lower)
    ) {
        return { ...base, intent: 'data_summary', confidence: 'high' };
    }
    if (/\b(sample|show (me )?(some )?rows|preview data|show (me )?data)\b/i.test(lower)) {
        return { ...base, intent: 'sample', confidence: 'high' };
    }

    const topSailors = /\b(?:top|best)\s*\d*\s*(?:sailors?|people|skippers?|racers?|helms?)\b|\bmost active sailors?\b|\bbest sailor\b|\btop sailor\b/i.test(lower);
    const topClubs = /\b(?:top|best)\s*\d*\s*clubs?\b|\bmost active clubs?\b|\bbest club\b|\btop club\b/i.test(lower);
    if (topSailors || topClubs) {
        const limit = extractTopLimit(q) || 10;
        const category = extractClassCategory(q);
        return {
            ...base,
            intent: topClubs && !topSailors ? 'top_clubs' : 'top_sailors',
            limit,
            category,
            confidence: 'high'
        };
    }

    const clubsIn = q.match(/\bclubs?\s+(?:in|near|around)\s+(.+)/i)
        || q.match(/\b(?:yacht\s+)?clubs?\s+(?:from|of)\s+(.+)/i);
    if (clubsIn && !/\bsailors?\b/i.test(q)) {
        return { ...base, intent: 'clubs_in_region', region: cleanValue(clubsIn[1]), confidence: 'high' };
    }

    const sailorsAt = q.match(/\b(?:sailors?|people|skippers?|racers?)\s+(?:at|for|from|of)\s+(.+)/i)
        || q.match(/\bwho\s+(?:races?|sails?|competes?)\s+(?:at|for|from)\s+(.+)/i);
    if (sailorsAt) {
        return { ...base, intent: 'club_sailors', yacht_club: cleanValue(sailorsAt[1]), confidence: 'high' };
    }

    const sailNum = q.match(/\bsail(?:\s*(?:number|num|#|no\.?))?\s*[:=\s]+([A-Za-z]{0,4}\s*\d{2,6}[A-Za-z]?)\b/i)
        || q.match(/\bsail\s+([A-Za-z]{1,4}\d{2,6}|\d{2,6}[A-Za-z]?)\b/i);
    if (sailNum) {
        return {
            ...base,
            intent: 'sail_search',
            sail_number: stripJunk(sailNum[1]).replace(/\s+/g, ''),
            confidence: 'high'
        };
    }

    const won = q.match(/\b(?:who won|winner(?:s)? of|results? for|standings? for|places? (?:at|for))\s+(.+)/i);
    if (won) {
        const name = cleanValue(won[1].replace(/\b(?:regatta|race|event|series)\b/ig, ' '));
        return {
            ...base,
            intent: 'regatta_search',
            regatta_name: name || cleanValue(won[1]),
            position: base.position || (/who won|winner/i.test(q) ? '1' : null),
            confidence: 'high'
        };
    }

    // "first place at Sunfish" / "place 1 Harvest Day"
    if (base.position) {
        const eventBits = cleanValue(
            q.replace(/\b(?:first|second|third|fourth|fifth|sixth|seventh|eighth|ninth|tenth)\b/ig, ' ')
                .replace(/\b(?:place|position|finish(?:ed)?|pos|spot)\b/ig, ' ')
                .replace(/\b(\d{1,3})(?:st|nd|rd|th)?\b/g, ' ')
                .replace(/\b(?:regatta|race|event|series)\b/ig, ' ')
                .replace(/\b(20\d{2})\b/g, ' ')
        );
        if (eventBits.length > 1) {
            return {
                ...base,
                intent: 'regatta_search',
                regatta_name: eventBits,
                confidence: 'high'
            };
        }
    }

    const sailorLabeled = labeledCapture(q, ['sailor', 'person', 'skipper', 'racer', 'competitor', 'helm'])
        || (q.match(/\b(?:sailor|person|skipper|racer)\s+(?:named|called)\s+(.+)/i) || [])[1];
    if (sailorLabeled) {
        return { ...base, intent: 'sailor_search', skipper: cleanValue(sailorLabeled), confidence: 'high' };
    }

    // Club before boat: "yacht club …" must not become a boat named "club …"
    const clubLabeled = labeledCapture(q, ['yacht club', 'sailing club', 'club', 'yc'])
        || (q.match(/\b(?:yacht\s+club|sailing\s+club|club)\s+(?:named|called)\s+(.+)/i) || [])[1];
    if (clubLabeled) {
        return { ...base, intent: 'club_search', yacht_club: cleanValue(clubLabeled), confidence: 'high' };
    }

    const boatLabeled = labeledCapture(q, ['boat', 'vessel'])
        || (q.match(/\b(?:boat|yacht|vessel)\s+(?:named|called)\s+(.+)/i) || [])[1]
        || ((!/\byacht\s+club\b/i.test(q) && labeledCapture(q, ['yacht'])) || null);
    if (boatLabeled && !/\bwho\b/i.test(q) && !/^club\b/i.test(boatLabeled)) {
        return { ...base, intent: 'boat_search', boat_name: cleanValue(boatLabeled), confidence: 'high' };
    }

    const eventLabeled = labeledCapture(q, ['regatta', 'race', 'event', 'series']);
    if (eventLabeled) {
        return { ...base, intent: 'regatta_search', regatta_name: cleanValue(eventLabeled), confidence: 'high' };
    }

    if (/\b(?:regatta|race|event|series)\b/i.test(q)) {
        const name = cleanValue(
            q.replace(/\b(?:regatta|race|event|series|who|won|winner|winners|standings?|results?|places?|positions?)\b/ig, ' ')
                .replace(/\b(20\d{2})\b/g, ' ')
        );
        if (name.length > 1) {
            return { ...base, intent: 'regatta_search', regatta_name: name, confidence: 'high' };
        }
    }

    if (/\b(?:club|yacht club)\b/i.test(q) && !/\bsailor|person|skipper\b/i.test(q)) {
        const name = cleanValue(q.replace(/\b(?:club|yacht club|yc|sailing)\b/ig, ' ').replace(/\b(20\d{2})\b/g, ' '));
        if (name.length > 1) {
            return { ...base, intent: 'club_search', yacht_club: name, confidence: 'high' };
        }
    }

    if (/\b(?:boat|yacht)\b/i.test(q) && !/\bwho\b/i.test(q) && !/\byacht\s+club\b/i.test(q)) {
        const name = cleanValue(q.replace(/\b(?:boat|yacht|vessel)\b/ig, ' ').replace(/\b(20\d{2})\b/g, ' '));
        if (name.length > 1 && !/^club\b/i.test(name)) {
            return { ...base, intent: 'boat_search', boat_name: name, confidence: 'high' };
        }
    }

    // Bare person name: "Dominic Thomas" (not event-like phrases)
    const words = q.split(/\s+/).filter(Boolean);
    const eventy = /\b(day|series|cup|championship|championships|regatta|race|open|classic|memorial|invite|invitational|nationals?|worlds?|midwinters?|labour|labor)\b/i.test(q);
    const nameLike = !eventy && words.length >= 1 && words.length <= 4
        && words.every(w => /^[A-Za-z][A-Za-z.'-]*$/.test(w))
        && !/^(who|what|when|where|how|show|list|top|find|get|the|a|an|sailor|person|boat|club|race|regatta|place|date|sail|best)$/i.test(words[0]);
    if (nameLike && !/\b(club|yacht|regatta|race|won|results?|place|position|sail)\b/i.test(q)) {
        return { ...base, intent: 'sailor_search', skipper: q, confidence: 'high' };
    }
    if (eventy) {
        const name = cleanValue(
            q.replace(/\b(?:who|won|winner|winners|standings?|results?|places?|positions?)\b/ig, ' ')
                .replace(/\b(20\d{2})\b/g, ' ')
        );
        if (name.length > 1) {
            return { ...base, intent: 'regatta_search', regatta_name: name, confidence: 'high' };
        }
    }

    // "sailor Dominic" mid-sentence leftovers
    if (/\b(?:sailor|person|skipper|racer)\b/i.test(q)) {
        const name = cleanValue(q.replace(/\b(?:sailor|person|skipper|racer|competitor|helm)\b/ig, ' ').replace(/\b(20\d{2})\b/g, ' '));
        if (name.length > 1) {
            return { ...base, intent: 'sailor_search', skipper: name, confidence: 'high' };
        }
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
    const limitRaw = parsed.limit != null && parsed.limit !== '' ? parseInt(String(parsed.limit), 10) : rules.limit;
    const posRaw = parsed.position != null && parsed.position !== ''
        ? String(parsed.position).replace(/[^\d]/g, '')
        : rules.position;
    return {
        intent,
        skipper: parsed.skipper || null,
        boat_name: parsed.boat_name || null,
        yacht_club: parsed.yacht_club || null,
        regatta_name: parsed.regatta_name || null,
        sail_number: parsed.sail_number ? String(parsed.sail_number).replace(/\s+/g, '') : (rules.sail_number || null),
        position: posRaw || null,
        category: parsed.category || rules.category || null,
        limit: Number.isFinite(limitRaw) && limitRaw > 0 ? Math.min(limitRaw, 50) : null,
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
        const completion = await Promise.race([
            openai.chat.completions.create({
                model: process.env.OPENAI_CHAT_MODEL || 'gpt-4o-mini',
                messages: [
                    { role: 'system', content: OPENAI_INTENT_PROMPT },
                    { role: 'user', content: text.slice(0, 400) }
                ],
                max_tokens: 120,
                temperature: 0,
                response_format: { type: 'json_object' }
            }),
            new Promise((_, reject) =>
                setTimeout(() => reject(new Error('OpenAI intent timeout')), 12000)
            )
        ]);
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
