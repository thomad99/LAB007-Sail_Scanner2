const axios = require('axios');

const PARSE_APP_ID = 'myclubspot2017';
const PARSE_BASE = 'https://theclubspot.com/parse/classes';
const GEOCODE_USER_AGENT = 'LoveSailing/1.0 (regatta geocoder; https://lovesailing.ai)';
const GEOCODE_MIN_INTERVAL_MS = 1100;
const EARTH_RADIUS_MILES = 3958.7613;

const geocodeMemoryCache = new Map();
let lastGeocodeAt = 0;

const MONTHS = {
    jan: 1, january: 1,
    feb: 2, february: 2,
    mar: 3, march: 3,
    apr: 4, april: 4,
    may: 5,
    jun: 6, june: 6,
    jul: 7, july: 7,
    aug: 8, august: 8,
    sep: 9, sept: 9, september: 9,
    oct: 10, october: 10,
    nov: 11, november: 11,
    dec: 12, december: 12
};

const BOAT_CLASS_DEFS = [
    { name: 'Optimist', pattern: /\b(?:optimists?|optis?|ioda)\b/i },
    { name: '420', pattern: /\b(?:c-?420|i-?420|club\s*420|420s?)\b/i },
    { name: '29er', pattern: /\b29ers?\b/i },
    { name: '49erFX', pattern: /\b49er\s*fx\b/i },
    { name: '49er', pattern: /\b49ers?\b/i },
    { name: 'Nacra 17', pattern: /\bnacra\s*17\b/i },
    { name: 'ILCA 4', pattern: /\b(?:ilca\s*4|laser\s*4\.7)\b/i },
    { name: 'ILCA 6', pattern: /\b(?:ilca\s*6|laser\s*radial)\b/i },
    { name: 'ILCA 7', pattern: /\b(?:ilca\s*7|laser\s*std|laser\s*standard)\b/i },
    { name: 'ILCA', pattern: /\b(?:ilcas?|lasers?)\b/i },
    { name: 'Finn', pattern: /\bfinns?\b/i },
    { name: 'Europe', pattern: /\beurope\s*(?:class|dinghy)?\b/i },
    { name: 'RS Feva', pattern: /\brs\s*fevas?\b/i },
    { name: 'RS Tera', pattern: /\brs\s*teras?\b/i },
    { name: 'RS Aero', pattern: /\brs\s*aeros?\b/i },
    { name: 'RS21', pattern: /\brs\s*21s?\b/i },
    { name: 'RS200', pattern: /\brs\s*200s?\b/i },
    { name: 'RS400', pattern: /\brs\s*400s?\b/i },
    { name: 'RS500', pattern: /\brs\s*500s?\b/i },
    { name: 'RS800', pattern: /\brs\s*800s?\b/i },
    { name: 'Melges 15', pattern: /\bmelges\s*15s?\b/i },
    { name: 'Melges 24', pattern: /\bmelges\s*24s?\b/i },
    { name: 'Melges 32', pattern: /\bmelges\s*32s?\b/i },
    { name: 'J/22', pattern: /\bj\/?22s?\b/i },
    { name: 'J/24', pattern: /\bj\/?24s?\b/i },
    { name: 'J/70', pattern: /\bj\/?70s?\b/i },
    { name: 'J/80', pattern: /\bj\/?80s?\b/i },
    { name: 'J/88', pattern: /\bj\/?88s?\b/i },
    { name: 'J/105', pattern: /\bj\/?105s?\b/i },
    { name: 'J/111', pattern: /\bj\/?111s?\b/i },
    { name: 'Flying Scot', pattern: /\bflying\s*scots?\b/i },
    { name: 'Lightning', pattern: /\blightnings?\b/i },
    { name: 'Thistle', pattern: /\bthistles?\b/i },
    { name: 'Snipe', pattern: /\bsnipes?\b/i },
    { name: 'Star', pattern: /\bstars?\b/i },
    { name: 'Etchells', pattern: /\betchells\b/i },
    { name: 'Hobie 16', pattern: /\bhobie\s*16s?\b/i },
    { name: 'Hobie 18', pattern: /\bhobie\s*18s?\b/i },
    { name: 'Hobie Wave', pattern: /\bhobie\s*waves?\b/i },
    { name: 'Formula 18', pattern: /\b(?:formula\s*18|f18s?)\b/i },
    { name: 'A-Class', pattern: /\ba-?class(?:es)?\b/i },
    { name: 'Nacra', pattern: /\bnacras?\b/i },
    { name: 'Sunfish', pattern: /\bsunfish(?:es)?\b/i },
    { name: 'FJ', pattern: /\b(?:fjs?|flying\s*juniors?)\b/i },
    { name: 'Waszp', pattern: /\bwaszps?\b/i },
    { name: 'Moth', pattern: /\bmoths?\b/i },
    { name: 'iQFoil', pattern: /\biq\s*foils?\b/i },
    { name: 'Windsurfer', pattern: /\bwindsurf(?:er|ing)?s?\b/i },
    { name: 'VX One', pattern: /\bvx\s*ones?\b/i },
    { name: 'Viper 640', pattern: /\bviper\s*640s?\b/i },
    { name: 'Ensign', pattern: /\bensigns?\b/i },
    { name: 'Rhodes 19', pattern: /\brhodes\s*19s?\b/i },
    { name: 'Sonar', pattern: /\bsonars?\b/i },
    { name: 'Ideal 18', pattern: /\bideal\s*18s?\b/i },
    { name: 'Harbor 20', pattern: /\bharbor\s*20s?\b/i },
    { name: 'Express 37', pattern: /\bexpress\s*37s?\b/i },
    { name: 'Santa Cruz 27', pattern: /\bsanta\s*cruz\s*27s?\b/i },
    { name: 'Ultimate 20', pattern: /\bultimate\s*20s?\b/i },
    { name: '505', pattern: /\b(?:505|5o5)s?\b/i },
    { name: 'C&C 30', pattern: /\bc\s*&\s*c\s*30s?\b/i },
    { name: 'Farr 40', pattern: /\bfarr\s*40s?\b/i },
    { name: 'TP52', pattern: /\btp\s*52s?\b/i },
    { name: 'ORC', pattern: /\borc\b/i },
    { name: 'PHRF', pattern: /\bphrf\b/i },
    { name: 'ORR', pattern: /\borr\b/i },
    { name: 'Cruising', pattern: /\bcruis(?:ing|er)s?\b/i },
    { name: 'One-Design', pattern: /\b(?:one[-\s]?design|od)\b/i },
    { name: 'Keelboat', pattern: /\bkeelboats?\b/i },
    { name: 'Dinghy', pattern: /\bdingh(?:y|ies)\b/i },
    { name: 'Multihull', pattern: /\bmultihulls?\b/i },
    { name: 'Catamaran', pattern: /\bcatamarans?\b/i },
    { name: 'Foiling', pattern: /\bfoil(?:ing|er)s?\b/i },
    { name: 'Kite', pattern: /\bkite(?:board(?:ing|er)?s?|foil)?\b/i },
    { name: 'Match Race', pattern: /\bmatch\s*rac(?:e|ing)\b/i },
    { name: 'Team Race', pattern: /\bteam\s*rac(?:e|ing)\b/i },
    { name: 'Youth', pattern: /\byouth\b/i },
    { name: 'High School', pattern: /\b(?:high\s*school|hs\s*sailing)\b/i },
    { name: 'College', pattern: /\b(?:college|icsa)\b/i }
];

const GENERIC_BOAT_TYPES = new Set([
    'one-design', 'phrf', 'orc', 'orr', 'cruising', 'keelboat', 'dinghy',
    'multihull', 'catamaran', 'foiling', 'kite', 'match race', 'team race',
    'youth', 'high school', 'college'
]);

function pad2(n) {
    return String(n).padStart(2, '0');
}

function toYmd(year, month, day) {
    if (!year || !month || !day) return null;
    const y = Number(year);
    const m = Number(month);
    const d = Number(day);
    if (!y || m < 1 || m > 12 || d < 1 || d > 31) return null;
    const dt = new Date(Date.UTC(y, m - 1, d));
    if (dt.getUTCFullYear() !== y || dt.getUTCMonth() !== m - 1 || dt.getUTCDate() !== d) return null;
    return `${y}-${pad2(m)}-${pad2(d)}`;
}

function parseYmd(value) {
    if (!value) return null;
    if (value instanceof Date && !Number.isNaN(value.getTime())) {
        return `${value.getUTCFullYear()}-${pad2(value.getUTCMonth() + 1)}-${pad2(value.getUTCDate())}`;
    }
    const s = String(value).trim();
    const iso = s.match(/^(\d{4})-(\d{2})-(\d{2})/);
    if (iso) return `${iso[1]}-${iso[2]}-${iso[3]}`;
    return null;
}

function expandInclusiveDates(startYmd, endYmd, maxDays = 14) {
    const start = parseYmd(startYmd);
    if (!start) return [];
    const end = parseYmd(endYmd) || start;
    if (end <= start) return [start];

    const startDate = new Date(`${start}T00:00:00Z`);
    const endDate = new Date(`${end}T00:00:00Z`);
    const days = Math.round((endDate - startDate) / 86400000) + 1;
    if (days < 1) return [start];

    if (days > maxDays) {
        return uniqueSortedDates([start, end]);
    }

    const out = [];
    for (let i = 0; i < days; i++) {
        const d = new Date(startDate);
        d.setUTCDate(d.getUTCDate() + i);
        out.push(parseYmd(d));
    }
    return out;
}

function uniqueSortedDates(dates) {
    return [...new Set((dates || []).map(parseYmd).filter(Boolean))].sort();
}

function twoDigitYear(yearToken, fallbackYear) {
    if (!yearToken) return fallbackYear || new Date().getUTCFullYear();
    const n = parseInt(yearToken, 10);
    if (yearToken.length === 4) return n;
    return n < 50 ? 2000 + n : 1900 + n;
}

function parseRnDateText(dateText) {
    const normalized = String(dateText || '').replace(/\s+/g, ' ').trim();
    if (!normalized) return [];

    // RN listings use MM/DD/YY, MM/DD-DD/YY, MM/DD-MM/DD/YY, MM/DD/YY-MM/DD/YY
    const range = normalized.match(
        /^(\d{1,2})\/(\d{1,2})(?:\/(\d{2,4}))?(?:\s*[-–]\s*(\d{1,2})(?:\/(\d{1,2}))?(?:\/(\d{2,4}))?)?$/
    );
    if (range) {
        const startMonth = parseInt(range[1], 10);
        const startDay = parseInt(range[2], 10);
        let endMonth = startMonth;
        let endDay = startDay;
        let yearToken = range[3];

        if (range[4]) {
            if (range[6]) {
                // MM/DD[/YY]-MM/DD/YY
                endMonth = parseInt(range[4], 10);
                endDay = parseInt(range[5], 10);
                yearToken = range[6] || range[3];
            } else if (range[5]) {
                // RN common range: MM/DD-DD/YY (token after the day is the year)
                endDay = parseInt(range[4], 10);
                yearToken = range[5] || range[3];
            } else {
                endDay = parseInt(range[4], 10);
            }
        }

        const year = twoDigitYear(yearToken);
        let endYear = year;
        if (endMonth < startMonth || (endMonth === startMonth && endDay < startDay)) {
            endYear = year + 1;
        }
        const start = toYmd(year, startMonth, startDay);
        const end = toYmd(endYear, endMonth, endDay);
        return expandInclusiveDates(start, end);
    }

    const iso = parseYmd(normalized);
    return iso ? [iso] : [];
}

function rnCellText($, el) {
    return $(el).text().replace(/\u00a0/g, ' ').replace(/\s+/g, ' ').trim();
}

function rnFragmentText(fragment) {
    return String(fragment || '')
        .replace(/<[^>]+>/g, ' ')
        .replace(/&nbsp;/gi, ' ')
        .replace(/&amp;/gi, '&')
        .replace(/&lt;/gi, '<')
        .replace(/&gt;/gi, '>')
        .replace(/\s+/g, ' ')
        .trim();
}

function absoluteRnUrl(href) {
    const raw = String(href || '').trim();
    if (!raw || raw === '#' || /^javascript:/i.test(raw)) return null;
    if (/^https?:\/\//i.test(raw)) return raw.split('#')[0];
    const path = raw.startsWith('/')
        ? raw
        : `/clubmgmt/${raw.replace(/^(\.\/)?/, '')}`;
    return `https://www.regattanetwork.com${path}`.split('#')[0];
}

function withRnShowDivisions(url) {
    if (!url) return null;
    if (url.includes('show_divisions=')) return url;
    return `${url}${url.includes('?') ? '&' : '?'}show_divisions=1`;
}

/**
 * Shared RN table-row parser for calendar.php and past-results listings.
 * Calendar rows have Event Website / Registrants; results rows have View Results.
 */
function parseRnListingRows($, options = {}) {
    const fromDate = options.fromDate || null;
    const toDate = options.toDate || null;
    const requireResults = options.requireResults === true;
    const events = [];
    const seen = new Set();

    $('tr').each((_, tr) => {
        const $tr = $(tr);
        const $cells = $tr.children('td');
        if ($cells.length < 3) return;

        const eventDates = parseRnDateText(rnCellText($, $cells.eq(0)));
        const regattaDate = eventDates[0] || null;
        if (!regattaDate) return;
        if (fromDate && regattaDate < fromDate) return;
        if (toDate && regattaDate > toDate) return;

        const $eventCell = $cells.eq(1);
        const rowHtml = $tr.html() || '';
        let sourceEventId = null;
        const nameAnchor = $eventCell.find('a[name^="id"]').attr('name');
        if (nameAnchor) sourceEventId = String(nameAnchor).replace(/^id/i, '');
        if (!sourceEventId) {
            const idMatch = rowHtml.match(/regatta_id=(\d+)/)
                || rowHtml.match(/\/event\/(\d+)/)
                || rowHtml.match(/name=["']id(\d+)["']/i);
            if (idMatch) sourceEventId = idMatch[1];
        }

        const resultsHref = $cells.eq(2).find('a[href*="applet_regatta_results.php"]').attr('href')
            || $tr.find('a[href*="applet_regatta_results.php"]').attr('href')
            || $cells.eq(2).find('a[href*="regatta_id="]').attr('href');
        const resultsUrl = resultsHref ? withRnShowDivisions(absoluteRnUrl(resultsHref)) : null;
        if (requireResults) {
            if (!resultsUrl || !sourceEventId) return;
        }

        const parts = ($eventCell.clone().find('a').remove().end().html() || '')
            .split(/<br\s*\/?>/i)
            .map(rnFragmentText)
            .filter(Boolean);
        let name = (parts[0] || rnCellText($, $eventCell).split('[')[0].trim())
            .replace(/\[Event Website\]/i, '')
            .trim();
        if (!name || name.length < 3) return;

        const state = String($tr.attr('data-state') || '').trim();
        const locationLike = parts.filter((p, idx) => idx > 0 && /,\s*[A-Za-z]{2}$/.test(p));
        let location = locationLike.length ? locationLike[locationLike.length - 1] : null;
        let hostClub = parts[1] && parts[1] !== location ? parts[1] : null;
        if (!location && hostClub && state && /^[A-Za-z]{2}$/.test(state) && !hostClub.endsWith(state)) {
            location = `${hostClub}, ${state}`;
        } else if (!location && hostClub) {
            location = hostClub;
        } else if (!location && state) {
            location = state;
        }

        let eventWebsiteUrl = null;
        let registrantsUrl = null;
        $tr.find('a[href]').each((__, a) => {
            const href = $(a).attr('href') || '';
            const text = rnCellText($, a);
            if (!eventWebsiteUrl && (text.includes('Event Website') || /\/event\/\d+/.test(href))) {
                eventWebsiteUrl = absoluteRnUrl(href);
            }
            if (!registrantsUrl && (text.includes('Registrant') || href.includes('registrant'))) {
                registrantsUrl = absoluteRnUrl(href);
            }
        });
        if (!eventWebsiteUrl && sourceEventId) {
            eventWebsiteUrl = `https://www.regattanetwork.com/event/${sourceEventId}`;
        }

        const dedupeKey = sourceEventId || `${regattaDate}|${name.toLowerCase()}`;
        if (seen.has(dedupeKey)) return;
        seen.add(dedupeKey);

        const yearFromStart = parseInt(regattaDate.slice(0, 4), 10);
        const allDates = uniqueSortedDates([...eventDates, ...datesFromEventName(name, yearFromStart)]);

        events.push({
            source_event_id: sourceEventId,
            source_id: sourceEventId ? `rn-${sourceEventId}` : `${regattaDate}-${name.replace(/\s+/g, '-').toLowerCase().substring(0, 100)}`,
            regatta_name: name,
            regatta_date: regattaDate,
            event_dates: allDates.length ? allDates : [regattaDate],
            host_club: hostClub || null,
            location: location || null,
            event_website_url: eventWebsiteUrl || null,
            registrants_url: registrantsUrl || null,
            results_url: resultsUrl,
            boat_types: extractBoatTypesFromText(name, location, hostClub)
        });
    });

    return events;
}

function countTrueInserts(upsertResult) {
    if (!upsertResult?.rows?.length) return 0;
    return upsertResult.rows.filter((row) => row.was_inserted === true).length;
}

async function batchUpsertRegattas(pool, regattas) {
    await ensureRegattaExtraColumns(pool);
    const incoming = Array.isArray(regattas) ? regattas : [];
    const rows = dedupeRegattasForUpsert(incoming);
    if (incoming.length && rows.length < incoming.length) {
        console.log(`[regattas] Deduped upsert batch: ${incoming.length} → ${rows.length} unique name+date+source`);
    }
    let added = 0;
    let updated = 0;
    const INSERT_BATCH = 50;
    for (let i = 0; i < rows.length; i += INSERT_BATCH) {
        const batch = rows.slice(i, i + INSERT_BATCH);
        const values = [];
        const placeholders = batch.map((r, idx) => {
            const base = idx * 12;
            values.push(
                r.regatta_date,
                r.regatta_name,
                r.location || null,
                r.event_website_url || null,
                r.registrants_url || null,
                r.registrant_count == null ? null : r.registrant_count,
                r.source,
                r.source_id || null,
                r.event_dates,
                r.boat_types && r.boat_types.length ? r.boat_types : null,
                r.latitude == null ? null : r.latitude,
                r.longitude == null ? null : r.longitude
            );
            return `($${base + 1},$${base + 2},$${base + 3},$${base + 4},$${base + 5},$${base + 6},$${base + 7},$${base + 8},$${base + 9}::date[],$${base + 10}::text[],$${base + 11},$${base + 12})`;
        });
        const result = await pool.query(`
            INSERT INTO regattas (regatta_date, regatta_name, location, event_website_url, registrants_url, registrant_count, source, source_id, event_dates, boat_types, latitude, longitude)
            VALUES ${placeholders.join(',')}
            ON CONFLICT (regatta_name, regatta_date, source)
            DO UPDATE SET
                location = EXCLUDED.location,
                event_website_url = EXCLUDED.event_website_url,
                registrants_url = COALESCE(EXCLUDED.registrants_url, regattas.registrants_url),
                registrant_count = COALESCE(EXCLUDED.registrant_count, regattas.registrant_count),
                source_id = COALESCE(EXCLUDED.source_id, regattas.source_id),
                event_dates = EXCLUDED.event_dates,
                boat_types = COALESCE(EXCLUDED.boat_types, regattas.boat_types),
                latitude = COALESCE(EXCLUDED.latitude, regattas.latitude),
                longitude = COALESCE(EXCLUDED.longitude, regattas.longitude),
                last_updated = CURRENT_TIMESTAMP
            RETURNING (xmax = 0) AS was_inserted
        `, values);
        const inserted = countTrueInserts(result);
        added += inserted;
        updated += (result.rowCount || 0) - inserted;
    }
    return { added, updated, found: rows.length };
}

function monthNumber(token) {
    if (!token) return null;
    return MONTHS[String(token).toLowerCase().replace(/\./g, '').slice(0, 9)] || null;
}

function parseNamedDateRange(text, fallbackYear, fallbackMonthName) {
    const normalized = String(text || '').replace(/\s+/g, ' ').trim();
    if (!normalized) return [];

    const named = normalized.match(
        /(Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)[a-z]*\.?\s+(\d{1,2})(?:st|nd|rd|th)?(?:\s*[-–]\s*(?:(Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)[a-z]*\.?\s+)?(\d{1,2})(?:st|nd|rd|th)?)?(?:\s*,?\s*(\d{4}))?/i
    );
    if (named) {
        const startMonth = monthNumber(named[1]) || monthNumber(fallbackMonthName);
        const startDay = parseInt(named[2], 10);
        const endMonth = named[3] ? monthNumber(named[3]) : startMonth;
        const endDay = named[4] ? parseInt(named[4], 10) : startDay;
        const year = named[5] ? parseInt(named[5], 10) : (fallbackYear || new Date().getUTCFullYear());
        let endYear = year;
        if (endMonth && startMonth && endMonth < startMonth) endYear = year + 1;
        const start = toYmd(year, startMonth, startDay);
        const end = toYmd(endYear, endMonth, endDay);
        return expandInclusiveDates(start, end);
    }

    if (fallbackMonthName) {
        const dayOnly = normalized.match(/^(\d{1,2})(?:st|nd|rd|th)?(?:\s*[-–]\s*(\d{1,2})(?:st|nd|rd|th)?)?$/);
        const month = monthNumber(fallbackMonthName);
        if (dayOnly && month) {
            const year = fallbackYear || new Date().getUTCFullYear();
            const start = toYmd(year, month, parseInt(dayOnly[1], 10));
            const end = toYmd(year, month, parseInt(dayOnly[2] || dayOnly[1], 10));
            return expandInclusiveDates(start, end);
        }
    }

    return parseRnDateText(normalized);
}

function datesFromEventName(name, fallbackYear) {
    if (!name) return [];
    return parseNamedDateRange(name, fallbackYear, null);
}

function isoDateFromParse(value) {
    if (!value) return null;
    if (typeof value === 'string') return parseYmd(value);
    if (value.iso) return parseYmd(value.iso);
    return parseYmd(value);
}

function canonicalizeBoatType(raw) {
    const original = String(raw || '').replace(/\s+/g, ' ').trim();
    if (!original) return null;
    const lower = original.toLowerCase();

    if (/\b(?:optimist|opti|ioda)\b/.test(lower)) return 'Optimist';
    if (/\b(?:c-?420|i-?420|club\s*420|420)\b/.test(lower) && !/\b(?:29er|49er)\b/.test(lower)) return '420';
    if (/\b29er\b/.test(lower)) return '29er';
    if (/\b49er\s*fx\b/.test(lower)) return '49erFX';
    if (/\b49er\b/.test(lower)) return '49er';
    if (/\bilca\s*4\b|\blaser\s*4\.7\b/.test(lower)) return 'ILCA 4';
    if (/\bilca\s*6\b|\blaser\s*radial\b/.test(lower)) return 'ILCA 6';
    if (/\bilca\s*7\b|\blaser\s*(?:std|standard)\b/.test(lower)) return 'ILCA 7';
    if (/\bilca\b|\blaser\b/.test(lower)) return 'ILCA';
    if (/\bj\/?22\b/.test(lower)) return 'J/22';
    if (/\bj\/?24\b/.test(lower)) return 'J/24';
    if (/\bj\/?70\b/.test(lower)) return 'J/70';
    if (/\bsunfish\b/.test(lower)) return 'Sunfish';
    if (/\bflying\s*scot\b/.test(lower)) return 'Flying Scot';
    if (/\bmelges\s*15\b/.test(lower)) return 'Melges 15';
    if (/\bformula\s*18\b|\bf18\b/.test(lower)) return 'Formula 18';
    if (/\bhobie\s*16\b/.test(lower)) return 'Hobie 16';
    if (/\b(?:505|5o5)\b/.test(lower)) return '505';
    if (/\bfj\b|\bflying\s*junior\b/.test(lower)) return 'FJ';

    for (const def of BOAT_CLASS_DEFS) {
        if (def.pattern.test(original)) return def.name;
    }

    if (original.length < 2 || original.length > 40) return null;
    if (/^(class|fleet|open|race|regatta|series)$/i.test(original)) return null;
    return original;
}

function extractBoatTypesFromText(...parts) {
    const text = parts.filter(Boolean).join(' ');
    if (!text) return [];
    const found = [];
    for (const def of BOAT_CLASS_DEFS) {
        if (def.pattern.test(text)) found.push(def.name);
    }
    return uniqueBoatTypes(found);
}

function uniqueBoatTypes(types) {
    const seen = new Set();
    const out = [];
    for (const raw of types || []) {
        const name = canonicalizeBoatType(raw);
        if (!name) continue;
        const key = name.toLowerCase();
        if (seen.has(key)) continue;
        seen.add(key);
        out.push(name);
    }
    return out;
}

function mergeBoatTypes(...lists) {
    const specific = [];
    const generic = [];
    for (const list of lists) {
        for (const item of uniqueBoatTypes(list)) {
            if (GENERIC_BOAT_TYPES.has(item.toLowerCase())) generic.push(item);
            else specific.push(item);
        }
    }
    const merged = uniqueBoatTypes(specific);
    if (!merged.length) return uniqueBoatTypes(generic);
    return merged;
}

function namesFromBoatClassArray(arr) {
    if (!Array.isArray(arr)) return [];
    return arr.map(item => {
        if (!item) return null;
        if (typeof item === 'string') return item;
        return item.name || item.shortName || item.abbreviation || item.className || null;
    }).filter(Boolean);
}

function pointerIdsFromBoatClassArray(arr) {
    if (!Array.isArray(arr)) return [];
    const byClass = new Map();
    for (const item of arr) {
        if (!item || typeof item !== 'object') continue;
        if (item.name || item.shortName || item.abbreviation) continue;
        const className = item.className || (item.__type === 'Pointer' ? 'boatClasses' : null);
        const objectId = item.objectId;
        if (!className || !objectId) continue;
        if (!byClass.has(className)) byClass.set(className, []);
        byClass.get(className).push(objectId);
    }
    return byClass;
}

const boatClassCache = new Map();

async function resolveClubspotBoatTypes(axios, boatClassesArray) {
    const named = namesFromBoatClassArray(boatClassesArray);
    const byClass = pointerIdsFromBoatClassArray(boatClassesArray);
    if (!byClass.size) return uniqueBoatTypes(named);

    const lookedUp = [];
    for (const [className, ids] of byClass.entries()) {
        const uniqueIds = [...new Set(ids)];
        const missing = [];
        for (const id of uniqueIds) {
            const cacheKey = `${className}:${id}`;
            if (boatClassCache.has(cacheKey)) {
                lookedUp.push(boatClassCache.get(cacheKey));
            } else {
                missing.push(id);
            }
        }
        for (let i = 0; i < missing.length; i += 80) {
            const chunk = missing.slice(i, i + 80);
            try {
                const params = new URLSearchParams({
                    where: JSON.stringify({ objectId: { $in: chunk } }),
                    keys: 'name,shortName,abbreviation',
                    limit: String(chunk.length)
                });
                const response = await axios.get(`${PARSE_BASE}/${encodeURIComponent(className)}?${params}`, {
                    headers: { 'X-Parse-Application-Id': PARSE_APP_ID },
                    timeout: 20000
                });
                const found = new Set();
                for (const row of response.data.results || []) {
                    const name = row.name || row.shortName || row.abbreviation;
                    boatClassCache.set(`${className}:${row.objectId}`, name);
                    found.add(row.objectId);
                    lookedUp.push(name);
                }
                chunk.forEach(id => {
                    if (!found.has(id)) boatClassCache.set(`${className}:${id}`, null);
                });
            } catch (err) {
                console.warn(`Clubspot boat class lookup failed for ${className}:`, err.message);
            }
        }
    }
    return uniqueBoatTypes([...named, ...lookedUp]);
}

function eventDatesSqlExpr() {
    return `COALESCE(event_dates, ARRAY[regatta_date]::date[])`;
}

async function ensureRegattaExtraColumns(pool) {
    await pool.query(`ALTER TABLE regattas ADD COLUMN IF NOT EXISTS event_dates DATE[];`);
    await pool.query(`ALTER TABLE regattas ADD COLUMN IF NOT EXISTS boat_types TEXT[];`);
    await pool.query(`ALTER TABLE regattas ADD COLUMN IF NOT EXISTS latitude DOUBLE PRECISION;`);
    await pool.query(`ALTER TABLE regattas ADD COLUMN IF NOT EXISTS longitude DOUBLE PRECISION;`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_regattas_event_dates ON regattas USING GIN (event_dates);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_regattas_boat_types ON regattas USING GIN (boat_types);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_regattas_lat_lng ON regattas (latitude, longitude);`);
    await pool.query(`
        CREATE TABLE IF NOT EXISTS location_geocode_cache (
            location_key TEXT PRIMARY KEY,
            latitude DOUBLE PRECISION,
            longitude DOUBLE PRECISION,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    `);
}

function normalizeLocationKey(location) {
    return String(location || '').replace(/\s+/g, ' ').trim().toLowerCase();
}

function parseCoordinate(value) {
    if (value == null || value === '') return null;
    const n = Number(value);
    return Number.isFinite(n) ? n : null;
}

function clubspotLocationText(record) {
    const r = record || {};
    const club = r.clubObject || {};
    const city = r.city || club.city || null;
    const state = r.state || club.state || null;
    const zip = r.zipOrPostalCode || club.zipOrPostalCode || null;
    if (city && state && zip) return `${city}, ${state} ${zip}`;
    if (city && state) return `${city}, ${state}`;
    if (city) return city;
    if (club.name) return club.name;
    return null;
}

function geocodeQueryFromLocation(location) {
    let query = String(location || '').replace(/\s+/g, ' ').trim();
    if (!query) return '';
    if (/,\s*[A-Z]{2}$/.test(query) && !/,\s*(USA|United States|Canada|UK|Australia)$/i.test(query)) {
        query += ', USA';
    }
    return query;
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function geocodeLocation(pool, location) {
    const key = normalizeLocationKey(location);
    if (!key || key.length < 2) return null;
    if (geocodeMemoryCache.has(key)) return geocodeMemoryCache.get(key);

    if (pool) {
        try {
            const cached = await pool.query(
                `SELECT latitude, longitude FROM location_geocode_cache WHERE location_key = $1`,
                [key]
            );
            if (cached.rows.length) {
                const row = cached.rows[0];
                const coords = (row.latitude != null && row.longitude != null)
                    ? { latitude: Number(row.latitude), longitude: Number(row.longitude) }
                    : null;
                geocodeMemoryCache.set(key, coords);
                return coords;
            }
        } catch (err) {
            console.warn('Geocode cache read failed:', err.message);
        }
    }

    const query = geocodeQueryFromLocation(location);
    if (!query) {
        geocodeMemoryCache.set(key, null);
        return null;
    }

    const wait = GEOCODE_MIN_INTERVAL_MS - (Date.now() - lastGeocodeAt);
    if (wait > 0) await sleep(wait);
    lastGeocodeAt = Date.now();

    let coords = null;
    try {
        const response = await axios.get('https://nominatim.openstreetmap.org/search', {
            params: { format: 'json', limit: 1, q: query },
            headers: {
                'User-Agent': GEOCODE_USER_AGENT,
                Accept: 'application/json'
            },
            timeout: 10000
        });
        const hit = Array.isArray(response.data) ? response.data[0] : null;
        const lat = parseCoordinate(hit && hit.lat);
        const lng = parseCoordinate(hit && hit.lon);
        if (lat != null && lng != null) coords = { latitude: lat, longitude: lng };
    } catch (err) {
        console.warn(`Geocode failed for "${query}":`, err.message);
    }

    geocodeMemoryCache.set(key, coords);
    if (pool) {
        try {
            await pool.query(`
                INSERT INTO location_geocode_cache (location_key, latitude, longitude)
                VALUES ($1, $2, $3)
                ON CONFLICT (location_key) DO UPDATE SET
                    latitude = EXCLUDED.latitude,
                    longitude = EXCLUDED.longitude,
                    updated_at = CURRENT_TIMESTAMP
            `, [key, coords ? coords.latitude : null, coords ? coords.longitude : null]);
        } catch (err) {
            console.warn('Geocode cache write failed:', err.message);
        }
    }
    return coords;
}

async function attachRegattaCoordinates(pool, regattas) {
    const rows = Array.isArray(regattas) ? regattas : [];
    const unique = [];
    const seen = new Set();
    for (const row of rows) {
        if (parseCoordinate(row.latitude) != null && parseCoordinate(row.longitude) != null) continue;
        const key = normalizeLocationKey(row.geocode_query || row.location);
        if (!key || seen.has(key)) continue;
        seen.add(key);
        unique.push(row.geocode_query || row.location);
    }
    const resolved = new Map();
    for (const location of unique) {
        resolved.set(normalizeLocationKey(location), await geocodeLocation(pool, location));
    }
    for (const row of rows) {
        if (parseCoordinate(row.latitude) != null && parseCoordinate(row.longitude) != null) continue;
        const coords = resolved.get(normalizeLocationKey(row.geocode_query || row.location));
        if (coords) {
            row.latitude = coords.latitude;
            row.longitude = coords.longitude;
        }
    }
    return rows;
}

async function fillMissingRegattaCoordinates(pool, { limit = 5 } = {}) {
    const cap = Math.max(0, Math.min(20, parseInt(limit, 10) || 0));
    if (!cap) return 0;
    const missing = await pool.query(`
        SELECT DISTINCT r.location
        FROM regattas r
        LEFT JOIN location_geocode_cache c
          ON c.location_key = LOWER(TRIM(REGEXP_REPLACE(r.location, '\\s+', ' ', 'g')))
        WHERE r.location IS NOT NULL
          AND TRIM(r.location) <> ''
          AND (r.latitude IS NULL OR r.longitude IS NULL)
          AND c.location_key IS NULL
        LIMIT $1
    `, [cap]);
    let filled = 0;
    for (const row of missing.rows) {
        const coords = await geocodeLocation(pool, row.location);
        if (!coords) continue;
        const updated = await pool.query(`
            UPDATE regattas
            SET latitude = $2, longitude = $3
            WHERE location = $1
              AND (latitude IS NULL OR longitude IS NULL)
        `, [row.location, coords.latitude, coords.longitude]);
        filled += updated.rowCount || 0;
    }
    return filled;
}

function haversineMilesSql(latParam, lngParam) {
    return `(${EARTH_RADIUS_MILES} * acos(LEAST(1.0, GREATEST(-1.0,
        cos(radians($${latParam})) * cos(radians(latitude)) *
        cos(radians(longitude) - radians($${lngParam})) +
        sin(radians($${latParam})) * sin(radians(latitude))
    ))))`;
}

function normalizeRegattaForUpsert(regatta) {
    const start = parseYmd(regatta.regatta_date);
    const eventDates = uniqueSortedDates(
        (regatta.event_dates && regatta.event_dates.length)
            ? regatta.event_dates
            : [start]
    );
    const boatTypes = uniqueBoatTypes(regatta.boat_types || []);
    return {
        ...regatta,
        regatta_date: start || eventDates[0],
        event_dates: eventDates.length ? eventDates : (start ? [start] : []),
        boat_types: boatTypes.length ? boatTypes : null
    };
}

function regattaConflictKey(row) {
    return [
        String(row.regatta_name || '').trim(),
        parseYmd(row.regatta_date) || '',
        String(row.source || '').trim()
    ].join('|');
}

function mergeRegattaUpsertRows(prev, next) {
    return {
        ...prev,
        ...next,
        location: (next.location && String(next.location).trim()) || prev.location || null,
        event_website_url: (next.event_website_url && String(next.event_website_url).trim()) || prev.event_website_url || null,
        registrants_url: (next.registrants_url && String(next.registrants_url).trim()) || prev.registrants_url || null,
        registrant_count: next.registrant_count != null ? next.registrant_count : prev.registrant_count,
        source_id: (next.source_id && String(next.source_id).trim()) || prev.source_id || null,
        event_dates: uniqueSortedDates([...(prev.event_dates || []), ...(next.event_dates || [])]),
        boat_types: mergeBoatTypes(prev.boat_types, next.boat_types),
        latitude: next.latitude != null ? next.latitude : prev.latitude,
        longitude: next.longitude != null ? next.longitude : prev.longitude
    };
}

/** One row per UNIQUE(regatta_name, regatta_date, source). Last occurrence wins; richer fields merge. */
function dedupeRegattasForUpsert(regattas, defaultSource) {
    const byKey = new Map();
    for (const raw of Array.isArray(regattas) ? regattas : []) {
        const row = normalizeRegattaForUpsert({
            ...raw,
            source: raw.source || defaultSource || null
        });
        if (!row.regatta_date || !row.regatta_name) continue;
        const key = regattaConflictKey(row);
        const prev = byKey.get(key);
        byKey.set(key, prev ? mergeRegattaUpsertRows(prev, row) : row);
    }
    return Array.from(byKey.values());
}

async function upsertRegatta(pool, regatta) {
    const row = normalizeRegattaForUpsert(regatta);
    if (!row.regatta_date || !row.regatta_name) return false;
    let latitude = parseCoordinate(row.latitude);
    let longitude = parseCoordinate(row.longitude);
    if ((latitude == null || longitude == null) && (row.geocode_query || row.location)) {
        const coords = await geocodeLocation(pool, row.geocode_query || row.location);
        if (coords) {
            latitude = coords.latitude;
            longitude = coords.longitude;
        }
    }
    await pool.query(`
        INSERT INTO regattas (
            regatta_date, regatta_name, location, event_website_url, registrants_url,
            registrant_count, source, source_id, event_dates, boat_types, latitude, longitude
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::date[], $10::text[], $11, $12)
        ON CONFLICT (regatta_name, regatta_date, source)
        DO UPDATE SET
            location = EXCLUDED.location,
            event_website_url = EXCLUDED.event_website_url,
            registrants_url = EXCLUDED.registrants_url,
            registrant_count = COALESCE(EXCLUDED.registrant_count, regattas.registrant_count),
            source_id = EXCLUDED.source_id,
            event_dates = EXCLUDED.event_dates,
            boat_types = COALESCE(EXCLUDED.boat_types, regattas.boat_types),
            latitude = COALESCE(EXCLUDED.latitude, regattas.latitude),
            longitude = COALESCE(EXCLUDED.longitude, regattas.longitude),
            last_updated = CURRENT_TIMESTAMP
    `, [
        row.regatta_date,
        row.regatta_name,
        row.location || null,
        row.event_website_url || null,
        row.registrants_url || null,
        row.registrant_count == null ? null : row.registrant_count,
        row.source,
        row.source_id || null,
        row.event_dates,
        row.boat_types,
        latitude,
        longitude
    ]);
    return true;
}

function formatEventDatesForApi(row) {
    const dates = uniqueSortedDates(
        (row.event_dates && row.event_dates.length) ? row.event_dates : [row.regatta_date]
    );
    return {
        ...row,
        regatta_date: parseYmd(row.regatta_date),
        event_dates: dates,
        boat_types: Array.isArray(row.boat_types) ? row.boat_types : []
    };
}

module.exports = {
    PARSE_APP_ID,
    expandInclusiveDates,
    parseRnDateText,
    parseRnListingRows,
    absoluteRnUrl,
    withRnShowDivisions,
    parseNamedDateRange,
    datesFromEventName,
    isoDateFromParse,
    extractBoatTypesFromText,
    uniqueBoatTypes,
    mergeBoatTypes,
    canonicalizeBoatType,
    resolveClubspotBoatTypes,
    eventDatesSqlExpr,
    ensureRegattaExtraColumns,
    normalizeRegattaForUpsert,
    dedupeRegattasForUpsert,
    upsertRegatta,
    batchUpsertRegattas,
    countTrueInserts,
    formatEventDatesForApi,
    uniqueSortedDates,
    parseYmd,
    clubspotLocationText,
    geocodeLocation,
    attachRegattaCoordinates,
    fillMissingRegattaCoordinates,
    haversineMilesSql
};
