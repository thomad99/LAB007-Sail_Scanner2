const {
    parseRnListingRows,
    parseNamedDateRange,
    extractBoatTypesFromText,
    mergeBoatTypes,
    ensureRegattaExtraColumns,
    batchUpsertRegattas,
    fillMissingRegattaCoordinates
} = require('./regatta-scrape-helpers');

const RN_HTTP_HEADERS = {
    'User-Agent': 'LoveSailing/1.0 (regatta calendar indexer; https://lovesailing.ai)'
};

const RN_CALENDAR_URLS = [
    'https://www.regattanetwork.com/html/calendar.php?all=1',
    'https://www.regattanetwork.com/html/calendar.php',
    'https://www.regattanetwork.com/html/calendar.php?junior=1',
    'https://www.regattanetwork.com/html/calendar.php?series=1',
    'https://www.regattanetwork.com/html/calendar.php?classes=1',
    'https://www.regattanetwork.com/html/calendar.php?other=1'
];

function normalizeText(text) {
    return text ? String(text).replace(/\s+/g, ' ').trim() : '';
}

function utcTodayYmd() {
    return new Date().toISOString().slice(0, 10);
}

function addUtcDays(ymd, days) {
    const dt = new Date(`${ymd}T00:00:00Z`);
    dt.setUTCDate(dt.getUTCDate() + days);
    return dt.toISOString().slice(0, 10);
}

function parseHighSchoolSailingPage(cheerio, html, defaultYear) {
    const $ = cheerio.load(html);
    const regattas = [];
    let currentYear = defaultYear || new Date().getUTCFullYear();
    let currentMonthName = null;

    $('table tr').each((_, row) => {
        const cells = $(row).find('td, th');
        if (cells.length === 0) return;

        const headerText = normalizeText(cells.eq(0).text());
        const monthHeaderMatch = headerText.match(/(January|February|March|April|May|June|July|August|September|October|November|December)\s+(\d{4})/i);
        if (monthHeaderMatch) {
            currentMonthName = monthHeaderMatch[1];
            currentYear = parseInt(monthHeaderMatch[2], 10) || currentYear;
            return;
        }
        if (headerText.toLowerCase().startsWith('date')) return;
        if (cells.length < 4) return;

        const dateText = normalizeText(cells.eq(0).text());
        const eventCell = cells.eq(1);
        const regattaName = normalizeText(eventCell.text());
        const venueText = normalizeText(cells.eq(3).text());
        const hostText = normalizeText(cells.eq(2).text());
        const eventDates = parseNamedDateRange(dateText, currentYear, currentMonthName);
        const regattaDate = eventDates[0] || null;
        if (!regattaDate || !regattaName || regattaName.length < 3) return;

        let eventWebsiteUrl = null;
        const linkHref = eventCell.find('a').first().attr('href');
        if (linkHref) {
            eventWebsiteUrl = linkHref.startsWith('http') ? linkHref : `https://hssailing.org${linkHref}`;
        }

        const location = venueText || hostText || null;
        const sourceIdBase = eventWebsiteUrl || regattaName;
        const boatTypes = mergeBoatTypes(
            extractBoatTypesFromText(regattaName, venueText, hostText),
            ['High School']
        );

        regattas.push({
            regatta_date: regattaDate,
            event_dates: eventDates,
            boat_types: boatTypes,
            regatta_name: regattaName,
            location,
            event_website_url: eventWebsiteUrl,
            source: 'hssailing',
            source_id: `${regattaDate}-${sourceIdBase.replace(/\s+/g, '-').toLowerCase().substring(0, 120)}`
        });
    });

    return regattas;
}

async function collectRnCalendarRegattas(axios, cheerio) {
    const byId = new Map();
    const pageStats = [];

    for (const url of RN_CALENDAR_URLS) {
        try {
            console.log(`Fetching RN calendar: ${url}`);
            const response = await axios.get(url, {
                headers: RN_HTTP_HEADERS,
                timeout: 45000
            });
            const rows = parseRnListingRows(cheerio.load(response.data), {});
            let added = 0;
            for (const row of rows) {
                const key = row.source_event_id || `${row.regatta_date}|${row.regatta_name.toLowerCase()}`;
                if (byId.has(key)) continue;
                byId.set(key, {
                    ...row,
                    source: 'regattanetwork'
                });
                added += 1;
            }
            pageStats.push({ url, found: rows.length, uniqueAdded: added });
            console.log(`  ${rows.length} rows, ${added} new (${byId.size} unique so far)`);
        } catch (err) {
            console.error(`RN calendar fetch failed for ${url}:`, err.message);
            pageStats.push({ url, found: 0, uniqueAdded: 0, error: err.message });
        }
    }

    return { regattas: Array.from(byId.values()), pageStats };
}

async function scrapeRegattaNetworkCalendar({ axios, cheerio, pool }) {
    await ensureRegattaExtraColumns(pool);
    const { regattas, pageStats } = await collectRnCalendarRegattas(axios, cheerio);
    const today = utcTodayYmd();
    const futureCutoff = addUtcDays(today, -30);
    const upcoming = regattas.filter((row) => {
        const dates = (row.event_dates && row.event_dates.length) ? row.event_dates : [row.regatta_date];
        return dates.some((d) => d >= futureCutoff);
    });
    const futureCount = upcoming.filter((row) => {
        const dates = (row.event_dates && row.event_dates.length) ? row.event_dates : [row.regatta_date];
        return dates.some((d) => d >= today);
    }).length;

    console.log(`Found ${regattas.length} RN calendar events (${futureCount} on/after ${today})`);
    const result = await batchUpsertRegattas(pool, upcoming);
    try {
        await fillMissingRegattaCoordinates(pool, { limit: 8 });
    } catch (err) {
        console.warn('RN calendar geocode fill failed:', err.message);
    }

    await pool.query(`
        INSERT INTO scrape_log (source, regattas_found, regattas_added)
        VALUES ('regattanetwork', $1, $2)
    `, [upcoming.length, result.added]);

    console.log(`Regatta Network calendar: ${upcoming.length} stored, ${result.added} newly added, ${result.updated} updated`);
    return {
        found: upcoming.length,
        added: result.added,
        updated: result.updated,
        futureCount,
        pages: pageStats
    };
}

function highSchoolSeasonWindows(now = new Date()) {
    const year = now.getUTCFullYear();
    const month = now.getUTCMonth();
    // School-year calendars run roughly Aug–June. From August on, Y/Y+1 is current.
    const seasonStart = month >= 7 ? year : year - 1;
    return [
        { start: seasonStart, end: seasonStart + 1 },
        { start: seasonStart - 1, end: seasonStart },
        { start: seasonStart + 1, end: seasonStart + 2 }
    ];
}

async function scrapeHighSchoolSailingCalendar({ axios, cheerio, pool }) {
    await ensureRegattaExtraColumns(pool);
    const seasons = highSchoolSeasonWindows();
    const targetUrls = [];
    seasons.forEach((season) => {
        targetUrls.push({
            url: `https://hssailing.org/schedule-results/current/${season.start}/${season.end}`,
            season
        });
        targetUrls.push({
            url: `https://hssailing.org/schedule-results/${season.start}/${season.end}`,
            season
        });
    });

    const regattas = [];
    const seen = new Set();
    for (const { url, season } of targetUrls) {
        try {
            console.log(`Fetching High School Sailing schedule: ${url}`);
            const response = await axios.get(url, {
                headers: { 'User-Agent': RN_HTTP_HEADERS['User-Agent'] },
                timeout: 45000
            });
            const pageRegattas = parseHighSchoolSailingPage(cheerio, response.data, season.end);
            pageRegattas.forEach((regatta) => {
                const key = `${regatta.regatta_date}-${regatta.regatta_name}`.toLowerCase();
                if (seen.has(key)) return;
                seen.add(key);
                regattas.push(regatta);
            });
        } catch (err) {
            console.error(`High School Sailing fetch failed for ${url}:`, err.message);
        }
    }

    console.log(`Found ${regattas.length} regattas from High School Sailing`);
    const today = utcTodayYmd();
    const upcoming = regattas.filter((row) => row.regatta_date >= addUtcDays(today, -30));

    const result = await batchUpsertRegattas(pool, upcoming);
    await pool.query(`
        INSERT INTO scrape_log (source, regattas_found, regattas_added)
        VALUES ('hssailing', $1, $2)
    `, [upcoming.length, result.added]);

    console.log(`High School Sailing: ${upcoming.length} found, ${result.added} newly added, ${result.updated} updated`);
    return { found: upcoming.length, added: result.added, updated: result.updated };
}

module.exports = {
    RN_CALENDAR_URLS,
    collectRnCalendarRegattas,
    scrapeRegattaNetworkCalendar,
    scrapeHighSchoolSailingCalendar,
    parseHighSchoolSailingPage,
    highSchoolSeasonWindows
};
