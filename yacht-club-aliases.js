/**
 * Yacht club names that mean the same organization.
 * Matching is exact after trim/case-fold so "SYS" does not match "SYSCO".
 */
const CLUB_ALIAS_GROUPS = [
    {
        canonical: 'Sarasota Youth Sailing',
        aliases: [
            'SYS',
            'Sarasota Youth Sailing',
            'Sarasota Youth Sailing (SYS)',
            'Sarasota Youth Sailing Squadron'
        ]
    },
    {
        canonical: 'Venice Youth Boating Association',
        aliases: [
            'VYBA',
            'Venice Youth Boating Association'
        ]
    }
];

function clubKey(name) {
    return String(name || '').replace(/\s+/g, ' ').trim().toLowerCase();
}

function findClubGroup(name) {
    const key = clubKey(name);
    if (!key) return null;
    return CLUB_ALIAS_GROUPS.find(g =>
        clubKey(g.canonical) === key || g.aliases.some(alias => clubKey(alias) === key)
    ) || null;
}

function escapeRegExp(s) {
    return String(s || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Longest alias mentioned as a whole phrase, so "SYS" does not match "SYSCO". */
function findClubGroupInText(text) {
    const direct = findClubGroup(text);
    if (direct) return direct;
    const hay = String(text || '');
    if (!hay.trim()) return null;
    let best = null;
    let bestLen = 0;
    for (const group of CLUB_ALIAS_GROUPS) {
        for (const alias of [group.canonical, ...group.aliases]) {
            const trimmed = String(alias || '').replace(/\s+/g, ' ').trim();
            if (!trimmed || trimmed.length <= bestLen) continue;
            const re = new RegExp(`\\b${escapeRegExp(trimmed)}\\b`, 'i');
            if (re.test(hay)) {
                best = group;
                bestLen = trimmed.length;
            }
        }
    }
    return best;
}

function aliasesForClub(name) {
    const group = findClubGroup(name);
    if (!group) {
        const trimmed = String(name || '').replace(/\s+/g, ' ').trim();
        return trimmed ? [trimmed] : [];
    }
    const seen = new Set();
    const names = [];
    for (const alias of [group.canonical, ...group.aliases]) {
        const key = clubKey(alias);
        if (!key || seen.has(key)) continue;
        seen.add(key);
        names.push(String(alias).replace(/\s+/g, ' ').trim());
    }
    return names;
}

function canonicalClubName(name) {
    const group = findClubGroup(name);
    if (group) return group.canonical;
    return String(name || '').replace(/\s+/g, ' ').trim();
}

function clubsAreSame(a, b) {
    const left = clubKey(canonicalClubName(a));
    const right = clubKey(canonicalClubName(b));
    return Boolean(left && right && left === right);
}

function canonicalClubSql(column = 'yacht_club') {
    const whens = CLUB_ALIAS_GROUPS.map(group => {
        const keys = [group.canonical, ...group.aliases]
            .map(alias => clubKey(alias))
            .filter(Boolean)
            .filter((key, idx, all) => all.indexOf(key) === idx)
            .map(key => `'${key.replace(/'/g, "''")}'`)
            .join(', ');
        const canon = group.canonical.replace(/'/g, "''");
        return `WHEN LOWER(TRIM(${column})) IN (${keys}) THEN '${canon}'`;
    });
    if (!whens.length) return `TRIM(${column})`;
    return `CASE ${whens.join(' ')} ELSE TRIM(${column}) END`;
}

function yachtClubMatchSql(column, value, params) {
    const trimmed = String(value || '').replace(/\s+/g, ' ').trim();
    if (!trimmed) return '';
    const group = findClubGroup(trimmed);
    if (group) {
        params.push(aliasesForClub(trimmed).map(alias => clubKey(alias)));
        return `LOWER(TRIM(COALESCE(${column}, ''))) = ANY($${params.length}::text[])`;
    }
    params.push(`%${trimmed}%`);
    return `${column} ILIKE $${params.length}`;
}

module.exports = {
    CLUB_ALIAS_GROUPS,
    clubKey,
    findClubGroup,
    findClubGroupInText,
    aliasesForClub,
    canonicalClubName,
    clubsAreSame,
    canonicalClubSql,
    yachtClubMatchSql
};
