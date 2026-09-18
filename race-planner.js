/**
 * Race Planner: PMO lays out a course; Race Committee sees live GPS,
 * bearings to marks, and can pin dropped mark positions.
 */

const crypto = require('crypto');

function randomCode(len) {
    const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    const bytes = crypto.randomBytes(len);
    let out = '';
    for (let i = 0; i < len; i++) out += alphabet[bytes[i] % alphabet.length];
    return out;
}

function randomToken() {
    return crypto.randomBytes(24).toString('hex');
}

function pmoTokenFrom(req) {
    return String((req.body && req.body.pmoToken) || req.get('X-Pmo-Token') || '').trim();
}

async function attachRacePlanner(app, { pool }) {
    async function ensureTables() {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS race_planner_courses (
                id SERIAL PRIMARY KEY,
                code TEXT UNIQUE NOT NULL,
                pmo_token TEXT NOT NULL,
                name TEXT,
                home_lat DOUBLE PRECISION,
                home_lng DOUBLE PRECISION,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                updated_at TIMESTAMPTZ DEFAULT NOW()
            )
        `);
        await pool.query(`
            CREATE TABLE IF NOT EXISTS race_planner_markers (
                id SERIAL PRIMARY KEY,
                course_id INTEGER NOT NULL REFERENCES race_planner_courses(id) ON DELETE CASCADE,
                label TEXT NOT NULL,
                lat DOUBLE PRECISION NOT NULL,
                lng DOUBLE PRECISION NOT NULL,
                sort_order INTEGER DEFAULT 0,
                created_at TIMESTAMPTZ DEFAULT NOW()
            )
        `);
        await pool.query(`
            CREATE TABLE IF NOT EXISTS race_planner_drops (
                id SERIAL PRIMARY KEY,
                course_id INTEGER NOT NULL REFERENCES race_planner_courses(id) ON DELETE CASCADE,
                marker_id INTEGER REFERENCES race_planner_markers(id) ON DELETE SET NULL,
                user_id TEXT NOT NULL,
                user_name TEXT,
                lat DOUBLE PRECISION NOT NULL,
                lng DOUBLE PRECISION NOT NULL,
                dropped_at TIMESTAMPTZ DEFAULT NOW()
            )
        `);
        await pool.query(`
            CREATE TABLE IF NOT EXISTS race_planner_positions (
                course_id INTEGER NOT NULL REFERENCES race_planner_courses(id) ON DELETE CASCADE,
                user_id TEXT NOT NULL,
                user_name TEXT,
                role TEXT,
                lat DOUBLE PRECISION NOT NULL,
                lng DOUBLE PRECISION NOT NULL,
                heading DOUBLE PRECISION,
                updated_at TIMESTAMPTZ DEFAULT NOW(),
                PRIMARY KEY (course_id, user_id)
            )
        `);
    }

    ensureTables().catch((err) => console.error('Race planner table setup:', err));

    async function getCourseByCode(code) {
        const result = await pool.query(
            'SELECT * FROM race_planner_courses WHERE UPPER(code) = UPPER($1)',
            [String(code || '').trim()]
        );
        return result.rows[0] || null;
    }

    async function requirePmo(req, course) {
        const token = pmoTokenFrom(req);
        if (!token || token !== course.pmo_token) {
            const err = new Error('Only the Race PMO can change planned marks.');
            err.status = 403;
            throw err;
        }
    }

    async function courseState(course) {
        const [markers, drops, positions] = await Promise.all([
            pool.query(
                'SELECT id, label, lat, lng, sort_order FROM race_planner_markers WHERE course_id = $1 ORDER BY sort_order, id',
                [course.id]
            ),
            pool.query(
                `SELECT id, marker_id, user_id, user_name, lat, lng, dropped_at
                 FROM race_planner_drops WHERE course_id = $1 ORDER BY dropped_at`,
                [course.id]
            ),
            pool.query(
                `SELECT user_id, user_name, role, lat, lng, heading, updated_at
                 FROM race_planner_positions
                 WHERE course_id = $1 AND updated_at > NOW() - INTERVAL '3 minutes'`,
                [course.id]
            )
        ]);
        return {
            success: true,
            code: course.code,
            name: course.name || 'Race course',
            home: (course.home_lat != null && course.home_lng != null)
                ? { lat: course.home_lat, lng: course.home_lng }
                : null,
            markers: markers.rows,
            drops: drops.rows,
            positions: positions.rows
        };
    }

    app.post('/api/race-planner/courses', async (req, res) => {
        try {
            await ensureTables();
            const name = String((req.body && req.body.name) || 'Race course').slice(0, 80);
            let code = '';
            for (let i = 0; i < 8; i++) {
                code = randomCode(5);
                const exists = await pool.query('SELECT 1 FROM race_planner_courses WHERE code = $1', [code]);
                if (!exists.rows.length) break;
            }
            const pmoToken = randomToken();
            const homeLat = req.body && req.body.lat != null ? Number(req.body.lat) : null;
            const homeLng = req.body && req.body.lng != null ? Number(req.body.lng) : null;
            await pool.query(
                `INSERT INTO race_planner_courses (code, pmo_token, name, home_lat, home_lng)
                 VALUES ($1, $2, $3, $4, $5)`,
                [code, pmoToken, name, Number.isFinite(homeLat) ? homeLat : null, Number.isFinite(homeLng) ? homeLng : null]
            );
            res.json({ success: true, code, pmoToken, name });
        } catch (err) {
            console.error('Create race course:', err);
            res.status(500).json({ success: false, error: err.message });
        }
    });

    app.get('/api/race-planner/courses/:code', async (req, res) => {
        try {
            const course = await getCourseByCode(req.params.code);
            if (!course) return res.status(404).json({ success: false, error: 'Course not found' });
            res.json(await courseState(course));
        } catch (err) {
            res.status(500).json({ success: false, error: err.message });
        }
    });

    app.post('/api/race-planner/courses/:code/home', async (req, res) => {
        try {
            const course = await getCourseByCode(req.params.code);
            if (!course) return res.status(404).json({ success: false, error: 'Course not found' });
            await requirePmo(req, course);
            const lat = Number(req.body.lat);
            const lng = Number(req.body.lng);
            if (!Number.isFinite(lat) || !Number.isFinite(lng)) {
                return res.status(400).json({ success: false, error: 'lat and lng required' });
            }
            await pool.query(
                'UPDATE race_planner_courses SET home_lat = $1, home_lng = $2, updated_at = NOW() WHERE id = $3',
                [lat, lng, course.id]
            );
            course.home_lat = lat;
            course.home_lng = lng;
            res.json(await courseState(course));
        } catch (err) {
            res.status(err.status || 500).json({ success: false, error: err.message });
        }
    });

    app.post('/api/race-planner/courses/:code/markers', async (req, res) => {
        try {
            const course = await getCourseByCode(req.params.code);
            if (!course) return res.status(404).json({ success: false, error: 'Course not found' });
            await requirePmo(req, course);
            const lat = Number(req.body.lat);
            const lng = Number(req.body.lng);
            const label = String(req.body.label || 'Mark').slice(0, 40);
            if (!Number.isFinite(lat) || !Number.isFinite(lng)) {
                return res.status(400).json({ success: false, error: 'lat and lng required' });
            }
            const orderRow = await pool.query(
                'SELECT COALESCE(MAX(sort_order), 0) + 1 AS next FROM race_planner_markers WHERE course_id = $1',
                [course.id]
            );
            const inserted = await pool.query(
                `INSERT INTO race_planner_markers (course_id, label, lat, lng, sort_order)
                 VALUES ($1, $2, $3, $4, $5) RETURNING id, label, lat, lng, sort_order`,
                [course.id, label, lat, lng, orderRow.rows[0].next]
            );
            await pool.query('UPDATE race_planner_courses SET updated_at = NOW() WHERE id = $1', [course.id]);
            res.json({ success: true, marker: inserted.rows[0], ...(await courseState(course)) });
        } catch (err) {
            res.status(err.status || 500).json({ success: false, error: err.message });
        }
    });

    app.patch('/api/race-planner/courses/:code/markers/:id', async (req, res) => {
        try {
            const course = await getCourseByCode(req.params.code);
            if (!course) return res.status(404).json({ success: false, error: 'Course not found' });
            await requirePmo(req, course);
            const id = Number(req.params.id);
            const fields = [];
            const vals = [];
            let i = 1;
            if (req.body.lat != null && req.body.lng != null) {
                const lat = Number(req.body.lat);
                const lng = Number(req.body.lng);
                if (!Number.isFinite(lat) || !Number.isFinite(lng)) {
                    return res.status(400).json({ success: false, error: 'invalid lat/lng' });
                }
                fields.push(`lat = $${i++}`, `lng = $${i++}`);
                vals.push(lat, lng);
            }
            if (req.body.label != null) {
                fields.push(`label = $${i++}`);
                vals.push(String(req.body.label).slice(0, 40));
            }
            if (!fields.length) return res.status(400).json({ success: false, error: 'Nothing to update' });
            vals.push(id, course.id);
            const updated = await pool.query(
                `UPDATE race_planner_markers SET ${fields.join(', ')}
                 WHERE id = $${i++} AND course_id = $${i} RETURNING id`,
                vals
            );
            if (!updated.rows.length) return res.status(404).json({ success: false, error: 'Marker not found' });
            res.json(await courseState(course));
        } catch (err) {
            res.status(err.status || 500).json({ success: false, error: err.message });
        }
    });

    app.delete('/api/race-planner/courses/:code/markers/:id', async (req, res) => {
        try {
            const course = await getCourseByCode(req.params.code);
            if (!course) return res.status(404).json({ success: false, error: 'Course not found' });
            await requirePmo(req, course);
            await pool.query(
                'DELETE FROM race_planner_markers WHERE id = $1 AND course_id = $2',
                [Number(req.params.id), course.id]
            );
            res.json(await courseState(course));
        } catch (err) {
            res.status(err.status || 500).json({ success: false, error: err.message });
        }
    });

    app.post('/api/race-planner/courses/:code/position', async (req, res) => {
        try {
            const course = await getCourseByCode(req.params.code);
            if (!course) return res.status(404).json({ success: false, error: 'Course not found' });
            const userId = String(req.body.userId || '').slice(0, 80);
            const lat = Number(req.body.lat);
            const lng = Number(req.body.lng);
            if (!userId || !Number.isFinite(lat) || !Number.isFinite(lng)) {
                return res.status(400).json({ success: false, error: 'userId, lat, lng required' });
            }
            const heading = req.body.heading != null ? Number(req.body.heading) : null;
            await pool.query(
                `INSERT INTO race_planner_positions (course_id, user_id, user_name, role, lat, lng, heading, updated_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
                 ON CONFLICT (course_id, user_id) DO UPDATE SET
                    user_name = EXCLUDED.user_name,
                    role = EXCLUDED.role,
                    lat = EXCLUDED.lat,
                    lng = EXCLUDED.lng,
                    heading = EXCLUDED.heading,
                    updated_at = NOW()`,
                [
                    course.id,
                    userId,
                    String(req.body.userName || 'Committee').slice(0, 40),
                    String(req.body.role || 'committee').slice(0, 20),
                    lat,
                    lng,
                    Number.isFinite(heading) ? heading : null
                ]
            );
            if (req.body.role === 'pmo' && pmoTokenFrom(req) === course.pmo_token) {
                await pool.query(
                    'UPDATE race_planner_courses SET home_lat = $1, home_lng = $2, updated_at = NOW() WHERE id = $3',
                    [lat, lng, course.id]
                );
                course.home_lat = lat;
                course.home_lng = lng;
            }
            res.json(await courseState(course));
        } catch (err) {
            res.status(500).json({ success: false, error: err.message });
        }
    });

    app.post('/api/race-planner/courses/:code/drop', async (req, res) => {
        try {
            const course = await getCourseByCode(req.params.code);
            if (!course) return res.status(404).json({ success: false, error: 'Course not found' });
            const lat = Number(req.body.lat);
            const lng = Number(req.body.lng);
            const userId = String(req.body.userId || '').slice(0, 80);
            if (!userId || !Number.isFinite(lat) || !Number.isFinite(lng)) {
                return res.status(400).json({ success: false, error: 'userId, lat, lng required' });
            }
            const markerId = req.body.markerId ? Number(req.body.markerId) : null;
            const inserted = await pool.query(
                `INSERT INTO race_planner_drops (course_id, marker_id, user_id, user_name, lat, lng)
                 VALUES ($1, $2, $3, $4, $5, $6)
                 RETURNING id, marker_id, user_id, user_name, lat, lng, dropped_at`,
                [course.id, Number.isFinite(markerId) ? markerId : null, userId, String(req.body.userName || 'Committee').slice(0, 40), lat, lng]
            );
            res.json({ success: true, drop: inserted.rows[0], ...(await courseState(course)) });
        } catch (err) {
            res.status(500).json({ success: false, error: err.message });
        }
    });
}

module.exports = { attachRacePlanner };
