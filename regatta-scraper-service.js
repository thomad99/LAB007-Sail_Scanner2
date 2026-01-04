const express = require('express');
const { Pool } = require('pg');
const axios = require('axios');
const cheerio = require('cheerio');

// Load Playwright only if ENABLE_PUPPETEER environment variable is set to 'true'
// Load it lazily to avoid blocking startup
let playwright = null;
let playwrightLoadAttempted = false;

function loadPlaywright() {
  if (playwrightLoadAttempted) {
    return playwright;
  }
  playwrightLoadAttempted = true;
  
  const enablePuppeteer = process.env.ENABLE_PUPPETEER === 'true' || process.env.ENABLE_PUPPETEER === 'TRUE';
  if (enablePuppeteer) {
    try {
      playwright = require('playwright');
      console.log('✓ Playwright loaded successfully (ENABLE_PUPPETEER=true)');
    } catch (playwrightError) {
      console.error('✗ Failed to load Playwright:', playwrightError.message);
      console.error('Playwright may not be installed. Run: npm install playwright');
      console.error('Service will start but Clubspot scraping will not work');
    }
  } else {
    console.log('ℹ Playwright not loaded (ENABLE_PUPPETEER not set to true)');
  }
  return playwright;
}

// Load Playwright after server starts (non-blocking)
setTimeout(() => {
  loadPlaywright();
}, 2000);

const app = express();
const port = process.env.PORT || 3001;

app.use(express.json());

// Database connection - lazy initialization (don't connect until needed)
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    },
    // Don't connect immediately - wait until first query
    connectionTimeoutMillis: 10000,
    idleTimeoutMillis: 30000
});

// Initialize regattas table if needed
async function ensureRegattasTable() {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS regattas (
                id SERIAL PRIMARY KEY,
                regatta_date DATE NOT NULL,
                regatta_name TEXT NOT NULL,
                location TEXT,
                event_website_url TEXT,
                registrants_url TEXT,
                source TEXT NOT NULL,
                source_id TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(regatta_name, regatta_date, source)
            )
        `);
        
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_regattas_date ON regattas(regatta_date);`);
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_regattas_name ON regattas(regatta_name);`);
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_regattas_location ON regattas(location);`);
        
        await pool.query(`
            CREATE TABLE IF NOT EXISTS scrape_log (
                id SERIAL PRIMARY KEY,
                source TEXT NOT NULL,
                regattas_found INTEGER DEFAULT 0,
                regattas_added INTEGER DEFAULT 0,
                scrape_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        console.log('Regattas table verified');
    } catch (err) {
        console.error('Error ensuring regattas table:', err);
    }
}

// Scrape Regatta Network
async function scrapeRegattaNetwork() {
    try {
        const url = 'https://www.regattanetwork.com/html/calendar.php';
        const response = await axios.get(url, {
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            },
            timeout: 30000
        });
        
        const $ = cheerio.load(response.data);
        const regattas = [];
        
        $('table tr').each((index, element) => {
            const $row = $(element);
            const $cells = $row.find('td');
            
            if ($cells.length >= 3) {
                const dateText = $cells.eq(0).text().trim();
                const eventCell = $cells.eq(1);
                const linksCell = $cells.eq(2);
                
                let regattaDate = null;
                if (dateText) {
                    const dateMatch = dateText.match(/(\d{2})\/(\d{2})\/(\d{2})/);
                    if (dateMatch) {
                        const [, month, day, year] = dateMatch;
                        const fullYear = parseInt(year) < 50 ? 2000 + parseInt(year) : 1900 + parseInt(year);
                        regattaDate = `${fullYear}-${month}-${day}`;
                    }
                }
                
                let eventName = eventCell.clone().children().remove().end().text().trim();
                if (!eventName) {
                    eventName = eventCell.text().trim().split('\n')[0];
                }
                
                let location = '';
                const fullText = eventCell.text();
                const locationMatch = fullText.match(/([A-Z][^,]+(?:,\s*[A-Z][^,]+)*,\s*[A-Z]{2})/);
                if (locationMatch) {
                    location = locationMatch[1].trim();
                } else {
                    const lines = fullText.split('\n').map(l => l.trim()).filter(l => l);
                    if (lines.length > 1) {
                        location = lines[1];
                    }
                }
                
                let eventWebsiteUrl = '';
                eventCell.find('a').each((i, link) => {
                    const href = $(link).attr('href');
                    const text = $(link).text().trim();
                    if (text.includes('Event Website') || (href && href.includes('event'))) {
                        eventWebsiteUrl = href.startsWith('http') ? href : `https://www.regattanetwork.com${href}`;
                        return false;
                    }
                });
                
                let registrantsUrl = '';
                linksCell.find('a').each((i, link) => {
                    const href = $(link).attr('href');
                    const text = $(link).text().trim();
                    if (text.includes('View Registrants') || text.includes('Registrants') || (href && href.includes('registrant'))) {
                        registrantsUrl = href.startsWith('http') ? href : `https://www.regattanetwork.com${href}`;
                        return false;
                    }
                });
                
                if (eventName && location && eventName.includes(location)) {
                    eventName = eventName.replace(location, '').trim();
                }
                
                if (regattaDate && eventName && eventName.length > 3) {
                    const sourceId = `${regattaDate}-${eventName.replace(/\s+/g, '-').toLowerCase().substring(0, 100)}`;
                    
                    regattas.push({
                        regatta_date: regattaDate,
                        regatta_name: eventName,
                        location: location || null,
                        event_website_url: eventWebsiteUrl || null,
                        registrants_url: registrantsUrl || null,
                        source: 'regattanetwork',
                        source_id: sourceId
                    });
                }
            }
        });
        
        console.log(`Found ${regattas.length} regattas from Regatta Network`);
        
        let added = 0;
        for (const regatta of regattas) {
            try {
                await pool.query(`
                    INSERT INTO regattas (regatta_date, regatta_name, location, event_website_url, registrants_url, source, source_id)
                    VALUES ($1, $2, $3, $4, $5, $6, $7)
                    ON CONFLICT (regatta_name, regatta_date, source) 
                    DO UPDATE SET 
                        location = EXCLUDED.location,
                        event_website_url = EXCLUDED.event_website_url,
                        registrants_url = EXCLUDED.registrants_url,
                        source_id = EXCLUDED.source_id,
                        last_updated = CURRENT_TIMESTAMP
                `, [
                    regatta.regatta_date,
                    regatta.regatta_name,
                    regatta.location,
                    regatta.event_website_url,
                    regatta.registrants_url,
                    regatta.source,
                    regatta.source_id
                ]);
                added++;
            } catch (err) {
                if (!err.message.includes('duplicate')) {
                    console.error('Error inserting regatta:', err);
                }
            }
        }
        
        await pool.query(`
            INSERT INTO scrape_log (source, regattas_found, regattas_added)
            VALUES ('regattanetwork', $1, $2)
        `, [regattas.length, added]);
        
        return { found: regattas.length, added };
    } catch (error) {
        console.error('Error scraping Regatta Network:', error);
        throw error;
    }
}

// Scrape Clubspot using headless browser
async function scrapeClubspot() {
    // Load Playwright if not already loaded
    const playwrightInstance = loadPlaywright();
    
    // Verify Playwright is enabled and available
    const enablePuppeteer = process.env.ENABLE_PUPPETEER === 'true' || process.env.ENABLE_PUPPETEER === 'TRUE';
    
    if (!enablePuppeteer) {
        throw new Error('Playwright is disabled. Set ENABLE_PUPPETEER=true to enable Clubspot scraping.');
    }
    
    if (!playwrightInstance) {
        throw new Error('Playwright is not available. Cannot scrape Clubspot. Ensure Playwright is installed and ENABLE_PUPPETEER=true is set.');
    }
    
    let browser = null;
    try {
        console.log('Launching headless browser for Clubspot...');
        
        const launchOptions = {
            headless: true,
            args: [
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-dev-shm-usage',
                '--disable-accelerated-2d-canvas',
                '--disable-gpu',
                '--disable-software-rasterizer',
                '--disable-extensions',
                '--single-process', // Important for memory efficiency
                '--no-zygote' // Important for memory efficiency
            ]
        };
        
        browser = await playwrightInstance.chromium.launch(launchOptions);
        const context = await browser.newContext({
            viewport: { width: 1920, height: 1080 },
            userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        });
        const page = await context.newPage();
        
        console.log('Navigating to Clubspot...');
        await page.goto('https://racing.theclubspot.com/', {
            waitUntil: 'networkidle',
            timeout: 60000
        });
        
        console.log('Waiting for regatta data to load...');
        try {
            await page.waitForSelector('[class*="regatta"], [class*="event"], [class*="card"], .regatta-item, .event-item', {
                timeout: 30000
            });
        } catch (waitError) {
            console.log('Regatta selector not found, waiting additional time...');
            await page.waitForTimeout(5000);
        }
        
        console.log('Extracting regatta data...');
        const regattas = await page.evaluate(() => {
            const regattas = [];
            const selectors = [
                '[class*="regatta"]',
                '[class*="event"]',
                '[class*="card"]',
                '.regatta-item',
                '.event-item',
                'a[href*="/regatta/"]',
                '[data-regatta]'
            ];
            
            let elements = [];
            for (const selector of selectors) {
                const found = document.querySelectorAll(selector);
                if (found.length > 0) {
                    elements = Array.from(found);
                    break;
                }
            }
            
            if (elements.length === 0) {
                elements = Array.from(document.querySelectorAll('a[href*="regatta"], a[href*="event"]'));
            }
            
            elements.forEach((element) => {
                try {
                    const text = element.textContent || element.innerText || '';
                    const href = element.href || element.getAttribute('href') || '';
                    
                    const dateMatch = text.match(/(\d{1,2})\/(\d{1,2})\/(\d{4})/) || 
                                     text.match(/(\d{4})-(\d{1,2})-(\d{1,2})/) ||
                                     text.match(/([A-Z][a-z]+)\s+(\d{1,2}),\s+(\d{4})/);
                    
                    const lines = text.split('\n').map(l => l.trim()).filter(l => l && l.length > 3);
                    const nameText = lines[0] || text.substring(0, 100).trim();
                    const locationText = lines.length > 1 ? lines.slice(1).join(', ').substring(0, 200) : '';
                    
                    let regattaDate = null;
                    if (dateMatch) {
                        if (dateMatch[0].includes('-')) {
                            regattaDate = dateMatch[0];
                        } else if (dateMatch[0].includes('/')) {
                            const [, month, day, year] = dateMatch;
                            regattaDate = `${year}-${month.padStart(2, '0')}-${day.padStart(2, '0')}`;
                        } else {
                            const months = { 'January': '01', 'February': '02', 'March': '03', 'April': '04',
                                           'May': '05', 'June': '06', 'July': '07', 'August': '08', 
                                           'September': '09', 'October': '10', 'November': '11', 'December': '12' };
                            const month = months[dateMatch[1]];
                            if (month) {
                                regattaDate = `${dateMatch[3]}-${month}-${dateMatch[2].padStart(2, '0')}`;
                            }
                        }
                    }
                    
                    let eventWebsiteUrl = null;
                    if (href) {
                        eventWebsiteUrl = href.startsWith('http') ? href : `https://racing.theclubspot.com${href}`;
                    }
                    
                    if (regattaDate && nameText && nameText.length > 3) {
                        regattas.push({
                            regatta_date: regattaDate,
                            regatta_name: nameText,
                            location: locationText || null,
                            event_website_url: eventWebsiteUrl || null
                        });
                    }
                } catch (err) {
                    // Skip errors
                }
            });
            
            return regattas;
        });
        
        console.log(`Found ${regattas.length} regattas from Clubspot`);
        
        let added = 0;
        for (const regatta of regattas) {
            try {
                const sourceId = `${regatta.regatta_date}-${regatta.regatta_name.replace(/\s+/g, '-').toLowerCase().substring(0, 100)}`;
                
                await pool.query(`
                    INSERT INTO regattas (regatta_date, regatta_name, location, event_website_url, registrants_url, source, source_id)
                    VALUES ($1, $2, $3, $4, $5, $6, $7)
                    ON CONFLICT (regatta_name, regatta_date, source) 
                    DO UPDATE SET 
                        location = EXCLUDED.location,
                        event_website_url = EXCLUDED.event_website_url,
                        registrants_url = EXCLUDED.registrants_url,
                        source_id = EXCLUDED.source_id,
                        last_updated = CURRENT_TIMESTAMP
                `, [
                    regatta.regatta_date,
                    regatta.regatta_name,
                    regatta.location,
                    regatta.event_website_url,
                    null,
                    'clubspot',
                    sourceId
                ]);
                added++;
            } catch (err) {
                if (!err.message.includes('duplicate')) {
                    console.error('Error inserting regatta:', err);
                }
            }
        }
        
        await pool.query(`
            INSERT INTO scrape_log (source, regattas_found, regattas_added)
            VALUES ('clubspot', $1, $2)
        `, [regattas.length, added]);
        
        return { found: regattas.length, added };
        
    } catch (error) {
        console.error('Error scraping Clubspot:', error);
        throw error;
    } finally {
        if (browser) {
            try {
                await browser.close();
                console.log('Browser closed');
            } catch (closeError) {
                console.error('Error closing browser:', closeError);
            }
        }
    }
}

// Scraping endpoint
app.post('/api/scrape-regattas', async (req, res) => {
    console.log('=== Regatta Scraping Request Received ===');
    
    try {
        const { source } = req.body; // 'regattanetwork', 'clubspot', or 'all'
        let totalFound = 0;
        let totalAdded = 0;
        const results = { regattanetwork: { found: 0, added: 0 }, clubspot: { found: 0, added: 0 } };

        if (!source || source === 'all' || source === 'regattanetwork') {
            console.log('Scraping Regatta Network...');
            const rnResult = await scrapeRegattaNetwork();
            results.regattanetwork = rnResult;
            totalFound += rnResult.found;
            totalAdded += rnResult.added;
        }

        if (!source || source === 'all' || source === 'clubspot') {
            console.log('Scraping Clubspot...');
            try {
                const csResult = await scrapeClubspot();
                results.clubspot = csResult;
                totalFound += csResult.found;
                totalAdded += csResult.added;
            } catch (csError) {
                console.error('Clubspot scraping error:', csError);
                results.clubspot = { 
                    found: 0, 
                    added: 0, 
                    error: csError.message || 'Failed to scrape Clubspot' 
                };
            }
        }

        console.log(`=== Scraping Complete: ${totalFound} found, ${totalAdded} added ===`);
        res.json({
            success: true,
            totalFound,
            totalAdded,
            results
        });
    } catch (error) {
        console.error('=== Scraping Error ===', error);
        res.status(500).json({
            error: 'Failed to scrape regattas',
            details: error.message
        });
    }
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({ status: 'ok', service: 'regatta-scraper' });
});

// Start server - minimal synchronous startup
const server = app.listen(port, () => {
    console.log(`Regatta Scraper Service running on port ${port}`);
    console.log('Server is ready to accept requests');
});

// Log Playwright status after server starts
const enablePuppeteer = process.env.ENABLE_PUPPETEER === 'true' || process.env.ENABLE_PUPPETEER === 'TRUE';
if (enablePuppeteer && playwright) {
    console.log('✓ Playwright module loaded (ENABLE_PUPPETEER=true)');
} else if (enablePuppeteer && !playwright) {
    console.error('✗ ERROR: ENABLE_PUPPETEER=true but Playwright failed to load');
} else {
    console.log('ℹ Playwright disabled (ENABLE_PUPPETEER not set)');
}

// Initialize database asynchronously in background (don't await)
setTimeout(() => {
    initializeDatabase().catch(err => {
        console.error('Database initialization error:', err.message);
    });
}, 1000); // Wait 1 second after server starts

// Separate function for database initialization
async function initializeDatabase() {
    try {
        // Test database connection
        await pool.query('SELECT 1');
        console.log('✓ Database connected');
        
        // Ensure tables exist
        await ensureRegattasTable();
        
        console.log('✓ Service ready to accept scraping requests');
        console.log('  - Regatta Network scraping: Available');
        const enablePuppeteer = process.env.ENABLE_PUPPETEER === 'true' || process.env.ENABLE_PUPPETEER === 'TRUE';
        if (enablePuppeteer && playwright) {
            console.log('  - Clubspot scraping: Available');
        } else {
            console.log('  - Clubspot scraping: UNAVAILABLE');
        }
    } catch (err) {
        console.error('✗ Database initialization failed:', err.message);
        if (err.code === 'ENOTFOUND') {
            console.error('  DNS lookup failed - check DATABASE_URL');
        }
        if (!process.env.DATABASE_URL) {
            console.error('  DATABASE_URL environment variable is not set!');
        }
        console.error('  Service will continue but database operations may fail');
    }
}

// Handle unhandled promise rejections to prevent crashes
process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
    // Don't exit - log and continue
});

process.on('uncaughtException', (error) => {
    console.error('Uncaught Exception:', error);
    console.error('Stack:', error.stack);
    // Don't exit - log and continue (or exit if critical)
    // For now, let it continue to see what happens
});

