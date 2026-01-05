const express = require('express');
const { Pool } = require('pg');
const axios = require('axios');
const cheerio = require('cheerio');
const fs = require('fs');
const path = require('path');

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

// Load Playwright immediately (synchronously) so it's ready when service starts
loadPlaywright();

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
    // Verify Playwright is enabled
    const enablePuppeteer = process.env.ENABLE_PUPPETEER === 'true' || process.env.ENABLE_PUPPETEER === 'TRUE';
    
    if (!enablePuppeteer) {
        throw new Error('Playwright is disabled. Set ENABLE_PUPPETEER=true to enable Clubspot scraping.');
    }
    
    // Wait for Playwright to be loaded (with timeout)
    let playwrightInstance = loadPlaywright();
    let attempts = 0;
    const maxAttempts = 10;
    
    while (!playwrightInstance && attempts < maxAttempts) {
        console.log(`⏳ Waiting for Playwright to load... (attempt ${attempts + 1}/${maxAttempts})`);
        await new Promise(resolve => setTimeout(resolve, 500)); // Wait 500ms
        playwrightInstance = loadPlaywright();
        attempts++;
    }
    
    if (!playwrightInstance) {
        throw new Error('Playwright is not available. Cannot scrape Clubspot. Ensure Playwright is installed and ENABLE_PUPPETEER=true is set.');
    }
    
    console.log('✓ Playwright is ready, starting scrape...');
    
    let browser = null;
    try {
        console.log('Launching headless browser for Clubspot...');
        
        const fs = require('fs');
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
        
        // Try to launch browser - if it fails due to missing browsers, install them
        try {
            browser = await playwrightInstance.chromium.launch(launchOptions);
        } catch (launchError) {
            // If browsers aren't installed, try to install them
            if (launchError.message && launchError.message.includes('Executable doesn\'t exist')) {
                console.log('Playwright browsers not found, attempting to install...');
                try {
                    const { execSync } = require('child_process');
                    // Skip system dependencies as they're not needed on Render
                    process.env.PLAYWRIGHT_SKIP_DEPENDENCY_DOWNLOAD = '1';
                    execSync('npx playwright install chromium', { 
                        stdio: 'inherit',
                        timeout: 300000, // 5 minutes timeout
                        env: { ...process.env, PLAYWRIGHT_SKIP_DEPENDENCY_DOWNLOAD: '1' }
                    });
                    console.log('✓ Playwright browsers installed successfully');
                    // Try launching again
                    browser = await playwrightInstance.chromium.launch(launchOptions);
                } catch (installError) {
                    console.error('✗ Failed to install Playwright browsers:', installError.message);
                    throw new Error('Playwright browsers are not installed and installation failed. Please install browsers during build: npx playwright install chromium');
                }
            } else {
                throw launchError;
            }
        }
        const context = await browser.newContext({
            viewport: { width: 1920, height: 1080 },
            userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        });
        const page = await context.newPage();
        
        // Set up debug directory for screenshots
        const debugDir = path.join(process.cwd(), 'debug_screenshots');
        if (!fs.existsSync(debugDir)) {
            fs.mkdirSync(debugDir, { recursive: true });
        }
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-').substring(0, 19);
        
        // Track navigation
        page.on('framenavigated', frame => {
            if (frame === page.mainFrame()) {
                console.log(`🔗 Navigated to URL: ${frame.url()}`);
            }
        });
        
        const targetUrl = 'https://racing.theclubspot.com/';
        console.log(`🌐 Navigating to Clubspot: ${targetUrl}`);
        
        await page.goto(targetUrl, {
            waitUntil: 'networkidle',
            timeout: 60000
        });
        
        // Log page info
        const pageTitle = await page.title();
        const currentUrl = page.url();
        console.log(`📄 Page Title: "${pageTitle}"`);
        console.log(`📍 Current URL: ${currentUrl}`);
        
        // Take screenshot after initial load (non-blocking)
        const screenshot1Path = path.join(debugDir, `clubspot-initial-${timestamp}.png`);
        try {
            await page.screenshot({ 
                path: screenshot1Path, 
                fullPage: false, // Use viewport instead of fullPage to avoid timeout
                timeout: 10000 // 10 second timeout
            });
            console.log(`📸 Screenshot saved: ${screenshot1Path}`);
        } catch (screenshotError) {
            console.log(`⚠️ Screenshot failed (non-critical): ${screenshotError.message}`);
        }
        
        // Get page HTML content for debugging
        const pageContent = await page.content();
        const contentLength = pageContent.length;
        console.log(`📊 Page HTML length: ${contentLength} characters`);
        
        // Log visible text sample
        const visibleText = await page.evaluate(() => {
            return document.body.innerText.substring(0, 1000);
        });
        console.log(`📝 Visible text sample (first 1000 chars):\n${visibleText}\n`);
        
        console.log('⏳ Waiting for regatta data to load...');
        try {
            await page.waitForSelector('[class*="regatta"], [class*="event"], [class*="card"], .regatta-item, .event-item', {
                timeout: 30000
            });
            console.log('✅ Regatta selector found');
        } catch (waitError) {
            console.log('⚠️ Regatta selector not found, waiting additional time...');
            await page.waitForTimeout(5000);
        }
        
        // Take screenshot after waiting (non-blocking)
        const screenshot2Path = path.join(debugDir, `clubspot-after-wait-${timestamp}.png`);
        try {
            await page.screenshot({ 
                path: screenshot2Path, 
                fullPage: false, // Use viewport instead of fullPage to avoid timeout
                timeout: 10000 // 10 second timeout
            });
            console.log(`📸 Screenshot saved: ${screenshot2Path}`);
        } catch (screenshotError) {
            console.log(`⚠️ Screenshot failed (non-critical): ${screenshotError.message}`);
        }
        
        console.log('🔍 Extracting regatta data...');
        
        // First, let's see what's actually on the page
        const pageInfo = await page.evaluate(() => {
            return {
                bodyText: document.body.innerText.substring(0, 2000),
                allLinks: Array.from(document.querySelectorAll('a')).map(a => ({
                    text: a.textContent.trim().substring(0, 100),
                    href: a.href
                })).filter(a => a.text.length > 3).slice(0, 20),
                allDivs: Array.from(document.querySelectorAll('div')).length,
                allCards: Array.from(document.querySelectorAll('[class*="card"], [class*="Card"]')).length,
                allRegattas: Array.from(document.querySelectorAll('[class*="regatta"], [class*="Regatta"]')).length,
                allEvents: Array.from(document.querySelectorAll('[class*="event"], [class*="Event"]')).length
            };
        });
        
        console.log(`\n📊 Page Analysis:`);
        console.log(`  - Total divs: ${pageInfo.allDivs}`);
        console.log(`  - Elements with "card" in class: ${pageInfo.allCards}`);
        console.log(`  - Elements with "regatta" in class: ${pageInfo.allRegattas}`);
        console.log(`  - Elements with "event" in class: ${pageInfo.allEvents}`);
        console.log(`  - Links found: ${pageInfo.allLinks.length}`);
        if (pageInfo.allLinks.length > 0) {
            console.log(`  - Sample links:`);
            pageInfo.allLinks.slice(0, 5).forEach((link, i) => {
                console.log(`    ${i + 1}. "${link.text}" → ${link.href}`);
            });
        }
        console.log(`\n📝 Page text sample:\n${pageInfo.bodyText.substring(0, 500)}...\n`);
        
        const extractionResult = await page.evaluate(() => {
            const regattas = [];
            const debugInfo = { foundElements: [], processedElements: [] };
            
            // Try to find regatta cards/items - Clubspot uses a specific structure
            const selectors = [
                '[class*="regatta"]',
                '[class*="event"]',
                '[class*="card"]',
                '[class*="Card"]',
                '.regatta-item',
                '.event-item',
                'a[href*="/regatta/"]',
                '[data-regatta]'
            ];
            
            let elements = [];
            let usedSelector = null;
            
            // Try each selector
            for (const selector of selectors) {
                const found = document.querySelectorAll(selector);
                if (found.length > 0 && elements.length === 0) {
                    elements = Array.from(found);
                    usedSelector = selector;
                    break;
                }
            }
            
            // If elements found but they might be too granular, try to find parent containers
            // Look for divs that contain both a date pattern and regatta-like text
            // This helps find the actual regatta card containers
            if (elements.length === 0 || elements.length > 100) {
                const allDivs = Array.from(document.querySelectorAll('div'));
                const clubspotDatePattern = /(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),\s+[A-Z][a-z]{2}\s+\d{1,2}/i;
                
                elements = allDivs.filter(div => {
                    const text = div.textContent || '';
                    const hasDate = clubspotDatePattern.test(text);
                    const hasName = /[A-Z][a-z]+.*(?:Series|Regatta|Championship|Cup|Race|Invitational)/i.test(text);
                    const hasLocation = /[A-Z][a-z]+,\s+[A-Z]{2}/.test(text); // City, State format
                    const textLength = text.trim().length;
                    
                    // Should have date, name-like text, and reasonable length
                    return hasDate && (hasName || textLength > 30) && textLength > 20 && textLength < 1000;
                });
                
                // Remove nested duplicates - keep only top-level containers
                elements = elements.filter((el, idx) => {
                    return !elements.some((otherEl, otherIdx) => 
                        otherIdx !== idx && otherEl.contains(el)
                    );
                });
                
                usedSelector = 'div-with-regatta-content';
            }
            
            debugInfo.totalElements = elements.length;
            debugInfo.usedSelector = usedSelector;
            
            // Month abbreviations for Clubspot format
            const monthAbbrev = {
                'Jan': '01', 'Feb': '02', 'Mar': '03', 'Apr': '04',
                'May': '05', 'Jun': '06', 'Jul': '07', 'Aug': '08',
                'Sep': '09', 'Oct': '10', 'Nov': '11', 'Dec': '12'
            };
            
            // Pattern for Clubspot date format: "Sat, Jan 10 - Sun, Jan 11" or "Sat, Jan 10"
            const clubspotDatePattern = /(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),\s+([A-Z][a-z]{2})\s+(\d{1,2})(?:\s*-\s*(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),\s+[A-Z][a-z]{2}\s+\d{1,2})?/i;
            
            elements.forEach((element, index) => {
                try {
                    const text = element.textContent || element.innerText || '';
                    const href = element.href || element.getAttribute('href') || '';
                    const elementHtml = element.outerHTML.substring(0, 200);
                    
                    console.log(`\n--- Element ${index + 1} ---`);
                    console.log(`Text: "${text.substring(0, 200)}"`);
                    console.log(`Href: ${href}`);
                    console.log(`HTML: ${elementHtml}...`);
                    
                    // Try Clubspot format first: "Sat, Jan 10 - Sun, Jan 11" or "Sat, Jan 10"
                    let dateMatch = null;
                    let regattaDate = null;
                    
                    const clubspotMatch = text.match(clubspotDatePattern);
                    
                    if (clubspotMatch) {
                        const monthAbbr = clubspotMatch[1];
                        const day = clubspotMatch[2];
                        const month = monthAbbrev[monthAbbr];
                        
                        // Try to find year in the text or use current/next year
                        const yearMatch = text.match(/(\d{4})/);
                        let year = yearMatch ? yearMatch[1] : new Date().getFullYear().toString();
                        
                        // If we're in December and see Jan dates, it's probably next year
                        const currentMonth = new Date().getMonth() + 1;
                        if (month === '01' && currentMonth === 12) {
                            year = (parseInt(year) + 1).toString();
                        }
                        
                        if (month && day) {
                            regattaDate = `${year}-${month}-${day.padStart(2, '0')}`;
                            dateMatch = clubspotMatch;
                        }
                    }
                    
                    // Fallback to other date patterns if Clubspot format not found
                    if (!dateMatch) {
                        const datePatterns = [
                            /(\d{1,2})\/(\d{1,2})\/(\d{4})/,  // MM/DD/YYYY
                            /(\d{4})-(\d{1,2})-(\d{1,2})/,   // YYYY-MM-DD
                            /([A-Z][a-z]+)\s+(\d{1,2}),\s+(\d{4})/,  // Month DD, YYYY
                            /(\d{1,2})\s+([A-Z][a-z]+)\s+(\d{4})/,   // DD Month YYYY
                        ];
                        
                        for (const pattern of datePatterns) {
                            const match = text.match(pattern);
                            if (match) {
                                dateMatch = match;
                                try {
                                    if (match[0].includes('-') && match[0].match(/^\d{4}-\d{2}-\d{2}/)) {
                                        regattaDate = match[0].substring(0, 10);
                                    } else if (match[0].includes('/')) {
                                        const [, month, day, year] = match;
                                        regattaDate = `${year}-${month.padStart(2, '0')}-${day.padStart(2, '0')}`;
                                    } else {
                                        const months = { 'January': '01', 'February': '02', 'March': '03', 'April': '04',
                                                       'May': '05', 'June': '06', 'July': '07', 'August': '08', 
                                                       'September': '09', 'October': '10', 'November': '11', 'December': '12' };
                                        if (match.length >= 4) {
                                            const month = months[match[1]] || months[match[2]];
                                            const day = match[2] || match[1];
                                            const year = match[3];
                                            if (month && day && year) {
                                                regattaDate = `${year}-${month}-${day.padStart(2, '0')}`;
                                            }
                                        }
                                    }
                                } catch (dateErr) {
                                    // Skip
                                }
                                break;
                            }
                        }
                    }
                    
                    // Extract regatta name and location from text
                    const lines = text.split('\n').map(l => l.trim()).filter(l => l && l.length > 2);
                    
                    // Find regatta name - usually the first substantial line that's not a date
                    let nameText = '';
                    for (const line of lines) {
                        if (line.length > 5 && 
                            !clubspotDatePattern.test(line) && 
                            !line.match(/^[A-Z][a-z]+,\s+[A-Z]{2}$/) && // Not location
                            !line.match(/^[A-Z][a-z]+\s+Yacht Club$/) && // Not just club name
                            !line.match(/^\d{4}$/)) { // Not just year
                            nameText = line.replace(/^(SCYYRA|2026|2025|2024|2023|2022|2021|2020)\s+/i, '').trim();
                            if (nameText.length > 3) break;
                        }
                    }
                    
                    // If no name found, try first line
                    if (!nameText || nameText.length < 3) {
                        nameText = lines.find(l => l.length > 3 && !clubspotDatePattern.test(l)) || lines[0] || text.substring(0, 100).trim();
                        nameText = nameText.replace(/^(SCYYRA|2026|2025|2024|2023|2022|2021|2020)\s+/i, '').trim();
                    }
                    
                    // Find location - usually after date, format like "City, State"
                    let locationText = '';
                    const dateLineIndex = lines.findIndex(line => clubspotDatePattern.test(line));
                    if (dateLineIndex >= 0) {
                        // Look for location after date
                        for (let i = dateLineIndex + 1; i < lines.length && i < dateLineIndex + 3; i++) {
                            const line = lines[i];
                            if (line.match(/^[A-Z][a-z]+(?:,\s+[A-Z]{2})?$/) || // City, State or City
                                line.match(/^[A-Z][a-z]+\s+Yacht Club$/)) { // Club name
                                locationText = line;
                                break;
                            }
                        }
                    }
                    
                    // Fallback: find any location-like text
                    if (!locationText) {
                        locationText = lines.find(line => 
                            line.match(/^[A-Z][a-z]+,\s+[A-Z]{2}$/) || // City, State
                            line.match(/^[A-Z][a-z]+\s+Yacht Club$/) // Club name
                        ) || '';
                    }
                    
                    let eventWebsiteUrl = null;
                    if (href) {
                        eventWebsiteUrl = href.startsWith('http') ? href : `https://racing.theclubspot.com${href}`;
                        console.log(`Event URL: ${eventWebsiteUrl}`);
                    }
                    
                    if (regattaDate && nameText && nameText.length > 3) {
                        console.log(`✅ Valid regatta found!`);
                        regattas.push({
                            regatta_date: regattaDate,
                            regatta_name: nameText,
                            location: locationText || null,
                            event_website_url: eventWebsiteUrl || null
                        });
                    } else {
                        console.log(`❌ Skipping - missing date: ${!regattaDate}, name too short: ${!nameText || nameText.length <= 3}`);
                    }
                } catch (err) {
                    console.log(`❌ Error processing element ${index + 1}: ${err.message}`);
                }
            });
            
            return { regattas, debugInfo };
        });
        
        // Log debug info
        console.log(`\n=== Extraction Debug Info ===`);
        console.log(`Total elements found: ${extractionResult.debugInfo.totalElements}`);
        console.log(`Selector used: "${extractionResult.debugInfo.usedSelector}"`);
        
        // Extract regattas from result
        const extractedRegattas = extractionResult.regattas;
        
        // Take final screenshot (non-blocking)
        const screenshot3Path = path.join(debugDir, `clubspot-final-${timestamp}.png`);
        try {
            await page.screenshot({ 
                path: screenshot3Path, 
                fullPage: false, // Use viewport instead of fullPage to avoid timeout
                timeout: 10000 // 10 second timeout
            });
            console.log(`📸 Final screenshot saved: ${screenshot3Path}`);
        } catch (screenshotError) {
            console.log(`⚠️ Final screenshot failed (non-critical): ${screenshotError.message}`);
        }
        
        console.log(`\n✅ Found ${extractedRegattas.length} regattas from Clubspot`);
        if (extractedRegattas.length === 0) {
            console.log('⚠️ WARNING: No regattas found!');
            console.log(`📁 Debug screenshots saved in: ${debugDir}`);
            console.log(`📄 Check logs above for page content and selector results`);
        } else {
            console.log('📋 Regattas found:');
            extractedRegattas.forEach((regatta, index) => {
                console.log(`  ${index + 1}. ${regatta.regatta_name} - ${regatta.regatta_date} - ${regatta.location || 'No location'}`);
                if (regatta.event_website_url) {
                    console.log(`     URL: ${regatta.event_website_url}`);
                }
            });
        }
        
        let added = 0;
        for (const regatta of extractedRegattas) {
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
        `, [extractedRegattas.length, added]);
        
        return { found: extractedRegattas.length, added };
        
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

