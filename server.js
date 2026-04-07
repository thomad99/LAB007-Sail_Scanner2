const express = require('express');
const { Pool } = require('pg');
const mqtt = require('mqtt');
const path = require('path');
const multer = require('multer');
const { ComputerVisionClient } = require('@azure/cognitiveservices-computervision');
const { CognitiveServicesCredentials } = require('@azure/ms-rest-azure-js');
const fs = require('fs');
const fsPromises = require('fs').promises;
const {
    S3Client,
    PutObjectCommand,
    GetObjectCommand,
    DeleteObjectCommand,
    CopyObjectCommand,
    ListObjectsV2Command
} = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const ExifParser = require('exif-parser');
const nodemailer = require('nodemailer');
const cheerio = require('cheerio');
const axios = require('axios');
const OpenAI = require('openai').default;
const cron = require('node-cron');
const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);

// Load Puppeteer only if ENABLE_PUPPETEER environment variable is set to 'true'
// Main server should NOT have this set - only the dedicated scraper service should
let puppeteer = null;
const enablePuppeteer = process.env.ENABLE_PUPPETEER === 'true' || process.env.ENABLE_PUPPETEER === 'TRUE';

if (enablePuppeteer) {
    console.log('ENABLE_PUPPETEER=true detected - loading Puppeteer...');
    try {
        puppeteer = require('puppeteer');
        console.log('✓ Puppeteer loaded successfully');
    } catch (puppeteerError) {
        console.warn('⚠ Puppeteer not available:', puppeteerError.message);
        console.warn('  To enable: npm install puppeteer');
    }
} else {
    console.log('ℹ Puppeteer not loaded (ENABLE_PUPPETEER not set - this is correct for main server)');
    console.log('  Scraping is handled by dedicated scraper service');
}

const app = express();
const port = process.env.PORT || 3000;

// AWS S3 Configuration and Validation
if (!process.env.AWS_ACCESS_KEY || !process.env.AWS_SECRET_ACCESS_KEY || !process.env.AWS_REGION) {
    console.error('Missing required AWS credentials:');
    console.error('AWS_ACCESS_KEY:', process.env.AWS_ACCESS_KEY ? 'Set' : 'Missing');
    console.error('AWS_SECRET_ACCESS_KEY:', process.env.AWS_SECRET_ACCESS_KEY ? 'Set' : 'Missing');
    console.error('AWS_REGION:', process.env.AWS_REGION ? 'Set' : 'Missing');
    console.error('AWS_BUCKET_NAME:', process.env.AWS_BUCKET_NAME || 'lovesailing-photostore');
}

// Create the S3 client with explicit credentials
const s3Client = new S3Client({
    region: process.env.AWS_REGION,
    credentials: {
        accessKeyId: process.env.AWS_ACCESS_KEY,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
    },
    forcePathStyle: true
});

const BUCKET_NAME = process.env.AWS_BUCKET_NAME || 'lovesailing-photostore';

// Test S3 connection on startup
async function testS3Connection() {
    try {
        console.log('Testing S3 connection...');
        const command = new ListObjectsV2Command({
            Bucket: BUCKET_NAME,
            MaxKeys: 1
        });
        await s3Client.send(command);
        console.log('Successfully connected to S3');
    } catch (err) {
        console.error('Error connecting to S3:', err);
        console.error('AWS Credentials:', {
            region: process.env.AWS_REGION,
            accessKeyId: process.env.AWS_ACCESS_KEY ? '***' : 'Missing',
            secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY ? '***' : 'Missing',
            bucket: BUCKET_NAME
        });
    }
}

// Helper function to upload file to S3
async function uploadToS3(buffer, key, contentType) {
    try {
        console.log(`Uploading to S3: ${key}`);
        console.log('Using credentials:', {
            region: process.env.AWS_REGION,
            accessKeyId: process.env.AWS_ACCESS_KEY ? '***' : 'Missing',
            secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY ? '***' : 'Missing',
            bucket: BUCKET_NAME
        });

        const command = new PutObjectCommand({
            Bucket: BUCKET_NAME,
            Key: key,
            Body: buffer,
            ContentType: contentType
        });

        await s3Client.send(command);
        console.log(`Successfully uploaded to S3: ${key}`);
        return `https://${BUCKET_NAME}.s3.amazonaws.com/${key}`;
    } catch (err) {
        console.error('Error uploading to S3:', err);
        console.error('Upload details:', {
            key,
            contentType,
            bufferSize: buffer.length,
            bucket: BUCKET_NAME
        });
        throw err;
    }
}

// Helper function to get signed URL for S3 object
async function getS3SignedUrl(key) {
    try {
        console.log(`Getting signed URL for: ${key}`);
        const command = new GetObjectCommand({
            Bucket: BUCKET_NAME,
            Key: key
        });
        const url = await getSignedUrl(s3Client, command, { expiresIn: 3600 }); // URL expires in 1 hour
        console.log(`Generated signed URL for: ${key}`);
        return url;
    } catch (err) {
        console.error('Error getting signed URL:', err);
        throw err;
    }
}

// Helper function to delete from S3
async function deleteFromS3(key) {
    try {
        console.log(`Deleting from S3: ${key}`);
        const command = new DeleteObjectCommand({
            Bucket: BUCKET_NAME,
            Key: key
        });
        await s3Client.send(command);
        console.log(`Successfully deleted from S3: ${key}`);
    } catch (err) {
        console.error('Error deleting from S3:', err);
        throw err;
    }
}

// Helper function to list objects in S3 (handles pagination, not just first 1000)
async function listS3Objects(prefix = '') {
    try {
        console.log(`Listing S3 objects with prefix: ${prefix}`);

        const allObjects = [];
        let continuationToken = undefined;
        let page = 0;

        do {
            const command = new ListObjectsV2Command({
                Bucket: BUCKET_NAME,
                Prefix: prefix,
                ContinuationToken: continuationToken
            });

            const response = await s3Client.send(command);
            const contents = response.Contents || [];
            page += 1;

            console.log(
                `S3 list page ${page}: fetched ${contents.length} object(s)${
                    response.IsTruncated ? ' (more pages available)' : ''
                }`
            );

            allObjects.push(...contents);

            if (response.IsTruncated && response.NextContinuationToken) {
                continuationToken = response.NextContinuationToken;
            } else {
                continuationToken = undefined;
            }
        } while (continuationToken);

        console.log(`Found total ${allObjects.length} objects in S3 for prefix "${prefix}"`);
        return allObjects;
    } catch (err) {
        console.error('Error listing S3 objects:', err);
        throw err;
    }
}

// Helper to convert S3 stream to Buffer
function streamToBuffer(stream) {
    return new Promise((resolve, reject) => {
        const chunks = [];
        stream.on('data', (chunk) => chunks.push(chunk));
        stream.on('error', (err) => reject(err));
        stream.on('end', () => resolve(Buffer.concat(chunks)));
    });
}

// Helper to download an object from S3 into a buffer (for rescans, etc.)
async function downloadS3ObjectToBuffer(key) {
    try {
        console.log(`Downloading from S3 for rescan: ${key}`);
        const command = new GetObjectCommand({
            Bucket: BUCKET_NAME,
            Key: key
        });

        const response = await s3Client.send(command);
        const bodyStream = response.Body;

        if (!bodyStream) {
            throw new Error('Empty S3 response body');
        }

        const buffer = await streamToBuffer(bodyStream);
        const contentType = response.ContentType || 'application/octet-stream';

        console.log(`Downloaded ${buffer.length} bytes from S3 for key: ${key}`);

        return { buffer, contentType };
    } catch (err) {
        console.error('Error downloading S3 object:', err);
        throw err;
    }
}

// Add these near the top of server.js
const LOCAL_SAVE_PATH = process.env.LOCAL_SAVE_PATH || path.join(process.cwd(), 'local_saves');
const SAVE_TO_SERVER = true; // Set to false if you don't want server copies
const IGNORED_NUMBERS = ['420']; // Numbers to ignore (boat class markings)
const validSailNumbers = [13, 118, 9610, 5318, 8008]; // Valid sail numbers

// Add these constants at the top of your file
const RATE_LIMIT_DELAY = 30000; // 30 seconds
let lastAzureCallTime = 0;
const UPLOAD_DIR = path.join(__dirname, 'uploads');
const PROCESSED_DIR = path.join(__dirname, 'processed_images');
const LIVEVIEW_FRAMES_DIR = path.join(__dirname, 'liveview_frames');
const LIVEVIEW_VIDEOS_DIR = path.join(__dirname, 'liveview_videos');

// Add these constants at the top
const MAX_RETRIES = 3;
const BASE_RETRY_DELAY = 5000; // 5 seconds

// Add rate limiting configuration
const RATE_LIMIT_WINDOW = 60 * 1000; // 1 minute window
const MAX_REQUESTS_PER_WINDOW = 10; // 10 requests per minute

// Simple in-memory store for rate limiting
const rateLimitStore = new Map();

// Rate limiting middleware
const rateLimiter = (req, res, next) => {
    const apiKey = req.headers['x-api-key'];
    const now = Date.now();

    // Initialize or get rate limit data for this API key
    if (!rateLimitStore.has(apiKey)) {
        rateLimitStore.set(apiKey, {
            count: 0,
            resetTime: now + RATE_LIMIT_WINDOW
        });
    }

    const rateLimitData = rateLimitStore.get(apiKey);

    // Reset counter if window has passed
    if (now > rateLimitData.resetTime) {
        rateLimitData.count = 0;
        rateLimitData.resetTime = now + RATE_LIMIT_WINDOW;
    }

    // Increment counter
    rateLimitData.count++;

    // Check if rate limit exceeded
    if (rateLimitData.count > MAX_REQUESTS_PER_WINDOW) {
        const retryAfter = Math.ceil((rateLimitData.resetTime - now) / 1000);
        return res.status(429).json({
            success: false,
            error: 'Rate limit exceeded',
            retryAfter,
            limit: MAX_REQUESTS_PER_WINDOW,
            window: RATE_LIMIT_WINDOW / 1000
        });
    }

    // Add rate limit headers
    res.set({
        'X-RateLimit-Limit': MAX_REQUESTS_PER_WINDOW,
        'X-RateLimit-Remaining': MAX_REQUESTS_PER_WINDOW - rateLimitData.count,
        'X-RateLimit-Reset': rateLimitData.resetTime
    });

    next();
};

// Update API key authentication to include rate limiting
const authenticateApiKey = (req, res, next) => {
    const apiKey = req.headers['x-api-key'];

    // Updated to use APIKEY instead of API_KEY
    const validApiKey = process.env.APIKEY || 'your-static-api-key-here';

    if (!apiKey || apiKey !== validApiKey) {
        console.log('Invalid or missing API key');
        return res.status(401).json({
            success: false,
            error: 'Invalid or missing API key'
        });
    }

    // Apply rate limiting
    rateLimiter(req, res, next);
};

// Email service API key authentication middleware
const authenticateEmailApiKey = (req, res, next) => {
    const emailApiKey = process.env.EMAIL_SERVICE_API_KEY;

    // If EMAIL_SERVICE_API_KEY is not set, skip authentication
    if (!emailApiKey) {
        return next();
    }

    const providedKey = req.headers['x-api-key'];

    if (!providedKey || providedKey !== emailApiKey) {
        console.log('Invalid or missing email service API key');
        return res.status(401).json({
            error: 'Invalid or missing API key',
            details: 'X-API-Key header required'
        });
    }

    next();
};

// Update the search endpoint to use the combined auth and rate limiting
app.get('/api/search-by-sail/:sailNumber', authenticateApiKey, async (req, res) => {
    console.log('Received request for sail number:', req.params.sailNumber);

    try {
        const sailNumber = req.params.sailNumber;

        // Updated validation to allow alphanumeric sail numbers
        if (!sailNumber || !/^[A-Za-z0-9]{1,10}$/.test(sailNumber)) {
            console.log('Invalid sail number format:', sailNumber);
            return res.status(400).json({
                success: false,
                error: 'Invalid sail number format. Must be 1-10 alphanumeric characters.',
                receivedValue: sailNumber
            });
        }

        console.log('Querying database for sail number:', sailNumber);

        // Query the database for photos with matching sail number
        const result = await pool.query(`
            SELECT * FROM photo_metadata 
            WHERE sail_number ILIKE $1
            ORDER BY created_at DESC
        `, [sailNumber]);

        console.log(`Found ${result.rows.length} photos for sail number ${sailNumber}`);

        // Generate signed URLs for each photo
        const photosWithUrls = await Promise.all(result.rows.map(async (photo) => {
            try {
                const s3Key = `processed/${photo.filename}`;
                console.log('Generating signed URL for:', s3Key);
                const signedUrl = await getS3SignedUrl(s3Key);
                return {
                    ...photo,
                    url: signedUrl
                };
            } catch (err) {
                console.error(`Error generating signed URL for ${photo.filename}:`, err);
                return {
                    ...photo,
                    url: null,
                    error: 'Unable to generate photo URL'
                };
            }
        }));

        res.json({
            success: true,
            sailNumber: sailNumber,
            count: photosWithUrls.length,
            photos: photosWithUrls,
            rateLimit: {
                remaining: res.get('X-RateLimit-Remaining'),
                reset: res.get('X-RateLimit-Reset')
            }
        });
    } catch (err) {
        console.error('Error searching photos by sail number:', err);
        res.status(500).json({
            success: false,
            error: 'Error searching photos by sail number',
            details: err.message
        });
    }
});

// Add a test endpoint that also uses API key auth
app.get('/api/test', authenticateApiKey, (req, res) => {
    res.json({
        status: 'ok',
        message: 'Server is running',
        timestamp: new Date().toISOString(),
        rateLimit: {
            remaining: res.get('X-RateLimit-Remaining'),
            reset: res.get('X-RateLimit-Reset')
        }
    });
});

// Keep the health endpoint public and without rate limiting
app.get('/api/health', (req, res) => {
    res.json({
        status: 'ok',
        message: 'Server is running',
        timestamp: new Date().toISOString(),
        version: '1.0.0'
    });
});

// Update webhook handler for one-time payments (must be before any body parsers)
app.post('/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
    const sig = req.headers['stripe-signature'];
    let event;

    try {
        event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
        console.log('Stripe webhook event received:', event.type);
    } catch (err) {
        console.error('Webhook signature verification failed:', err.message);
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    if (event.type === 'checkout.session.completed') {
        const session = event.data.object;
        console.log('Checkout session completed. Session metadata:', session.metadata);
        // Record the image purchase
        try {
            await pool.query(
                `INSERT INTO purchased_images (user_id, image_filename, stripe_payment_id)
                 VALUES ($1, $2, $3)`,
                [session.metadata.userId, session.metadata.imageFilename, session.payment_intent]
            );
            console.log('Purchase recorded in database:', session.metadata);
        } catch (dbErr) {
            console.error('Error inserting purchase into database:', dbErr);
        }
    }

    res.json({ received: true });
});

// Add general error handler
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ error: 'Internal server error' });
});

// Add more detailed startup logging
console.log('Starting server...');
console.log('Node environment:', process.env.NODE_ENV);
console.log('Port:', port);

// Verify we have a DATABASE_URL
if (!process.env.DATABASE_URL) {
    console.error('DATABASE_URL environment variable is not set');
    process.exit(1);
}

// PostgreSQL connection configuration
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

// Test database connection on startup
pool.connect()
    .then(() => console.log('Successfully connected to database'))
    .catch(err => {
        console.error('Error connecting to database:', err);
        process.exit(1);
    });

// Configure express.json with 50MB limit for email attachments
app.use(express.json({ limit: '50mb' }));

// SMTP configuration for email forwarding
const smtpConfig = {
    host: process.env.SMTP_HOST || 'smtp.ionos.com',
    port: parseInt(process.env.SMTP_PORT || '587'),
    secure: process.env.SMTP_SECURE === 'true' || process.env.SMTP_SECURE === '1',
    auth: {
        user: process.env.SMTP_USER || '',
        pass: process.env.SMTP_PASS || ''
    },
    requireTLS: process.env.SMTP_SECURE !== 'true' && process.env.SMTP_SECURE !== '1',
    connectionTimeout: 30000,
    greetingTimeout: 30000,
    socketTimeout: 30000,
    tls: {
        rejectUnauthorized: true,
        minVersion: 'TLSv1.2'
    }
};

const emailTransporter = nodemailer.createTransport(smtpConfig);

// Optional: API key for authentication
const EMAIL_SERVICE_API_KEY = process.env.EMAIL_SERVICE_API_KEY || null;



// Fallback favicon route - try root public directory
app.get('/favicon.ico', (req, res) => {
    const faviconPath = path.join(__dirname, 'public', 'favicon.ico');
    const imagesFaviconPath = path.join(__dirname, 'public', 'Images', 'favicon.ico');

    // Try root public directory first, then Images directory
    if (require('fs').existsSync(faviconPath)) {
        res.setHeader('Content-Type', 'image/x-icon');
        res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
        res.setHeader('Pragma', 'no-cache');
        res.setHeader('Expires', '0');
        res.sendFile(faviconPath);
    } else if (require('fs').existsSync(imagesFaviconPath)) {
        res.setHeader('Content-Type', 'image/x-icon');
        res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
        res.setHeader('Pragma', 'no-cache');
        res.setHeader('Expires', '0');
        res.sendFile(imagesFaviconPath);
    } else {
        res.status(404).send('Favicon not found');
    }
});



// Define multer storage configurations
const trainUpload = multer({
    dest: 'training_data/',
    limits: {
        fileSize: 5 * 1024 * 1024 // 5MB limit
    }
});

const upload = multer({
    storage: multer.memoryStorage(),
    limits: {
        fileSize: 5 * 1024 * 1024 // 5MB limit
    }
});

const csvUpload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 25 * 1024 * 1024 }
});

function parseCSVLine(line) {
    const out = [];
    let cur = '';
    let inQ = false;
    for (let i = 0; i < line.length; i++) {
        const c = line[i];
        if (c === '"') inQ = !inQ;
        else if (c === ',' && !inQ) { out.push(cur.trim()); cur = ''; }
        else cur += c;
    }
    out.push(cur.trim());
    return out;
}

function parseCSVBuffer(buf) {
    let text = buf.toString('utf8').replace(/\uFEFF/g, '').replace(/\r\n/g, '\n').replace(/\r/g, '\n');
    const lines = text.split('\n').map(l => l.trim()).filter(l => l);
    if (lines.length < 1) return { headers: [], rows: [] };
    const headers = parseCSVLine(lines[0]).map(h => h.replace(/^"|"$/g, '').trim());
    const rows = [];
    for (let i = 1; i < lines.length; i++) rows.push(parseCSVLine(lines[i]));
    return { headers, rows };
}

const MONTHS = {
    january: '01', february: '02', march: '03', april: '04', may: '05', june: '06',
    july: '07', august: '08', september: '09', october: '10', november: '11', december: '12'
};

function parseRegattaDate(s) {
    if (!s || !String(s).trim()) return null;
    const raw = String(s).trim();
    const iso = raw.match(/^(\d{4})-(\d{2})-(\d{2})/);
    if (iso) return `${iso[1]}-${iso[2]}-${iso[3]}`;
    const slash = raw.match(/(\d{1,2})\/(\d{1,2})\/(\d{4})/);
    if (slash) return `${slash[3]}-${slash[1].padStart(2, '0')}-${slash[2].padStart(2, '0')}`;
    const monthName = raw.match(/(January|February|March|April|May|June|July|August|September|October|November|December)\s+(\d{1,2})(?:\s*-\s*\d{1,2})?\s*,?\s*(\d{4})/i);
    if (monthName) {
        const key = monthName[1].toLowerCase();
        const m = MONTHS[key];
        const d = monthName[2].padStart(2, '0');
        const y = monthName[3];
        if (m && d && y) return `${y}-${m}-${d}`;
    }
    return null;
}

// Add these environment variables in Render
const computerVisionKey = process.env.AZURE_VISION_KEY;
const computerVisionEndpoint = process.env.AZURE_VISION_ENDPOINT;

// Initialize Azure client
const computerVisionClient = new ComputerVisionClient(
    new CognitiveServicesCredentials(computerVisionKey),
    computerVisionEndpoint
);

// Azure Document Intelligence (for LiveView only - separate from Computer Vision / SailScan).
// Create a Document Intelligence resource in Azure and set:
//   AZURE_DOCUMENT_INTELLIGENCE_ENDPOINT  e.g. https://YOUR_RESOURCE.cognitiveservices.azure.com
//   AZURE_DOCUMENT_INTELLIGENCE_KEY       one of the resource keys
const documentIntelligenceEndpoint = process.env.AZURE_DOCUMENT_INTELLIGENCE_ENDPOINT || '';
const documentIntelligenceKey = process.env.AZURE_DOCUMENT_INTELLIGENCE_KEY || '';
const DOC_INTEL_API_VERSION = '2024-11-30';
// Standard text on sails to ignore when detecting sail number
const SAIL_TEXT_TO_IGNORE = new Set(['c420', 'usa', 'nacra15', 'us']);

// Add this helper function
async function saveFile(buffer, filename, originalFilename) {
    console.log('Starting file save operations...');

    try {
        // 1. Save to local configured directory
        const localDir = LOCAL_SAVE_PATH;
        console.log('Ensuring local directory exists:', localDir);
        await fsPromises.mkdir(localDir, { recursive: true });

        const localFilePath = path.join(localDir, filename);
        await fsPromises.writeFile(localFilePath, buffer);
        console.log('File saved locally:', localFilePath);

        // 2. Optionally save to server uploads directory
        if (SAVE_TO_SERVER) {
            const uploadsDir = path.join('public', 'uploads');
            await fsPromises.mkdir(uploadsDir, { recursive: true });
            const serverFilePath = path.join(uploadsDir, filename);
            await fsPromises.writeFile(serverFilePath, buffer);
            console.log('File saved on server:', serverFilePath);
        }

        return {
            localPath: localFilePath,
            serverPath: SAVE_TO_SERVER ? `/uploads/${filename}` : null
        };
    } catch (error) {
        console.error('Error saving file:', error);
        throw error;
    }
}

// API endpoint to save numbers
app.post('/api/numbers', async (req, res) => {
    const { numbers } = req.body;

    try {
        for (const number of numbers) {
            await pool.query(
                'INSERT INTO sail_numbers (number, timestamp) VALUES ($1, NOW())',
                [number]
            );
            console.log(`Saved number: ${number}`);
        }
        res.json({ success: true });
    } catch (err) {
        console.error('Error saving to database:', err);
        res.status(500).json({ error: 'Failed to save numbers' });
    }
});

// Add test endpoint to view saved numbers
app.get('/api/numbers', async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM sail_numbers ORDER BY timestamp DESC LIMIT 10'
        );
        res.json(result.rows);
    } catch (err) {
        console.error('Error fetching numbers:', err);
        res.status(500).json({ error: 'Failed to fetch numbers' });
    }
});

// Update training endpoint to use trainUpload
app.post('/api/train', trainUpload.single('image'), async (req, res) => {
    try {
        const { number } = req.body;
        const imagePath = req.file.path;

        // Store training data
        await pool.query(
            'INSERT INTO training_data (number, image_path, timestamp) VALUES ($1, $2, NOW())',
            [number, imagePath]
        );

        res.json({ success: true });
    } catch (err) {
        console.error('Error saving training data:', err);
        res.status(500).json({ error: 'Failed to save training data' });
    }
});

// Function to clean up directories
async function cleanupDirectories(cleanProcessed = false) {
    console.log('Starting directory cleanup...');
    console.log('UPLOAD_DIR:', UPLOAD_DIR);
    console.log('PROCESSED_DIR:', PROCESSED_DIR);

    try {
        // Ensure directories exist
        await fsPromises.mkdir(UPLOAD_DIR, { recursive: true });
        await fsPromises.mkdir(PROCESSED_DIR, { recursive: true });

        // Clean up upload directory
        const uploadFiles = await fsPromises.readdir(UPLOAD_DIR);
        console.log(`Found ${uploadFiles.length} files in upload directory`);

        for (const file of uploadFiles) {
            const filePath = path.join(UPLOAD_DIR, file);
            await fsPromises.unlink(filePath);
            console.log(`Deleted upload: ${file}`);
        }

        // Only clean processed directory if explicitly requested
        if (cleanProcessed) {
            console.log('WARNING: Cleaning processed files directory - this will remove all processed images');
            const processedFiles = await fsPromises.readdir(PROCESSED_DIR);
            console.log(`Found ${processedFiles.length} files in processed directory`);

            for (const file of processedFiles) {
                const filePath = path.join(PROCESSED_DIR, file);
                await fsPromises.unlink(filePath);
                console.log(`Deleted processed: ${file}`);
            }
        }

        console.log('Directory cleanup completed');
    } catch (err) {
        console.error('Error during cleanup:', err);
        // Don't throw the error - we want to continue even if cleanup fails
    }
}

// Helper function for exponential backoff delay
function getRetryDelay(attempt) {
    return BASE_RETRY_DELAY * Math.pow(2, attempt);
}

// Updated Azure processing function with retry logic
async function processWithRetry(operation, operationName) {
    let attempt = 0;

    while (attempt <= MAX_RETRIES) {
        try {
            await waitForRateLimit();
            return await operation();
        } catch (err) {
            attempt++;

            // Check specifically for rate limit errors
            const isRateLimit =
                err.message?.includes('rate limit') ||
                err.message?.includes('429') ||
                err.statusCode === 429;

            if (isRateLimit && attempt <= MAX_RETRIES) {
                const delay = getRetryDelay(attempt);
                console.log(`Rate limit hit for ${operationName}. Attempt ${attempt} of ${MAX_RETRIES}. Waiting ${delay / 1000} seconds...`);
                await new Promise(resolve => setTimeout(resolve, delay));
                continue;
            }

            // If it's not a rate limit error or we're out of retries, throw the error
            throw err;
        }
    }
}

// Add this after the database connection setup
async function createPhotoMetadataTable() {
    try {
        // First create the table if it doesn't exist
        await pool.query(`
            CREATE TABLE IF NOT EXISTS photo_metadata (
                id SERIAL PRIMARY KEY,
                filename TEXT NOT NULL,
                sail_number TEXT,
                date DATE,
                regatta_name TEXT,
                photographer_name TEXT,
                photographer_website TEXT,
                location TEXT,
                additional_tags TEXT[],
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Check if new columns exist and add them if they don't
        const columnsToAdd = [
            { name: 'file_checksum', type: 'TEXT UNIQUE' },
            { name: 'photo_timestamp', type: 'TIMESTAMP' },
            { name: 'gps_latitude', type: 'DECIMAL' },
            { name: 'gps_longitude', type: 'DECIMAL' },
            { name: 'gps_altitude', type: 'DECIMAL' },
            { name: 'device_fingerprint', type: 'TEXT' },
            { name: 'device_type', type: 'TEXT' },
            { name: 'user_agent', type: 'TEXT' },
            { name: 'screen_resolution', type: 'TEXT' },
            { name: 'timezone', type: 'TEXT' },
            { name: 'upload_timestamp', type: 'TIMESTAMP' },
            { name: 'original_filename', type: 'TEXT' },
            { name: 'new_filename', type: 'TEXT' },
            { name: 'file_size', type: 'BIGINT' },
            { name: 'file_type', type: 'TEXT' },
            { name: 'yacht_club', type: 'TEXT' },
            { name: 's3_url', type: 'TEXT' },
            { name: 'processing_status', type: 'TEXT DEFAULT \'pending\'' },
            { name: 'sail_numbers', type: 'JSONB' },
            { name: 'analysis_timestamp', type: 'TIMESTAMP' }
        ];

        for (const column of columnsToAdd) {
            try {
                // Check if column exists
                const columnCheck = await pool.query(`
                    SELECT EXISTS (
                        SELECT FROM information_schema.columns 
                        WHERE table_name = 'photo_metadata' 
                        AND column_name = $1
                    );
                `, [column.name]);

                if (!columnCheck.rows[0].exists) {
                    console.log(`Adding column ${column.name} to photo_metadata table`);
                    await pool.query(`ALTER TABLE photo_metadata ADD COLUMN ${column.name} ${column.type}`);
                }
            } catch (err) {
                console.error(`Error adding column ${column.name}:`, err);
            }
        }

        console.log('Photo metadata table created or verified with all columns');
    } catch (err) {
        console.error('Error creating photo metadata table:', err);
    }
}

async function createLiveviewResultsTable() {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS liveview_results (
                id SERIAL PRIMARY KEY,
                created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                sail_numbers TEXT[] NOT NULL,
                session_id TEXT
            )
        `);
        // Migration: add columns if they don't exist yet
        const additions = [
            { col: 'session_id', def: 'TEXT' },
            { col: 'filename',   def: 'TEXT' },
            { col: 'metadata',   def: 'JSONB DEFAULT \'{}\'::jsonb' },
        ];
        for (const { col, def } of additions) {
            const r = await pool.query(
                `SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='liveview_results' AND column_name=$1)`,
                [col]
            );
            if (!r.rows[0].exists) {
                await pool.query(`ALTER TABLE liveview_results ADD COLUMN ${col} ${def}`);
            }
        }
        console.log('Liveview results table created or verified');
    } catch (err) {
        console.error('Error creating liveview_results table:', err);
    }
}

// Add this function to create directories if they don't exist
async function ensureDirectories() {
    try {
        await fsPromises.mkdir(UPLOAD_DIR, { recursive: true });
        console.log('Upload directory created/verified:', UPLOAD_DIR);

        await fsPromises.mkdir(PROCESSED_DIR, { recursive: true });
        console.log('Processed directory created/verified:', PROCESSED_DIR);
    } catch (err) {
        console.error('Error creating directories:', err);
    }
}

// Call this when the server starts (moved to end of file)

// Update the scan endpoint to include metadata
app.post('/api/scan', upload.single('image'), async (req, res) => {
    let processedFiles = [];
    const storeUnmatchSails = req.body.store_unmatch_sails !== 'false' && req.body.store_unmatch_sails !== false;
    const metadata = {
        date: req.body.date || new Date().toISOString().split('T')[0],
        regatta_name: req.body.regatta_name,
        photographer_name: req.body.photographer_name,
        photographer_website: req.body.photographer_website,
        location: req.body.location,
        additional_tags: req.body.additional_tags ? req.body.additional_tags.split(',').map(tag => tag.trim()) : [],
        device_fingerprint: req.body.device_fingerprint,
        device_type: req.body.device_type,
        user_agent: req.body.user_agent,
        screen_resolution: req.body.screen_resolution,
        timezone: req.body.timezone,
        upload_timestamp: req.body.upload_timestamp && req.body.upload_timestamp !== 'undefined' ? req.body.upload_timestamp : new Date().toISOString()
    };

    try {
        console.log('=== Starting New Scan ===');

        if (!req.file || !req.file.buffer) {
            throw new Error('No image file received');
        }

        const originalFilename = req.file.originalname;
        console.log('Processing file:', originalFilename);

        // Extract EXIF data and generate checksum
        const exifData = extractExifData(req.file.buffer);
        const fileChecksum = generateFileChecksum(req.file.buffer);

        console.log('File checksum:', fileChecksum);
        console.log('EXIF data extracted:', exifData);

        // Check for duplicate files
        const existingFile = await checkForDuplicate(fileChecksum);
        if (existingFile) {
            console.log('Duplicate file detected:', existingFile.filename);
            return res.status(409).json({
                success: false,
                error: 'Duplicate file detected',
                existingFile: existingFile.filename,
                message: 'This image has already been uploaded and processed.'
            });
        }

        // Initialize tracking variables
        let processingSteps = {
            rawText: [],
            potentialNumbers: [],
            validNumbers: [],
            ignoredNumbers: [],
            sailNumbers: {
                numbers: [],
                ignored: []
            },
            debug: {
                azureResponse: null,
                processingTime: null,
                retryAttempts: 0
            }
        };

        try {
            // STEP 2: Send to Azure for Text Detection
            console.log('Step 2: Sending to Azure Vision...');
            const result = await processWithRetry(
                () => computerVisionClient.readInStream(req.file.buffer, { language: 'en' }),
                'Azure Vision API call'
            );

            // STEP 3: Wait for Azure Processing
            console.log('Step 3: Waiting for Azure analysis...');
            const operationId = result.operationLocation.split('/').pop();

            let operationResult;
            let attempts = 0;
            const maxAttempts = 30;
            const delayMs = 1000;

            do {
                attempts++;
                console.log(`Checking Azure results - Attempt ${attempts}...`);
                operationResult = await processWithRetry(
                    () => computerVisionClient.getReadResult(operationId),
                    'Azure Results Polling'
                );

                if (operationResult.status === 'running' || operationResult.status === 'notStarted') {
                    await new Promise(resolve => setTimeout(resolve, delayMs));
                }
            } while ((operationResult.status === 'running' || operationResult.status === 'notStarted') && attempts < maxAttempts);

            if (operationResult.status === 'succeeded') {
                console.log('Azure processing completed successfully!');
                processingSteps.debug.azureResponse = operationResult.analyzeResult;
                const foundNumbers = extractSailNumbers(operationResult.analyzeResult);
                const sortedNumbers = foundNumbers.sort((a, b) => b.confidence - a.confidence);

                // Filter sail numbers by confidence level (>90%)
                const highConfidenceNumbers = sortedNumbers.filter(sailData => sailData.confidence > 0.9);
                processingSteps.sailNumbers.numbers = highConfidenceNumbers;

                console.log(`Found ${sortedNumbers.length} sail numbers, ${highConfidenceNumbers.length} with >90% confidence`);

                // Process each detected sail number (only high confidence ones)
                if (highConfidenceNumbers.length > 0) {
                    for (const sailData of highConfidenceNumbers) {
                        try {
                            const sailorInfo = await lookupSailorInDatabase(sailData.number);
                            const sailorName = sailorInfo ? sanitizeForFilename(sailorInfo.sailorName) : 'NONAME';
                            const newFilename = `${sailData.number}_${sailorName}_${originalFilename}`;
                            const s3Key = `processed/${newFilename}`;

                            // Upload to S3
                            await uploadToS3(req.file.buffer, s3Key, req.file.mimetype);
                            const s3Url = await getS3SignedUrl(s3Key);

                            processedFiles.push({
                                originalFilename: originalFilename,
                                newFilename: newFilename,
                                downloadUrl: s3Url,
                                sailNumber: sailData.number,
                                sailorName: sailorName
                            });
                        } catch (err) {
                            console.error(`Error processing sail number ${sailData.number}:`, err);
                        }
                    }
                }
            }
        } catch (azureErr) {
            console.error('Error during Azure processing:', azureErr);
        }

        // If no files were processed and Store Unmatch Sails is ON, create a NOSAIL version
        if (processedFiles.length === 0 && storeUnmatchSails) {
            const newFilename = `NOSAIL_NONAME_${originalFilename}`;
            const s3Key = `processed/${newFilename}`;

            try {
                // Upload to S3
                await uploadToS3(req.file.buffer, s3Key, req.file.mimetype);
                const s3Url = await getS3SignedUrl(s3Key);

                processedFiles.push({
                    originalFilename: originalFilename,
                    newFilename: newFilename,
                    downloadUrl: s3Url,
                    sailNumber: 'NOSAIL',
                    sailorName: 'NONAME'
                });
            } catch (s3Err) {
                console.error('Error creating NOSAIL fallback file in S3:', s3Err);
            }
        }

        // Store metadata for each processed file (only for photos with detected sail numbers)
        let dbInsertionSuccess = true;

        // Ensure the photo_metadata table exists
        try {
            await createPhotoMetadataTable();
            console.log('Photo metadata table verified/created');
        } catch (tableErr) {
            console.error('Error ensuring photo_metadata table exists:', tableErr);
            dbInsertionSuccess = false;
        }

        for (const file of processedFiles) {
            const isNosail = !file.sailNumber || file.sailNumber === 'NOSAIL';
            const shouldStore = !isNosail || storeUnmatchSails;
            if (shouldStore) {
                try {
                    console.log(`Attempting to insert metadata for file: ${file.newFilename} (Sail #${file.sailNumber || 'NOSAIL'})`);
                    const result = await pool.query(
                        `INSERT INTO photo_metadata (
                            filename, sail_number, date, regatta_name, 
                            photographer_name, photographer_website, 
                            location, additional_tags, file_checksum, photo_timestamp, gps_latitude, gps_longitude, gps_altitude,
                            device_fingerprint, device_type, user_agent, screen_resolution, timezone, upload_timestamp
                        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)`,
                        [
                            file.newFilename,
                            file.sailNumber || 'NOSAIL',
                            metadata.date || null,
                            metadata.regatta_name || null,
                            metadata.photographer_name || null,
                            metadata.photographer_website || null,
                            metadata.location || null,
                            metadata.additional_tags || [],
                            fileChecksum,
                            exifData.photo_timestamp || null,
                            exifData.gps_latitude || null,
                            exifData.gps_longitude || null,
                            exifData.gps_altitude || null,
                            metadata.device_fingerprint || null,
                            metadata.device_type || null,
                            metadata.user_agent || null,
                            metadata.screen_resolution || null,
                            metadata.timezone || null,
                            metadata.upload_timestamp || null
                        ]
                    );
                    console.log(`Successfully inserted metadata for file: ${file.newFilename}, rows affected: ${result.rowCount}`);
                } catch (dbErr) {
                    console.error('Error storing metadata for file:', file.newFilename, dbErr);
                    dbInsertionSuccess = false;
                    // Don't throw here, but mark that insertion failed
                }
            } else {
                console.log(`Skipping database metadata storage for NOSAIL file: ${file.newFilename} (Store Unmatch Sails is OFF)`);
            }
        }

        if (!dbInsertionSuccess) {
            console.error('Some or all database insertions failed');
        }

        res.json({
            success: true,
            sailNumbers: processingSteps.sailNumbers,
            processedFiles: processedFiles,
            exifData: exifData, // Include EXIF data for client display
            stats: {
                totalFiles: processedFiles.length,
                filesWithSailNumbers: processingSteps.sailNumbers.numbers.length
            },
            debug: {
                status: processingSteps.debug.azureResponse ? 'succeeded' : 'failed',
                processingTime: processingSteps.debug.processingTime || 'unknown',
                azureResponse: processingSteps.debug.azureResponse
            }
        });

    } catch (err) {
        console.error('Unhandled error during scan:', err);
        res.json({
            success: true,
            error: 'Error during processing: ' + err.message,
            processedFiles: processedFiles,
            sailNumbers: { numbers: [] },
            stats: {
                totalFiles: processedFiles.length,
                filesWithSailNumbers: 0
            },
            debug: {
                error: err.message,
                stack: err.stack
            }
        });
    }
});

// LiveView: uses Azure Document Intelligence (Read model), not Computer Vision
app.post('/api/liveview-scan', upload.single('image'), async (req, res) => {
    if (!req.file || !req.file.buffer) {
        return res.status(400).json({ error: 'No image provided', sailNumbers: [] });
    }
    if (!documentIntelligenceEndpoint || !documentIntelligenceKey) {
        return res.status(503).json({
            error: 'LiveView requires Azure Document Intelligence. Set AZURE_DOCUMENT_INTELLIGENCE_ENDPOINT and AZURE_DOCUMENT_INTELLIGENCE_KEY.',
            sailNumbers: []
        });
    }
    try {
        const analyzeResult = await analyzeWithDocumentIntelligence(req.file.buffer, req.file.mimetype || 'image/jpeg');
        const sailNumbers = extractSailNumbersFromDocumentIntelligence(analyzeResult);
        res.json({ sailNumbers });
    } catch (err) {
        console.error('LiveView scan error:', err);
        res.status(500).json({ error: err.message, sailNumbers: [] });
    }
});

// ── Upload2: scan with Document Intelligence AND save to photo_metadata (like /api/scan) ──
app.post('/api/scan2', upload.single('image'), async (req, res) => {
    if (!req.file || !req.file.buffer) {
        return res.status(400).json({ error: 'No image provided', sailNumbers: [] });
    }
    if (!documentIntelligenceEndpoint || !documentIntelligenceKey) {
        return res.status(503).json({ error: 'Azure Document Intelligence not configured', sailNumbers: [] });
    }

    const originalFilename = req.file.originalname;
    const uploadNoSail = req.body.upload_no_sail !== 'false';

    const metadata = {
        date:                req.body.date               || new Date().toISOString().split('T')[0],
        regatta_name:        req.body.regatta_name        || null,
        yacht_club:          req.body.yacht_club          || null,
        photographer_name:   req.body.photographer_name   || null,
        photographer_website:req.body.photographer_website|| null,
        location:            req.body.location            || null,
        additional_tags:     req.body.additional_tags
                               ? req.body.additional_tags.split(',').map(t => t.trim())
                               : [],
        upload_timestamp:    new Date().toISOString(),
    };

    try {
        // Duplicate check
        const fileChecksum = generateFileChecksum(req.file.buffer);
        const existing = await checkForDuplicate(fileChecksum);
        if (existing) {
            return res.status(409).json({
                success: false,
                error: 'Duplicate file detected',
                existingFile: existing.filename,
                message: 'This image has already been uploaded.'
            });
        }

        // Scan with Document Intelligence
        const analyzeResult = await analyzeWithDocumentIntelligence(req.file.buffer, req.file.mimetype || 'image/jpeg');
        const sailNumbers    = extractSailNumbersFromDocumentIntelligence(analyzeResult);
        const exifData       = extractExifData(req.file.buffer);

        const processedFiles = [];

        // Store one record per detected sail number (high-confidence first)
        const validSails = sailNumbers.filter(s => isValidSailNumber(s.number) && (s.confidence || 0) >= 0.5);

        if (validSails.length > 0) {
            for (const sailData of validSails) {
                try {
                    const sailorInfo = await lookupSailorInDatabase(sailData.number);
                    const sailorName = sailorInfo ? sanitizeForFilename(sailorInfo.sailorName) : 'NONAME';
                    const newFilename = `${sailData.number}_${sailorName}_${originalFilename}`;
                    const s3Key = `processed/${newFilename}`;
                    await uploadToS3(req.file.buffer, s3Key, req.file.mimetype);
                    // file_checksum is UNIQUE — one row per output file, not per source bytes
                    const rowChecksum = `${fileChecksum}::${newFilename}`;
                    processedFiles.push({
                        newFilename,
                        sailNumber: sailData.number,
                        confidence: sailData.confidence,
                        rowChecksum,
                    });
                } catch (err) {
                    console.error(`scan2: error saving sail ${sailData.number}:`, err.message);
                }
            }
        } else {
            // No qualifying sail — save as NOSAIL when allowed (default on)
            if (uploadNoSail) {
                const newFilename = `NOSAIL_NONAME_${originalFilename}`;
                const s3Key = `processed/${newFilename}`;
                try {
                    await uploadToS3(req.file.buffer, s3Key, req.file.mimetype);
                    processedFiles.push({
                        newFilename,
                        sailNumber: 'NOSAIL',
                        confidence: 0,
                        rowChecksum: fileChecksum,
                    });
                } catch (err) {
                    console.error('scan2: error saving NOSAIL:', err.message);
                }
            } else {
                console.log(`scan2: skipping NOSAIL save for ${originalFilename} (upload_no_sail=false)`);
            }
        }

        // If every S3 write failed but user wants no-sail saves, store one NOSAIL copy
        if (processedFiles.length === 0 && uploadNoSail) {
            const newFilename = `NOSAIL_NONAME_${originalFilename}`;
            const s3Key = `processed/${newFilename}`;
            try {
                await uploadToS3(req.file.buffer, s3Key, req.file.mimetype);
                processedFiles.push({
                    newFilename,
                    sailNumber: 'NOSAIL',
                    confidence: 0,
                    rowChecksum: fileChecksum,
                });
                console.log(`scan2: fallback NOSAIL save for ${originalFilename} (after failed sail uploads or empty queue)`);
            } catch (err) {
                console.error('scan2: fallback NOSAIL save failed:', err.message);
            }
        }

        // Insert into photo_metadata for each saved file
        for (const file of processedFiles) {
            try {
                const rowChecksum = file.rowChecksum || `${fileChecksum}::${file.newFilename}`;
                await pool.query(
                    `INSERT INTO photo_metadata (
                        filename, sail_number, date, regatta_name, yacht_club,
                        photographer_name, photographer_website,
                        location, additional_tags, file_checksum,
                        photo_timestamp, gps_latitude, gps_longitude, gps_altitude,
                        upload_timestamp
                    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
                    [
                        file.newFilename,
                        file.sailNumber,
                        metadata.date,
                        metadata.regatta_name,
                        metadata.yacht_club,
                        metadata.photographer_name,
                        metadata.photographer_website,
                        metadata.location,
                        metadata.additional_tags,
                        rowChecksum,
                        exifData.photo_timestamp  || null,
                        exifData.gps_latitude     || null,
                        exifData.gps_longitude    || null,
                        exifData.gps_altitude     || null,
                        metadata.upload_timestamp,
                    ]
                );
            } catch (dbErr) {
                console.error('scan2: db insert error:', dbErr.message);
            }
        }

        res.json({
            success: true,
            sailNumbers,
            processedFiles,
            originalFilename,
        });
    } catch (err) {
        console.error('scan2 error:', err);
        res.status(500).json({ error: err.message, sailNumbers: [] });
    }
});

// Store LiveView scan results in Postgres (timestamp added server-side)
app.post('/api/liveview-store-results', express.json(), async (req, res) => {
    const sailNumbers = req.body.sailNumbers;
    const sessionId  = req.body.sessionId && String(req.body.sessionId).trim() ? String(req.body.sessionId).trim() : null;
    const filename   = req.body.filename   ? String(req.body.filename).trim()  : null;
    const metadata   = req.body.metadata && typeof req.body.metadata === 'object' ? req.body.metadata : null;
    if (!Array.isArray(sailNumbers)) {
        return res.status(400).json({ error: 'sailNumbers array required' });
    }
    try {
        await createLiveviewResultsTable();
        await pool.query(
            'INSERT INTO liveview_results (sail_numbers, session_id, filename, metadata) VALUES ($1, $2, $3, $4)',
            [sailNumbers.map(String), sessionId, filename, metadata ? JSON.stringify(metadata) : null]
        );
        res.json({ ok: true });
    } catch (err) {
        console.error('LiveView store results error:', err);
        res.status(500).json({ error: err.message });
    }
});

// Get last LiveView stored results for feedback display
app.get('/api/liveview-results', async (req, res) => {
    const limit = Math.min(parseInt(req.query.limit, 10) || 50, 100);
    const sessionId = req.query.session_id && String(req.query.session_id).trim() ? String(req.query.session_id).trim() : null;
    try {
        await createLiveviewResultsTable();
        if (sessionId) {
            const result = await pool.query(
                'SELECT id, created_at, sail_numbers FROM liveview_results WHERE session_id = $1 ORDER BY created_at DESC LIMIT $2',
                [sessionId, limit]
            );
            return res.json({
                results: result.rows.map((r) => ({
                    id: r.id,
                    created_at: r.created_at,
                    sail_numbers: r.sail_numbers || []
                }))
            });
        }
        const result = await pool.query(
            'SELECT id, created_at, sail_numbers FROM liveview_results ORDER BY created_at DESC LIMIT $1',
            [limit]
        );
        res.json({
            results: result.rows.map((r) => ({
                id: r.id,
                created_at: r.created_at,
                sail_numbers: r.sail_numbers || []
            }))
        });
    } catch (err) {
        console.error('LiveView get results error:', err);
        res.status(500).json({ error: err.message, results: [] });
    }
});

// List LiveView capture sessions (grouped by session_id, newest first)
app.get('/api/liveview-sessions', async (req, res) => {
    try {
        await createLiveviewResultsTable();
        const result = await pool.query(`
            SELECT session_id, MIN(created_at) AS started_at, COUNT(*) AS capture_count
            FROM liveview_results
            WHERE session_id IS NOT NULL AND session_id != ''
            GROUP BY session_id
            ORDER BY started_at DESC
            LIMIT 200
        `);
        res.json({
            sessions: result.rows.map((r) => ({
                session_id: r.session_id,
                started_at: r.started_at,
                capture_count: parseInt(r.capture_count, 10)
            }))
        });
    } catch (err) {
        console.error('LiveView sessions error:', err);
        res.status(500).json({ error: err.message, sessions: [] });
    }
});

// Delete a LiveView capture session (all rows with that session_id)
app.delete('/api/liveview-session', express.json(), async (req, res) => {
    const sessionId = req.body && req.body.sessionId && String(req.body.sessionId).trim();
    if (!sessionId) {
        return res.status(400).json({ error: 'sessionId required' });
    }
    try {
        const result = await pool.query('DELETE FROM liveview_results WHERE session_id = $1 RETURNING id', [sessionId]);
        res.json({ ok: true, deleted: result.rowCount });
    } catch (err) {
        console.error('LiveView delete session error:', err);
        res.status(500).json({ error: err.message });
    }
});

// Download LiveView session results as CSV
app.get('/api/liveview-results-csv', async (req, res) => {
    const sessionId = req.query.session_id && String(req.query.session_id).trim();
    if (!sessionId) {
        return res.status(400).send('session_id required');
    }
    try {
        const result = await pool.query(
            'SELECT id, created_at, sail_numbers FROM liveview_results WHERE session_id = $1 ORDER BY created_at DESC',
            [sessionId]
        );
        const rows = result.rows || [];
        const header = 'capture_id,created_at_utc,sail_numbers\n';
        const csv = header + rows.map((r) => {
            const id = r.id;
            const at = r.created_at ? new Date(r.created_at).toISOString() : '';
            const nums = (r.sail_numbers || []).map((n) => String(n).replace(/"/g, '""')).join(',');
            return `${id},${at},"${nums}"`;
        }).join('\n');
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', `attachment; filename="liveview-session-${sessionId}.csv"`);
        res.send(csv);
    } catch (err) {
        console.error('LiveView CSV error:', err);
        res.status(500).send(err.message);
    }
});

// Save one frame for LiveView recording (low-res, ~10s interval); sessionId in body or query
app.post('/api/liveview-frame', upload.single('image'), async (req, res) => {
    const sessionId = (req.body && req.body.sessionId) || req.query.sessionId;
    if (!sessionId || !/^[a-zA-Z0-9_-]+$/.test(sessionId)) {
        return res.status(400).json({ error: 'Valid sessionId required' });
    }
    if (!req.file || !req.file.buffer) {
        return res.status(400).json({ error: 'No image provided' });
    }
    try {
        const dir = path.join(LIVEVIEW_FRAMES_DIR, sessionId);
        await fsPromises.mkdir(dir, { recursive: true });
        const files = await fsPromises.readdir(dir);
        const nextNum = files.filter((f) => /^frame_\d+\.jpg$/i.test(f)).length + 1;
        const name = `frame_${String(nextNum).padStart(4, '0')}.jpg`;
        await fsPromises.writeFile(path.join(dir, name), req.file.buffer);
        res.json({ ok: true, frame: name });
    } catch (err) {
        console.error('LiveView frame save error:', err);
        res.status(500).json({ error: err.message });
    }
});

// Finalize LiveView recording: build video from frames (0.1 fps = 10s per frame), optional cleanup
app.post('/api/liveview-recording-stop', express.json(), async (req, res) => {
    const sessionId = req.body && req.body.sessionId;
    if (!sessionId || !/^[a-zA-Z0-9_-]+$/.test(sessionId)) {
        return res.status(400).json({ error: 'Valid sessionId required' });
    }
    const framesDir = path.join(LIVEVIEW_FRAMES_DIR, sessionId);
    const outDir = LIVEVIEW_VIDEOS_DIR;
    try {
        await fsPromises.mkdir(outDir, { recursive: true });
        const exists = await fsPromises.stat(framesDir).then(() => true).catch(() => false);
        if (!exists) {
            return res.json({ ok: true, videoUrl: null, message: 'No frames recorded' });
        }
        const files = (await fsPromises.readdir(framesDir))
            .filter((f) => /^frame_\d+\.jpg$/i.test(f))
            .sort();
        if (files.length === 0) {
            return res.json({ ok: true, videoUrl: null, message: 'No frames to encode' });
        }
        const outPath = path.join(outDir, `${sessionId}.mp4`);
        // 0.1 fps = one frame every 10 seconds; 1024x800 or keep original
        const inputPattern = path.join(framesDir, 'frame_%04d.jpg');
        await execAsync(
            `ffmpeg -y -framerate 0.1 -i "${inputPattern.replace(/\\/g, '/')}" -c:v libx264 -pix_fmt yuv420p "${outPath.replace(/\\/g, '/')}"`,
            { timeout: 120000 }
        );
        const videoUrl = `/liveview_videos/${sessionId}.mp4`;
        res.json({ ok: true, videoUrl });
    } catch (err) {
        if (err.message && err.message.includes('ffmpeg')) {
            console.warn('LiveView recording-stop: ffmpeg not available or failed; frames saved in', framesDir);
            return res.json({ ok: true, videoUrl: null, message: 'Frames saved; ffmpeg not available to create video' });
        }
        console.error('LiveView recording-stop error:', err);
        res.status(500).json({ error: err.message });
    }
});

// Call Azure Document Intelligence prebuilt-read: analyze then poll until done
async function analyzeWithDocumentIntelligence(imageBuffer, contentType) {
    const url = `${documentIntelligenceEndpoint.replace(/\/$/, '')}/documentintelligence/documentModels/prebuilt-read:analyze?api-version=${DOC_INTEL_API_VERSION}`;
    const response = await axios({
        method: 'POST',
        url,
        data: imageBuffer,
        headers: {
            'Content-Type': contentType || 'application/octet-stream',
            'Ocp-Apim-Subscription-Key': documentIntelligenceKey
        },
        maxBodyLength: Infinity,
        maxContentLength: Infinity,
        validateStatus: (status) => status === 202
    });
    const operationLocation = response.headers['operation-location'];
    if (!operationLocation) {
        throw new Error('Document Intelligence did not return Operation-Location');
    }
    let attempts = 0;
    const maxAttempts = 60;
    const delayMs = 1000;
    while (attempts < maxAttempts) {
        attempts++;
        await new Promise(resolve => setTimeout(resolve, delayMs));
        const pollResponse = await axios.get(operationLocation, {
            headers: { 'Ocp-Apim-Subscription-Key': documentIntelligenceKey }
        });
        const body = pollResponse.data;
        const status = body.status;
        if (status === 'succeeded') {
            return body.analyzeResult;
        }
        if (status === 'failed') {
            throw new Error(body.error?.message || 'Document Intelligence analysis failed');
        }
    }
    throw new Error('Document Intelligence analysis timed out');
}

// Convert Document Intelligence polygon to [x1,y1, x2,y2, x3,y3, x4,y4] for overlay
function polygonToBoundingBox(polygon) {
    if (!polygon || !Array.isArray(polygon)) return null;
    if (polygon.length >= 4 && typeof polygon[0] === 'number') {
        return polygon.length >= 8 ? polygon.slice(0, 8) : null;
    }
    const flat = [];
    for (const p of polygon) {
        const x = typeof p === 'object' && p !== null && 'x' in p ? p.x : p;
        const y = typeof p === 'object' && p !== null && 'y' in p ? p.y : (Array.isArray(p) ? p[1] : undefined);
        if (typeof x !== 'number' || typeof y !== 'number') return null;
        flat.push(x, y);
    }
    if (flat.length >= 8) return flat.slice(0, 8);
    if (flat.length === 6) return [flat[0], flat[1], flat[2], flat[3], flat[4], flat[5], flat[0], flat[1]];
    return null;
}

// Return axis-aligned rect {minX, minY, maxX, maxY} from an 8-coord bounding box
function bbRect(bb) {
    return {
        minX: Math.min(bb[0], bb[2], bb[4], bb[6]),
        minY: Math.min(bb[1], bb[3], bb[5], bb[7]),
        maxX: Math.max(bb[0], bb[2], bb[4], bb[6]),
        maxY: Math.max(bb[1], bb[3], bb[5], bb[7]),
    };
}

// Merge two bounding boxes into the smallest enclosing box
function mergeBoundingBoxes(bb1, bb2) {
    const r1 = bbRect(bb1), r2 = bbRect(bb2);
    const minX = Math.min(r1.minX, r2.minX), minY = Math.min(r1.minY, r2.minY);
    const maxX = Math.max(r1.maxX, r2.maxX), maxY = Math.max(r1.maxY, r2.maxY);
    return [minX, minY, maxX, minY, maxX, maxY, minX, maxY];
}

// Two digit fragments are "part of the same sail number" if they occupy the same
// horizontal band and the gap between them is small relative to their height.
function areSailFragmentsNearby(bb1, bb2) {
    const r1 = bbRect(bb1), r2 = bbRect(bb2);
    const h1 = r1.maxY - r1.minY, h2 = r2.maxY - r2.minY;
    const avgH = (h1 + h2) / 2 || 1;
    // Must share a significant vertical overlap
    const overlapY = Math.min(r1.maxY, r2.maxY) - Math.max(r1.minY, r2.minY);
    if (overlapY < avgH * 0.3) return false;
    // Must be horizontally close — gap ≤ 2× average height
    const gap = Math.max(r1.minX, r2.minX) - Math.min(r1.maxX, r2.maxX);
    return gap < avgH * 2;
}

// Extract sail numbers from Document Intelligence analyze result; ignore standard sail text (C420, USA, Nacra15, US)
function extractSailNumbersFromDocumentIntelligence(analyzeResult) {
    const candidates = [];
    if (!analyzeResult || !analyzeResult.pages) return candidates;

    for (const page of analyzeResult.pages) {
        const lines = page.lines || [];
        const digitLines = []; // digit-only fragments for merge pass

        for (const line of lines) {
            const raw = (line.content || line.text || '').trim();
            const normalized = raw.toLowerCase();
            if (SAIL_TEXT_TO_IGNORE.has(normalized)) continue;

            const polygon = line.polygon || line.boundingPolygon || line.boundingBox;
            const boundingBox = polygon ? polygonToBoundingBox(Array.isArray(polygon) ? polygon : [polygon]) : null;
            if (!boundingBox) continue;

            // Case 1: pure digit string (1–8 digits) — direct match
            if (/^\d{1,8}$/.test(raw)) {
                candidates.push({ number: raw, confidence: line.confidence ?? 0.9, boundingBox });
                digitLines.push({ number: raw, confidence: line.confidence ?? 0.9, boundingBox });
                continue;
            }

            // Case 2: digits separated by spaces — large close-up sail numbers
            // e.g. Azure returns "1 2 3 4 5" for "12345" painted large on a sail
            const stripped = raw.replace(/\s+/g, '');
            if (/^\d{2,8}$/.test(stripped)) {
                candidates.push({ number: stripped, confidence: (line.confidence ?? 0.9) * 0.9, boundingBox });
                digitLines.push({ number: stripped, confidence: (line.confidence ?? 0.9) * 0.9, boundingBox });
            }
        }

        // Pass 2: merge pairs of spatially adjacent digit fragments into a longer number.
        // This handles large single-sail photos where one number is split across OCR lines.
        for (let i = 0; i < digitLines.length; i++) {
            for (let j = i + 1; j < digitLines.length; j++) {
                if (!areSailFragmentsNearby(digitLines[i].boundingBox, digitLines[j].boundingBox)) continue;
                // Try both orderings (left-to-right) based on X position
                const r1 = bbRect(digitLines[i].boundingBox), r2 = bbRect(digitLines[j].boundingBox);
                const [first, second] = r1.minX <= r2.minX ? [digitLines[i], digitLines[j]] : [digitLines[j], digitLines[i]];
                const merged = first.number + second.number;
                if (/^\d{2,8}$/.test(merged) && isValidSailNumber(merged)) {
                    candidates.push({
                        number: merged,
                        confidence: Math.min(first.confidence, second.confidence) * 0.95,
                        boundingBox: mergeBoundingBoxes(first.boundingBox, second.boundingBox)
                    });
                }
            }
        }
    }

    // Deduplicate: keep highest-confidence entry per unique number
    const seen = new Map();
    for (const c of candidates) {
        if (!seen.has(c.number) || (seen.get(c.number).confidence < c.confidence)) {
            seen.set(c.number, c);
        }
    }
    const deduped = Array.from(seen.values());

    // Prefer valid sail numbers (2–8 digits, range 10–999999), then any digit line; sort by confidence
    const valid = deduped.filter((c) => isValidSailNumber(c.number));
    const rest  = deduped.filter((c) => !isValidSailNumber(c.number));
    return [...valid.sort((a, b) => (b.confidence || 0) - (a.confidence || 0)), ...rest.sort((a, b) => (b.confidence || 0) - (a.confidence || 0))];
}

// Helper function to group nearby lines
function groupNearbyLines(lines) {
    const groups = [];
    const used = new Set();

    lines.forEach((line, i) => {
        if (used.has(i)) return;

        const group = [line];
        used.add(i);

        // Look for nearby lines
        lines.forEach((otherLine, j) => {
            if (i !== j && !used.has(j) && areLinesNearby(line, otherLine)) {
                group.push(otherLine);
                used.add(j);
            }
        });

        groups.push(group);
    });

    return groups;
}

// Helper function to check if lines are nearby
function areLinesNearby(line1, line2) {
    const box1 = line1.boundingBox;
    const box2 = line2.boundingBox;

    // Calculate centers
    const center1Y = (box1[1] + box1[5]) / 2;
    const center2Y = (box2[1] + box2[5]) / 2;

    // Check vertical distance
    const verticalDistance = Math.abs(center1Y - center2Y);
    const averageHeight = (box1[5] - box1[1] + box2[5] - box2[1]) / 2;

    // Lines are nearby if they're within 1.5x the average height
    return verticalDistance < averageHeight * 1.5;
}

// Helper function to extract sail numbers from Azure results
function extractSailNumbers(azureResults) {
    const numbers = [];

    if (azureResults && azureResults.readResults) {
        for (const page of azureResults.readResults) {
            for (const line of page.lines) {
                // Check if the text matches a sail number pattern (1-6 digits)
                const text = line.text.trim();
                if (/^\d{1,6}$/.test(text)) {
                    numbers.push({
                        number: text,
                        confidence: line.words[0].confidence,
                        boundingBox: line.boundingBox
                    });
                }
            }
        }
    }
    return numbers;
}

// Helper function to create a filename-safe string
function sanitizeForFilename(str) {
    return str.replace(/[^a-zA-Z0-9]/g, '');
}

// Helper function to validate sail numbers
function isValidSailNumber(number) {
    const num = parseInt(number);
    // Typical sail number ranges; allow up to 8 digits for large-class boats
    return num >= 10 && num <= 99999999 &&
        number.length >= 2 && number.length <= 8;
}

// Helper function to calculate group bounding box
function calculateGroupBox(group) {
    let minX = Infinity, minY = Infinity;
    let maxX = -Infinity, maxY = -Infinity;

    group.forEach(line => {
        const box = line.boundingBox;
        minX = Math.min(minX, box[0], box[2], box[4], box[6]);
        minY = Math.min(minY, box[1], box[3], box[5], box[7]);
        maxX = Math.max(maxX, box[0], box[2], box[4], box[6]);
        maxY = Math.max(maxY, box[1], box[3], box[5], box[7]);
    });

    return {
        x: minX,
        y: minY,
        width: maxX - minX,
        height: maxY - minY
    };
}

// Make database connection more resilient
pool.on('error', (err) => {
    console.error('Unexpected database error:', err);
});

// Add more detailed health check
app.get('/health', (req, res) => {
    pool.query('SELECT NOW()')
        .then(() => {
            res.json({
                status: 'ok',
                timestamp: new Date().toISOString(),
                database: 'connected'
            });
        })
        .catch(err => {
            res.status(500).json({
                status: 'error',
                error: err.message,
                timestamp: new Date().toISOString()
            });
        });
});

// Add route to serve results page
app.get('/results', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'results.html'));
});

// Add route to serve PhotoAdmin page
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'photoAdmin.html'));
});

// Add this helper function to look up skipper info
async function lookupSailorInDatabase(sailNumber) {
    try {
        console.log(`Looking up sailor for number: ${sailNumber}`);

        const query = `
            SELECT "Sail_Number", "Boat_Name"
            FROM imported_data 
            WHERE "Sail_Number" = $1 
            LIMIT 1
        `;

        const result = await pool.query(query, [sailNumber]);
        if (result.rows && result.rows.length > 0) {
            console.log(`Found sailor for sail number ${sailNumber}:`, result.rows[0]);
            return {
                sailNumber: result.rows[0].Sail_Number,
                sailorName: result.rows[0].Boat_Name // Using Boat_Name as sailor name
            };
        }
        console.log(`No sailor found for sail number ${sailNumber}`);
        return null;
    } catch (err) {
        console.error(`Database lookup error for sail number ${sailNumber}:`, err);
        return null;
    }
}

// Add route to serve test page
app.get('/test', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'test.html'));
});

// Add this endpoint to expose the publishable key
app.get('/api/config', (req, res) => {
    res.json({
        stripePublishableKey: process.env.STRIPE_PUBLISHABLE_KEY
    });
});

// Add endpoint to get scan history
app.get('/api/scans', async (req, res) => {
    try {
        console.log('Fetching scan history...');
        const result = await pool.query(`
            SELECT 
                id,
                sail_number,
                confidence::float,
                scan_time,
                status,
                skipper_name,
                boat_name,
                yacht_club
            FROM scan_results 
            ORDER BY scan_time DESC 
            LIMIT 100
        `);
        console.log('Found scan results:', result.rows.length);

        // Format the data
        const formattedResults = result.rows.map(row => ({
            ...row,
            scan_time: row.scan_time.toISOString(),
            confidence: parseFloat(row.confidence)
        }));

        res.json(formattedResults);
    } catch (err) {
        console.error('Error fetching scan history:', err);
        res.status(500).json({ error: 'Failed to fetch scan history' });
    }
});

// Helper function to wait for rate limit
async function waitForRateLimit() {
    const now = Date.now();
    const timeSinceLastCall = now - lastAzureCallTime;

    if (timeSinceLastCall < RATE_LIMIT_DELAY) {
        const waitTime = RATE_LIMIT_DELAY - timeSinceLastCall;
        console.log(`Rate limit cooling down. Waiting ${waitTime / 1000} seconds...`);
        await new Promise(resolve => setTimeout(resolve, waitTime));
    }
    lastAzureCallTime = Date.now();
}

// Update your processImage function
async function processImage(file) {
    console.log('=== Starting New Scan ===');
    console.log('Processing file:', file.originalname);

    try {
        // Ensure directories exist
        await fsPromises.mkdir(UPLOAD_DIR, { recursive: true });
        await fsPromises.mkdir(PROCESSED_DIR, { recursive: true });

        // Wrap Azure API call in retry logic
        const azureResults = await processWithRetry(
            () => computerVisionClient.readInStream(
                file.buffer,
                { language: 'en' }
            ),
            'Azure Vision API call'
        );

        let operationId = azureResults.operationLocation.split('/').pop();
        let results;

        // Wrap the results polling in retry logic
        results = await processWithRetry(
            async () => {
                let attempts = 0;
                while (attempts < 30) {
                    attempts++;
                    console.log(`Checking Azure results - Attempt ${attempts}...`);

                    const getResults = await computerVisionClient.getReadResult(operationId);

                    if (getResults.status === 'succeeded') {
                        console.log('Azure processing completed successfully!');
                        return getResults;
                    } else if (getResults.status === 'failed') {
                        throw new Error('Azure processing failed');
                    }

                    console.log(`Status: ${getResults.status}`);
                    console.log('Waiting 1000ms before next check...');
                    await new Promise(resolve => setTimeout(resolve, 1000));
                }
                throw new Error('Timeout waiting for Azure processing');
            },
            'Azure Results Polling'
        );

        const processedFiles = [];

        // Process each detected sail number
        for (const sailData of results.analyzeResult.readResults) {
            try {
                let sailorName = 'NONAME';
                if (sailData.lines.length > 0) {
                    const text = sailData.lines[0].text.trim();
                    if (isValidSailNumber(text)) {
                        sailorName = text.substring(0, 30);
                    }
                }

                const newFilename = `${sailData.number}_${sailorName}_${file.originalname}`;
                const originalPath = path.join(UPLOAD_DIR, file.filename);
                const newPath = path.join(PROCESSED_DIR, newFilename);

                // Log paths for debugging
                console.log('Original path:', originalPath);
                console.log('New path:', newPath);

                // Copy file
                await fsPromises.copyFile(originalPath, newPath);
                console.log(`Successfully created file: ${newFilename}`);

                processedFiles.push({
                    originalFilename: file.originalname,
                    newFilename: newFilename,
                    downloadUrl: `/processed-images/${newFilename}`,
                    sailNumber: sailData.number,
                    sailorName: sailorName
                });
            } catch (fileErr) {
                console.error(`Error creating file for sail number ${sailData.number}:`, fileErr);
            }
        }

        return {
            success: true,
            sailNumbers: results.analyzeResult.readResults.map(r => ({
                number: r.number,
                confidence: r.confidence,
                boundingBox: r.boundingBox
            })),
            processedFiles: processedFiles,
            debug: {
                azureResponse: results.analyzeResult,
                processingTime: `${results.analyzeResult.readResults.length} seconds`
            }
        };

    } catch (err) {
        console.error('Error during scan:', err);
        throw err;
    }
}

// Update your batch processing logic
async function processBatch(files) {
    const results = [];

    for (const file of files) {
        try {
            const result = await processImage(file);
            results.push({
                file: file.originalname,
                success: true,
                ...result
            });
        } catch (err) {
            console.error(`Error processing ${file.originalname}:`, err);
            results.push({
                file: file.originalname,
                success: false,
                error: err.message
            });

            // If it's a rate limit error, wait before continuing
            if (err.message && err.message.includes('rate limit')) {
                await new Promise(resolve => setTimeout(resolve, RATE_LIMIT_DELAY));
            }
        }
    }

    return results;
}

// For batch uploads, clean up before processing the batch
app.post('/api/batch-scan', upload.array('images'), async (req, res) => {
    try {
        // Only clean up upload directory, not processed files
        await cleanupDirectories(false);

        const results = await processBatch(req.files);
        res.json({
            success: true,
            results: results
        });
    } catch (err) {
        console.error('Error during batch scan:', err);
        res.status(500).json({ success: false, error: err.message });
    }
});

// Add a cleanup endpoint that can be called manually if needed
app.post('/api/cleanup', async (req, res) => {
    try {
        // Only clean up upload directory, not processed files
        await cleanupDirectories(false);
        res.json({ success: true, message: 'Cleanup completed successfully' });
    } catch (err) {
        console.error('Error during cleanup:', err);
        res.status(500).json({ success: false, error: err.message });
    }
});

// Add a separate endpoint for cleaning up processed files
app.post('/api/cleanup-processed', async (req, res) => {
    try {
        // Clean up both upload and processed directories
        await cleanupDirectories(true);
        res.json({ success: true, message: 'Processed files cleanup completed successfully' });
    } catch (err) {
        console.error('Error during processed files cleanup:', err);
        res.status(500).json({ success: false, error: err.message });
    }
});

// Update the download endpoint to serve files from the processed-images directory
app.get('/processed-images/:filename', async (req, res) => {
    try {
        const filename = req.params.filename;
        const filePath = path.join(PROCESSED_DIR, filename);

        // Check if file exists before trying to download
        try {
            const stats = await fsPromises.stat(filePath);
            console.log(`File found. Size: ${stats.size} bytes`);

            if (stats.size === 0) {
                console.error('File exists but is empty');
                return res.status(500).send('File exists but is empty');
            }

            // Use sendFile instead of download for more reliable behavior
            res.sendFile(filePath, (err) => {
                if (err) {
                    console.error(`Error during download: ${err.message}`);
                    // Only send error if headers not sent yet
                    if (!res.headersSent) {
                        res.status(500).send(`Error downloading file: ${err.message}`);
                    }
                } else {
                    console.log(`File ${filename} sent successfully`);
                }
            });
        } catch (err) {
            console.error(`File not found: ${filePath}`);
            console.error(`Error details: ${err.message}`);
            res.status(404).send(`File not found: ${filename}`);
        }
    } catch (err) {
        console.error('Download error:', err);
        res.status(500).send(`Error processing download request: ${err.message}`);
    }
});

// Add endpoint to clear sail numbers
app.post('/api/numbers/clear', async (req, res) => {
    try {
        console.log('Request to clear sail numbers from database received');

        // Delete all records from the sail_numbers table
        const result = await pool.query('DELETE FROM sail_numbers');

        console.log(`Cleared ${result.rowCount} sail number records from database`);

        res.json({
            success: true,
            message: 'All sail numbers cleared successfully',
            recordsDeleted: result.rowCount
        });
    } catch (err) {
        console.error('Error clearing sail numbers from database:', err);
        res.status(500).json({
            success: false,
            error: 'Failed to clear sail numbers from database'
        });
    }
});

// Add new search endpoint
app.get('/api/search-photos', async (req, res) => {
    try {
        const {
            sail_number,
            date,
            regatta_name,
            photographer_name,
            location,
            photo_timestamp_start,
            photo_timestamp_end,
            gps_latitude,
            gps_longitude,
            radius_km,
            device_fingerprint,
            device_type
        } = req.query;

        let query = `
            SELECT * FROM photo_metadata 
            WHERE 1=1
        `;
        const params = [];
        let paramCount = 1;

        if (sail_number) {
            query += ` AND (
                sail_number = $${paramCount}
                OR EXISTS (
                    SELECT 1 FROM jsonb_array_elements(COALESCE(sail_numbers, '[]'::jsonb)) AS elem
                    WHERE elem->>'number' = $${paramCount}
                )
            )`;
            params.push(sail_number);
            paramCount++;
        }
        if (date) {
            query += ` AND date = $${paramCount}`;
            params.push(date);
            paramCount++;
        }
        if (regatta_name) {
            query += ` AND regatta_name ILIKE $${paramCount}`;
            params.push(`%${regatta_name}%`);
            paramCount++;
        }
        if (photographer_name) {
            query += ` AND photographer_name ILIKE $${paramCount}`;
            params.push(`%${photographer_name}%`);
            paramCount++;
        }
        if (location) {
            query += ` AND location ILIKE $${paramCount}`;
            params.push(`%${location}%`);
            paramCount++;
        }
        if (photo_timestamp_start) {
            query += ` AND photo_timestamp >= $${paramCount}`;
            params.push(photo_timestamp_start);
            paramCount++;
        }
        if (photo_timestamp_end) {
            query += ` AND photo_timestamp <= $${paramCount}`;
            params.push(photo_timestamp_end);
            paramCount++;
        }
        if (gps_latitude && gps_longitude && radius_km) {
            // Search within radius using Haversine formula
            query += ` AND (
                6371 * acos(
                    cos(radians($${paramCount})) * cos(radians(gps_latitude)) * 
                    cos(radians(gps_longitude) - radians($${paramCount + 1})) + 
                    sin(radians($${paramCount})) * sin(radians(gps_latitude))
                ) <= $${paramCount + 2}
            )`;
            params.push(parseFloat(gps_latitude), parseFloat(gps_longitude), parseFloat(radius_km));
            paramCount += 3;
        }
        if (device_fingerprint) {
            query += ` AND device_fingerprint = $${paramCount}`;
            params.push(device_fingerprint);
            paramCount++;
        }
        if (device_type) {
            query += ` AND device_type = $${paramCount}`;
            params.push(device_type);
            paramCount++;
        }

        query += ` ORDER BY created_at DESC`;

        const result = await pool.query(query, params);

        // Generate signed URLs for each photo
        const photosWithUrls = await Promise.all(result.rows.map(async (photo) => {
            try {
                const s3Key = `processed/${photo.filename}`;
                const signedUrl = await getS3SignedUrl(s3Key);
                return {
                    ...photo,
                    url: signedUrl
                };
            } catch (err) {
                console.error(`Error generating signed URL for ${photo.filename}:`, err);
                return {
                    ...photo,
                    url: null,
                    error: 'Unable to generate photo URL'
                };
            }
        }));

        res.json(photosWithUrls);
    } catch (err) {
        console.error('Error searching photos:', err);
        res.status(500).json({ error: err.message });
    }
});

// Add sail numbers to a photo (admin)
app.patch('/api/photos/:id/sail-numbers', async (req, res) => {
    try {
        const photoId = parseInt(req.params.id, 10);
        if (isNaN(photoId)) {
            return res.status(400).json({ success: false, error: 'Invalid photo ID' });
        }
        const { additionalSailNumbers } = req.body || {};
        if (!Array.isArray(additionalSailNumbers) || additionalSailNumbers.length === 0) {
            return res.status(400).json({ success: false, error: 'additionalSailNumbers array is required' });
        }
        const numbers = additionalSailNumbers
            .map(n => String(n).trim())
            .filter(n => n.length > 0);
        if (numbers.length === 0) {
            return res.status(400).json({ success: false, error: 'At least one sail number is required' });
        }

        const current = await pool.query(
            'SELECT sail_number, sail_numbers FROM photo_metadata WHERE id = $1',
            [photoId]
        );
        if (current.rows.length === 0) {
            return res.status(404).json({ success: false, error: 'Photo not found' });
        }

        const existingArr = Array.isArray(current.rows[0].sail_numbers) ? current.rows[0].sail_numbers : [];
        const toObj = (e) => {
            if (!e) return null;
            const n = (typeof e === 'object' && e.number != null) ? e.number : e;
            return n != null ? { number: String(n), confidence: (e.confidence != null ? e.confidence : 1) } : null;
        };
        const existingNumbers = new Set(existingArr.map(e => {
            const n = e && (typeof e === 'object' ? e.number : e);
            return n != null ? String(n) : null;
        }).filter(Boolean));
        const merged = existingArr.map(toObj).filter(Boolean);
        for (const num of numbers) {
            const s = String(num);
            if (!existingNumbers.has(s)) {
                merged.push({ number: s, confidence: 1 });
                existingNumbers.add(s);
            }
        }

        await pool.query(
            `UPDATE photo_metadata SET sail_numbers = $1 WHERE id = $2`,
            [JSON.stringify(merged), photoId]
        );

        res.json({
            success: true,
            sail_numbers: merged,
            message: `Added ${numbers.length} sail number(s)`
        });
    } catch (err) {
        console.error('Error adding sail numbers:', err);
        res.status(500).json({ success: false, error: err.message });
    }
});

// Add new endpoint to get total photo count
app.get('/api/photo-count', async (req, res) => {
    try {
        const result = await pool.query('SELECT COUNT(*) as total FROM photo_metadata');
        res.json({ total: parseInt(result.rows[0].total) });
    } catch (err) {
        console.error('Error getting photo count:', err);
        res.status(500).json({ error: err.message });
    }
});

// Get distinct regatta names that have photos
app.get('/api/photo-regattas', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT DISTINCT regatta_name
            FROM photo_metadata
            WHERE regatta_name IS NOT NULL AND regatta_name <> ''
            ORDER BY regatta_name ASC
        `);
        const names = result.rows.map(r => r.regatta_name);
        res.json({ success: true, regattas: names });
    } catch (err) {
        console.error('Error fetching photo regattas:', err);
        res.status(500).json({ success: false, error: 'Error fetching regatta list' });
    }
});

// Get distinct locations that have photos
app.get('/api/photo-locations', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT DISTINCT location
            FROM photo_metadata
            WHERE location IS NOT NULL AND location <> ''
            ORDER BY location ASC
        `);
        const locations = result.rows.map(r => r.location);
        res.json({ success: true, locations });
    } catch (err) {
        console.error('Error fetching photo locations:', err);
        res.status(500).json({ success: false, error: 'Error fetching location list' });
    }
});

// Add endpoint to get most recent upload date
app.get('/api/recent-upload', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT created_at 
            FROM photo_metadata 
            ORDER BY created_at DESC 
            LIMIT 1
        `);

        const recentUpload = result.rows.length > 0 ? result.rows[0].created_at : null;
        res.json({ recentUpload });
    } catch (err) {
        console.error('Error fetching recent upload:', err);
        res.status(500).json({ error: 'Error fetching recent upload' });
    }
});

// Preview bulk photo metadata update by upload date (admin)
app.get('/api/photo-bulk-preview', async (req, res) => {
    try {
        const { upload_date } = req.query;

        if (!upload_date || !/^\d{4}-\d{2}-\d{2}$/.test(upload_date)) {
            return res.status(400).json({
                success: false,
                error: 'Invalid or missing upload_date. Expected format YYYY-MM-DD.'
            });
        }

        const MAX_BULK_UPDATE = 100;

        const result = await pool.query(
            `
            SELECT COUNT(*) AS total
            FROM photo_metadata
            WHERE upload_timestamp::date = $1
            `,
            [upload_date]
        );

        const total = parseInt(result.rows[0].total, 10) || 0;
        const affected = Math.min(total, MAX_BULK_UPDATE);

        res.json({
            success: true,
            total,
            affected,
            capped: total > MAX_BULK_UPDATE,
            maxLimit: MAX_BULK_UPDATE
        });
    } catch (err) {
        console.error('Error in photo bulk preview:', err);
        res.status(500).json({
            success: false,
            error: 'Error generating bulk preview'
        });
    }
});

// Apply bulk photo metadata update by upload date (admin)
app.post('/api/photo-bulk-update', async (req, res) => {
    try {
        const { upload_date, regatta_name, location, date, limit } = req.body || {};

        if (!upload_date || !/^\d{4}-\d{2}-\d{2}$/.test(upload_date)) {
            return res.status(400).json({
                success: false,
                error: 'Invalid or missing upload_date. Expected format YYYY-MM-DD.'
            });
        }

        const updates = [];
        const params = [];
        let paramIndex = 1;

        if (regatta_name && regatta_name.trim() !== '') {
            updates.push(`regatta_name = $${paramIndex++}`);
            params.push(regatta_name.trim());
        }
        if (location && location.trim() !== '') {
            updates.push(`location = $${paramIndex++}`);
            params.push(location.trim());
        }
        if (date && date.trim() !== '') {
            updates.push(`date = $${paramIndex++}`);
            params.push(date.trim());
        }

        if (updates.length === 0) {
            return res.status(400).json({
                success: false,
                error: 'No fields provided to update. Provide at least one of regatta_name, location, or date.'
            });
        }

        const MAX_BULK_UPDATE = 100;
        let rawLimit;
        if (typeof limit === 'number') {
            rawLimit = limit;
        } else if (typeof limit === 'string') {
            rawLimit = parseInt(limit, 10);
        }
        if (!rawLimit || rawLimit <= 0 || Number.isNaN(rawLimit)) {
            rawLimit = MAX_BULK_UPDATE;
        }
        const effectiveLimit = Math.min(rawLimit, MAX_BULK_UPDATE);

        // upload_date parameter index
        const uploadDateParamIndex = paramIndex;
        params.push(upload_date);
        paramIndex++;

        // limit parameter index
        const limitParamIndex = paramIndex;
        params.push(effectiveLimit);

        const query = `
            UPDATE photo_metadata
            SET ${updates.join(', ')}
            WHERE id IN (
                SELECT id
                FROM photo_metadata
                WHERE upload_timestamp::date = $${uploadDateParamIndex}
                ORDER BY upload_timestamp ASC, id ASC
                LIMIT $${limitParamIndex}
            )
            RETURNING id
        `;

        const result = await pool.query(query, params);

        res.json({
            success: true,
            updatedCount: result.rowCount,
            maxLimit: MAX_BULK_UPDATE
        });
    } catch (err) {
        console.error('Error in photo bulk update:', err);
        res.status(500).json({
            success: false,
            error: 'Error applying bulk update'
        });
    }
});

// Preview rescan by upload date (distinct original photos by file_checksum)
app.get('/api/photo-rescan-preview', async (req, res) => {
    try {
        const { upload_date } = req.query;

        if (!upload_date || !/^\d{4}-\d{2}-\d{2}$/.test(upload_date)) {
            return res.status(400).json({
                success: false,
                error: 'Invalid or missing upload_date. Expected format YYYY-MM-DD.'
            });
        }

        const result = await pool.query(
            `
            SELECT COUNT(DISTINCT file_checksum) AS total_originals
            FROM photo_metadata
            WHERE upload_timestamp::date = $1
              AND file_checksum IS NOT NULL
            `,
            [upload_date]
        );

        const totalOriginals = parseInt(result.rows[0].total_originals, 10) || 0;

        res.json({
            success: true,
            totalOriginals
        });
    } catch (err) {
        console.error('Error in photo rescan preview:', err);
        res.status(500).json({
            success: false,
            error: 'Error generating rescan preview'
        });
    }
});

// List originals eligible for rescan by upload date
app.get('/api/photo-rescan-list', async (req, res) => {
    try {
        const { upload_date } = req.query;

        if (!upload_date || !/^\d{4}-\d{2}-\d{2}$/.test(upload_date)) {
            return res.status(400).json({
                success: false,
                error: 'Invalid or missing upload_date. Expected format YYYY-MM-DD.'
            });
        }

        const result = await pool.query(
            `
            SELECT 
                file_checksum,
                MIN(filename) AS filename,
                COUNT(DISTINCT sail_number) FILTER (WHERE sail_number IS NOT NULL AND sail_number <> 'NOSAIL') AS sail_count,
                MIN(upload_timestamp) AS upload_timestamp,
                MIN(location) AS location,
                MIN(regatta_name) AS regatta_name
            FROM photo_metadata
            WHERE upload_timestamp::date = $1
              AND file_checksum IS NOT NULL
            GROUP BY file_checksum
            ORDER BY MIN(upload_timestamp) ASC
            `,
            [upload_date]
        );

        const rows = result.rows || [];

        // Attach a signed URL for a representative processed image for each original
        const originalsWithUrls = await Promise.all(
            rows.map(async (row) => {
                const s3Key = row.filename ? `processed/${row.filename}` : null;
                let url = null;
                if (s3Key) {
                    try {
                        url = await getS3SignedUrl(s3Key);
                    } catch (err) {
                        console.error(`Error generating signed URL for rescan list item ${row.filename}:`, err);
                    }
                }

                return {
                    file_checksum: row.file_checksum,
                    filename: row.filename,
                    sail_count: parseInt(row.sail_count, 10) || 0,
                    upload_timestamp: row.upload_timestamp,
                    location: row.location,
                    regatta_name: row.regatta_name,
                    url
                };
            })
        );

        res.json({
            success: true,
            originals: originalsWithUrls
        });
    } catch (err) {
        console.error('Error in photo rescan list:', err);
        res.status(500).json({
            success: false,
            error: 'Error loading rescan list'
        });
    }
});

// Apply rescan by upload date or explicit selection: keep existing sail numbers, add only newly found ones
app.post('/api/photo-rescan', async (req, res) => {
    try {
        const { upload_date, limit, selected_checksums } = req.body || {};

        if (!upload_date || !/^\d{4}-\d{2}-\d{2}$/.test(upload_date)) {
            return res.status(400).json({
                success: false,
                error: 'Invalid or missing upload_date. Expected format YYYY-MM-DD.'
            });
        }

        // Normalize selected_checksums if provided
        let checksumList = Array.isArray(selected_checksums)
            ? selected_checksums
                  .map((c) => (typeof c === 'string' ? c.trim() : ''))
                  .filter((c) => c.length > 0)
            : [];

        let originalsResult;

        if (checksumList.length > 0) {
            // Rescan only explicitly selected originals
            originalsResult = await pool.query(
                `
                SELECT 
                    file_checksum,
                    MIN(filename) AS filename,
                    MIN(date) AS date,
                    MIN(regatta_name) AS regatta_name,
                    MIN(photographer_name) AS photographer_name,
                    MIN(photographer_website) AS photographer_website,
                    MIN(location) AS location,
                    MIN(photo_timestamp) AS photo_timestamp,
                    MIN(gps_latitude) AS gps_latitude,
                    MIN(gps_longitude) AS gps_longitude,
                    MIN(gps_altitude) AS gps_altitude,
                    MIN(device_fingerprint) AS device_fingerprint,
                    MIN(device_type) AS device_type,
                    MIN(user_agent) AS user_agent,
                    MIN(screen_resolution) AS screen_resolution,
                    MIN(timezone) AS timezone,
                    MIN(upload_timestamp) AS upload_timestamp
                FROM photo_metadata
                WHERE upload_timestamp::date = $1
                  AND file_checksum = ANY($2::text[])
                GROUP BY file_checksum
                ORDER BY MIN(upload_timestamp) ASC
                `,
                [upload_date, checksumList]
            );
        } else {
            // Original behavior: rescan by upload date (no artificial cap)
            originalsResult = await pool.query(
                `
                SELECT 
                    file_checksum,
                    MIN(filename) AS filename,
                    MIN(date) AS date,
                    MIN(regatta_name) AS regatta_name,
                    MIN(photographer_name) AS photographer_name,
                    MIN(photographer_website) AS photographer_website,
                    MIN(location) AS location,
                    MIN(photo_timestamp) AS photo_timestamp,
                    MIN(gps_latitude) AS gps_latitude,
                    MIN(gps_longitude) AS gps_longitude,
                    MIN(gps_altitude) AS gps_altitude,
                    MIN(device_fingerprint) AS device_fingerprint,
                    MIN(device_type) AS device_type,
                    MIN(user_agent) AS user_agent,
                    MIN(screen_resolution) AS screen_resolution,
                    MIN(timezone) AS timezone,
                    MIN(upload_timestamp) AS upload_timestamp
                FROM photo_metadata
                WHERE upload_timestamp::date = $1
                  AND file_checksum IS NOT NULL
                GROUP BY file_checksum
                ORDER BY MIN(upload_timestamp) ASC
                `,
                [upload_date]
            );
        }

        if (originalsResult.rows.length === 0) {
            return res.json({
                success: true,
                analyzedOriginals: 0,
                newSailNumbers: 0,
                maxLimit: MAX_RESCAN_LIMIT
            });
        }

        let analyzedOriginals = 0;
        let newSailNumbers = 0;

        for (const original of originalsResult.rows) {
            analyzedOriginals++;

            const {
                file_checksum,
                filename,
                date,
                regatta_name,
                photographer_name,
                photographer_website,
                location,
                photo_timestamp,
                gps_latitude,
                gps_longitude,
                gps_altitude,
                device_fingerprint,
                device_type,
                user_agent,
                screen_resolution,
                timezone,
                upload_timestamp
            } = original;

            if (!file_checksum || !filename) {
                continue;
            }

            try {
                // Get existing sail numbers for this original image
                const existingResult = await pool.query(
                    `
                    SELECT DISTINCT sail_number
                    FROM photo_metadata
                    WHERE file_checksum = $1
                      AND sail_number IS NOT NULL
                      AND sail_number <> 'NOSAIL'
                    `,
                    [file_checksum]
                );

                const existingNumbers = new Set(
                    existingResult.rows
                        .map((r) => r.sail_number)
                        .filter((n) => n && n !== 'NOSAIL')
                );

                // Download one of the processed images (they all come from the same original)
                const processedKey = `processed/${filename}`;
                const { buffer: imageBuffer, contentType } = await downloadS3ObjectToBuffer(processedKey);

                // Re-run Azure OCR on this image
                const detectedNumbers = await analyzeImageWithAzure(imageBuffer);

                if (!detectedNumbers || detectedNumbers.length === 0) {
                    continue;
                }

                // Only keep sail numbers that are not already stored
                const newNumbers = detectedNumbers.filter(
                    (sailData) => sailData && sailData.number && !existingNumbers.has(String(sailData.number))
                );

                if (newNumbers.length === 0) {
                    continue;
                }

                // Derive original filename from processed filename: NUMBER_SAILORNAME_originalFilename
                let originalFilename = filename;
                const parts = filename.split('_');
                if (parts.length >= 3) {
                    originalFilename = parts.slice(2).join('_');
                }

                for (const sailData of newNumbers) {
                    try {
                        const sailNumber = String(sailData.number);

                        // Double-check against existing numbers in case of race conditions
                        if (existingNumbers.has(sailNumber)) {
                            continue;
                        }

                        const sailorInfo = await lookupSailorInDatabase(sailNumber);
                        const sailorName = sailorInfo ? sanitizeForFilename(sailorInfo.sailorName) : 'NONAME';
                        const newFilename = `${sailNumber}_${sailorName}_${originalFilename}`;
                        const newS3Key = `processed/${newFilename}`;

                        // Upload a new processed image entry (same pixels, new logical photo for that sail)
                        await uploadToS3(imageBuffer, newS3Key, contentType || 'image/jpeg');

                        // Store metadata row for this new sail number
                        await pool.query(
                            `
                            INSERT INTO photo_metadata (
                                filename, sail_number, date, regatta_name,
                                photographer_name, photographer_website,
                                location, additional_tags, file_checksum, photo_timestamp,
                                gps_latitude, gps_longitude, gps_altitude,
                                device_fingerprint, device_type, user_agent,
                                screen_resolution, timezone, upload_timestamp
                            ) VALUES (
                                $1, $2, $3, $4,
                                $5, $6,
                                $7, $8, $9, $10,
                                $11, $12, $13,
                                $14, $15, $16,
                                $17, $18, $19
                            )
                            `,
                            [
                                newFilename,
                                sailNumber,
                                date || null,
                                regatta_name || null,
                                photographer_name || null,
                                photographer_website || null,
                                location || null,
                                [], // additional_tags
                                file_checksum,
                                photo_timestamp || null,
                                gps_latitude || null,
                                gps_longitude || null,
                                gps_altitude || null,
                                device_fingerprint || null,
                                device_type || null,
                                user_agent || null,
                                screen_resolution || null,
                                timezone || null,
                                upload_timestamp || new Date().toISOString()
                            ]
                        );

                        existingNumbers.add(sailNumber);
                        newSailNumbers++;
                    } catch (singleErr) {
                        console.error('Error storing new sail number during rescan:', singleErr);
                    }
                }
            } catch (originalErr) {
                console.error('Error during rescan for original image:', originalErr);
            }
        }

        res.json({
            success: true,
            analyzedOriginals,
            newSailNumbers
        });
    } catch (err) {
        console.error('Error in photo rescan:', err);
        res.status(500).json({
            success: false,
            error: 'Error applying rescan'
        });
    }
});

// Add endpoint to get total storage size
app.get('/api/storage-size', async (req, res) => {
    try {
        // Get all objects from S3 processed folder
        const objects = await listS3Objects('processed/');

        let totalSize = 0;
        for (const obj of objects) {
            totalSize += obj.Size || 0;
        }

        res.json({ totalSize });
    } catch (err) {
        console.error('Error calculating storage size:', err);
        res.status(500).json({ error: 'Error calculating storage size' });
    }
});

// Add endpoint to get S3 count
app.get('/api/s3-count', async (req, res) => {
    try {
        const objects = await listS3Objects('processed/');
        res.json({ count: objects.length });
    } catch (err) {
        console.error('Error counting S3 objects:', err);
        res.status(500).json({ error: 'Error counting S3 objects' });
    }
});

// Add endpoint to get unique device fingerprints
app.get('/api/device-fingerprints', async (req, res) => {
    try {
        // First, let's check if we have any photos with device fingerprints
        const checkResult = await pool.query(`
            SELECT COUNT(*) as total_photos, 
                   COUNT(device_fingerprint) as photos_with_fingerprint
            FROM photo_metadata
        `);

        console.log('Device fingerprint check:', checkResult.rows[0]);

        const result = await pool.query(`
            SELECT DISTINCT 
                device_fingerprint,
                device_type,
                user_agent,
                screen_resolution,
                timezone,
                COUNT(*) as photo_count,
                MIN(upload_timestamp) as first_upload,
                MAX(upload_timestamp) as last_upload
            FROM photo_metadata 
            WHERE device_fingerprint IS NOT NULL 
            GROUP BY device_fingerprint, device_type, user_agent, screen_resolution, timezone
            ORDER BY photo_count DESC, last_upload DESC
        `);

        console.log(`Found ${result.rows.length} unique device fingerprints`);

        res.json({
            fingerprints: result.rows,
            total: result.rows.length,
            debug: {
                total_photos: checkResult.rows[0].total_photos,
                photos_with_fingerprint: checkResult.rows[0].photos_with_fingerprint
            }
        });
    } catch (err) {
        console.error('Error fetching device fingerprints:', err);
        res.status(500).json({ error: err.message });
    }
});

// Add a simple test endpoint for PhotoAdmin debugging
app.get('/api/admin-test', async (req, res) => {
    try {
        res.json({
            success: true,
            message: 'PhotoAdmin API is working',
            timestamp: new Date().toISOString(),
            databaseConnected: !!pool,
            s3Configured: !!(process.env.AWS_ACCESS_KEY && process.env.AWS_SECRET_ACCESS_KEY)
        });
    } catch (error) {
        console.error('Error in admin-test endpoint:', error);
        res.status(500).json({ error: error.message });
    }
});

// Update the validate-files endpoint to check S3
app.get('/api/validate-files', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM photo_metadata');
        const photos = result.rows;

        const results = [];
        let orphanedCount = 0;

        for (const photo of photos) {
            try {
                // Check if file exists in S3
                const s3Key = `processed/${photo.filename}`;
                const command = new GetObjectCommand({
                    Bucket: BUCKET_NAME,
                    Key: s3Key
                });

                try {
                    await s3Client.send(command);
                    results.push({
                        filename: photo.filename,
                        status: 'success',
                        message: 'File exists in S3',
                        storage: 'S3'
                    });
                } catch (s3Err) {
                    if (s3Err.name === 'NoSuchKey') {
                        results.push({
                            filename: photo.filename,
                            status: 'error',
                            message: 'File not found in S3',
                            storage: 'S3'
                        });
                        orphanedCount++;
                    } else {
                        results.push({
                            filename: photo.filename,
                            status: 'error',
                            message: `Error checking S3: ${s3Err.message}`,
                            storage: 'S3'
                        });
                        orphanedCount++;
                    }
                }
            } catch (err) {
                results.push({
                    filename: photo.filename,
                    status: 'error',
                    message: `Error checking file: ${err.message}`,
                    storage: 'S3'
                });
                orphanedCount++;
            }
        }

        res.json({
            orphanedCount,
            results,
            storage: 'S3'
        });
    } catch (err) {
        console.error('Error validating files:', err);
        res.status(500).json({ error: 'Error validating files' });
    }
});

// Update the clean-orphaned endpoint
app.post('/api/clean-orphaned', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM photo_metadata');
        const photos = result.rows;
        let removedCount = 0;

        for (const photo of photos) {
            const filePath = path.join(PROCESSED_DIR, photo.filename);
            try {
                await fsPromises.stat(filePath);
            } catch (err) {
                if (err.code === 'ENOENT') {
                    await pool.query('DELETE FROM photo_metadata WHERE id = $1', [photo.id]);
                    removedCount++;
                }
            }
        }

        res.json({
            message: `Removed ${removedCount} orphaned database entries`,
            removedCount
        });
    } catch (err) {
        console.error('Error cleaning orphaned entries:', err);
        res.status(500).json({ error: 'Error cleaning orphaned entries' });
    }
});

app.get('/api/folder-count', async (req, res) => {
    try {
        const folder = req.query.folder;

        if (folder === 'uploads') {
            // For uploads, still check local directory
            const files = await fsPromises.readdir(UPLOAD_DIR);
            const validFiles = await Promise.all(
                files.map(async (file) => {
                    try {
                        const filePath = path.join(UPLOAD_DIR, file);
                        const stats = await fsPromises.stat(filePath);
                        return stats.isFile() && stats.size > 0;
                    } catch (err) {
                        console.error(`Error checking file ${file}:`, err);
                        return false;
                    }
                })
            );
            res.json({ count: validFiles.filter(Boolean).length });
        } else if (folder === 'processed') {
            // For processed files, check S3
            const objects = await listS3Objects('processed/');
            res.json({
                count: objects.length,
                storage: 'S3'  // Add this to indicate where files are stored
            });
        } else {
            return res.status(400).json({ error: 'Invalid folder specified' });
        }
    } catch (err) {
        console.error('Error counting files:', err);
        res.status(500).json({
            error: 'Error counting files',
            details: err.message
        });
    }
});

// Add clean-database endpoint
app.post('/api/clean-database', async (req, res) => {
    try {
        // Delete all records from photo_metadata table
        const result = await pool.query('DELETE FROM photo_metadata');

        res.json({
            success: true,
            message: `Successfully removed ${result.rowCount} entries from the database`,
            removedCount: result.rowCount
        });
    } catch (err) {
        console.error('Error cleaning database:', err);
        res.status(500).json({
            success: false,
            error: 'Error cleaning database',
            details: err.message
        });
    }
});

// Add clean-uploads endpoint
app.post('/api/clean-uploads', async (req, res) => {
    try {
        // Read all files in uploads directory
        const files = await fsPromises.readdir(UPLOAD_DIR);
        let removedCount = 0;

        // Delete each file
        for (const file of files) {
            try {
                const filePath = path.join(UPLOAD_DIR, file);
                await fsPromises.unlink(filePath);
                removedCount++;
            } catch (err) {
                console.error(`Error deleting file ${file}:`, err);
            }
        }

        res.json({
            success: true,
            message: `Successfully removed ${removedCount} files from uploads directory`,
            removedCount
        });
    } catch (err) {
        console.error('Error cleaning uploads directory:', err);
        res.status(500).json({
            success: false,
            error: 'Error cleaning uploads directory',
            details: err.message
        });
    }
});

// Add export-images endpoint
app.post('/api/export-images', async (req, res) => {
    try {
        // Create a zip file of all images
        const archiver = require('archiver');
        const archive = archiver('zip', {
            zlib: { level: 9 } // Sets the compression level
        });

        // Set the response headers
        res.attachment('exported_images.zip');
        archive.pipe(res);

        // Add all files from the processed directory
        const files = await fsPromises.readdir(PROCESSED_DIR);
        for (const file of files) {
            const filePath = path.join(PROCESSED_DIR, file);
            archive.file(filePath, { name: file });
        }

        // Finalize the archive
        await archive.finalize();
    } catch (err) {
        console.error('Error exporting images:', err);
        res.status(500).json({
            success: false,
            error: 'Error exporting images',
            details: err.message
        });
    }
});

// Add endpoint to get unique regatta names
app.get('/api/regatta-names', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT DISTINCT regatta_name 
            FROM photo_metadata 
            WHERE regatta_name IS NOT NULL 
            AND regatta_name != ''
            ORDER BY regatta_name
        `);

        const regattaNames = result.rows.map(row => row.regatta_name);
        res.json(regattaNames);
    } catch (err) {
        console.error('Error fetching regatta names:', err);
        res.status(500).json({ error: 'Error fetching regatta names' });
    }
});

// Add this after the createPhotoMetadataTable function
async function createUserTables() {
    try {
        // Create users table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Create purchased_images table instead of subscriptions
        await pool.query(`
            CREATE TABLE IF NOT EXISTS purchased_images (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                image_filename TEXT NOT NULL,
                stripe_payment_id TEXT,
                purchased_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        console.log('User and purchased images tables created or verified');
    } catch (err) {
        console.error('Error creating user tables:', err);
    }
}

// Create regattas table
async function createRegattasTable() {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS regattas (
                id SERIAL PRIMARY KEY,
                regatta_date DATE NOT NULL,
                regatta_name TEXT NOT NULL,
                location TEXT,
                event_website_url TEXT,
                registrants_url TEXT,
                registrant_count INTEGER,
                source TEXT NOT NULL,
                source_id TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(regatta_name, regatta_date, source)
            )
        `);

        // Create index for faster searches
        await pool.query(`
            CREATE INDEX IF NOT EXISTS idx_regattas_date ON regattas(regatta_date);
        `);
        await pool.query(`
            CREATE INDEX IF NOT EXISTS idx_regattas_name ON regattas(regatta_name);
        `);
        await pool.query(`
            CREATE INDEX IF NOT EXISTS idx_regattas_location ON regattas(location);
        `);
        await pool.query(`ALTER TABLE regattas ADD COLUMN IF NOT EXISTS registrant_count INTEGER;`);

        console.log('Regattas table created or verified');
    } catch (err) {
        console.error('Error creating regattas table:', err);
    }
}

// RegattaNetworkData: flattened regatta results for SailBot / ChatBot
// Use lowercase unquoted name so we hit the same table as other apps (e.g. external chatbot).
// Override with SAILBOT_TABLE if your data lives in a different table.
const REGATTA_NETWORK_DATA_TABLE = (() => {
    const env = process.env.SAILBOT_TABLE;
    if (env && /^[a-zA-Z0-9_]+$/.test(env)) return env.toLowerCase();
    return 'regattanetworkdata';
})();

async function ensureRegattaNetworkDataTable() {
    try {
        const createTable = !process.env.SAILBOT_TABLE;
        if (!createTable) {
            return; // use external table; do not create
        }
        await pool.query(`
            CREATE TABLE IF NOT EXISTS ${REGATTA_NETWORK_DATA_TABLE} (
                id SERIAL PRIMARY KEY,
                regatta_name TEXT,
                regatta_date DATE,
                category TEXT,
                position TEXT,
                sail_number TEXT,
                boat_name TEXT,
                skipper TEXT,
                yacht_club TEXT,
                results TEXT,
                total_points TEXT,
                dataset_id TEXT DEFAULT 'legacy'
            )
        `);
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_rnd_regatta_date ON ${REGATTA_NETWORK_DATA_TABLE}(regatta_date);`);
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_rnd_regatta_name ON ${REGATTA_NETWORK_DATA_TABLE}(regatta_name);`);
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_rnd_skipper ON ${REGATTA_NETWORK_DATA_TABLE}(skipper);`);
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_rnd_yacht_club ON ${REGATTA_NETWORK_DATA_TABLE}(yacht_club);`);
        await pool.query(`ALTER TABLE ${REGATTA_NETWORK_DATA_TABLE} ADD COLUMN IF NOT EXISTS source_url TEXT;`);
        console.log('regattanetworkdata table created or verified');
    } catch (err) {
        console.error('Error creating regattanetworkdata table:', err);
    }
}

// Add middleware for authentication
const authenticateToken = async (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Authentication required' });
    }

    try {
        const user = jwt.verify(token, process.env.JWT_SECRET);
        req.user = user;
        next();
    } catch (err) {
        return res.status(403).json({ error: 'Invalid token' });
    }
};

// Add authentication endpoints
app.post('/api/register', async (req, res) => {
    try {
        const { email, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);

        const result = await pool.query(
            'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id',
            [email, hashedPassword]
        );

        const token = jwt.sign({ userId: result.rows[0].id }, process.env.JWT_SECRET);
        res.json({ token });
    } catch (err) {
        res.status(500).json({ error: 'Error creating user' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const user = result.rows[0];
        const validPassword = await bcrypt.compare(password, user.password_hash);

        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET);
        res.json({ token });
    } catch (err) {
        res.status(500).json({ error: 'Error logging in' });
    }
});

// Replace subscription endpoints with per-image purchase endpoints
app.post('/api/create-payment-session', authenticateToken, async (req, res) => {
    try {
        const { imageFilename } = req.body;

        if (!imageFilename) {
            return res.status(400).json({ error: 'Image filename is required' });
        }

        // Check if user has already purchased this image
        const existingPurchase = await pool.query(
            'SELECT * FROM purchased_images WHERE user_id = $1 AND image_filename = $2',
            [req.user.userId, imageFilename]
        );

        if (existingPurchase.rows.length > 0) {
            return res.status(400).json({ error: 'Image already purchased' });
        }

        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            line_items: [
                {
                    price_data: {
                        currency: 'usd',
                        product_data: {
                            name: 'Photo Watermark Removal',
                            description: `Remove watermark from ${imageFilename}`
                        },
                        unit_amount: 500, // $5.00 in cents
                    },
                    quantity: 1,
                },
            ],
            mode: 'payment',
            success_url: `${req.headers.origin}/payment-success?session_id={CHECKOUT_SESSION_ID}&image=${encodeURIComponent(imageFilename)}`,
            cancel_url: `${req.headers.origin}/payment-cancelled`,
            metadata: {
                userId: req.user.userId,
                imageFilename: imageFilename
            }
        });

        res.json({ url: session.url });
    } catch (err) {
        console.error('Error creating payment session:', err);
        res.status(500).json({ error: 'Error creating payment session' });
    }
});

// Add endpoint to check if an image is purchased
app.get('/api/check-image-purchase/:filename', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM purchased_images WHERE user_id = $1 AND image_filename = $2',
            [req.user.userId, req.params.filename]
        );

        res.json({ isPurchased: result.rows.length > 0 });
    } catch (err) {
        res.status(500).json({ error: 'Error checking image purchase status' });
    }
});

// Serve the payment success page for Stripe redirect
app.get('/payment-success', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'payment-success.html'));
});

// Add a simple test endpoint to verify API key
app.get('/api/verify-key', authenticateApiKey, (req, res) => {
    res.json({
        success: true,
        message: 'API key is valid',
        timestamp: new Date().toISOString(),
        rateLimit: {
            remaining: res.get('X-RateLimit-Remaining'),
            reset: res.get('X-RateLimit-Reset')
        }
    });
});

// Add debug endpoint to check database status
app.get('/api/debug-database', async (req, res) => {
    try {
        // Check if table exists
        const tableCheck = await pool.query(`
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_name = 'photo_metadata'
            );
        `);

        const tableExists = tableCheck.rows[0].exists;

        if (!tableExists) {
            return res.json({
                tableExists: false,
                message: 'photo_metadata table does not exist'
            });
        }

        // Get table structure
        const structure = await pool.query(`
            SELECT column_name, data_type, is_nullable
            FROM information_schema.columns 
            WHERE table_name = 'photo_metadata'
            ORDER BY ordinal_position;
        `);

        // Get row count
        const countResult = await pool.query('SELECT COUNT(*) as total FROM photo_metadata');
        const totalRows = parseInt(countResult.rows[0].total);

        // Get recent entries
        const recentEntries = await pool.query(`
            SELECT id, filename, sail_number, created_at, file_checksum
            FROM photo_metadata 
            ORDER BY created_at DESC 
            LIMIT 5
        `);

        res.json({
            tableExists: true,
            totalRows: totalRows,
            tableStructure: structure.rows,
            recentEntries: recentEntries.rows,
            message: 'Database check completed'
        });

    } catch (err) {
        console.error('Error in debug-database endpoint:', err);
        res.status(500).json({
            error: err.message,
            stack: err.stack
        });
    }
});

// Delete photo endpoint
app.delete('/api/delete-photo/:id', async (req, res) => {
    try {
        const photoId = req.params.id;

        // Get photo details from database
        const photoResult = await pool.query(
            'SELECT filename FROM photo_metadata WHERE id = $1',
            [photoId]
        );

        if (photoResult.rows.length === 0) {
            return res.status(404).json({ error: 'Photo not found' });
        }

        const photo = photoResult.rows[0];
        const filename = photo.filename;

        // Delete from database
        await pool.query('DELETE FROM photo_metadata WHERE id = $1', [photoId]);

        // Delete file from storage
        try {
            // Try to delete from local storage
            const fullPath = path.join(PROCESSED_DIR, filename);
            if (fs.existsSync(fullPath)) {
                fs.unlinkSync(fullPath);
                console.log(`Deleted local file: ${fullPath}`);
            }

            // Try to delete from S3 if configured
            if (process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY) {
                try {
                    await deleteFromS3(filename);
                    console.log(`Deleted S3 file: ${filename}`);
                } catch (s3Error) {
                    console.log(`S3 deletion failed for ${filename}:`, s3Error.message);
                }
            }
        } catch (fileError) {
            console.log(`File deletion failed for ${filename}:`, fileError.message);
            // Continue even if file deletion fails - database entry is already deleted
        }

        res.json({
            success: true,
            message: `Photo "${filename}" deleted successfully`,
            deletedId: photoId
        });

    } catch (err) {
        console.error('Error deleting photo:', err);
        res.status(500).json({ error: err.message });
    }
});

// Secure delete by filename with password and validation
app.post('/api/delete-by-filename', async (req, res) => {
    try {
        const { filename, password } = req.body || {};

        // 1) Password check
        if (password !== '0403') {
            return res.status(403).json({ success: false, error: 'Invalid password' });
        }

        // 2) Validate filename strictly: no slashes, limited chars, allowed extensions
        if (typeof filename !== 'string' || filename.length < 3 || filename.length > 200) {
            return res.status(400).json({ success: false, error: 'Invalid filename length' });
        }
        const safeNamePattern = /^[A-Za-z0-9_.-]+\.(jpg|jpeg|png|gif|webp)$/i;
        if (!safeNamePattern.test(filename)) {
            return res.status(400).json({ success: false, error: 'Invalid filename format' });
        }
        if (filename.includes('..') || filename.includes('/') || filename.includes('\\')) {
            return res.status(400).json({ success: false, error: 'Path traversal detected' });
        }

        const storageDeleted = [];

        // 3) Delete from S3 processed folder
        try {
            await deleteFromS3(`processed/${filename}`);
            storageDeleted.push('s3');
        } catch (s3Err) {
            // If it's a not found error, continue; otherwise log
            console.log('S3 delete error (continuing):', s3Err.message || s3Err);
        }

        // 4) Delete from local processed folder if exists
        try {
            const localPath = path.join(PROCESSED_DIR, filename);
            if (fs.existsSync(localPath)) {
                fs.unlinkSync(localPath);
                storageDeleted.push('local');
            }
        } catch (fsErr) {
            console.log('Local delete error (continuing):', fsErr.message || fsErr);
        }

        // 5) Remove database references (delete rows where filename matches)
        let dbDeleted = 0;
        try {
            const dbRes = await pool.query('DELETE FROM photo_metadata WHERE filename = $1 RETURNING id', [filename]);
            dbDeleted = dbRes.rowCount;
        } catch (dbErr) {
            console.error('Database delete error:', dbErr);
        }

        // Also remove any purchased_images that reference this filename
        try {
            await pool.query('DELETE FROM purchased_images WHERE image_filename = $1', [filename]);
        } catch (dbErr2) {
            console.error('Purchased images cleanup error:', dbErr2);
        }

        return res.json({
            success: true,
            filename,
            storageDeleted,
            dbDeleted
        });
    } catch (err) {
        console.error('Error in delete-by-filename:', err);
        return res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

// Helper function to extract EXIF data from image buffer
function extractExifData(buffer) {
    try {
        const parser = ExifParser.create(buffer);
        const result = parser.parse();

        const exifData = {
            photo_timestamp: null,
            gps_latitude: null,
            gps_longitude: null,
            gps_altitude: null
        };

        // Extract photo timestamp (try multiple EXIF fields)
        if (result.tags) {
            if (result.tags.DateTimeOriginal) {
                exifData.photo_timestamp = new Date(result.tags.DateTimeOriginal * 1000);
            } else if (result.tags.DateTime) {
                exifData.photo_timestamp = new Date(result.tags.DateTime * 1000);
            } else if (result.tags.CreateDate) {
                exifData.photo_timestamp = new Date(result.tags.CreateDate * 1000);
            }
        }

        // Extract GPS data
        if (result.gps) {
            if (result.gps.GPSLatitude && result.gps.GPSLongitude) {
                exifData.gps_latitude = result.gps.GPSLatitude;
                exifData.gps_longitude = result.gps.GPSLongitude;
            }
            if (result.gps.GPSAltitude) {
                exifData.gps_altitude = result.gps.GPSAltitude;
            }
        }

        console.log('EXIF extraction successful:', {
            hasTimestamp: !!exifData.photo_timestamp,
            hasGPS: !!(exifData.gps_latitude && exifData.gps_longitude),
            hasAltitude: !!exifData.gps_altitude
        });

        return exifData;
    } catch (error) {
        console.log('No EXIF data found or error parsing EXIF:', error.message);
        return {
            photo_timestamp: null,
            gps_latitude: null,
            gps_longitude: null,
            gps_altitude: null
        };
    }
}

// Helper function to generate file checksum
function generateFileChecksum(buffer) {
    return crypto.createHash('sha256').update(buffer).digest('hex');
}

// Helper function to check for duplicate files
async function checkForDuplicate(checksum) {
    try {
        // First check if the file_checksum column exists
        const columnCheck = await pool.query(`
            SELECT EXISTS (
                SELECT FROM information_schema.columns 
                WHERE table_name = 'photo_metadata' 
                AND column_name = 'file_checksum'
            );
        `);

        if (!columnCheck.rows[0].exists) {
            console.log('file_checksum column does not exist yet, skipping duplicate check');
            return null;
        }

        // Match raw checksum or scan2 multi-sail form "hash::outputFilename"
        const result = await pool.query(
            `SELECT filename FROM photo_metadata
             WHERE file_checksum = $1 OR file_checksum LIKE $1 || '::%'`,
            [checksum]
        );
        return result.rows.length > 0 ? result.rows[0] : null;
    } catch (error) {
        console.error('Error checking for duplicate:', error);
        return null;
    }
}

// ---------- SailBot / RegattaNetworkData API ----------
const RND = REGATTA_NETWORK_DATA_TABLE;
/** Exclude SOZNODATA ("sorry no data") placeholder from all results. */
const SOZNODATA_EXCLUDE = ` AND NOT (
    UPPER(TRIM(COALESCE(skipper,''))) = 'SOZNODATA' OR
    UPPER(TRIM(COALESCE(yacht_club,''))) = 'SOZNODATA' OR
    UPPER(TRIM(COALESCE(regatta_name,''))) = 'SOZNODATA' OR
    UPPER(TRIM(COALESCE(boat_name,''))) = 'SOZNODATA' OR
    UPPER(TRIM(COALESCE(category,''))) = 'SOZNODATA'
)`;
const openai = process.env.OPENAI_API_KEY ? new OpenAI({ apiKey: process.env.OPENAI_API_KEY }) : null;

app.get('/api/sailbot/stats', async (req, res) => {
    try {
        await ensureRegattaNetworkDataTable();
        const r = await pool.query(`
            SELECT
                COUNT(*)::int AS total_records,
                COUNT(DISTINCT TRIM(skipper)) FILTER (WHERE skipper IS NOT NULL AND TRIM(skipper) <> '')::int AS total_sailors,
                COUNT(DISTINCT TRIM(regatta_name)) FILTER (WHERE regatta_name IS NOT NULL AND TRIM(regatta_name) <> '')::int AS total_regattas,
                COUNT(DISTINCT TRIM(yacht_club)) FILTER (WHERE yacht_club IS NOT NULL AND TRIM(yacht_club) <> '')::int AS total_clubs,
                MIN(regatta_date)::text AS earliest_date,
                MAX(regatta_date)::text AS latest_date
            FROM ${RND}
            WHERE 1=1${SOZNODATA_EXCLUDE}
        `);
        const row = r.rows[0];
        res.json({
            success: true,
            tableName: RND,
            total_records: row.total_records,
            total_sailors: row.total_sailors,
            total_regattas: row.total_regattas,
            total_clubs: row.total_clubs,
            earliest_date: row.earliest_date,
            latest_date: row.latest_date
        });
    } catch (e) {
        console.error('SailBot stats error:', e);
        res.status(500).json({ success: false, error: e.message });
    }
});

app.get('/api/sailbot/healthcheck', async (req, res) => {
    try {
        await pool.query('SELECT 1');
        let tableOk = false;
        try {
            await ensureRegattaNetworkDataTable();
            await pool.query(`SELECT 1 FROM ${RND} LIMIT 1`);
            tableOk = true;
        } catch (tErr) {
            // table may not exist yet or be empty
        }
        res.json({
            success: true,
            database: 'connected',
            tableName: RND,
            regattaNetworkDataTable: tableOk ? 'ok' : 'empty or missing',
            message: 'Database connection OK.'
        });
    } catch (e) {
        console.error('SailBot healthcheck error:', e);
        res.status(500).json({
            success: false,
            database: 'error',
            error: e.message,
            message: 'Database connection failed.'
        });
    }
});

app.get('/api/sailbot/test-openai', async (req, res) => {
    try {
        if (!openai) {
            return res.status(503).json({
                success: false,
                openai: 'not configured',
                error: 'OPENAI_API_KEY not set',
                message: 'OpenAI is not configured.'
            });
        }
        const completion = await openai.chat.completions.create({
            model: 'gpt-4o-mini',
            messages: [{ role: 'user', content: 'Reply with exactly: OK' }],
            max_tokens: 10,
            temperature: 0
        });
        const reply = completion.choices?.[0]?.message?.content?.trim() || '';
        res.json({
            success: true,
            openai: 'ok',
            reply,
            message: 'OpenAI connection OK.'
        });
    } catch (e) {
        console.error('SailBot test-openai error:', e);
        res.status(500).json({
            success: false,
            openai: 'error',
            error: e.message,
            message: 'OpenAI test failed.'
        });
    }
});

app.get('/api/sailbot/debug', async (req, res) => {
    try {
        await ensureRegattaNetworkDataTable();
        const r = await pool.query(`SELECT COUNT(*)::int AS n FROM ${RND} WHERE 1=1${SOZNODATA_EXCLUDE}`);
        res.json({
            success: true,
            tableUsed: RND,
            totalRecords: r.rows[0].n
        });
    } catch (e) {
        console.error('SailBot debug error:', e);
        res.status(500).json({ success: false, error: e.message, tableUsed: RND });
    }
});

app.get('/api/sailbot/download-sailors', async (req, res) => {
    try {
        await ensureRegattaNetworkDataTable();
        const r = await pool.query(`
            SELECT DISTINCT TRIM(skipper) AS name FROM ${RND}
            WHERE skipper IS NOT NULL AND TRIM(skipper) <> ''${SOZNODATA_EXCLUDE}
            ORDER BY name ASC
        `);
        const lines = ['"name"'];
        r.rows.forEach(row => lines.push('"' + String(row.name || '').replace(/"/g, '""') + '"'));
        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader('Content-Disposition', `attachment; filename=sailors-${Date.now()}.csv`);
        res.send(lines.join('\n'));
    } catch (e) {
        console.error('Download sailors error:', e);
        res.status(500).json({ success: false, error: e.message });
    }
});

app.get('/api/sailbot/download-clubs', async (req, res) => {
    try {
        await ensureRegattaNetworkDataTable();
        const r = await pool.query(`
            SELECT DISTINCT TRIM(yacht_club) AS name FROM ${RND}
            WHERE yacht_club IS NOT NULL AND TRIM(yacht_club) <> ''${SOZNODATA_EXCLUDE}
            ORDER BY name ASC
        `);
        const lines = ['"name"'];
        r.rows.forEach(row => lines.push('"' + String(row.name || '').replace(/"/g, '""') + '"'));
        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader('Content-Disposition', `attachment; filename=clubs-${Date.now()}.csv`);
        res.send(lines.join('\n'));
    } catch (e) {
        console.error('Download clubs error:', e);
        res.status(500).json({ success: false, error: e.message });
    }
});

app.get('/api/sailbot/download-regattas', async (req, res) => {
    try {
        await ensureRegattaNetworkDataTable();
        const r = await pool.query(`
            SELECT DISTINCT TRIM(regatta_name) AS name FROM ${RND}
            WHERE regatta_name IS NOT NULL AND TRIM(regatta_name) <> ''${SOZNODATA_EXCLUDE}
            ORDER BY name ASC
        `);
        const lines = ['"name"'];
        r.rows.forEach(row => lines.push('"' + String(row.name || '').replace(/"/g, '""') + '"'));
        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader('Content-Disposition', `attachment; filename=regattas-${Date.now()}.csv`);
        res.send(lines.join('\n'));
    } catch (e) {
        console.error('Download regattas error:', e);
        res.status(500).json({ success: false, error: e.message });
    }
});

app.post('/api/sailbot/cleanup-clubs', async (req, res) => {
    try {
        await ensureRegattaNetworkDataTable();
        const r = await pool.query(`
            UPDATE ${RND}
            SET yacht_club = 'Unknown'
            WHERE yacht_club IS NOT NULL
              AND TRIM(yacht_club) <> ''
              AND yacht_club !~ '^[A-Za-z]'
        `);
        res.json({
            success: true,
            updated: r.rowCount,
            message: `Set ${r.rowCount} invalid club name(s) to "Unknown".`
        });
    } catch (e) {
        console.error('Cleanup clubs error:', e);
        res.status(500).json({ success: false, error: e.message });
    }
});

app.post('/api/sailbot/search', async (req, res) => {
    try {
        const { skipper, boat_name, yacht_club, regatta_name, year } = req.body || {};
        const params = [];
        let n = 0;
        let where = '1=1';
        const add = (col, val, op = 'ILIKE') => {
            if (!val || String(val).trim() === '') return;
            n++;
            if (op === 'ILIKE') {
                where += ` AND ${col} ILIKE $${n}`;
                params.push(`%${String(val).trim()}%`);
            } else {
                where += ` AND ${col} = $${n}`;
                params.push(val);
            }
        };
        add('skipper', skipper);
        add('boat_name', boat_name);
        add('yacht_club', yacht_club);
        add('regatta_name', regatta_name);
        if (year != null && year !== '') {
            n++;
            where += ` AND EXTRACT(YEAR FROM regatta_date) = $${n}`;
            params.push(parseInt(String(year), 10));
        }
        n++;
        params.push(100);
        const q = `
            SELECT id, regatta_name, regatta_date, category, position, sail_number, boat_name, skipper, yacht_club, results, total_points
            FROM ${RND} WHERE ${where}
            ORDER BY regatta_date DESC NULLS LAST, position ASC NULLS LAST
            LIMIT $${n}
        `;
        const result = await pool.query(q, params);
        res.json({ success: true, rows: result.rows });
    } catch (e) {
        console.error('SailBot search error:', e);
        res.status(500).json({ success: false, error: e.message });
    }
});

app.get('/api/sailbot/export', async (req, res) => {
    try {
        const { skipper, boat_name, yacht_club, regatta_name, year, format } = req.query;
        const params = [];
        let n = 0;
        let where = '1=1';
        const add = (col, val) => {
            if (!val || String(val).trim() === '') return;
            n++;
            where += ` AND ${col} ILIKE $${n}`;
            params.push(`%${String(val).trim()}%`);
        };
        add('skipper', skipper);
        add('boat_name', boat_name);
        add('yacht_club', yacht_club);
        add('regatta_name', regatta_name);
        if (year != null && year !== '') {
            n++;
            where += ` AND EXTRACT(YEAR FROM regatta_date) = $${n}`;
            params.push(parseInt(String(year), 10));
        }
        const result = await pool.query(
            `SELECT * FROM ${RND} WHERE ${where}${SOZNODATA_EXCLUDE} ORDER BY regatta_date DESC, id ASC LIMIT 10000`,
            params
        );
        const asCsv = (format || 'csv').toLowerCase() === 'csv';
        if (asCsv) {
            const cols = result.rows.length ? Object.keys(result.rows[0]) : [];
            const header = cols.map(c => `"${String(c).replace(/"/g, '""')}"`).join(',');
            const lines = [header];
            for (const row of result.rows) {
                const vs = cols.map(c => {
                    const v = row[c];
                    const s = v == null ? '' : String(v).replace(/"/g, '""');
                    return `"${s}"`;
                });
                lines.push(vs.join(','));
            }
            res.setHeader('Content-Type', 'text/csv; charset=utf-8');
            res.setHeader('Content-Disposition', `attachment; filename=sailbot-export-${Date.now()}.csv`);
            return res.send(lines.join('\n'));
        }
        res.json({ success: true, rows: result.rows, count: result.rows.length });
    } catch (e) {
        console.error('SailBot export error:', e);
        res.status(500).json({ success: false, error: e.message });
    }
});

app.get('/api/sailbot/backup', async (req, res) => {
    try {
        const result = await pool.query(`SELECT * FROM ${RND} WHERE 1=1${SOZNODATA_EXCLUDE} ORDER BY id ASC`);
        const cols = result.rows.length ? Object.keys(result.rows[0]) : [];
        const header = cols.map(c => `"${String(c).replace(/"/g, '""')}"`).join(',');
        const lines = [header];
        for (const row of result.rows) {
            const vs = cols.map(c => {
                const v = row[c];
                const s = v == null ? '' : String(v).replace(/"/g, '""');
                return `"${s}"`;
            });
            lines.push(vs.join(','));
        }
        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader('Content-Disposition', `attachment; filename=RegattaNetworkData-backup-${Date.now()}.csv`);
        res.send(lines.join('\n'));
    } catch (e) {
        console.error('SailBot backup error:', e);
        res.status(500).json({ success: false, error: e.message });
    }
});

app.post('/api/sailbot/restore', csvUpload.single('file'), async (req, res) => {
    try {
        if (!req.file || !req.file.buffer) {
            return res.status(400).json({ success: false, error: 'No file uploaded' });
        }
        const { replace } = req.body || {};
        const doReplace = replace === 'true' || replace === '1';
        if (doReplace) {
            await pool.query(`TRUNCATE ${RND} RESTART IDENTITY`);
        }
        const { headers, rows } = parseCSVBuffer(req.file.buffer);
        const colMap = {};
        const schemaCols = ['regatta_name', 'regatta_date', 'category', 'position', 'sail_number', 'boat_name', 'skipper', 'yacht_club', 'results', 'total_points', 'source_url'];
        headers.forEach((h, i) => {
            const k = h.replace(/\s+/g, '_').toLowerCase().replace(/"/g, '');
            if (schemaCols.includes(k) || k === 'dataset_id') colMap[k] = i;
        });
        let inserted = 0;
        for (const row of rows) {
            const get = (k) => (colMap[k] != null && row[colMap[k]] != null) ? String(row[colMap[k]]).trim() : null;
            const regatta_date = parseRegattaDate(get('regatta_date'));
            const yacht_club = get('yacht_club') || 'Unknown';
            try {
                await pool.query(`
                    INSERT INTO ${RND} (regatta_name, regatta_date, category, position, sail_number, boat_name, skipper, yacht_club, results, total_points, source_url, dataset_id)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                `, [
                    get('regatta_name') || null,
                    regatta_date || null,
                    get('category') || null,
                    get('position') || null,
                    get('sail_number') || null,
                    get('boat_name') || null,
                    get('skipper') || null,
                    yacht_club,
                    get('results') || null,
                    get('total_points') || null,
                    get('source_url') || null,
                    get('dataset_id') || 'new'
                ]);
                inserted++;
            } catch (err) {
                console.warn('SailBot restore skip row:', err.message);
            }
        }
        res.json({ success: true, inserted });
    } catch (e) {
        console.error('SailBot restore error:', e);
        res.status(500).json({ success: false, error: e.message });
    }
});

app.post('/api/sailbot/upload', csvUpload.single('file'), async (req, res) => {
    try {
        if (!req.file || !req.file.buffer) {
            return res.status(400).json({ success: false, error: 'No file uploaded' });
        }
        const { headers, rows } = parseCSVBuffer(req.file.buffer);
        const colMap = {};
        const schemaCols = ['regatta_name', 'regatta_date', 'category', 'position', 'sail_number', 'boat_name', 'skipper', 'yacht_club', 'results', 'total_points', 'source_url'];
        headers.forEach((h, i) => {
            const k = h.replace(/\s+/g, '_').toLowerCase().replace(/"/g, '');
            if (schemaCols.includes(k) || k === 'dataset_id') colMap[k] = i;
        });
        let inserted = 0;
        for (const row of rows) {
            const get = (k) => (colMap[k] != null && row[colMap[k]] != null) ? String(row[colMap[k]]).trim() : null;
            const regatta_date = parseRegattaDate(get('regatta_date'));
            const yacht_club = get('yacht_club') || 'Unknown';
            try {
                await pool.query(`
                    INSERT INTO ${RND} (regatta_name, regatta_date, category, position, sail_number, boat_name, skipper, yacht_club, results, total_points, source_url, dataset_id)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                `, [
                    get('regatta_name') || null,
                    regatta_date || null,
                    get('category') || null,
                    get('position') || null,
                    get('sail_number') || null,
                    get('boat_name') || null,
                    get('skipper') || null,
                    yacht_club,
                    get('results') || null,
                    get('total_points') || null,
                    get('source_url') || null,
                    get('dataset_id') || 'new'
                ]);
                inserted++;
            } catch (err) {
                console.warn('SailBot upload skip row:', err.message);
            }
        }
        res.json({ success: true, inserted });
    } catch (e) {
        console.error('SailBot upload error:', e);
        res.status(500).json({ success: false, error: e.message });
    }
});

// ---------- Chatbot (OpenAI + SailBot search) ----------
const CHAT_SYSTEM = `You are a sailing results assistant. Users ask about sailors, boats, clubs, regattas, rankings, or regions.

First, interpret and refine the user's question into a clear, specific search (e.g. "top 10 sailors by regatta count" → top_sailors; "sailors who race for Coral Reef YC" → club_sailors with yacht_club).

Then output a JSON object with:
- "intent": one of sailor_search, boat_search, club_search, regatta_search, club_sailors, top_sailors, top_clubs, clubs_in_region
- "skipper": person name when searching for a sailor's results
- "boat_name": when searching by boat
- "yacht_club": club name when searching by club or "sailors at club X"
- "regatta_name": when searching by regatta
- "year": optional integer (e.g. 2024)
- "region": location/state name for "clubs in X" (e.g. "Florida", "Texas")

Rules:
- If the user's message contains "regatta" (or "the regatta") and any name or phrase → intent "regatta_search", "regatta_name": that phrase. Extract the regatta name (e.g. "Optimist regatta", "Coral Reef", "Natl Champs") and use it as regatta_name. Do NOT treat it as a sailor. Match broadly: even partial names like "Optimist" or "Spring" are fine.
- Person name only, no "regatta" (e.g. "Dominic Thomas") → intent "sailor_search", "skipper": "Dominic Thomas"
- "Sailors at [club]" / "who races for [club]" / "[club name]" when meaning list sailors → intent "club_sailors", "yacht_club": "[club]"
- "Top 10 sailors" / "best sailors" / "most active sailors" → intent "top_sailors"
- "Top 10 clubs" / "most active clubs" → intent "top_clubs"
- "Clubs in Florida" / "Florida clubs" → intent "clubs_in_region", "region": "Florida"
- Use the most specific intent that matches. Prefer club_sailors over club_search when user wants a list of sailors at a club.
- For regatta_search, always set regatta_name to the best matching phrase from the user (even if vague); we will match flexibly.

Reply with ONLY valid JSON, no markdown or extra text.`;

async function runSailbotSearch(criteria) {
    const { skipper, boat_name, yacht_club, regatta_name, year } = criteria || {};
    const params = [];
    let n = 0;
    let where = '1=1';
    const add = (col, val) => {
        if (!val || String(val).trim() === '') return;
        n++;
        where += ` AND ${col} ILIKE $${n}`;
        params.push(`%${String(val).trim()}%`);
    };
    add('skipper', skipper);
    add('boat_name', boat_name);
    add('yacht_club', yacht_club);
    add('regatta_name', regatta_name);
    if (year != null && year !== '') {
        n++;
        where += ` AND EXTRACT(YEAR FROM regatta_date) = $${n}`;
        params.push(parseInt(String(year), 10));
    }
    params.push(500);
    const q = `SELECT id, regatta_name, regatta_date, category, position, sail_number, boat_name, skipper, yacht_club, results, total_points
        FROM ${RND} WHERE ${where}${SOZNODATA_EXCLUDE}
        ORDER BY regatta_date DESC NULLS LAST, position ASC NULLS LAST
        LIMIT $${n + 1}`;
    const result = await pool.query(q, params);
    return result.rows;
}

async function runClubSailors(yachtClub) {
    if (!yachtClub || !String(yachtClub).trim()) return [];
    const q = `SELECT skipper, COUNT(*)::int AS regattas
        FROM ${RND}
        WHERE yacht_club ILIKE $1 AND skipper IS NOT NULL AND TRIM(skipper) <> ''${SOZNODATA_EXCLUDE}
        GROUP BY skipper
        ORDER BY regattas DESC, skipper ASC
        LIMIT 200`;
    const r = await pool.query(q, ['%' + String(yachtClub).trim() + '%']);
    return r.rows;
}

async function runTopSailors(limit = 10) {
    const q = `SELECT skipper, COUNT(*)::int AS regattas
        FROM ${RND}
        WHERE skipper IS NOT NULL AND TRIM(skipper) <> ''${SOZNODATA_EXCLUDE}
        GROUP BY skipper
        ORDER BY regattas DESC, skipper ASC
        LIMIT $1`;
    const r = await pool.query(q, [limit]);
    return r.rows;
}

async function runTopClubs(limit = 10) {
    const q = `SELECT yacht_club AS club, COUNT(*)::int AS count
        FROM ${RND}
        WHERE yacht_club IS NOT NULL AND TRIM(yacht_club) <> ''${SOZNODATA_EXCLUDE}
        GROUP BY yacht_club
        ORDER BY count DESC, yacht_club ASC
        LIMIT $1`;
    const r = await pool.query(q, [limit]);
    return r.rows;
}

async function runClubsInRegion(region) {
    if (!region || !String(region).trim()) return [];
    const q = `SELECT DISTINCT yacht_club AS club
        FROM ${RND}
        WHERE yacht_club ILIKE $1 AND yacht_club IS NOT NULL AND TRIM(yacht_club) <> ''${SOZNODATA_EXCLUDE}
        ORDER BY yacht_club ASC
        LIMIT 200`;
    const r = await pool.query(q, ['%' + String(region).trim() + '%']);
    return r.rows;
}

/** Format date for display - always includes year (e.g. "15 Jan 2024"). */
function formatDateWithYear(val) {
    if (val == null) return null;
    const d = val instanceof Date ? val : new Date(String(val));
    if (isNaN(d.getTime())) return String(val);
    const pad = n => String(n).padStart(2, '0');
    const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    const day = d.getUTCDate?.() ?? d.getDate();
    const month = d.getUTCMonth?.() ?? d.getMonth();
    const year = d.getUTCFullYear?.() ?? d.getFullYear();
    return `${pad(day)} ${months[month]} ${year}`;
}

/** Regatta summary: dates, sailor count, top 5 sailors per class (by best position). */
async function runRegattaSummary(regattaName) {
    if (!regattaName || !String(regattaName).trim()) return null;
    const q = `SELECT regatta_date, category, position, skipper, yacht_club
        FROM ${RND}
        WHERE regatta_name ILIKE $1${SOZNODATA_EXCLUDE}
        ORDER BY regatta_date, category, position`;
    const r = await pool.query(q, ['%' + String(regattaName).trim() + '%']);
    const rows = r.rows;
    if (!rows.length) return null;

    const rawDates = [...new Set(rows.map(x => x.regatta_date).filter(Boolean))];
    rawDates.sort((a, b) => new Date(a) - new Date(b));
    const dates = rawDates.map(d => formatDateWithYear(d));
    const sailors = new Set();
    rows.forEach(x => { if (x.skipper && String(x.skipper).trim()) sailors.add(String(x.skipper).trim()); });

    const byCategory = {};
    for (const row of rows) {
        const cat = row.category || 'Unclassified';
        if (!byCategory[cat]) byCategory[cat] = {};
        const pos = row.position;
        if (pos == null || !/^\d+$/.test(String(pos).trim())) continue;
        const n = parseInt(String(pos).trim(), 10);
        const sk = (row.skipper || '').trim();
        if (!sk) continue;
        if (!byCategory[cat][sk] || byCategory[cat][sk].position > n) {
            byCategory[cat][sk] = { skipper: sk, position: n, yacht_club: row.yacht_club || null };
        }
    }
    const byClass = [];
    for (const [cls, map] of Object.entries(byCategory)) {
        const arr = Object.values(map).sort((a, b) => a.position - b.position);
        byClass.push({ class: cls, topSailors: arr.slice(0, 5) });
    }
    byClass.sort((a, b) => (a.class || '').localeCompare(b.class || ''));

    return {
        regattaName: String(regattaName).trim(),
        dates,
        sailorCount: sailors.size,
        byClass
    };
}

app.post('/api/chat', async (req, res) => {
    try {
        const { message } = req.body || {};
        if (!message || !String(message).trim()) {
            return res.status(400).json({ success: false, error: 'Message required' });
        }
        if (!openai) {
            return res.status(503).json({ success: false, error: 'OpenAI not configured (OPENAI_API_KEY)' });
        }
        const completion = await openai.chat.completions.create({
            model: 'gpt-4o-mini',
            messages: [
                { role: 'system', content: CHAT_SYSTEM },
                { role: 'user', content: String(message).trim() }
            ],
            max_tokens: 256,
            temperature: 0
        });
        const raw = completion.choices?.[0]?.message?.content?.trim() || '{}';
        let parsed = {};
        try {
            const json = raw.replace(/^```(?:json)?\s*|\s*```$/g, '').trim();
            parsed = JSON.parse(json);
        } catch (_) {
            return res.status(502).json({ success: false, error: 'Could not parse OpenAI reply as JSON' });
        }
        const intent = (parsed.intent || '').toLowerCase();
        const criteria = {
            skipper: parsed.skipper,
            boat_name: parsed.boat_name,
            yacht_club: parsed.yacht_club,
            regatta_name: parsed.regatta_name,
            year: parsed.year,
            region: parsed.region
        };

        const hasSearchCriteria = [criteria.skipper, criteria.boat_name, criteria.yacht_club, criteria.regatta_name].some(Boolean);
        const hasAggregateIntent = ['top_sailors', 'top_clubs'].includes(intent);
        const hasClubSailors = intent === 'club_sailors' && criteria.yacht_club;
        const hasClubsInRegion = intent === 'clubs_in_region' && criteria.region;
        if (intent === 'regatta_search' && !criteria.regatta_name) {
            return res.json({
                success: true,
                reply: "Which regatta? Please include the regatta name (e.g. \"Optimist regatta\", \"Spring Champs\"). I'll show dates, sailor count, and top 5 per class.",
                data: null
            });
        }
        if (!hasSearchCriteria && !hasAggregateIntent && !hasClubSailors && !hasClubsInRegion) {
            return res.json({
                success: true,
                reply: "I couldn't determine what to look up. Try a sailor name, boat, club, a regatta name (e.g. \"Optimist regatta\"), \"sailors at [club]\", \"top 10 sailors\", \"top 10 clubs\", or \"clubs in Florida\".",
                data: null
            });
        }

        let reply = '';
        let data = null;
        let resultType = 'race_history';

        if (intent === 'club_sailors') {
            const rows = await runClubSailors(criteria.yacht_club);
            const list = rows.map(r => ({ name: r.skipper, count: r.regattas }));
            resultType = 'sailors_list';
            reply = list.length
                ? `Sailors who have raced for **${String(criteria.yacht_club).trim()}** (${list.length}):\n\nSee the table below.`
                : `I didn't find any sailors for that club. Try a different club name.`;
            data = list.length ? { resultType, list, subtitle: 'Sailors at ' + String(criteria.yacht_club).trim() } : null;
        } else if (intent === 'top_sailors') {
            const rows = await runTopSailors(10);
            const list = rows.map(r => ({ name: r.skipper, count: r.regattas }));
            resultType = 'sailors_list';
            reply = list.length
                ? `**Top 10 sailors** by number of regattas:\n\nSee the table below.`
                : "I don't have any data to rank sailors.";
            data = list.length ? { resultType, list, subtitle: 'Top 10 sailors by regattas' } : null;
        } else if (intent === 'top_clubs') {
            const rows = await runTopClubs(10);
            const list = rows.map(r => ({ name: r.club, count: r.count }));
            resultType = 'clubs_list';
            reply = list.length
                ? `**Top 10 clubs** by activity (race results):\n\nSee the table below.`
                : "I don't have any data to rank clubs.";
            data = list.length ? { resultType, list, subtitle: 'Top 10 clubs' } : null;
        } else if (intent === 'clubs_in_region') {
            const rows = await runClubsInRegion(criteria.region);
            const list = rows.map(r => ({ name: r.club }));
            resultType = 'clubs_list';
            reply = list.length
                ? `Clubs in **${String(criteria.region).trim()}** (${list.length}):\n\nSee the table below.`
                : `I didn't find any clubs matching "${String(criteria.region).trim()}".`;
            data = list.length ? { resultType, list, subtitle: 'Clubs in ' + String(criteria.region).trim() } : null;
        } else if (intent === 'regatta_search' && criteria.regatta_name) {
            const summary = await runRegattaSummary(criteria.regatta_name);
            resultType = 'regatta_summary';
            if (summary) {
                const dateStr = summary.dates.length ? summary.dates.join(', ') : '—';
                reply = `**${summary.regattaName}**\n\n**Dates:** ${dateStr}\n**Sailors:** ${summary.sailorCount}\n\nTop 5 sailors per class below.`;
                data = { resultType: 'regatta_summary', ...summary };
            } else {
                reply = `I didn't find a regatta matching "${String(criteria.regatta_name).trim()}". Try a different name or partial match (e.g. "Optimist", "Spring").`;
                data = null;
            }
        } else {
            const rows = await runSailbotSearch(criteria);
            const seen = new Set();
            let totalRegattas = 0;
            for (const r of rows) {
                const k = `${r.regatta_name}|${r.regatta_date}`;
                if (!seen.has(k)) { seen.add(k); totalRegattas++; }
            }
            let topPosition = null;
            for (const r of rows) {
                const p = r.position;
                if (p != null && /^\d+$/.test(String(p).trim())) {
                    const n = parseInt(String(p).trim(), 10);
                    if (topPosition == null || n < topPosition) topPosition = n;
                }
            }
            const basicInfo = rows.length ? {
                name: (intent === 'sailor_search' ? rows[0].skipper : null) || rows[0].boat_name || rows[0].regatta_name || '—',
                club: rows[0].yacht_club || '—'
            } : null;
            const raceHistory = rows.map(r => ({
                position: r.position,
                regatta_name: r.regatta_name,
                regatta_date: formatDateWithYear(r.regatta_date)
            }));
            reply = rows.length
                ? `I found the following information:\n\n**Total number of regattas:** ${totalRegattas}\n**Top position:** ${topPosition != null ? topPosition : '—'}\n\nSee the table below for each regatta and result.`
                : "I didn't find any results for that search. Try a different sailor, boat, club, or regatta.";
            data = rows.length ? {
                resultType: 'race_history',
                basicInfo,
                totalRegattas,
                topPosition: topPosition != null ? topPosition : null,
                rows: raceHistory
            } : null;
        }

        res.json({
            success: true,
            reply,
            data
        });
    } catch (e) {
        console.error('Chat API error:', e);
        res.status(500).json({ success: false, error: e.message });
    }
});

// Static file serving (AFTER all API routes)
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(UPLOAD_DIR));

// Debug middleware to log all requests
app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);

    // Special logging for image requests
    if (req.url.startsWith('/Images/') || req.url.startsWith('/images/')) {
        console.log(`🖼️  Image request: ${req.url}`);
        console.log(`   Static path: ${path.join(__dirname, 'Images')}`);
        console.log(`   File exists: ${require('fs').existsSync(path.join(__dirname, 'Images', req.url.replace(/^\/Images\//, '').replace(/^\/images\//, '')))}`);
    }

    next();
});

// Serve website images from Images directory (since Render serves from repo root)
app.use('/Images', express.static(path.join(__dirname, 'Images')));
// Also serve common alias paths to be resilient across hosts/configs
app.use('/images', express.static(path.join(__dirname, 'Images')));
app.use('/public/Images', express.static(path.join(__dirname, 'Images')));
app.use('/public/images', express.static(path.join(__dirname, 'Images')));
// Also serve from public/Images as backup
app.use('/public/Images', express.static(path.join(__dirname, 'public', 'Images')));
app.use('/public/images', express.static(path.join(__dirname, 'public', 'Images')));
// Then serve processed images from processed_images directory
app.use('/processed-images', express.static(PROCESSED_DIR));
app.use('/liveview_videos', express.static(LIVEVIEW_VIDEOS_DIR));

// In-memory job storage (in production, use a proper database)
const analysisJobs = new Map();

// Bulk upload endpoint - STAGE 1: Upload files to temporary storage
app.post('/api/bulk-upload', upload.single('image'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ success: false, error: 'No file uploaded' });
        }

        const file = req.file;
        const metadata = req.body;

        // Generate unique filename
        const timestamp = Date.now();
        const randomString = Math.random().toString(36).substring(2, 15);
        const fileExtension = path.extname(file.originalname);
        const newFilename = `bulk_${timestamp}_${randomString}${fileExtension}`;

        console.log('=== Stage 1: Bulk Upload ===');
        console.log('Uploading file:', file.originalname, '→', newFilename);

        // Upload to S3 in bulk-uploads folder (temporary storage)
        const s3Key = `bulk-uploads/${newFilename}`;
        const s3Url = await uploadToS3(file.buffer, s3Key, file.mimetype);

        // Process additional_tags to handle array format
        let additionalTagsArray = null;
        if (metadata.additional_tags && metadata.additional_tags.trim()) {
            additionalTagsArray = metadata.additional_tags
                .split(',')
                .map(tag => tag.trim())
                .filter(tag => tag.length > 0);
        }

        // Store file info in database with 'uploaded' status (not analyzed yet)
        const query = `
            INSERT INTO photo_metadata (
                filename, original_filename, new_filename, file_size, file_type, 
                date, regatta_name, yacht_club, photographer_name, 
                photographer_website, location, additional_tags, 
                s3_url, upload_timestamp, processing_status
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
            RETURNING id
        `;

        const values = [
            newFilename, // filename (required NOT NULL field)
            file.originalname, // original_filename
            newFilename, // new_filename
            file.size,
            file.mimetype,
            metadata.date || null,
            metadata.regatta_name || null,
            metadata.yacht_club || null,
            metadata.photographer_name || null,
            metadata.photographer_website || null,
            metadata.location || null,
            additionalTagsArray, // Now properly formatted as array
            s3Url,
            new Date().toISOString(),
            'uploaded' // Status: uploaded (ready for analysis)
        ];

        const result = await pool.query(query, values);

        console.log(`Successfully uploaded ${file.originalname} to temporary storage`);

        res.json({
            success: true,
            storedName: newFilename,
            s3Url: s3Url,
            id: result.rows[0].id,
            message: 'File uploaded - ready for analysis'
        });

    } catch (error) {
        console.error('Bulk upload error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Create analysis job endpoint
app.post('/api/create-analysis-job', async (req, res) => {
    try {
        const { files, metadata } = req.body;

        if (!files || files.length === 0) {
            return res.status(400).json({ success: false, error: 'No files provided' });
        }

        // Generate job ID
        const jobId = `job_${Date.now()}_${Math.random().toString(36).substring(2, 15)}`;

        // Create job object
        const job = {
            id: jobId,
            status: 'pending',
            totalFiles: files.length,
            completedFiles: 0,
            fileStatus: {},
            metadata: metadata,
            createdAt: new Date().toISOString(),
            startedAt: null,
            completedAt: null,
            files: files
        };

        // Initialize file status
        files.forEach(file => {
            job.fileStatus[file.originalName] = 'pending';
        });

        // Store job
        analysisJobs.set(jobId, job);

        // Start background processing
        processAnalysisJob(jobId);

        res.json({
            success: true,
            jobId: jobId,
            message: 'Analysis job created and started'
        });

    } catch (error) {
        console.error('Error creating analysis job:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Get job status endpoint
app.get('/api/job-status/:jobId', async (req, res) => {
    try {
        const jobId = req.params.jobId;
        const job = analysisJobs.get(jobId);

        if (!job) {
            return res.status(404).json({ success: false, error: 'Job not found' });
        }

        res.json({
            success: true,
            job: job
        });

    } catch (error) {
        console.error('Error getting job status:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Background job processing function - STAGE 2: Analyze files and cleanup
async function processAnalysisJob(jobId) {
    const job = analysisJobs.get(jobId);
    if (!job) return;

    try {
        job.status = 'processing';
        job.startedAt = new Date().toISOString();

        console.log(`=== Stage 2: Starting Analysis Job ${jobId} ===`);
        console.log(`Processing ${job.files.length} files for sail number detection`);

        for (let i = 0; i < job.files.length; i++) {
            const file = job.files[i];

            try {
                job.fileStatus[file.originalName] = 'processing';
                console.log(`Analyzing file ${i + 1}/${job.files.length}: ${file.originalName}`);

                // Get file from S3 temporary storage
                const s3Key = `bulk-uploads/${file.storedName}`;
                const s3Response = await s3Client.send(new GetObjectCommand({
                    Bucket: BUCKET_NAME,
                    Key: s3Key
                }));

                const imageBuffer = await streamToBuffer(s3Response.Body);

                // Process with Azure Computer Vision
                const sailNumbers = await analyzeImageWithAzure(imageBuffer);

                // CRITICAL LOGIC: Handle based on sail number detection
                if (sailNumbers && sailNumbers.length > 0) {
                    // SAIL NUMBERS FOUND - Process and move to permanent storage
                    console.log(`✓ Sail numbers found in ${file.originalName}:`, sailNumbers.map(sn => sn.number));

                    for (const sailData of sailNumbers) {
                        try {
                            // Look up sailor name in database
                            const sailorInfo = await lookupSailorInDatabase(sailData.number);
                            const sailorName = sailorInfo ? sailorInfo.sailorName : 'NONAME';

                            const processedFilename = `${sailData.number}_${sailorName}_${file.originalName}`;
                            const processedS3Key = `processed/${processedFilename}`;

                            // Copy to permanent processed storage
                            await s3Client.send(new CopyObjectCommand({
                                Bucket: BUCKET_NAME,
                                CopySource: `${BUCKET_NAME}/${s3Key}`,
                                Key: processedS3Key
                            }));

                            console.log(`Moved to processed storage: ${processedFilename}`);
                        } catch (processError) {
                            console.error(`Error processing sail number ${sailData.number}:`, processError);
                        }
                    }

                    // Update database record with sail numbers and change status
                    await updatePhotoMetadataWithSailNumbers(file.storedName, sailNumbers);
                    job.fileStatus[file.originalName] = 'processed_with_sail_numbers';

                } else {
                    // NO SAIL NUMBERS FOUND - Delete from S3 and database
                    console.log(`✗ No sail numbers found in ${file.originalName} - cleaning up`);

                    // Delete from S3 temporary storage
                    try {
                        await s3Client.send(new DeleteObjectCommand({
                            Bucket: BUCKET_NAME,
                            Key: s3Key
                        }));
                        console.log(`Deleted from S3: ${s3Key}`);
                    } catch (deleteError) {
                        console.error(`Error deleting from S3: ${s3Key}`, deleteError);
                    }

                    // Delete from database
                    try {
                        await pool.query('DELETE FROM photo_metadata WHERE new_filename = $1', [file.storedName]);
                        console.log(`Deleted from database: ${file.storedName}`);
                    } catch (dbDeleteError) {
                        console.error(`Error deleting from database: ${file.storedName}`, dbDeleteError);
                    }

                    job.fileStatus[file.originalName] = 'deleted_no_sail_numbers';
                }

                job.completedFiles++;

            } catch (error) {
                console.error(`Error processing file ${file.originalName}:`, error);
                job.fileStatus[file.originalName] = 'error';
                job.completedFiles++;
            }

            // Rate limiting - wait 26 seconds between API calls (Azure free tier limit)
            if (i < job.files.length - 1) {
                console.log('Waiting 26 seconds before next analysis (rate limiting)...');
                await new Promise(resolve => setTimeout(resolve, 26000));
            }
        }

        job.status = 'completed';
        job.completedAt = new Date().toISOString();

        // Log final summary
        const processedCount = Object.values(job.fileStatus).filter(status => status === 'processed_with_sail_numbers').length;
        const deletedCount = Object.values(job.fileStatus).filter(status => status === 'deleted_no_sail_numbers').length;
        const errorCount = Object.values(job.fileStatus).filter(status => status === 'error').length;

        console.log(`=== Analysis Job ${jobId} Complete ===`);
        console.log(`Files with sail numbers: ${processedCount}`);
        console.log(`Files without sail numbers (deleted): ${deletedCount}`);
        console.log(`Errors: ${errorCount}`);

    } catch (error) {
        console.error(`Error in analysis job ${jobId}:`, error);
        job.status = 'error';
        job.completedAt = new Date().toISOString();
    }
}

// Helper function to convert stream to buffer
function streamToBuffer(stream) {
    return new Promise((resolve, reject) => {
        const chunks = [];
        stream.on('data', chunk => chunks.push(chunk));
        stream.on('end', () => resolve(Buffer.concat(chunks)));
        stream.on('error', reject);
    });
}

// Helper function to update photo metadata with analysis results
async function updatePhotoMetadataWithResults(filename, sailNumbers) {
    try {
        const query = `
            UPDATE photo_metadata 
            SET 
                processing_status = 'completed',
                sail_numbers = $1,
                analysis_timestamp = $2
            WHERE new_filename = $3
        `;

        const sailNumbersJson = JSON.stringify(sailNumbers);
        const analysisTimestamp = new Date().toISOString();

        await pool.query(query, [sailNumbersJson, analysisTimestamp, filename]);

    } catch (error) {
        console.error('Error updating photo metadata with results:', error);
        throw error;
    }
}

// Helper function to update photo metadata with sail numbers and proper filename
async function updatePhotoMetadataWithSailNumbers(tempFilename, sailNumbers) {
    try {
        if (sailNumbers && sailNumbers.length > 0) {
            // Get the highest confidence sail number
            const primarySailNumber = sailNumbers.sort((a, b) => b.confidence - a.confidence)[0];

            // Look up sailor name
            const sailorInfo = await lookupSailorInDatabase(primarySailNumber.number);
            const sailorName = sailorInfo ? sailorInfo.sailorName : 'NONAME';

            // Get original filename from database
            const originalRecord = await pool.query('SELECT original_filename FROM photo_metadata WHERE new_filename = $1', [tempFilename]);
            const originalFilename = originalRecord.rows[0]?.original_filename || 'unknown.jpg';

            const processedFilename = `${primarySailNumber.number}_${sailorName}_${originalFilename}`;

            const query = `
                UPDATE photo_metadata 
                SET 
                    filename = $1,
                    sail_number = $2,
                    processing_status = 'completed',
                    sail_numbers = $3,
                    analysis_timestamp = $4,
                    s3_url = $5
                WHERE new_filename = $6
            `;

            const sailNumbersJson = JSON.stringify(sailNumbers);
            const analysisTimestamp = new Date().toISOString();
            const newS3Url = await getS3SignedUrl(`processed/${processedFilename}`);

            await pool.query(query, [
                processedFilename,
                primarySailNumber.number,
                sailNumbersJson,
                analysisTimestamp,
                newS3Url,
                tempFilename
            ]);

            console.log(`Updated database record: ${tempFilename} → ${processedFilename}`);
        }
    } catch (error) {
        console.error('Error updating photo metadata with sail numbers:', error);
        throw error;
    }
}

// Azure Computer Vision analysis function for bulk upload
async function analyzeImageWithAzure(imageBuffer) {
    try {
        console.log('Starting Azure analysis for bulk upload...');

        // Send to Azure for Text Detection
        const result = await processWithRetry(
            () => computerVisionClient.readInStream(imageBuffer, { language: 'en' }),
            'Azure Vision API call'
        );

        // Wait for Azure Processing
        const operationId = result.operationLocation.split('/').pop();

        let operationResult;
        let attempts = 0;
        const maxAttempts = 30;
        const delayMs = 1000;

        do {
            attempts++;
            console.log(`Checking Azure results - Attempt ${attempts}...`);
            operationResult = await processWithRetry(
                () => computerVisionClient.getReadResult(operationId),
                'Azure Results Polling'
            );

            if (operationResult.status === 'running' || operationResult.status === 'notStarted') {
                await new Promise(resolve => setTimeout(resolve, delayMs));
            }
        } while ((operationResult.status === 'running' || operationResult.status === 'notStarted') && attempts < maxAttempts);

        if (operationResult.status === 'succeeded') {
            console.log('Azure processing completed successfully!');
            const foundNumbers = extractSailNumbers(operationResult.analyzeResult);
            const sortedNumbers = foundNumbers.sort((a, b) => b.confidence - a.confidence);

            // Filter sail numbers by confidence level (>90%)
            const highConfidenceNumbers = sortedNumbers.filter(sailData => sailData.confidence > 0.9);

            console.log(`Found ${sortedNumbers.length} sail numbers, ${highConfidenceNumbers.length} with >90% confidence`);

            return highConfidenceNumbers;
        } else {
            console.error('Azure processing failed:', operationResult.status);
            return [];
        }

    } catch (error) {
        console.error('Error during Azure analysis:', error);
        return [];
    }
}

// Test route to verify Images directory is accessible
app.get('/test-images', (req, res) => {
    const imagesDir = path.join(__dirname, 'Images');
    const publicImagesDir = path.join(__dirname, 'public', 'Images');
    const fs = require('fs');

    res.json({
        debug: {
            __dirname: __dirname,
            imagesDir: imagesDir,
            publicImagesDir: publicImagesDir,
            imagesExists: fs.existsSync(imagesDir),
            publicImagesDirExists: fs.existsSync(publicImagesDir),
            currentWorkingDir: process.cwd()
        },
        success: fs.existsSync(imagesDir) || fs.existsSync(publicImagesDir),
        error: (fs.existsSync(imagesDir) || fs.existsSync(publicImagesDir)) ? null : 'No Images directory found in either location'
    });
});

// Test route to serve a specific image
app.get('/test-image/:filename', (req, res) => {
    const filename = req.params.filename;
    const imagePath = path.join(__dirname, 'Images', filename);
    const fs = require('fs');

    if (fs.existsSync(imagePath)) {
        res.sendFile(imagePath);
    } else {
        res.status(404).json({
            error: 'Image not found',
            requestedFile: filename,
            fullPath: imagePath,
            exists: false
        });
    }
});

// Serve favicon directly with proper headers (AFTER static file serving)
app.get('/Images/favicon.ico', (req, res) => {
    const faviconPath = path.join(__dirname, 'Images', 'favicon.ico');
    res.setHeader('Content-Type', 'image/x-icon');
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate'); // Prevent caching for debugging
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.sendFile(faviconPath);
});

// Weekly scheduled scrape - runs every Sunday at 2:00 AM UTC
function setupScheduledScrape() {
    const scraperUrl = process.env.SCRAPER_SERVICE_URL;
    if (!scraperUrl) {
        console.log('[Scheduled Scrape] SCRAPER_SERVICE_URL not set - weekly scrape disabled');
        return;
    }
    // Cron: minute hour day-of-month month day-of-week (0 = Sunday)
    cron.schedule('0 2 * * 0', async () => {
        console.log('[Scheduled Scrape] Running weekly scrape (all sources)...');
        try {
            const response = await axios.post(`${scraperUrl}/api/scrape-regattas`, { source: 'all' }, {
                timeout: 300000,
                headers: { 'Content-Type': 'application/json' }
            });
            console.log('[Scheduled Scrape] Complete:', response.data);
        } catch (err) {
            console.error('[Scheduled Scrape] Error:', err.message);
        }
    });
    console.log('[Scheduled Scrape] Weekly scrape enabled (Sundays 02:00 UTC)');
}
setupScheduledScrape();

// Regatta scrape status - last scrape, next scrape, new records per source
app.get('/api/regatta-scrape-status', async (req, res) => {
    try {
        const scraperUrl = process.env.SCRAPER_SERVICE_URL;
        const sources = [
            { id: 'regattanetwork', name: 'Regatta Network' },
            { id: 'clubspot', name: 'Clubspot' },
            { id: 'hssailing', name: 'High School Sailing' }
        ];

        let result;
        try {
            result = await pool.query(`
                SELECT DISTINCT ON (source) source, scrape_time as last_scrape, regattas_found, regattas_added
                FROM scrape_log
                ORDER BY source, scrape_time DESC
            `);
        } catch (tableErr) {
            if (tableErr.code === '42P01') {
                result = { rows: [] };
            } else {
                throw tableErr;
            }
        }
        const bySource = {};
        result.rows.forEach(r => { bySource[r.source] = r; });

        const scheduleEnabled = !!scraperUrl;
        const now = new Date();
        let nextScheduledRun = null;
        if (scheduleEnabled) {
            const nextSun = new Date(now);
            nextSun.setUTCDate(now.getUTCDate() + ((7 - now.getUTCDay() + 7) % 7));
            nextSun.setUTCHours(2, 0, 0, 0);
            if (nextSun <= now) nextSun.setUTCDate(nextSun.getUTCDate() + 7);
            nextScheduledRun = nextSun.toISOString();
        }

        const sourcesWithStatus = sources.map(s => {
            const row = bySource[s.id];
            const lastScrape = row ? new Date(row.last_scrape) : null;
            const nextScrape = scheduleEnabled && nextScheduledRun ? nextScheduledRun : null;
            return {
                source: s.id,
                displayName: s.name,
                lastScrape: lastScrape ? lastScrape.toISOString() : null,
                nextScrape,
                newRecordsLastScrape: row ? (row.regattas_added || 0) : null,
                totalFoundLastScrape: row ? (row.regattas_found || 0) : null
            };
        });

        res.json({
            success: true,
            scheduleEnabled,
            scheduleDescription: 'Every Sunday at 02:00 UTC',
            nextScheduledRun,
            sources: sourcesWithStatus
        });
    } catch (err) {
        console.error('Error getting scrape status:', err);
        res.status(500).json({ success: false, error: err.message });
    }
});

// Regatta scraping endpoint - forwards to dedicated scraper service
app.post('/api/scrape-regattas', async (req, res) => {
    const source = req.body && req.body.source ? req.body.source : 'all';
    console.log(`=== Regatta Scraping Request: source="${source}" ===`);

    // ClubSpot runs locally via the Parse Server API (no external service needed).
    // Run in background and respond immediately to avoid HTTP timeouts with large datasets.
    if (source === 'clubspot') {
        res.json({ status: 'started', message: 'Clubspot scrape started in background. Check scrape log for results.' });
        scrapeClubspot().then(result => {
            console.log('Background Clubspot scrape complete:', result);
        }).catch(err => {
            console.error('Background Clubspot scrape error:', err.message);
        });
        return;
    }

    // For other sources, forward to the external scraper service if configured
    const scraperServiceUrl = process.env.SCRAPER_SERVICE_URL;
    if (scraperServiceUrl) {
        try {
            console.log(`Forwarding to scraper service: ${scraperServiceUrl}`);
            const response = await axios.post(`${scraperServiceUrl}/api/scrape-regattas`, req.body, {
                timeout: 120000,
                headers: { 'Content-Type': 'application/json' }
            });
            console.log('Scraper service response:', response.data);
            return res.json(response.data);
        } catch (error) {
            console.error('Scraper service error:', error.message);
            if (error.response) {
                return res.status(error.response.status).json(error.response.data);
            }
            return res.status(503).json({
                error: 'Scraper service unavailable',
                details: error.message
            });
        }
    }

    // No external service and not a locally-handled source
    return res.status(503).json({
        error: 'Scraper service not configured',
        details: 'Set SCRAPER_SERVICE_URL to enable scraping for non-Clubspot sources.'
    });
});

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

        // Find the table with regatta data - look for table rows with date, event, and links
        $('table tr').each((index, element) => {
            const $row = $(element);
            const $cells = $row.find('td');

            if ($cells.length >= 3) {
                const dateText = $cells.eq(0).text().trim();
                const eventCell = $cells.eq(1);
                const linksCell = $cells.eq(2);

                // Extract date (format: MM/DD/YY)
                let regattaDate = null;
                if (dateText) {
                    const dateMatch = dateText.match(/(\d{2})\/(\d{2})\/(\d{2})/);
                    if (dateMatch) {
                        const [, month, day, year] = dateMatch;
                        const fullYear = parseInt(year) < 50 ? 2000 + parseInt(year) : 1900 + parseInt(year);
                        regattaDate = `${fullYear}-${month}-${day}`;
                    }
                }

                // Extract event name (first line or text before location)
                let eventName = eventCell.clone().children().remove().end().text().trim();
                // If no text, try getting from links
                if (!eventName) {
                    eventName = eventCell.text().trim().split('\n')[0];
                }

                // Extract location (usually after event name, often in format "Club Name, City, ST")
                let location = '';
                const fullText = eventCell.text();
                // Look for pattern: text ending with ", ST" or ", State"
                const locationMatch = fullText.match(/([A-Z][^,]+(?:,\s*[A-Z][^,]+)*,\s*[A-Z]{2})/);
                if (locationMatch) {
                    location = locationMatch[1].trim();
                } else {
                    // Try to find location in the text after event name
                    const lines = fullText.split('\n').map(l => l.trim()).filter(l => l);
                    if (lines.length > 1) {
                        location = lines[1];
                    }
                }

                // Extract links from event cell
                let eventWebsiteUrl = '';
                eventCell.find('a').each((i, link) => {
                    const href = $(link).attr('href');
                    const text = $(link).text().trim();
                    if (text.includes('Event Website') || (href && href.includes('event'))) {
                        eventWebsiteUrl = href.startsWith('http') ? href : `https://www.regattanetwork.com${href}`;
                        return false; // break
                    }
                });

                // Extract registrants link from links cell
                let registrantsUrl = '';
                linksCell.find('a').each((i, link) => {
                    const href = $(link).attr('href');
                    const text = $(link).text().trim();
                    if (text.includes('View Registrants') || text.includes('Registrants') || (href && href.includes('registrant'))) {
                        registrantsUrl = href.startsWith('http') ? href : `https://www.regattanetwork.com${href}`;
                        return false; // break
                    }
                });

                // Clean up event name (remove location if included)
                if (eventName && location && eventName.includes(location)) {
                    eventName = eventName.replace(location, '').trim();
                }

                if (regattaDate && eventName && eventName.length > 3) {
                    // Generate source_id for de-duplication
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

        // Insert regattas with de-duplication
        let added = 0;
        for (const regatta of regattas) {
            try {
                await pool.query(`
          INSERT INTO regattas (regatta_date, regatta_name, location, event_website_url, registrants_url, registrant_count, source, source_id)
          VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
          ON CONFLICT (regatta_name, regatta_date, source) 
          DO UPDATE SET 
            location = EXCLUDED.location,
            event_website_url = EXCLUDED.event_website_url,
            registrants_url = EXCLUDED.registrants_url,
            registrant_count = COALESCE(EXCLUDED.registrant_count, regattas.registrant_count),
            source_id = EXCLUDED.source_id,
            last_updated = CURRENT_TIMESTAMP
        `, [
                    regatta.regatta_date,
                    regatta.regatta_name,
                    regatta.location,
                    regatta.event_website_url,
                    regatta.registrants_url,
                    null,
                    regatta.source,
                    regatta.source_id
                ]);
                added++;
            } catch (err) {
                // Skip duplicates silently
                if (!err.message.includes('duplicate')) {
                    console.error('Error inserting regatta:', err);
                }
            }
        }

        // Log scrape
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

// Scrape Clubspot via the Parse Server REST API (no headless browser needed)
async function scrapeClubspot() {
    console.log('🌐 Starting Clubspot scrape via Parse Server API...');

    const PARSE_API_URL = 'https://theclubspot.com/parse/classes/regattas';
    const PARSE_APP_ID = 'myclubspot2017';
    const BATCH_SIZE = 100;

    try {
        // Fetch from 30 days ago to catch events already in progress
        const fromDate = new Date();
        fromDate.setDate(fromDate.getDate() - 30);

        const where = {
            archived: { $ne: true },
            startDate: { $gte: { __type: 'Date', iso: fromDate.toISOString() } }
        };

        const baseParams = new URLSearchParams({
            order: 'startDate',
            include: 'clubObject',
            keys: 'name,startDate,endDate,city,state,country,clubObject,objectId',
            where: JSON.stringify(where)
        });

        // Get total count first
        const countParams = new URLSearchParams(baseParams);
        countParams.set('count', '1');
        countParams.set('limit', '0');

        const countResponse = await axios.get(`${PARSE_API_URL}?${countParams}`, {
            headers: { 'X-Parse-Application-Id': PARSE_APP_ID },
            timeout: 30000
        });

        const totalCount = countResponse.data.count || 0;
        console.log(`📊 Total upcoming Clubspot regattas: ${totalCount}`);

        // Paginate through all results
        const allRegattas = [];
        const totalPages = Math.ceil(totalCount / BATCH_SIZE);

        for (let page = 0; page < totalPages; page++) {
            const pageParams = new URLSearchParams(baseParams);
            pageParams.set('limit', BATCH_SIZE.toString());
            pageParams.set('skip', (page * BATCH_SIZE).toString());

            console.log(`📄 Fetching page ${page + 1}/${totalPages}...`);

            const response = await axios.get(`${PARSE_API_URL}?${pageParams}`, {
                headers: { 'X-Parse-Application-Id': PARSE_APP_ID },
                timeout: 30000
            });

            const results = response.data.results || [];
            allRegattas.push(...results);

            if (page < totalPages - 1) {
                await new Promise(r => setTimeout(r, 200));
            }
        }

        console.log(`✅ Fetched ${allRegattas.length} regattas from Clubspot API`);

        // Map Parse objects to DB schema
        const extractedRegattas = allRegattas.map(r => {
            const startDateIso = r.startDate && r.startDate.iso ? r.startDate.iso : r.startDate;
            const regattaDate = startDateIso ? startDateIso.substring(0, 10) : null;

            let location = null;
            if (r.city && r.state) {
                location = `${r.city}, ${r.state}`;
            } else if (r.city) {
                location = r.city;
            } else if (r.clubObject && r.clubObject.name) {
                location = r.clubObject.name;
            }

            let eventWebsiteUrl = null;
            if (r.clubObject && r.clubObject.subdomain && r.objectId) {
                const subdomain = r.clubObject.subdomain.replace(/[^a-zA-Z0-9-]/g, '');
                if (subdomain) {
                    eventWebsiteUrl = `https://${subdomain}.theclubspot.com/regatta/${r.objectId}`;
                }
            }

            return {
                regatta_date: regattaDate,
                regatta_name: r.name || null,
                location,
                event_website_url: eventWebsiteUrl,
                source_id: r.objectId
            };
        }).filter(r => r.regatta_date && r.regatta_name && r.regatta_name.length > 2);

        console.log(`📋 Valid regattas after filtering: ${extractedRegattas.length}`);

        // Batch inserts: 50 rows per query to avoid per-row overhead with 1000+ regattas
        let added = 0;
        const INSERT_BATCH = 50;
        const totalBatches = Math.ceil(extractedRegattas.length / INSERT_BATCH);
        console.log(`💾 Inserting ${extractedRegattas.length} regattas in ${totalBatches} batches...`);

        for (let i = 0; i < extractedRegattas.length; i += INSERT_BATCH) {
            const batch = extractedRegattas.slice(i, i + INSERT_BATCH);
            const values = [];
            const placeholders = batch.map((r, idx) => {
                const base = idx * 8;
                values.push(r.regatta_date, r.regatta_name, r.location, r.event_website_url, null, null, 'clubspot', r.source_id);
                return `($${base+1},$${base+2},$${base+3},$${base+4},$${base+5},$${base+6},$${base+7},$${base+8})`;
            });
            try {
                const result = await pool.query(`
                    INSERT INTO regattas (regatta_date, regatta_name, location, event_website_url, registrants_url, registrant_count, source, source_id)
                    VALUES ${placeholders.join(',')}
                    ON CONFLICT (regatta_name, regatta_date, source)
                    DO UPDATE SET
                        location = EXCLUDED.location,
                        event_website_url = EXCLUDED.event_website_url,
                        source_id = EXCLUDED.source_id,
                        last_updated = CURRENT_TIMESTAMP
                `, values);
                added += result.rowCount || batch.length;
            } catch (err) {
                console.error(`Batch insert error (rows ${i}–${i + batch.length}):`, err.message);
            }
        }
        console.log(`💾 DB write complete: ${added} rows affected`);

        await pool.query(`
            INSERT INTO scrape_log (source, regattas_found, regattas_added)
            VALUES ('clubspot', $1, $2)
        `, [extractedRegattas.length, added]);

        console.log(`✅ Clubspot scrape complete: ${extractedRegattas.length} found, ${added} added/updated`);
        return { found: extractedRegattas.length, added };

    } catch (error) {
        console.error('Error scraping Clubspot via API:', error.message);
        if (error.response) {
            console.error('API response:', error.response.status, JSON.stringify(error.response.data));
        }

        try {
            await pool.query(`
                INSERT INTO scrape_log (source, regattas_found, regattas_added)
                VALUES ('clubspot', 0, 0)
            `);
        } catch (logError) {
            console.error('Error logging failed scrape:', logError.message);
        }

        return { found: 0, added: 0, error: error.message };
    }
}

// Search regattas endpoint
app.get('/api/search-regattas', async (req, res) => {
    try {
        const { date, startDate, endDate, location, name, q, latitude, longitude, radius, locationName } = req.query;

        let query = 'SELECT * FROM regattas WHERE 1=1';
        const params = [];
        let paramCount = 0;

        // Support date range (startDate and endDate), single date, or blank = today and forward
        if (startDate && endDate) {
            paramCount++;
            query += ` AND regatta_date::date >= $${paramCount}`;
            params.push(startDate);
            paramCount++;
            query += ` AND regatta_date::date <= $${paramCount}`;
            params.push(endDate);
        } else if (date) {
            paramCount++;
            query += ` AND regatta_date::date = $${paramCount}`;
            params.push(date);
        } else {
            query += ' AND regatta_date::date >= CURRENT_DATE';
        }

        if (q) {
            paramCount++;
            const qParam = paramCount;
            query += ` AND (location ILIKE $${qParam} OR regatta_name ILIKE $${qParam})`;
            params.push(`%${q}%`);
        } else {
            if (name) {
                paramCount++;
                query += ` AND regatta_name ILIKE $${paramCount}`;
                params.push(`%${name}%`);
            }
            if (location) {
                paramCount++;
                query += ` AND location ILIKE $${paramCount}`;
                params.push(`%${location}%`);
            }
        }

        // If locationName is provided (from reverse geocoding), try to match against regatta locations
        if (locationName) {
            const cityName = locationName.split(',')[0].trim();
            paramCount++;
            const cityParam = paramCount;
            paramCount++;
            const fullLocationParam = paramCount;
            query += ` AND (location ILIKE $${cityParam} OR location ILIKE $${fullLocationParam})`;
            params.push(`%${cityName}%`);
            params.push(`%${locationName}%`);
        }

        // If a single date is provided, prioritize alphabetical order within that date
        if (date && !startDate && !endDate) {
            query += ' ORDER BY regatta_name ASC';
        } else {
            query += ' ORDER BY regatta_date ASC, regatta_name ASC';
        }

        query += ' LIMIT 500';

        const result = await pool.query(query, params);
        res.json({ success: true, regattas: result.rows, count: result.rows.length });
    } catch (error) {
        console.error('Error searching regattas:', error);
        res.status(500).json({ error: 'Failed to search regattas', details: error.message });
    }
});

// Autocomplete suggestions for regatta names
app.get('/api/regatta-name-suggestions', async (req, res) => {
    try {
        const { query } = req.query;

        if (!query || query.length < 2) {
            return res.json({ success: true, suggestions: [] });
        }

        const result = await pool.query(`
      SELECT DISTINCT regatta_name
      FROM regattas
      WHERE regatta_name ILIKE $1
      ORDER BY regatta_name
      LIMIT 10
    `, [`%${query}%`]);

        const suggestions = result.rows.map(row => row.regatta_name);
        res.json({ success: true, suggestions });
    } catch (error) {
        console.error('Error fetching regatta name suggestions:', error);
        res.status(500).json({ error: 'Failed to fetch suggestions', details: error.message });
    }
});

// Autocomplete suggestions for locations
app.get('/api/location-suggestions', async (req, res) => {
    try {
        const { query } = req.query;

        if (!query || query.length < 2) {
            return res.json({ success: true, suggestions: [] });
        }

        const result = await pool.query(`
      SELECT DISTINCT location
      FROM regattas
      WHERE location IS NOT NULL 
      AND location != ''
      AND location ILIKE $1
      -- Filter out regatta names that might be in location field
      -- Locations typically contain commas (City, State) or are short city names
      AND (
        location LIKE '%,%' 
        OR location ~ '^[A-Z][a-z]+(, [A-Z]{2})?$'
        OR LENGTH(location) < 50
      )
      -- Exclude common regatta name patterns
      AND location !~* '(regatta|series|championship|cup|race|invitational|event|tournament)'
      ORDER BY location
      LIMIT 10
    `, [`%${query}%`]);

        const suggestions = result.rows.map(row => row.location);
        res.json({ success: true, suggestions });
    } catch (error) {
        console.error('Error fetching location suggestions:', error);
        res.status(500).json({ error: 'Failed to fetch suggestions', details: error.message });
    }
});

// Web-Alert proxy: forward to external monitor service
// WEBALERT_API_URL: base (e.g. https://webalert.lab007.ai) or full endpoint (e.g. https://www.lab007.ai/webalert/api/monitor)
app.post('/api/webalert/monitor', async (req, res) => {
    const baseUrl = (process.env.WEBALERT_API_URL || '').trim();
    let target;
    try {
        if (!baseUrl) {
            return res.status(503).json({
                success: false,
                error: 'Web-Alert service not configured. Set WEBALERT_API_URL environment variable.'
            });
        }
        if (!/^https?:\/\//i.test(baseUrl)) {
            return res.status(503).json({
                success: false,
                error: 'WEBALERT_API_URL must include protocol (e.g. https://webalert.lab007.ai)'
            });
        }
        // If baseUrl already ends with /webalert/api/monitor, use as-is; otherwise append
        target = /\/webalert\/api\/monitor\/?$/i.test(baseUrl)
            ? baseUrl.replace(/\/$/, '')
            : baseUrl.replace(/\/$/, '') + '/webalert/api/monitor';
        const { websiteUrl, email, phone, duration, pollingInterval } = req.body || {};
        if (!websiteUrl || !String(websiteUrl).trim()) {
            return res.status(400).json({ success: false, error: 'websiteUrl is required' });
        }
        const payload = {
            websiteUrl: String(websiteUrl).trim(),
            duration: duration || '420',
            pollingInterval: pollingInterval || '10'
        };
        if (email) payload.email = String(email).trim();
        if (phone) payload.phone = String(phone).trim();
        console.log('[Web-Alert] websiteUrl:', payload.websiteUrl, '| target:', target);
        const r = await axios.post(target, payload, {
            headers: { 'Content-Type': 'application/json' },
            timeout: 30000
        });
        res.json(r.data || { success: true });
    } catch (e) {
        console.error('[Web-Alert] error:', e.message, '| response:', e.response?.data, '| target:', target || baseUrl || 'N/A');
        res.status(502).json({
            success: false,
            error: e.response?.data?.error || e.message
        });
    }
});

// Admin stats endpoint
app.get('/api/regatta-stats', async (req, res) => {
    try {
        // Get total regattas count
        const totalResult = await pool.query('SELECT COUNT(*) as total FROM regattas');
        const total = parseInt(totalResult.rows[0].total);

        // Get count by source
        const sourceResult = await pool.query(`
      SELECT source, COUNT(*) as count 
      FROM regattas 
      GROUP BY source
    `);

        // Get last scrape times
        const lastScrapeResult = await pool.query(`
      SELECT source, MAX(scrape_time) as last_scrape, 
             SUM(regattas_found) as total_found,
             SUM(regattas_added) as total_added
      FROM scrape_log 
      GROUP BY source
    `);

        // Get upcoming regattas count
        const today = new Date().toISOString().split('T')[0];
        const upcomingResult = await pool.query(`
      SELECT COUNT(*) as count 
      FROM regattas 
      WHERE regatta_date >= $1
    `, [today]);

        res.json({
            success: true,
            totalRegattas: total,
            upcomingRegattas: parseInt(upcomingResult.rows[0].count),
            bySource: sourceResult.rows,
            lastScrapes: lastScrapeResult.rows
        });
    } catch (error) {
        console.error('Error getting regatta stats:', error);
        res.status(500).json({ error: 'Failed to get stats', details: error.message });
    }
});

// Clear all regattas endpoint
app.delete('/api/clear-all-regattas', async (req, res) => {
    try {
        // Delete all regattas
        const deleteResult = await pool.query('DELETE FROM regattas');
        const deletedCount = deleteResult.rowCount;

        // Also clear scrape log
        await pool.query('DELETE FROM scrape_log');

        console.log(`Cleared ${deletedCount} regattas from database`);

        res.json({
            success: true,
            message: `Successfully cleared ${deletedCount} regattas from database`,
            deletedCount: deletedCount
        });
    } catch (error) {
        console.error('Error clearing regattas:', error);
        res.status(500).json({
            error: 'Failed to clear regattas',
            details: error.message
        });
    }
});

// Get all regattas for admin page
app.get('/api/all-regattas', async (req, res) => {
    try {
        const {
            limit = 1000,
            offset = 0,
            orderBy = 'regatta_date',
            order = 'ASC',
            dateFilter = '',
            nameFilter = '',
            locationFilter = '',
            sourceFilter = ''
        } = req.query;

        const validOrderBy = ['regatta_date', 'regatta_name', 'location', 'source'];
        const validOrder = ['ASC', 'DESC'];
        const orderByColumn = validOrderBy.includes(orderBy) ? orderBy : 'regatta_date';
        const orderDirection = validOrder.includes(order.toUpperCase()) ? order.toUpperCase() : 'ASC';

        // Build WHERE clause for filters
        let whereClause = 'WHERE 1=1';
        const params = [];
        let paramCount = 0;

        if (dateFilter) {
            paramCount++;
            whereClause += ` AND regatta_date::text ILIKE $${paramCount}`;
            params.push(`%${dateFilter}%`);
        }

        if (nameFilter) {
            paramCount++;
            whereClause += ` AND regatta_name ILIKE $${paramCount}`;
            params.push(`%${nameFilter}%`);
        }

        if (locationFilter) {
            paramCount++;
            whereClause += ` AND (location ILIKE $${paramCount} OR location IS NULL)`;
            params.push(`%${locationFilter}%`);
        }

        if (sourceFilter) {
            paramCount++;
            whereClause += ` AND source = $${paramCount}`;
            params.push(sourceFilter);
        }

        // Add limit and offset
        paramCount++;
        params.push(parseInt(limit));
        paramCount++;
        params.push(parseInt(offset));

        const result = await pool.query(`
      SELECT regatta_date, regatta_name, location, event_website_url, registrants_url, registrant_count, source
      FROM regattas
      ${whereClause}
      ORDER BY ${orderByColumn} ${orderDirection}
      LIMIT $${paramCount - 1} OFFSET $${paramCount}
    `, params);

        // Get total count for pagination
        const countResult = await pool.query(`
      SELECT COUNT(*) as total
      FROM regattas
      ${whereClause}
    `, params.slice(0, -2)); // Remove limit and offset params

        res.json({
            success: true,
            regattas: result.rows,
            count: result.rows.length,
            total: parseInt(countResult.rows[0].total)
        });
    } catch (error) {
        console.error('Error getting all regattas:', error);
        res.status(500).json({ error: 'Failed to get regattas', details: error.message });
    }
});

// Email forwarding endpoint (for free Render service)
app.post('/api/send-email', (req, res) => {
    console.log('=== Email Forwarding Request Received ===');

    // Optional: Check API key if set
    if (EMAIL_SERVICE_API_KEY && req.headers['x-api-key'] !== EMAIL_SERVICE_API_KEY) {
        console.error('Invalid API key provided');
        return res.status(401).json({ error: 'Invalid API key' });
    }

    const { from, to, subject, text, attachment } = req.body;

    // Validate required fields
    if (!from || !to || !subject || !text) {
        console.error('Missing required fields:', { from: !!from, to: !!to, subject: !!subject, text: !!text });
        return res.status(400).json({ error: 'Missing required fields: from, to, subject, text' });
    }

    console.log(`Sending email from ${from} to ${to}`);
    console.log(`Subject: ${subject}`);
    console.log(`Has attachment: ${!!attachment}`);

    // Validate attachment if provided
    if (attachment) {
        if (!attachment.filename || !attachment.content) {
            console.error('Invalid attachment format:', { hasFilename: !!attachment.filename, hasContent: !!attachment.content });
            return res.status(400).json({
                error: 'Invalid attachment format',
                details: 'attachment must include filename and content (base64 encoded)'
            });
        }
        console.log(`Attachment: ${attachment.filename} (${attachment.content.length} characters)`);
    }

    const mailOptions = {
        from: from,
        to: to,
        subject: subject,
        text: text,
        attachments: attachment ? [
            {
                filename: attachment.filename,
                content: attachment.content,
                encoding: attachment.encoding || 'base64'
            }
        ] : []
    };

    emailTransporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.error('=== Email Send FAILED ===');
            console.error('Error:', error.message);
            console.error('Error Code:', error.code);
            console.error('Full Error:', error);
            return res.status(500).json({
                error: 'Failed to send email',
                details: error.message,
                code: error.code
            });
        }

        console.log('=== Email Send SUCCESS ===');
        console.log('Message ID:', info.messageId);
        console.log('Response:', info.response);
        res.json({
            success: true,
            messageId: info.messageId,
            response: info.response
        });
    });
});

// Start the server (AFTER all routes are defined)
const server = app.listen(port, () => {
    console.log(`Server running on port ${port}`);
    console.log('Server is ready to accept requests');
});

// Log Puppeteer status after server starts
if (puppeteer) {
    console.log('✓ Puppeteer module loaded - Clubspot scraping available');
} else {
    console.warn('⚠ Puppeteer is NOT loaded - Clubspot scraping will be disabled');
}

// Initialize asynchronously in background (don't await)
setTimeout(() => {
    initializeServer().catch(err => {
        console.error('Server initialization error:', err.message);
    });
}, 1000); // Wait 1 second after server starts

// Separate function for server initialization
async function initializeServer() {
    try {
        await ensureDirectories();
        await createPhotoMetadataTable();
        await createUserTables();
        await createRegattasTable();
        await ensureRegattaNetworkDataTable();
        await createTrackerTables();
        await createPiTables();
        await testS3Connection();
        console.log('✓ Server initialization complete');
    } catch (startupError) {
        console.error('Error during server initialization:', startupError);
        console.error('Stack:', startupError.stack);
    }
}

// ─── PiSailBox Device Management ──────────────────────────────────────────────

const PI_CAPTURES_DIR = path.join(__dirname, 'pi_captures');
if (!fs.existsSync(PI_CAPTURES_DIR)) fs.mkdirSync(PI_CAPTURES_DIR, { recursive: true });

// Serve stored Pi photos as static files
app.use('/pi_captures', express.static(PI_CAPTURES_DIR));

async function createPiTables() {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS pi_devices (
            id          SERIAL PRIMARY KEY,
            device_id   TEXT UNIQUE NOT NULL,
            name        TEXT,
            last_seen   TIMESTAMP,
            ip_address  TEXT,
            os_info     TEXT,
            config      JSONB NOT NULL DEFAULT '{}',
            created_at  TIMESTAMP NOT NULL DEFAULT NOW()
        )
    `);
    await pool.query(`
        CREATE TABLE IF NOT EXISTS pi_photos (
            id          SERIAL PRIMARY KEY,
            device_id   TEXT NOT NULL,
            filename    TEXT NOT NULL,
            captured_at TIMESTAMP,
            uploaded_at TIMESTAMP NOT NULL DEFAULT NOW(),
            file_size   INTEGER,
            storage_path TEXT,
            lat         DOUBLE PRECISION,
            lng         DOUBLE PRECISION
        )
    `);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_pi_photos_device ON pi_photos(device_id)`);
    // Migrations: add columns to existing tables
    await pool.query(`ALTER TABLE pi_devices ADD COLUMN IF NOT EXISTS sim_status        JSONB DEFAULT '{}'`);
    await pool.query(`ALTER TABLE pi_devices ADD COLUMN IF NOT EXISTS ip_addresses      JSONB DEFAULT '{}'`);
    await pool.query(`ALTER TABLE pi_devices ADD COLUMN IF NOT EXISTS pending_commands  JSONB DEFAULT '[]'`);
    await pool.query(`ALTER TABLE pi_devices ADD COLUMN IF NOT EXISTS gps_status          JSONB DEFAULT '{}'`);
    await pool.query(`ALTER TABLE pi_devices ADD COLUMN IF NOT EXISTS service_started_at  TIMESTAMPTZ`);
    console.log('✓ PiSailBox tables ready');
}

// Default config template for new devices
function defaultPiConfig() {
    return {
        auto_track: false,                  // start GPS tracking automatically on boot
        gps_poll_seconds: 10,               // how often to read GPS position (seconds)
        gps_upload_interval_seconds: 60,    // how often to send batched points to server
        camera_enabled: false,
        camera_auto_photo: false,
        photo_interval_seconds: 30,
        photo_session_minutes: 60,
        photo_upload_interval_minutes: 5,
        video_enabled: false,
        video_auto_record: false,
        video_interval_minutes: 10,
        video_duration_seconds: 60,
        sim_apn: '',
        sim_apn_user: '',
        sim_apn_pass: '',
        sim_status_interval_seconds: 60
    };
}

// Register / heartbeat — called by Pi on boot and periodically
app.post('/api/pi/register', express.json(), async (req, res) => {
    try {
        const { device_id, name, ip_address, ip_addresses, os_info, started_at } = req.body;
        if (!device_id) return res.status(400).json({ error: 'device_id required' });

        // Build a display IP — prefer the first non-loopback from ip_addresses map
        let displayIp = ip_address || null;
        if (ip_addresses && typeof ip_addresses === 'object') {
            const preferred = ['wlan0','eth0','wwan0','ppp0','usb0'];
            for (const iface of preferred) {
                if (ip_addresses[iface]) { displayIp = ip_addresses[iface]; break; }
            }
            if (!displayIp) {
                const first = Object.values(ip_addresses)[0];
                if (first) displayIp = first;
            }
        }

        const result = await pool.query(`
            INSERT INTO pi_devices (device_id, name, ip_address, ip_addresses, os_info, last_seen, config, service_started_at)
            VALUES ($1, $2, $3, $4, $5, NOW(), $6, $7)
            ON CONFLICT (device_id) DO UPDATE SET
                name                = COALESCE(EXCLUDED.name, pi_devices.name),
                ip_address          = EXCLUDED.ip_address,
                ip_addresses        = EXCLUDED.ip_addresses,
                os_info             = EXCLUDED.os_info,
                last_seen           = NOW(),
                pending_commands    = '[]',
                service_started_at  = COALESCE(EXCLUDED.service_started_at, pi_devices.service_started_at)
            RETURNING *
        `, [device_id, name || device_id, displayIp, JSON.stringify(ip_addresses || {}),
            os_info || null, JSON.stringify(defaultPiConfig()), started_at || null]);

        const device = result.rows[0];
        const config = typeof device.config === 'string' ? JSON.parse(device.config) : device.config;
        res.json({ ok: true, device_id: device.device_id, config });
    } catch (err) {
        console.error('Pi register error:', err.message);
        res.status(500).json({ error: err.message });
    }
});

// Get device config (polled by Pi) — also returns and clears any pending commands
app.get('/api/pi/devices/:deviceId/config', async (req, res) => {
    try {
        const result = await pool.query(
            `UPDATE pi_devices
             SET last_seen = NOW(), pending_commands = '[]'
             WHERE device_id = $1
             RETURNING config, pending_commands`,
            [req.params.deviceId]
        );
        if (!result.rows.length) return res.status(404).json({ error: 'Device not found' });
        const row = result.rows[0];
        const config   = row.config || defaultPiConfig();
        const commands = row.pending_commands || [];
        // Embed commands inside the config response under a reserved key
        config.__commands = Array.isArray(commands) ? commands : [];
        res.json(config);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Queue a remote command for the Pi to execute on its next config poll
// Valid commands: start_track, stop_track, capture_photo, start_video, stop_video
app.post('/api/pi/devices/:deviceId/command', express.json(), async (req, res) => {
    try {
        const { command } = req.body;
        const deviceId = req.params.deviceId;
        const valid = ['start_track','stop_track','capture_photo','start_video','stop_video','restart','test_sim'];
        if (!valid.includes(command)) {
            return res.status(400).json({ error: `Unknown command. Valid: ${valid.join(', ')}` });
        }

        // start_track / stop_track: manage the track server-side so it works over SIM MQTT
        if (command === 'start_track') {
            // Create the track now so we can embed the id in the MQTT config
            const now = new Date();
            const etOffset = -5 * 60;  // ET = UTC-5 (close enough for name label)
            const etTime = new Date(now.getTime() + etOffset * 60000);
            const trackName = `${deviceId} — ${etTime.toISOString().slice(0,16).replace('T',' ')} ET`;
            const trackResult = await pool.query(
                `INSERT INTO tracks (name, device_name) VALUES ($1, $2) RETURNING id`,
                [trackName, deviceId]
            );
            const trackId = trackResult.rows[0].id;
            // Store active_track_id in config so Pi uses it via MQTT or HTTP poll
            await pool.query(
                `UPDATE pi_devices SET config = config || $1::jsonb WHERE device_id = $2`,
                [JSON.stringify({ active_track_id: trackId }), deviceId]
            );
            console.log(`start_track: created track ${trackId} for ${deviceId}`);

        } else if (command === 'stop_track') {
            // End the active track on the server now
            await pool.query(
                `UPDATE tracks SET ended_at = NOW() WHERE device_name = $1 AND ended_at IS NULL`,
                [deviceId]
            );
            // Clear active_track_id from config
            await pool.query(
                `UPDATE pi_devices SET config = config - 'active_track_id' WHERE device_id = $1`,
                [deviceId]
            );
            console.log(`stop_track: ended active track(s) for ${deviceId}`);
        }

        // Add command to pending_commands (Pi picks up via HTTP poll or MQTT)
        await pool.query(
            `UPDATE pi_devices
             SET pending_commands = (
                 SELECT jsonb_agg(DISTINCT v)
                 FROM jsonb_array_elements_text(
                     COALESCE(pending_commands, '[]'::jsonb) || $1::jsonb
                 ) v
             )
             WHERE device_id = $2`,
            [JSON.stringify([command]), deviceId]
        );

        // Push updated config+commands to Pi via MQTT (works without WiFi)
        await publishMqttDeviceConfig(deviceId);

        res.json({ ok: true, command, note: 'Sent via MQTT and queued for HTTP poll' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Update device config (from admin panel)
app.put('/api/pi/devices/:deviceId/config', express.json(), async (req, res) => {
    try {
        const deviceId = req.params.deviceId;
        const result = await pool.query(
            `UPDATE pi_devices SET config = $1 WHERE device_id = $2 RETURNING *`,
            [JSON.stringify(req.body), deviceId]
        );
        if (!result.rows.length) return res.status(404).json({ error: 'Device not found' });
        // Push updated config to Pi via MQTT so it picks it up even without WiFi
        await publishMqttDeviceConfig(deviceId);
        res.json({ ok: true, config: result.rows[0].config });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Rename a device
app.patch('/api/pi/devices/:deviceId', express.json(), async (req, res) => {
    try {
        const { name } = req.body;
        const result = await pool.query(
            `UPDATE pi_devices SET name = $1 WHERE device_id = $2 RETURNING *`,
            [name, req.params.deviceId]
        );
        res.json(result.rows[0] || {});
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// List all registered devices
app.get('/api/pi/devices', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT d.*,
                (SELECT COUNT(*) FROM pi_photos p WHERE p.device_id = d.device_id)::int AS photo_count,
                NOW() - d.last_seen < INTERVAL '2 minutes' AS online,
                EXISTS (
                    SELECT 1 FROM tracks t
                    WHERE t.device_name = d.device_id
                    AND t.ended_at IS NULL
                ) AS tracking_active,
                (
                    SELECT tp.recorded_at
                    FROM track_points tp
                    JOIN tracks t ON t.id = tp.track_id
                    WHERE t.device_name = d.device_id
                    ORDER BY tp.recorded_at DESC
                    LIMIT 1
                ) AS last_gps_at
            FROM pi_devices d
            ORDER BY d.last_seen DESC NULLS LAST
        `);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Pi reports SIM / modem status (called periodically by the Pi)
app.post('/api/pi/devices/:deviceId/sim-status', express.json(), async (req, res) => {
    try {
        const incoming = req.body && typeof req.body === 'object' ? req.body : {};
        const status = { ...incoming, reported_at: new Date().toISOString() };
        await pool.query(
            `UPDATE pi_devices SET sim_status = $1, last_seen = NOW() WHERE device_id = $2`,
            [JSON.stringify(status), req.params.deviceId]
        );
        res.json({ ok: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Get latest SIM status for a device (used by admin panel)
app.get('/api/pi/devices/:deviceId/sim-status', async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT sim_status FROM pi_devices WHERE device_id = $1`,
            [req.params.deviceId]
        );
        if (!result.rows.length) return res.status(404).json({ error: 'Device not found' });
        res.json(result.rows[0].sim_status || {});
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// GPS status — Pi reports diagnostic info
app.post('/api/pi/devices/:deviceId/gps-status', express.json(), async (req, res) => {
    try {
        await pool.query(
            `UPDATE pi_devices SET gps_status = $1, last_seen = NOW() WHERE device_id = $2`,
            [JSON.stringify(req.body), req.params.deviceId]
        );
        res.json({ ok: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/pi/devices/:deviceId/gps-status', async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT gps_status FROM pi_devices WHERE device_id = $1`,
            [req.params.deviceId]
        );
        if (!result.rows.length) return res.status(404).json({ error: 'Device not found' });
        res.json(result.rows[0].gps_status || {});
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Delete a device
app.delete('/api/pi/devices/:deviceId', async (req, res) => {
    try {
        await pool.query(`DELETE FROM pi_devices WHERE device_id = $1`, [req.params.deviceId]);
        res.json({ ok: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Upload batch of photos from Pi (multipart, multiple files)
app.post('/api/pi/devices/:deviceId/photos', upload.array('photos', 50), async (req, res) => {
    try {
        const deviceId = req.params.deviceId;
        const files = req.files || [];
        const meta = req.body.meta ? JSON.parse(req.body.meta) : [];  // [{captured_at, lat, lng}, ...]

        const today = new Date().toISOString().slice(0, 10);
        const deviceDir = path.join(PI_CAPTURES_DIR, deviceId, today);
        if (!fs.existsSync(deviceDir)) fs.mkdirSync(deviceDir, { recursive: true });

        const saved = [];
        for (let i = 0; i < files.length; i++) {
            const file = files[i];
            const m = meta[i] || {};
            const ts = m.captured_at ? new Date(m.captured_at).getTime() : Date.now();
            const filename = `${ts}_${i}.jpg`;
            const storagePath = path.join(deviceDir, filename);
            fs.writeFileSync(storagePath, file.buffer);

            const webPath = `/pi_captures/${deviceId}/${today}/${filename}`;
            await pool.query(
                `INSERT INTO pi_photos (device_id, filename, captured_at, file_size, storage_path, lat, lng)
                 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
                [deviceId, filename, m.captured_at || new Date(), file.size,
                 webPath, m.lat || null, m.lng || null]
            );
            saved.push(webPath);
        }

        res.json({ ok: true, saved: saved.length });
    } catch (err) {
        console.error('Pi photo upload error:', err.message);
        res.status(500).json({ error: err.message });
    }
});

// List photos for a device
app.get('/api/pi/devices/:deviceId/photos', async (req, res) => {
    try {
        const limit = Math.min(parseInt(req.query.limit) || 50, 200);
        const result = await pool.query(
            `SELECT * FROM pi_photos WHERE device_id = $1 ORDER BY captured_at DESC LIMIT $2`,
            [req.params.deviceId, limit]
        );
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Bulk-delete photos for a device
app.delete('/api/pi/devices/:deviceId/photos', express.json(), async (req, res) => {
    try {
        const { ids } = req.body;
        if (!Array.isArray(ids) || ids.length === 0) {
            return res.status(400).json({ error: 'ids array required' });
        }

        // Fetch storage paths before deleting so we can remove the files
        const placeholders = ids.map((_, i) => `$${i + 2}`).join(',');
        const rows = await pool.query(
            `SELECT id, storage_path FROM pi_photos WHERE device_id = $1 AND id IN (${placeholders})`,
            [req.params.deviceId, ...ids]
        );

        // Delete DB records
        await pool.query(
            `DELETE FROM pi_photos WHERE device_id = $1 AND id IN (${placeholders})`,
            [req.params.deviceId, ...ids]
        );

        // Delete files from disk (storage_path is a web path like /pi_captures/...)
        let filesDeleted = 0;
        for (const row of rows.rows) {
            if (row.storage_path) {
                // Convert web path → absolute filesystem path
                const relPath = row.storage_path.replace(/^\/pi_captures\//, '');
                const absPath = path.join(PI_CAPTURES_DIR, relPath);
                try {
                    if (fs.existsSync(absPath)) {
                        fs.unlinkSync(absPath);
                        filesDeleted++;
                    }
                } catch (e) {
                    console.warn(`Could not delete file ${absPath}: ${e.message}`);
                }
            }
        }

        res.json({ ok: true, deleted: rows.rows.length, filesDeleted });
    } catch (err) {
        console.error('Pi photo delete error:', err.message);
        res.status(500).json({ error: err.message });
    }
});

// ─── GPS Tracker ─────────────────────────────────────────────────────────────

async function createTrackerTables() {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS tracks (
            id          SERIAL PRIMARY KEY,
            name        TEXT,
            device_name TEXT,
            started_at  TIMESTAMP NOT NULL DEFAULT NOW(),
            ended_at    TIMESTAMP,
            created_at  TIMESTAMP NOT NULL DEFAULT NOW()
        )
    `);
    await pool.query(`
        CREATE TABLE IF NOT EXISTS track_points (
            id          SERIAL PRIMARY KEY,
            track_id    INTEGER NOT NULL REFERENCES tracks(id) ON DELETE CASCADE,
            lat         DOUBLE PRECISION NOT NULL,
            lng         DOUBLE PRECISION NOT NULL,
            accuracy    REAL,
            altitude    REAL,
            speed       REAL,
            heading     REAL,
            recorded_at TIMESTAMP NOT NULL DEFAULT NOW()
        )
    `);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_track_points_track_id ON track_points(track_id)`);
    console.log('✓ Tracker tables ready');
}

// Start a new track
app.post('/api/tracks', async (req, res) => {
    try {
        const { name, device_name } = req.body || {};
        const result = await pool.query(
            `INSERT INTO tracks (name, device_name) VALUES ($1, $2) RETURNING *`,
            [name || null, device_name || null]
        );
        res.json(result.rows[0]);
    } catch (err) {
        console.error('Error starting track:', err.message);
        res.status(500).json({ error: err.message });
    }
});

// Stop a track
app.patch('/api/tracks/:id/stop', async (req, res) => {
    try {
        const result = await pool.query(
            `UPDATE tracks SET ended_at = NOW() WHERE id = $1 AND ended_at IS NULL RETURNING *`,
            [req.params.id]
        );
        if (result.rows.length === 0) return res.status(404).json({ error: 'Track not found or already stopped' });
        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Add a GPS point to a track
app.post('/api/tracks/:id/points', async (req, res) => {
    try {
        const { lat, lng, accuracy, altitude, speed, heading } = req.body;
        if (!lat || !lng) return res.status(400).json({ error: 'lat and lng are required' });
        const result = await pool.query(
            `INSERT INTO track_points (track_id, lat, lng, accuracy, altitude, speed, heading)
             VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
            [req.params.id, lat, lng, accuracy || null, altitude || null, speed || null, heading || null]
        );
        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// List all tracks with point count and computed stats
app.get('/api/tracks', async (req, res) => {
    try {
        const device = req.query.device || null;
        const params = device ? [device] : [];
        const where  = device ? `WHERE t.device_name = $1` : '';
        const result = await pool.query(`
            SELECT
                t.*,
                COUNT(p.id)::int                                    AS point_count,
                MIN(p.recorded_at)                                  AS first_point_at,
                MAX(p.recorded_at)                                  AS last_point_at,
                MAX(p.speed)                                        AS max_speed_ms,
                AVG(NULLIF(p.speed, 0))                             AS avg_speed_ms
            FROM tracks t
            LEFT JOIN track_points p ON p.track_id = t.id
            ${where}
            GROUP BY t.id
            ORDER BY t.started_at DESC
        `, params);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Get all points for a track
app.get('/api/tracks/:id/points', async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT * FROM track_points WHERE track_id = $1 ORDER BY recorded_at ASC`,
            [req.params.id]
        );
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Delete a track (cascade deletes points)
app.delete('/api/tracks/:id', async (req, res) => {
    try {
        await pool.query(`DELETE FROM tracks WHERE id = $1`, [req.params.id]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Delete ALL tracks for a device
app.delete('/api/tracks', async (req, res) => {
    try {
        const { device } = req.query;
        if (!device) return res.status(400).json({ error: 'device query param required' });
        const result = await pool.query(
            `DELETE FROM tracks WHERE device_name = $1`, [device]
        );
        res.json({ success: true, deleted: result.rowCount });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Rename a track
app.patch('/api/tracks/:id', async (req, res) => {
    try {
        const { name } = req.body;
        const result = await pool.query(
            `UPDATE tracks SET name = $1 WHERE id = $2 RETURNING *`,
            [name, req.params.id]
        );
        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Latest position for every currently-active track (live multi-device view)
app.get('/api/tracks/live', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT
                t.id, t.name, t.device_name, t.started_at,
                p.lat, p.lng, p.accuracy, p.speed, p.heading,
                p.recorded_at AS point_time,
                (SELECT COUNT(*) FROM track_points WHERE track_id = t.id)::int AS point_count
            FROM tracks t
            LEFT JOIN LATERAL (
                SELECT * FROM track_points
                WHERE track_id = t.id
                ORDER BY recorded_at DESC
                LIMIT 1
            ) p ON true
            WHERE t.ended_at IS NULL
              AND p.recorded_at > NOW() - INTERVAL '10 minutes'
            ORDER BY t.started_at DESC
        `);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Group finished + active tracks into sessions (tracks starting within 1 hour of each other)
app.get('/api/tracks/sessions', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT t.*, COUNT(p.id)::int AS point_count
            FROM tracks t
            LEFT JOIN track_points p ON p.track_id = t.id
            GROUP BY t.id
            ORDER BY t.started_at ASC
        `);
        const tracks = result.rows;

        // Group by 1-hour window from earliest track in each session
        const sessions = [];
        const assigned = new Set();

        for (const track of tracks) {
            if (assigned.has(track.id)) continue;
            const anchor = new Date(track.started_at);
            const group = [track];
            assigned.add(track.id);

            for (const other of tracks) {
                if (assigned.has(other.id)) continue;
                const diffH = (new Date(other.started_at) - anchor) / 3600000;
                if (diffH >= 0 && diffH <= 1) {
                    group.push(other);
                    assigned.add(other.id);
                }
            }

            sessions.push({
                id: sessions.length,
                label: anchor.toLocaleDateString() + ' ' +
                       anchor.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
                started_at: track.started_at,
                track_count: group.length,
                total_points: group.reduce((s, t) => s + (t.point_count || 0), 0),
                tracks: group
            });
        }

        // Newest sessions first
        sessions.sort((a, b) => new Date(b.started_at) - new Date(a.started_at));
        res.json(sessions);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ── SIM MQTT manager ─────────────────────────────────────────────────────────
// Bidirectional MQTT bridge for PiSailBox devices.
//
// Pi → server:  pisailbox/{id}/gps     GPS track points
//               pisailbox/{id}/status  device diagnostics (updates last_seen / gps_status)
// Server → Pi:  pisailbox/{id}/config  RETAINED — full config + active_track_id + __commands
//               Pi subscribes each cycle and picks up any changes without WiFi.

let pisailboxMqtt = null;

(function startMqttManager() {
    const BROKER = process.env.PISAILBOX_MQTT_BROKER || 'mqtt://broker.hivemq.com:1883';

    pisailboxMqtt = mqtt.connect(BROKER, {
        clientId:        `lovesailing-server-${Math.random().toString(16).slice(2, 8)}`,
        clean:           true,
        reconnectPeriod: 5000,
        connectTimeout:  15000,
    });

    pisailboxMqtt.on('connect', () => {
        console.log(`MQTT: connected to ${BROKER}`);
        pisailboxMqtt.subscribe('pisailbox/+/gps',    { qos: 1 }, (err) => { if (err) console.error('MQTT sub gps error:', err); });
        pisailboxMqtt.subscribe('pisailbox/+/status', { qos: 0 }, (err) => { if (err) console.error('MQTT sub status error:', err); });
    });

    pisailboxMqtt.on('reconnect', () => console.log('MQTT: reconnecting…'));
    pisailboxMqtt.on('error',     (e) => console.error('MQTT error:', e.message));

    pisailboxMqtt.on('message', async (topic, buffer) => {
        try {
            const parts    = topic.split('/');
            const deviceId = parts[1];
            const msgType  = parts[2];
            const data     = JSON.parse(buffer.toString());

            if (msgType === 'gps') {
                const { lat, lng, speed, altitude, accuracy, heading, track_id } = data;
                if (!lat || !lng || !track_id) {
                    console.warn(`MQTT: incomplete GPS payload on ${topic}:`, data);
                    return;
                }
                await pool.query(
                    `INSERT INTO track_points (track_id, lat, lng, accuracy, altitude, speed, heading)
                     VALUES ($1,$2,$3,$4,$5,$6,$7)`,
                    [track_id, lat, lng, accuracy || null, altitude || null, speed || null, heading || null]
                );
                console.log(`MQTT: GPS point track=${track_id} lat=${lat} lng=${lng}`);

            } else if (msgType === 'status') {
                // Pi publishes status (gps diagnostics, tracking_active, etc.)
                // Update last_seen + gps_status in DB
                await pool.query(
                    `UPDATE pi_devices SET last_seen = NOW(), gps_status = $1 WHERE device_id = $2`,
                    [JSON.stringify(data), deviceId]
                );
                console.log(`MQTT: status from ${deviceId} — tracking=${data.tracking_active} fix=${data.fix_valid}`);
            }
        } catch (e) {
            console.error('MQTT message handler error:', e.message);
        }
    });
})();

// Publish retained config + commands to the Pi's MQTT config topic.
// Pi subscribes each cycle and reacts to any changes, even without WiFi.
async function publishMqttDeviceConfig(deviceId) {
    if (!pisailboxMqtt || !pisailboxMqtt.connected) {
        console.log(`MQTT: not connected, skipping config publish for ${deviceId}`);
        return;
    }
    try {
        const result = await pool.query(
            `SELECT config, pending_commands FROM pi_devices WHERE device_id = $1`,
            [deviceId]
        );
        if (!result.rows.length) return;

        const row      = result.rows[0];
        const config   = typeof row.config === 'string' ? JSON.parse(row.config) : (row.config || {});
        const commands = Array.isArray(row.pending_commands) ? row.pending_commands : [];

        const payload  = JSON.stringify({ ...config, __commands: commands });

        pisailboxMqtt.publish(`pisailbox/${deviceId}/config`, payload, { retain: true, qos: 1 }, (err) => {
            if (err) console.error(`MQTT: config publish failed for ${deviceId}:`, err);
            else     console.log(`MQTT: published retained config for ${deviceId} (track=${config.active_track_id || 'none'})`);
        });
    } catch (e) {
        console.error('publishMqttDeviceConfig error:', e.message);
    }
}

// ─────────────────────────────────────────────────────────────────────────────

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
