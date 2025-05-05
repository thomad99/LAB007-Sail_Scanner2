const express = require('express');
const { Pool } = require('pg');
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
    ListObjectsV2Command
} = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

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

// Helper function to list objects in S3
async function listS3Objects(prefix = '') {
    try {
        console.log(`Listing S3 objects with prefix: ${prefix}`);
        const command = new ListObjectsV2Command({
            Bucket: BUCKET_NAME,
            Prefix: prefix
        });
        const response = await s3Client.send(command);
        console.log(`Found ${response.Contents?.length || 0} objects in S3`);
        return response.Contents || [];
    } catch (err) {
        console.error('Error listing S3 objects:', err);
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

// Add these constants at the top
const MAX_RETRIES = 3;
const BASE_RETRY_DELAY = 5000; // 5 seconds

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

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(UPLOAD_DIR));
app.use('/Images', express.static(PROCESSED_DIR));

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

// Add these environment variables in Render
const computerVisionKey = process.env.AZURE_VISION_KEY;
const computerVisionEndpoint = process.env.AZURE_VISION_ENDPOINT;

// Initialize Azure client
const computerVisionClient = new ComputerVisionClient(
    new CognitiveServicesCredentials(computerVisionKey),
    computerVisionEndpoint
);

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
        console.log('Photo metadata table created or verified');
    } catch (err) {
        console.error('Error creating photo metadata table:', err);
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

// Call this when the server starts
app.listen(port, async () => {
    console.log(`Server running on port ${port}`);
    await ensureDirectories();
    await createPhotoMetadataTable();
    await createUserTables();
    await testS3Connection();
});

// Update the scan endpoint to include metadata
app.post('/api/scan', upload.single('image'), async (req, res) => {
    let processedFiles = [];
    const metadata = {
        date: req.body.date || new Date().toISOString().split('T')[0],
        regatta_name: req.body.regatta_name,
        photographer_name: req.body.photographer_name,
        photographer_website: req.body.photographer_website,
        location: req.body.location,
        additional_tags: req.body.additional_tags ? req.body.additional_tags.split(',').map(tag => tag.trim()) : []
    };

    try {
        console.log('=== Starting New Scan ===');

        if (!req.file || !req.file.buffer) {
            throw new Error('No image file received');
        }

        const originalFilename = req.file.originalname;
        console.log('Processing file:', originalFilename);

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
                processingSteps.sailNumbers.numbers = sortedNumbers;

                // Process each detected sail number
                if (sortedNumbers.length > 0) {
                    for (const sailData of sortedNumbers) {
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

        // If no files were processed, create a NOSAIL version
        if (processedFiles.length === 0) {
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

        // Store metadata for each processed file
        for (const file of processedFiles) {
            try {
                await pool.query(
                    `INSERT INTO photo_metadata (
                        filename, sail_number, date, regatta_name, 
                        photographer_name, photographer_website, 
                        location, additional_tags
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
                    [
                        file.newFilename,
                        file.sailNumber,
                        metadata.date || null,
                        metadata.regatta_name || null,
                        metadata.photographer_name || null,
                        metadata.photographer_website || null,
                        metadata.location || null,
                        metadata.additional_tags || []
                    ]
                );
            } catch (dbErr) {
                console.error('Error storing metadata:', dbErr);
            }
        }

        res.json({
            success: true,
            sailNumbers: processingSteps.sailNumbers,
            processedFiles: processedFiles,
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
    // Typical sail number ranges
    return num >= 10 && num <= 999999 &&
        number.length >= 2 && number.length <= 6;
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

// Add this endpoint to view database schema
app.get('/api/schema', async (req, res) => {
    try {
        // Get all tables
        const tables = await pool.query(`
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public'
        `);

        // Get schema for each table
        const schema = {};
        for (const table of tables.rows) {
            const tableName = table.table_name;
            const columns = await pool.query(`
                SELECT 
                    column_name,
                    data_type,
                    column_default,
                    is_nullable
                FROM information_schema.columns
                WHERE table_schema = 'public'
                AND table_name = $1
                ORDER BY ordinal_position
            `, [tableName]);

            schema[tableName] = columns.rows;
        }

        res.json(schema);
    } catch (err) {
        console.error('Error fetching schema:', err);
        res.status(500).json({ error: 'Failed to fetch database schema' });
    }
});

// Add detailed schema endpoint
app.get('/api/schema/details', async (req, res) => {
    try {
        // Get detailed table information
        const schemaDetails = await pool.query(`
            SELECT 
                t.table_name,
                c.column_name,
                c.data_type,
                c.column_default,
                c.is_nullable,
                c.character_maximum_length,
                c.numeric_precision,
                c.numeric_scale
            FROM information_schema.tables t
            JOIN information_schema.columns c 
                ON t.table_name = c.table_name
            WHERE t.table_schema = 'public'
                AND c.table_schema = 'public'
            ORDER BY t.table_name, c.ordinal_position;
        `);

        // Format the results in a more readable way
        const formattedSchema = {};
        schemaDetails.rows.forEach(row => {
            if (!formattedSchema[row.table_name]) {
                formattedSchema[row.table_name] = [];
            }
            formattedSchema[row.table_name].push({
                column: row.column_name,
                type: row.data_type,
                nullable: row.is_nullable,
                default: row.column_default,
                maxLength: row.character_maximum_length,
                precision: row.numeric_precision,
                scale: row.numeric_scale
            });
        });

        res.json(formattedSchema);
    } catch (err) {
        console.error('Error fetching detailed schema:', err);
        res.status(500).json({ error: 'Failed to fetch detailed schema' });
    }
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
                    downloadUrl: `/Images/${newFilename}`,
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

// Update the download endpoint to serve files from the Images directory
app.get('/Images/:filename', async (req, res) => {
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
            location
        } = req.query;

        let query = `
            SELECT * FROM photo_metadata 
            WHERE 1=1
        `;
        const params = [];
        let paramCount = 1;

        if (sail_number) {
            query += ` AND sail_number = $${paramCount}`;
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

// Update webhook handler for one-time payments
app.post('/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
    const sig = req.headers['stripe-signature'];
    let event;

    try {
        event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
    } catch (err) {
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    if (event.type === 'checkout.session.completed') {
        const session = event.data.object;

        // Record the image purchase
        await pool.query(
            `INSERT INTO purchased_images (user_id, image_filename, stripe_payment_id)
             VALUES ($1, $2, $3)`,
            [session.metadata.userId, session.metadata.imageFilename, session.payment_intent]
        );
    }

    res.json({ received: true });
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

// Add this endpoint to expose the publishable key
app.get('/api/config', (req, res) => {
    res.json({
        stripePublishableKey: process.env.STRIPE_PUBLISHABLE_KEY
    });
}); 
