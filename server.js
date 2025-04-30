const express = require('express');
const { Pool } = require('pg');
const path = require('path');
const multer = require('multer');
const { ComputerVisionClient } = require('@azure/cognitiveservices-computervision');
const { CognitiveServicesCredentials } = require('@azure/ms-rest-azure-js');
const fs = require('fs');
const fsPromises = require('fs').promises;

const app = express();
const port = process.env.PORT || 3000;

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
});

// Update the scan endpoint to include metadata
app.post('/api/scan', upload.single('image'), async (req, res) => {
    let processedFiles = [];
    const metadata = {
        date: req.body.date || new Date().toISOString().split('T')[0], // Use today's date if not specified
        regatta_name: req.body.regatta_name,
        photographer_name: req.body.photographer_name,
        photographer_website: req.body.photographer_website,
        location: req.body.location,
        additional_tags: req.body.additional_tags ? req.body.additional_tags.split(',').map(tag => tag.trim()) : []
    };

    try {
        // Only clean up upload directory, not processed files
        await cleanupDirectories(false);

        console.log('=== Starting New Scan ===');

        if (!req.file || !req.file.buffer) {
            throw new Error('No image file received');
        }

        const originalFilename = req.file.originalname;
        const fileExtension = path.extname(originalFilename);
        const filenameWithoutExt = path.basename(originalFilename, fileExtension);

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

        // STEP 1: Initial Image Upload
        console.log('Step 1: Image received', {
            size: `${(req.file.size / 1024).toFixed(2)} KB`,
            type: req.file.mimetype
        });

        try {
            // STEP 2: Send to Azure for Text Detection
            console.log('Step 2: Sending to Azure Vision...');
            const result = await processWithRetry(
                () => computerVisionClient.readInStream(
                    req.file.buffer,
                    { language: 'en' }
                ),
                'Azure Vision API call'
            );

            // STEP 3: Wait for Azure Processing
            console.log('Step 3: Waiting for Azure analysis...');
            const operationId = result.operationLocation.split('/').pop();

            let operationResult;
            let attempts = 0;
            const maxAttempts = 30;  // Maximum number of attempts
            const delayMs = 1000;    // Delay between attempts (1 second)

            do {
                attempts++;
                console.log(`Checking Azure results - Attempt ${attempts}...`);

                operationResult = await processWithRetry(
                    () => computerVisionClient.getReadResult(operationId),
                    'Azure Results Polling'
                );
                console.log(`Status: ${operationResult.status}`);

                if (operationResult.status === 'running' || operationResult.status === 'notStarted') {
                    console.log(`Waiting ${delayMs}ms before next check...`);
                    await new Promise(resolve => setTimeout(resolve, delayMs));
                }
            } while ((operationResult.status === 'running' || operationResult.status === 'notStarted') && attempts < maxAttempts);

            if (operationResult.status !== 'succeeded') {
                console.log('Azure processing did not complete successfully:', operationResult.status);
                // Don't throw an error, just continue with fallback
                console.log('Will proceed with fallback file creation');
            } else {
                console.log('Azure processing completed successfully!');
                console.log('Results:', JSON.stringify(operationResult.analyzeResult, null, 2));

                processingSteps.debug.azureResponse = operationResult.analyzeResult;

                // Extract sail numbers from results
                const foundNumbers = extractSailNumbers(operationResult.analyzeResult);

                // Sort by confidence but keep all numbers
                const sortedNumbers = foundNumbers.sort((a, b) => b.confidence - a.confidence);

                processingSteps.sailNumbers.numbers = sortedNumbers;

                // Look up sailor information for each number
                for (const num of processingSteps.sailNumbers.numbers) {
                    try {
                        const sailorInfo = await lookupSailorInDatabase(num.number);
                        if (sailorInfo) {
                            num.skipperInfo = sailorInfo;
                        }
                    } catch (err) {
                        console.error(`Error looking up sailor for number ${num.number}:`, err);
                        // Continue with processing even if lookup fails
                    }
                }
            }
        } catch (azureErr) {
            console.error('Error during Azure processing:', azureErr);
            console.log('Will proceed with fallback file creation');
            // Continue with empty numbers - don't throw error
        }

        // Ensure processed directory exists
        await fsPromises.mkdir(PROCESSED_DIR, { recursive: true });

        // IMPORTANT: Always at least generate one file, even if processing failed
        // Process each detected sail number and create files
        if (processingSteps.sailNumbers && processingSteps.sailNumbers.numbers && processingSteps.sailNumbers.numbers.length > 0) {
            for (const sailData of processingSteps.sailNumbers.numbers) {
                // Default to NONAME if no sailor info found
                let sailorName = 'NONAME';

                // If we have sailor info, use it
                if (sailData.skipperInfo && sailData.skipperInfo.sailorName) {
                    sailorName = sanitizeForFilename(sailData.skipperInfo.sailorName);
                }

                // Create new filename
                const newFilename = `${sailData.number}_${sailorName}_${req.file.originalname}`;
                const newPath = path.join(PROCESSED_DIR, newFilename);

                try {
                    // Make sure directory exists
                    await fsPromises.mkdir(path.dirname(newPath), { recursive: true });

                    // Write the file with buffer directly - most reliable method
                    await fsPromises.writeFile(newPath, req.file.buffer);

                    // Verify file was created
                    const stats = await fsPromises.stat(newPath);
                    console.log(`Created file: ${newFilename} (${stats.size} bytes)`);

                    // Add to processed files list
                    processedFiles.push({
                        originalFilename: req.file.originalname,
                        newFilename: newFilename,
                        downloadUrl: `/Images/${newFilename}`,
                        sailNumber: sailData.number,
                        sailorName: sailorName
                    });
                } catch (fileErr) {
                    console.error(`Error creating file for sail number ${sailData.number}:`, fileErr);
                }
            }
        }

        // If we didn't create any files yet (either no sail numbers or errors occurred)
        // create the fallback NOSAIL version
        if (processedFiles.length === 0) {
            const newFilename = `NOSAIL_NONAME_${req.file.originalname}`;
            const newPath = path.join(PROCESSED_DIR, newFilename);

            try {
                // Make sure directory exists
                await fsPromises.mkdir(path.dirname(newPath), { recursive: true });

                // Write the file with buffer directly
                await fsPromises.writeFile(newPath, req.file.buffer);

                // Verify file was created
                const stats = await fsPromises.stat(newPath);
                console.log(`Created NOSAIL fallback file: ${newFilename} (${stats.size} bytes)`);

                processedFiles.push({
                    originalFilename: req.file.originalname,
                    newFilename: newFilename,
                    downloadUrl: `/Images/${newFilename}`,
                    sailNumber: 'NOSAIL',
                    sailorName: 'NONAME'
                });
            } catch (fileErr) {
                console.error('Error creating NOSAIL fallback file:', fileErr);
                // Even in this worst case, we still need to return a response
            }
        }

        // Prepare debug info based on what we have available
        const debugInfo = {
            status: processingSteps.debug.azureResponse ? 'succeeded' : 'failed',
            processingTime: processingSteps.debug.processingTime || 'unknown',
            textProcessing: {
                totalTextItems: processingSteps.rawText.length,
                rawTextFound: processingSteps.rawText
            },
            numberProcessing: {
                totalPotentialNumbers: processingSteps.potentialNumbers.length,
                ignoredNumbers: processingSteps.ignoredNumbers,
                potentialNumbers: processingSteps.potentialNumbers,
                validNumbers: processingSteps.validNumbers
            }
        };

        // Send the API response with what we have, always marking as success
        res.json({
            success: true,
            sailNumbers: processingSteps.sailNumbers || { numbers: [] },
            processedFiles: processedFiles,
            stats: {
                totalFiles: processedFiles.length,
                filesWithSailNumbers: (processingSteps.sailNumbers && processingSteps.sailNumbers.numbers)
                    ? processingSteps.sailNumbers.numbers.length
                    : 0
            },
            debug: debugInfo
        });

        // After processing files, store metadata
        for (const file of processedFiles) {
            // Convert empty strings to null for date field
            const dateValue = metadata.date && metadata.date !== '' ? metadata.date : null;

            await pool.query(
                `INSERT INTO photo_metadata (
                    filename, sail_number, date, regatta_name, 
                    photographer_name, photographer_website, 
                    location, additional_tags
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
                [
                    file.newFilename,
                    file.sailNumber,
                    dateValue,
                    metadata.regatta_name || null,
                    metadata.photographer_name || null,
                    metadata.photographer_website || null,
                    metadata.location || null,
                    metadata.additional_tags || []
                ]
            );
        }

    } catch (err) {
        console.error('Unhandled error during scan:', err);

        // Create emergency fallback file even for completely unhandled errors
        try {
            const originalFilename = req.file ? req.file.originalname : 'unknown_file.jpg';
            const newFilename = `NOSAIL_NONAME_ERROR_${originalFilename}`;
            const newPath = path.join(PROCESSED_DIR, newFilename);

            // Ensure directory exists
            await fsPromises.mkdir(PROCESSED_DIR, { recursive: true });

            // Write the file with buffer if available
            if (req.file && req.file.buffer) {
                await fsPromises.writeFile(newPath, req.file.buffer);

                // Verify file was created
                const stats = await fsPromises.stat(newPath);
                console.log(`Created emergency file: ${newFilename} (${stats.size} bytes)`);

                processedFiles.push({
                    originalFilename: originalFilename,
                    newFilename: newFilename,
                    downloadUrl: `/Images/${newFilename}`,
                    sailNumber: 'NOSAIL',
                    sailorName: 'NONAME'
                });
            }
        } catch (emergencyErr) {
            console.error('Failed to create emergency fallback file:', emergencyErr);
        }

        // Always respond with success and whatever files we created
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
        res.json(result.rows);
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

// Update the validate-files endpoint
app.get('/api/validate-files', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM photo_metadata');
        const photos = result.rows;

        const results = [];
        let orphanedCount = 0;

        for (const photo of photos) {
            const filePath = path.join(PROCESSED_DIR, photo.filename);
            try {
                const stats = await fsPromises.stat(filePath);

                if (stats.size === 0) {
                    results.push({
                        filename: photo.filename,
                        status: 'error',
                        message: 'File exists but is empty (0 bytes)'
                    });
                    orphanedCount++;
                } else {
                    results.push({
                        filename: photo.filename,
                        status: 'success',
                        message: 'File exists and is valid'
                    });
                }
            } catch (err) {
                if (err.code === 'ENOENT') {
                    results.push({
                        filename: photo.filename,
                        status: 'error',
                        message: 'File not found in processed images directory'
                    });
                    orphanedCount++;
                } else {
                    results.push({
                        filename: photo.filename,
                        status: 'error',
                        message: `Error checking file: ${err.message}`
                    });
                    orphanedCount++;
                }
            }
        }

        res.json({
            orphanedCount,
            results
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
        let dirPath;

        if (folder === 'uploads') {
            dirPath = UPLOAD_DIR;
        } else if (folder === 'processed') {
            dirPath = PROCESSED_DIR;  // Changed from public/Images to PROCESSED_DIR
        } else {
            return res.status(400).json({ error: 'Invalid folder specified' });
        }

        // Ensure directory exists
        try {
            await fsPromises.access(dirPath);
        } catch (err) {
            if (err.code === 'ENOENT') {
                // Directory doesn't exist, create it
                await fsPromises.mkdir(dirPath, { recursive: true });
                return res.json({ count: 0 });
            }
            throw err;
        }

        // Read directory and count files
        const files = await fsPromises.readdir(dirPath);
        const validFiles = await Promise.all(
            files.map(async (file) => {
                try {
                    const filePath = path.join(dirPath, file);
                    const stats = await fsPromises.stat(filePath);
                    return stats.isFile() && stats.size > 0;
                } catch (err) {
                    console.error(`Error checking file ${file}:`, err);
                    return false;
                }
            })
        );

        res.json({ count: validFiles.filter(Boolean).length });
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
