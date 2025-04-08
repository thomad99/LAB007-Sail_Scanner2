const express = require('express');
const { Pool } = require('pg');
const path = require('path');
const multer = require('multer');
const { ComputerVisionClient } = require('@azure/cognitiveservices-computervision');
const { CognitiveServicesCredentials } = require('@azure/ms-rest-azure-js');
const fs = require('fs').promises;

const app = express();
const port = process.env.PORT || 3000;

// Add these near the top of server.js
const LOCAL_SAVE_PATH = process.env.LOCAL_SAVE_PATH || path.join(process.cwd(), 'saved_photos');
const SAVE_TO_SERVER = true; // Set to false if you don't want server copies
const IGNORED_NUMBERS = ['420']; // Numbers to ignore (boat class markings)
const validSailNumbers = [13, 118, 9610, 5318, 8008]; // Valid sail numbers

// Add these constants at the top of your file
const RATE_LIMIT_DELAY = 30000; // 30 seconds
let lastAzureCallTime = 0;
const UPLOAD_DIR = path.join(__dirname, 'uploads');
const PROCESSED_DIR = path.join(__dirname, 'processed');

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
app.use('/uploads', express.static(path.join(__dirname, 'public', 'uploads')));
app.use('/download', express.static(PROCESSED_DIR));

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
        await fs.mkdir(localDir, { recursive: true });
        
        const localFilePath = path.join(localDir, filename);
        await fs.writeFile(localFilePath, buffer);
        console.log('File saved locally:', localFilePath);

        // 2. Optionally save to server uploads directory
        if (SAVE_TO_SERVER) {
            const uploadsDir = path.join('public', 'uploads');
            await fs.mkdir(uploadsDir, { recursive: true });
            const serverFilePath = path.join(uploadsDir, filename);
            await fs.writeFile(serverFilePath, buffer);
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
async function cleanupDirectories() {
    console.log('Starting directory cleanup...');
    
    try {
        // Ensure directories exist
        await fs.mkdir(UPLOAD_DIR, { recursive: true });
        await fs.mkdir(PROCESSED_DIR, { recursive: true });
        
        // Clean up upload directory
        const uploadFiles = await fs.readdir(UPLOAD_DIR);
        for (const file of uploadFiles) {
            const filePath = path.join(UPLOAD_DIR, file);
            await fs.unlink(filePath);
            console.log(`Deleted upload: ${file}`);
        }
        
        // Clean up processed directory
        const processedFiles = await fs.readdir(PROCESSED_DIR);
        for (const file of processedFiles) {
            const filePath = path.join(PROCESSED_DIR, file);
            await fs.unlink(filePath);
            console.log(`Deleted processed: ${file}`);
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
                console.log(`Rate limit hit for ${operationName}. Attempt ${attempt} of ${MAX_RETRIES}. Waiting ${delay/1000} seconds...`);
                await new Promise(resolve => setTimeout(resolve, delay));
                continue;
            }
            
            // If it's not a rate limit error or we're out of retries, throw the error
            throw err;
        }
    }
}

// Update your upload endpoint to include cleanup
app.post('/api/scan', upload.single('image'), async (req, res) => {
    let processedFiles = [];
    
    try {
        // Clean up old files before processing new ones
        await cleanupDirectories();
        
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
        await fs.mkdir(PROCESSED_DIR, { recursive: true });
        
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
                    await fs.mkdir(path.dirname(newPath), { recursive: true });
                    
                    // Write the file with buffer directly - most reliable method
                    await fs.writeFile(newPath, req.file.buffer);
                    
                    // Verify file was created
                    const stats = await fs.stat(newPath);
                    console.log(`Created file: ${newFilename} (${stats.size} bytes)`);
                    
                    // Add to processed files list
                    processedFiles.push({
                        originalFilename: req.file.originalname,
                        newFilename: newFilename,
                        downloadUrl: `/download/${newFilename}`,
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
                await fs.mkdir(path.dirname(newPath), { recursive: true });
                
                // Write the file with buffer directly
                await fs.writeFile(newPath, req.file.buffer);
                
                // Verify file was created
                const stats = await fs.stat(newPath);
                console.log(`Created NOSAIL fallback file: ${newFilename} (${stats.size} bytes)`);
                
                processedFiles.push({
                    originalFilename: req.file.originalname,
                    newFilename: newFilename,
                    downloadUrl: `/download/${newFilename}`,
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

    } catch (err) {
        console.error('Unhandled error during scan:', err);
        
        // Create emergency fallback file even for completely unhandled errors
        try {
            const originalFilename = req.file ? req.file.originalname : 'unknown_file.jpg';
            const newFilename = `NOSAIL_NONAME_ERROR_${originalFilename}`;
            const newPath = path.join(PROCESSED_DIR, newFilename);
            
            // Ensure directory exists
            await fs.mkdir(PROCESSED_DIR, { recursive: true });
            
            // Write the file with buffer if available
            if (req.file && req.file.buffer) {
                await fs.writeFile(newPath, req.file.buffer);
                
                // Verify file was created
                const stats = await fs.stat(newPath);
                console.log(`Created emergency file: ${newFilename} (${stats.size} bytes)`);
                
                processedFiles.push({
                    originalFilename: originalFilename,
                    newFilename: newFilename,
                    downloadUrl: `/download/${newFilename}`,
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
        console.log(`Rate limit cooling down. Waiting ${waitTime/1000} seconds...`);
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
        await fs.mkdir(UPLOAD_DIR, { recursive: true });
        await fs.mkdir(PROCESSED_DIR, { recursive: true });

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
                await fs.copyFile(originalPath, newPath);
                console.log(`Successfully created file: ${newFilename}`);

                processedFiles.push({
                    originalFilename: file.originalname,
                    newFilename: newFilename,
                    downloadUrl: `/download/${newFilename}`,
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
        // Clean up old files before processing new batch
        await cleanupDirectories();
        
        // Your existing batch processing code...
    } catch (err) {
        console.error('Error during batch scan:', err);
        res.status(500).json({ success: false, error: err.message });
    }
});

// Add a cleanup endpoint that can be called manually if needed
app.post('/api/cleanup', async (req, res) => {
    try {
        await cleanupDirectories();
        res.json({ success: true, message: 'Cleanup completed successfully' });
    } catch (err) {
        console.error('Error during cleanup:', err);
        res.status(500).json({ success: false, error: err.message });
    }
});

// Add automatic cleanup on server startup
app.listen(port, async () => {
    console.log(`Server running on port ${port}`);
    
    // Ensure upload and processed directories exist
    try {
        await fs.mkdir(UPLOAD_DIR, { recursive: true });
        console.log(`Created/verified upload directory: ${UPLOAD_DIR}`);
        
        await fs.mkdir(PROCESSED_DIR, { recursive: true });
        console.log(`Created/verified processed directory: ${PROCESSED_DIR}`);
        
        // Run initial cleanup
        await cleanupDirectories();
    } catch (err) {
        console.error('Error creating directories:', err);
    }
});

// Fix the download endpoint
app.get('/download/:filename', async (req, res) => {
    try {
        const filename = req.params.filename;
        const filePath = path.join(PROCESSED_DIR, filename);
        
        console.log(`Download request for: ${filename}`);
        console.log(`Looking in directory: ${PROCESSED_DIR}`);
        console.log(`Full path: ${filePath}`);
        
        // List files in directory to debug
        try {
            const files = await fs.readdir(PROCESSED_DIR);
            console.log(`Files in ${PROCESSED_DIR}:`, files);
            
            if (files.includes(filename)) {
                console.log(`File ${filename} found in directory listing`);
            } else {
                console.log(`File ${filename} NOT found in directory listing`);
            }
        } catch (dirErr) {
            console.error(`Error reading directory ${PROCESSED_DIR}:`, dirErr);
        }
        
        // Check if file exists before trying to download
        try {
            const stats = await fs.stat(filePath);
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
