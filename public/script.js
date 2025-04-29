let isScanning = false;
let videoStream = null;
let canvas, video, resultDiv, debugDiv, debugCheckbox;
let canvasContext; // Define context globally
let imageCounter = 0; // Counter for images taken
let lastScanTime = 0; // Timestamp of last scan for throttling

// Initialize the application
async function init() {
    try {
        console.log('Initializing application...');
        imageCounter = 0; // Reset counter on initialization

        // Get DOM elements
        video = document.getElementById('video');
        canvas = document.getElementById('processingCanvas'); // Match the ID in HTML
        const snapshotCanvas = document.getElementById('snapshotCanvas');
        const startBtn = document.getElementById('startBtn');
        const stopBtn = document.getElementById('stopBtn');
        resultDiv = document.getElementById('result');
        debugCheckbox = document.getElementById('debugMode');
        debugDiv = document.getElementById('debug');

        // Log DOM elements for debugging
        console.log('DOM Elements:', {
            video: !!video,
            canvas: !!canvas,
            snapshotCanvas: !!snapshotCanvas,
            startBtn: !!startBtn,
            stopBtn: !!stopBtn,
            resultDiv: !!resultDiv,
            debugCheckbox: !!debugCheckbox,
            debugDiv: !!debugDiv
        });

        // Check for required elements
        if (!video || !canvas || !snapshotCanvas) {
            throw new Error('Required video or canvas elements not found');
        }

        // Initialize canvas context early
        try {
            canvasContext = canvas.getContext('2d', { willReadFrequently: true });
            if (!canvasContext) {
                throw new Error('Failed to get canvas context');
            }
            console.log('Canvas context initialized successfully');
        } catch (err) {
            console.error('Canvas context initialization error:', err);
            if (resultDiv) resultDiv.textContent = 'Error: ' + err.message;
            throw err;
        }

        // Set initial canvas dimensions
        canvas.width = 640;
        canvas.height = 480;
        snapshotCanvas.width = 640;
        snapshotCanvas.height = 480;

        // Setup event listeners
        startBtn.addEventListener('click', startScanning);
        stopBtn.addEventListener('click', stopScanning);

        debugCheckbox.addEventListener('change', (e) => {
            debugDiv.style.display = e.target.checked ? 'block' : 'none';
        });

        video.addEventListener('play', () => {
            console.log('Video started playing');
            addDebugMessage('Video started playing', '▶️');
        });

        video.addEventListener('error', (e) => {
            const errorMsg = 'Video error: ' + (video.error ? video.error.message : 'unknown error');
            console.error(errorMsg, e);
            addDebugMessage(errorMsg, '❌');
            if (resultDiv) resultDiv.textContent = errorMsg;
        });

        console.log('Initialization complete');
        addDebugMessage('Application initialized successfully', '✅');
    } catch (err) {
        console.error('Initialization error:', err);
        if (resultDiv) resultDiv.textContent = 'Initialization error: ' + err.message;
    }
}

// Helper function to add debug messages
function addDebugMessage(message, status = '') {
    if (!debugDiv) return;

    const timestamp = new Date().toLocaleTimeString();
    const messageDiv = document.createElement('div');
    messageDiv.className = 'debug-message';
    messageDiv.innerHTML = `
        <span class="debug-timestamp">[${timestamp}]</span>
        <span class="debug-status">${status}</span>
        ${message}
    `;
    debugDiv.insertBefore(messageDiv, debugDiv.firstChild);

    // Keep only last 50 messages
    const messages = debugDiv.getElementsByClassName('debug-message');
    while (messages.length > 50) {
        debugDiv.removeChild(messages[messages.length - 1]);
    }
}

async function startScanning() {
    try {
        imageCounter = 0; // Reset counter when starting new scanning session
        lastScanTime = 0; // Reset throttle timer

        if (resultDiv) resultDiv.textContent = 'Starting camera...';
        console.log('Requesting camera access...');
        addDebugMessage('Initializing camera...', '📸');

        // Check if getUserMedia is supported
        if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
            throw new Error('Camera API is not supported in this browser');
        }

        const constraints = {
            video: {
                facingMode: "environment",
                width: { ideal: 1280 },
                height: { ideal: 720 }
            }
        };

        console.log('Camera constraints:', constraints);
        addDebugMessage('Requesting camera with constraints: ' + JSON.stringify(constraints), '🎥');
        videoStream = await navigator.mediaDevices.getUserMedia(constraints);
        console.log('Camera access granted');
        addDebugMessage('Camera access granted', '✅');

        video.srcObject = videoStream;

        // Wait for video to be ready
        await new Promise((resolve) => {
            video.onloadedmetadata = () => {
                console.log('Video metadata loaded');
                addDebugMessage(`Video metadata loaded - ${video.videoWidth}x${video.videoHeight}`, '📊');
                video.play();
                resolve();
            };
        });

        // Wait additional 2 seconds for camera to stabilize
        if (resultDiv) resultDiv.textContent = 'Camera started. Taking first image in 2 seconds...';
        addDebugMessage('Waiting 2 seconds before first capture...', '⏲️');
        await new Promise(resolve => setTimeout(resolve, 2000));

        isScanning = true;
        if (resultDiv) resultDiv.textContent = 'Starting first scan...';
        addDebugMessage('Starting first scan', '🔄');
        scanFrame();
    } catch (err) {
        console.error('Error accessing camera:', err);
        addDebugMessage('Camera access error: ' + err.message, '❌');
        if (resultDiv) {
            resultDiv.textContent = 'Error accessing camera: ' + err.message +
                '. Please ensure you have granted camera permissions.';
        }
    }
}

function stopScanning() {
    isScanning = false;
    addDebugMessage('Scanning stopped', '🛑');
    if (videoStream) {
        videoStream.getTracks().forEach(track => track.stop());
    }
    video.srcObject = null;
    if (resultDiv) resultDiv.textContent = 'Scanning stopped';
}

async function scanFrame() {
    if (!isScanning) {
        console.log('Scanning stopped, exiting scanFrame');
        return;
    }

    // Implement throttling - check if it's been at least 30 seconds since last scan
    const now = Date.now();
    const timeSinceLastScan = now - lastScanTime;
    const throttleTime = 30000; // 30 seconds in milliseconds

    if (timeSinceLastScan < throttleTime && lastScanTime > 0) {
        const waitTime = throttleTime - timeSinceLastScan;
        const waitSeconds = Math.ceil(waitTime / 1000);

        if (resultDiv) resultDiv.textContent = `Waiting ${waitSeconds} seconds before next scan...`;
        addDebugMessage(`Throttling: Waiting ${waitSeconds} seconds before next scan...`, '⏱️');

        // Schedule next scan after throttle time expires
        setTimeout(() => scanFrame(), waitTime);
        return;
    }

    // Set last scan time to now
    lastScanTime = now;

    // Increment counter for each new scan
    imageCounter++;

    try {
        console.log(`Starting scan #${imageCounter}`);
        addDebugMessage(`Starting scan #${imageCounter}`, '🔄');

        if (resultDiv) resultDiv.textContent = `Scan #${imageCounter}: Capturing image...`;

        // Ensure canvas and context are available
        if (!canvas || !canvasContext || !video) {
            throw new Error('Required elements not available for scanning');
        }

        // Ensure video is actually playing and has dimensions
        if (video.readyState !== 4 || video.videoWidth === 0 || video.videoHeight === 0) {
            throw new Error('Video not ready or has invalid dimensions');
        }

        // Update canvas size to match video
        canvas.width = video.videoWidth;
        canvas.height = video.videoHeight;

        // Clear canvas and draw video frame
        canvasContext.clearRect(0, 0, canvas.width, canvas.height);
        canvasContext.drawImage(video, 0, 0, canvas.width, canvas.height);

        // Get snapshot canvas and copy the image there too
        const snapshotCanvas = document.getElementById('snapshotCanvas');
        if (snapshotCanvas) {
            const snapshotContext = snapshotCanvas.getContext('2d');
            if (snapshotContext) {
                snapshotCanvas.width = video.videoWidth;
                snapshotCanvas.height = video.videoHeight;
                snapshotContext.clearRect(0, 0, snapshotCanvas.width, snapshotCanvas.height);
                snapshotContext.drawImage(video, 0, 0, snapshotCanvas.width, snapshotCanvas.height);
            }
        }

        if (resultDiv) resultDiv.textContent = `Scan #${imageCounter}: Processing image...`;
        addDebugMessage(`Image #${imageCounter} captured, preparing to send to Azure`, '📸');

        // Convert canvas to blob
        const blob = await new Promise(resolve => {
            canvas.toBlob(resolve, 'image/jpeg', 0.95);
        });

        if (!blob) {
            throw new Error('Failed to create image blob');
        }

        // Create a timestamp for the filename
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const file = new File([blob], `scan-${imageCounter}-${timestamp}.jpg`, { type: 'image/jpeg' });

        // Send to backend for Azure processing
        const formData = new FormData();
        formData.append('image', file);

        addDebugMessage(`Sending image #${imageCounter} to Azure...`, '🚀');
        if (resultDiv) resultDiv.textContent = `Scan #${imageCounter}: Sending to Azure Vision...`;

        const response = await fetch('/api/scan', {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            throw new Error(`Server error: ${response.status}`);
        }

        if (resultDiv) resultDiv.textContent = `Scan #${imageCounter}: Processing results...`;
        addDebugMessage(`Waiting for Azure response for image #${imageCounter}...`, '⏳');
        const data = await response.json();

        addDebugMessage(`Results received from Azure for image #${imageCounter}`, '✅');

        // Update top results box with numbers and skipper info
        const topResultsBox = document.getElementById('topResultsBox');
        if (topResultsBox && data.sailNumbers && data.sailNumbers.numbers && data.sailNumbers.numbers.length > 0) {
            const foundNumbers = data.sailNumbers.numbers;
            addDebugMessage(`Found ${foundNumbers.length} sail numbers in image #${imageCounter}`, '🔍');

            // Display in the top results box
            topResultsBox.querySelector('.top-results-content').innerHTML =
                foundNumbers.map(result => `
                    <div class="top-result-item">
                        <div class="result-info">
                            <span class="top-result-number">${result.number}</span>
                            ${result.skipperInfo ?
                        `<span class="skipper-info">${result.skipperInfo.sailorName || result.skipperInfo.boat_name || ''}</span>` :
                        '<span class="no-match">(No Sailor Match)</span>'
                    }
                        </div>
                        <span class="top-result-confidence ${getConfidenceClass(result.confidence)}">
                            ${(result.confidence * 100).toFixed(1)}%
                        </span>
                    </div>
                `).join('');

            // Log the found numbers
            foundNumbers.forEach(result => {
                addDebugMessage(`Detected sail number: ${result.number} (${(result.confidence * 100).toFixed(1)}% confidence)`, '🔢');
            });

            // Save sail numbers to database
            saveSailNumbersToDatabase(foundNumbers);
        } else if (topResultsBox) {
            addDebugMessage(`No sail numbers detected in image #${imageCounter}`, '❓');
            topResultsBox.querySelector('.top-results-content').textContent = 'No numbers detected';
        }

        // Show detailed debug information if enabled
        if (debugCheckbox && debugCheckbox.checked) {
            addDebugMessage('Full Azure Response:', '📊');
            const debugInfo = `
                === Azure Vision Analysis ===
                Time: ${new Date().toLocaleString()}
                Status: ${data.status || 'Unknown'}

                === Detected Numbers ===
                ${data.sailNumbers && data.sailNumbers.numbers ?
                    data.sailNumbers.numbers.map(num =>
                        `• ${num.number} (${(num.confidence * 100).toFixed(1)}% confident)
                     ${num.skipperInfo ?
                            `Skipper: ${num.skipperInfo.sailorName || num.skipperInfo.boat_name || 'Unknown'}
                         Boat: ${num.skipperInfo.boat_name || 'Unknown'}
                         Club: ${num.skipperInfo.yacht_club || 'Unknown'}`
                            : 'No sailor match'
                        }`
                    ).join('\n') || 'No numbers detected' : 'No data available'}

                === Raw Text ===
                ${data.rawText ? data.rawText.map(item =>
                        `• "${item.text}" (${(item.confidence * 100).toFixed(1)}% confident)`
                    ).join('\n') : 'No raw text available'}
            `;
            addDebugMessage(debugInfo);
        }

        if (resultDiv) resultDiv.textContent = `Scan #${imageCounter} complete. Found ${data.sailNumbers?.numbers?.length || 0} sail numbers. Total images: ${imageCounter}`;
        addDebugMessage(`Scan #${imageCounter} complete. Waiting 30 seconds for next scan...`, '⏱️');

        // Next scan will be triggered by timeout due to throttling

    } catch (err) {
        const errorMsg = `Scan #${imageCounter} error: ${err.message}`;
        console.error(errorMsg);
        addDebugMessage(errorMsg, '❌');
        if (resultDiv) resultDiv.textContent = errorMsg;

        // Even on error, we maintain the throttle
        addDebugMessage(`Waiting 30 seconds before attempting next scan...`, '⏱️');
    }

    // Schedule next scan respecting the throttle
    if (isScanning) {
        addDebugMessage(`Scheduling next scan in 30 seconds...`, '⏱️');
        // Wait for the full 30 seconds before next scan
        setTimeout(() => scanFrame(), 30000);
    }
}

// Add this function to format confidence levels
function getConfidenceClass(confidence) {
    if (confidence >= 0.9) return 'confidence-high';
    if (confidence >= 0.7) return 'confidence-medium';
    return 'confidence-low';
}

// Add this new function to save sail numbers to the database
async function saveSailNumbersToDatabase(sailNumbers) {
    try {
        // Extract just the number values for saving
        const numbers = sailNumbers.map(num => num.number);

        addDebugMessage(`Saving ${numbers.length} sail numbers to database: ${numbers.join(', ')}`, '💾');

        const response = await fetch('/api/numbers', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ numbers })
        });

        if (!response.ok) {
            throw new Error(`Failed to save numbers: ${response.status}`);
        }

        const result = await response.json();
        addDebugMessage('Sail numbers saved to database successfully', '✅');
        return result;
    } catch (err) {
        console.error('Error saving sail numbers to database:', err);
        addDebugMessage(`Failed to save sail numbers: ${err.message}`, '❌');
    }
}

// Start the application when the page loads
document.addEventListener('DOMContentLoaded', init); 
