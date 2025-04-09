let isScanning = false;
let videoStream = null;
let canvas, video, resultDiv, debugDiv, debugCheckbox;
let canvasContext; // Define context globally

// Initialize the application
async function init() {
    try {
        console.log('Initializing application...');

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

    try {
        console.log('Starting new scan');
        addDebugMessage('Starting new scan', '🔄');

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

        if (resultDiv) resultDiv.textContent = 'Capturing image and sending to Azure...';
        addDebugMessage('Image captured, preparing to send to Azure', '📸');

        // Convert canvas to blob
        const blob = await new Promise(resolve => {
            canvas.toBlob(resolve, 'image/jpeg', 0.95);
        });

        if (!blob) {
            throw new Error('Failed to create image blob');
        }

        // Create a timestamp for the filename
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const file = new File([blob], `scan-${timestamp}.jpg`, { type: 'image/jpeg' });

        // Send to backend for Azure processing
        const formData = new FormData();
        formData.append('image', file);

        addDebugMessage('Sending image to Azure...', '🚀');
        const response = await fetch('/api/analyze', {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            throw new Error(`Server error: ${response.status}`);
        }

        if (resultDiv) resultDiv.textContent = 'Processing results...';
        addDebugMessage('Waiting for Azure response...', '⏳');
        const data = await response.json();

        addDebugMessage('Results received from Azure', '✅');

        // Update top results box with numbers and skipper info
        const topResultsBox = document.getElementById('topResultsBox');
        if (topResultsBox && data.numbersWithSkippers && data.numbersWithSkippers.length > 0) {
            addDebugMessage(`Found ${data.numbersWithSkippers.length} sail numbers`, '🔍');
            topResultsBox.querySelector('.top-results-content').innerHTML =
                data.numbersWithSkippers.map(result => `
                    <div class="top-result-item">
                        <div class="result-info">
                            <span class="top-result-number">${result.number}</span>
                            ${result.skipperInfo ?
                        `<span class="skipper-info">${result.skipperInfo.skipper_name || result.skipperInfo.boat_name || ''}</span>` :
                        '<span class="no-match">(No Sailor Match)</span>'
                    }
                        </div>
                        <span class="top-result-confidence ${getConfidenceClass(result.confidence)}">
                            ${(result.confidence * 100).toFixed(1)}%
                        </span>
                    </div>
                `).join('');
        } else if (topResultsBox) {
            addDebugMessage('No sail numbers detected', '❓');
            topResultsBox.querySelector('.top-results-content').textContent = 'No numbers detected';
        }

        // Show debug information if enabled
        if (debugCheckbox && debugCheckbox.checked) {
            addDebugMessage('Full Azure Response:', '📊');
            const debugInfo = `
                === Azure Vision Analysis ===
                Time: ${new Date().toLocaleString()}
                Status: ${data.status}

                === Detected Numbers ===
                ${data.numbersWithSkippers?.map(num =>
                `• ${num.number} (${(num.confidence * 100).toFixed(1)}% confident)
                     ${num.skipperInfo ?
                    `Skipper: ${num.skipperInfo.skipper_name || 'Unknown'}
                         Boat: ${num.skipperInfo.boat_name || 'Unknown'}
                         Club: ${num.skipperInfo.yacht_club || 'Unknown'}`
                    : 'No sailor match'
                }`
            ).join('\n') || 'No numbers detected'}

                === Raw Text ===
                ${data.rawText?.map(item =>
                `• "${item.text}" (${(item.confidence * 100).toFixed(1)}% confident)`
            ).join('\n')}
            `;
            addDebugMessage(debugInfo);
        }

        if (resultDiv) resultDiv.textContent = 'Scan complete. Starting next scan...';

    } catch (err) {
        const errorMsg = `Scan error: ${err.message}`;
        console.error(errorMsg);
        addDebugMessage(errorMsg, '❌');
        if (resultDiv) resultDiv.textContent = errorMsg;
    }

    // Continue scanning immediately after processing
    if (isScanning) {
        addDebugMessage('Starting next scan immediately...', '🔄');
        // Use requestAnimationFrame to prevent stack overflow with immediate recursion
        requestAnimationFrame(() => scanFrame());
    }
}

// Add this function to format confidence levels
function getConfidenceClass(confidence) {
    if (confidence >= 0.9) return 'confidence-high';
    if (confidence >= 0.7) return 'confidence-medium';
    return 'confidence-low';
}

// Start the application when the page loads
document.addEventListener('DOMContentLoaded', init); 
