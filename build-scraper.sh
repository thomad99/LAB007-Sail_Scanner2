#!/bin/bash
set -e  # Exit on error

# Build script for regatta-scraper service on Render
# This script:
# 1. Copies package-scraper.json to package.json
# 2. Installs dependencies (Playwright)
# 3. Installs Playwright browsers (Chromium only for headless)

echo "Building regatta-scraper service..."

# Copy package-scraper.json to package.json
cp package-scraper.json package.json
echo "✓ Copied package-scraper.json to package.json"

# Install dependencies
echo "Installing dependencies..."
npm install

# Install Playwright browsers (Chromium only - lighter and faster)
# Skip system dependencies as they're not needed on Render
echo "Installing Playwright Chromium browser..."
PLAYWRIGHT_SKIP_DEPENDENCY_DOWNLOAD=1 npx playwright install chromium

echo "✓ Build complete!"

