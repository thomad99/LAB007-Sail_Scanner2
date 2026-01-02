# Regatta Scraper Service

This is a **separate, dedicated service** for scraping regattas to reduce memory usage on your main server.

## Setup Instructions

### 1. Create a New Render Service

1. Go to your Render dashboard
2. Click "New +" → "Web Service"
3. Connect your repository
4. Configure:
   - **Name**: `regatta-scraper` (or any name you prefer)
   - **Root Directory**: Leave blank (or set if needed)
   - **Environment**: Node
   - **Build Command**: `npm install`
   - **Start Command**: `node regatta-scraper-service.js`
   - **Plan**: Free tier is fine (or upgrade if needed for more memory)

### 2. Environment Variables

Add these to your new Render service (same as main service):
- `DATABASE_URL` - Your PostgreSQL connection string (same database)
- `PORT` - Will be set automatically by Render

### 3. Update Main Server

Update your main `server.js` to call this service instead of scraping directly:

```javascript
// In your main server.js, replace the scraping endpoint with:
app.post('/api/scrape-regattas', async (req, res) => {
  try {
    const scraperServiceUrl = process.env.SCRAPER_SERVICE_URL || 'http://localhost:3001';
    const response = await axios.post(`${scraperServiceUrl}/api/scrape-regattas`, req.body);
    res.json(response.data);
  } catch (error) {
    res.status(500).json({ error: 'Scraper service unavailable', details: error.message });
  }
});
```

### 4. Environment Variable for Main Service

Add to your main Render service:
- `SCRAPER_SERVICE_URL` - URL of your scraper service (e.g., `https://regatta-scraper.onrender.com`)

## Benefits

- ✅ Reduces memory usage on main server
- ✅ Can scale scraper independently
- ✅ Main server stays responsive
- ✅ Can restart scraper without affecting main app

## Files

- `regatta-scraper-service.js` - The scraping service
- `regatta-scraper-package.json` - Rename to `package.json` in the scraper service directory
- `.npmrc` - Use the same one (skip Chromium download)

## Notes

- Both services use the **same database** (shared via DATABASE_URL)
- The scraper service only handles scraping, nothing else
- Main server forwards scraping requests to this service

