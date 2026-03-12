# ClubSpot Racing Website - API Investigation Results

## Investigation Date
March 12, 2026

## Website Overview
**Main URL:** https://racing.theclubspot.com/

The ClubSpot racing website is a sailing regatta management platform that displays upcoming and past regattas, with details like dates, locations, clubs, and entries.

## Page Structure

### Landing Page (https://racing.theclubspot.com/)
- **Header:** Logo, "Book a demo", "Switch from YS" buttons, search, navigation
- **Statistics:** Shows total regattas run, scores posted, scoring methods
- **Main Section:** "Find a regatta" with:
  - Filter dropdown (Upcoming, 2027, 2026, 2025, etc.)
  - "Add Filter" button
  - Search box (placeholder: "Search regattas...")
  - Grid display of regatta cards with images
  - Shows 24 regattas per page (1-24 of 778 total shown)

### Individual Regatta Page
**URL Pattern:** `https://{club-subdomain}.theclubspot.com/regatta/{regattaId}`

**Example:** https://melgeswatersportscenter.theclubspot.com/regatta/aLSDjdIGKh

**Sections:**
1. **Header:** Regatta name, logo, club info, dates, location
2. **Navigation Tabs:** Register, Notice board, Results, Entry list
3. **Notice Board:** Posted items/announcements
4. **Documents:** Sailing Instructions, Notice of Race, other files
5. **Entry List:** Table with columns:
   - Number
   - Sailors (names)
   - Class
   - Sail Number
   - Boat Name
   - Club/Organization

## API Endpoints Discovered

### 1. Parse Server Backend
The site uses **Parse Server** as its backend. All API calls are POST requests to `https://theclubspot.com/parse/classes/{className}`

### Key Endpoints:

#### a) Regatta Listings
```
URL: https://theclubspot.com/parse/classes/regattas
Method: POST
Type: XHR
Purpose: Fetch regatta data for the listing page
```

#### b) Club Data
```
URL: https://theclubspot.com/parse/classes/clubs
Method: POST
Type: XHR
Purpose: Fetch club/organization information
```

#### c) Documents
```
URL: https://theclubspot.com/parse/classes/documents
Method: POST
Type: XHR
Purpose: Fetch regatta documents (Sailing Instructions, Notice of Race, etc.)
```

### 2. Parse SDK
The site loads Parse SDK from:
```
https://racing.theclubspot.com/parse-sdk-js
```

### 3. Additional Infrastructure
- **CloudFront CDN:** `https://d282wvk2qi4wzk.cloudfront.net/` (for images)
- **S3 Bucket:** `https://myclubspot.s3-us-west-2.amazonaws.com/` (for images/assets)
- **Analytics:** Google Analytics (G-412LB87P0H)
- **Payment:** Stripe integration (js.stripe.com/v3/)

## URL Patterns

### Regatta Pages
Format: `https://{club-subdomain}.theclubspot.com/regatta/{regattaId}`

Where:
- `{club-subdomain}` = club's subdomain (e.g., "melgeswatersportscenter")
- `{regattaId}` = unique regatta identifier (e.g., "aLSDjdIGKh")

**Note:** The regatta ID appears to be a 10-character alphanumeric string.

### Example URLs:
- `https://melgeswatersportscenter.theclubspot.com/regatta/aLSDjdIGKh` (2026 Melges 14 Midwinter Championship)

## Interactions Needed

### To Get Regatta Listings:
1. **No interaction required** - Data loads automatically on page load
2. The initial page shows 24 regattas
3. Filter dropdown allows selecting time periods (Upcoming, specific years, etc.)
4. Search box allows text-based searching
5. "Add Filter" button allows additional filtering options

### To Get Individual Regatta Details:
1. Click on a regatta card from the listing page
2. **OR** Navigate directly to: `https://{club-subdomain}.theclubspot.com/regatta/{regattaId}`
   - Requires knowing the club subdomain and regatta ID

## Parse Server API Structure

Parse Server APIs typically use POST requests with JSON payloads containing query parameters.

### Expected Request Structure:
```json
{
  "where": {
    "field": "value"
  },
  "limit": 24,
  "skip": 0,
  "order": "-createdAt",
  "keys": "field1,field2,field3",
  "include": "relatedObject"
}
```

### Headers (likely required):
- `X-Parse-Application-Id`: Application identifier
- `X-Parse-REST-API-Key`: API key (if required)
- `Content-Type`: application/json

### Authentication:
Parse APIs may require authentication headers. These would need to be extracted from:
1. Page source (embedded in JavaScript)
2. Network request headers
3. Browser localStorage/sessionStorage

## Data Not Found

❌ **No sitemap.xml** - https://racing.theclubspot.com/sitemap.xml redirects to homepage
❌ **No REST API docs** - https://racing.theclubspot.com/api/ redirects to homepage
❌ **No GraphQL endpoint** discovered
❌ **No public API documentation** visible

## Embedded Data in Page Source

The page uses Vue.js for frontend rendering, which means:
- Data may be embedded in `<script>` tags as JSON
- Vue component data/props may contain initial state
- Parse Application ID and keys may be in JavaScript files

**Files to inspect for embedded data:**
1. `https://racing.theclubspot.com/sc-common` - Common script
2. `https://racing.theclubspot.com/parse-sdk-js` - Parse SDK configuration
3. `https://racing.theclubspot.com/public/assets/js/catch-all-minified/racing-hub.min.js` - Racing hub code

## Technology Stack

- **Frontend:** Vue.js 3.4.21
- **Backend:** Parse Server
- **CDN:** CloudFront
- **Storage:** AWS S3
- **Payment:** Stripe
- **UI Libraries:** jQuery, jQuery UI, Chart.js, Moment.js
- **CSS:** Material Icons, Font Awesome

## Scraping Strategy Recommendations

### Option 1: Parse API Direct Access (Recommended)
**Pros:**
- Clean JSON responses
- No HTML parsing needed
- Faster and more reliable
- Can query with filters

**Cons:**
- Requires finding Parse Application ID and API keys
- May need authentication

**Next Steps:**
1. Inspect JavaScript files to find Parse configuration
2. Monitor network requests to capture authentication headers
3. Replicate POST requests with proper headers

### Option 2: Page Scraping
**Pros:**
- No authentication needed
- Works immediately

**Cons:**
- Slower (need to load full pages)
- More fragile (breaks if HTML changes)
- Requires handling JavaScript rendering

### Option 3: Hybrid Approach
1. Scrape listing page to get regatta IDs and club subdomains
2. Use Parse API (if accessible) to fetch detailed data
3. Fall back to page scraping for data not in API

## Sample Data Structure (Entry List)

From the 2026 Melges 14 Midwinter Championship:

| # | Sailor | Class | Sail Number | Boat Name | Club |
|---|--------|-------|-------------|-----------|------|
| 1 | Jennifer Canestra | Melges 14 | USA 531 | Hot Wet Mess | Corinthian Yacht Club of San Francisco |
| 2 | Michael Easparam | Melges 14 | USA 640 | - | Privateer Yacht Club |
| 3 | Michael Gillian | Melges 14 | USA 534 | Sweetness | Chicago Yacht Club |

**Total entries in this regatta:** 8

## Next Investigation Steps

To complete API access:

1. **Capture Parse Configuration:**
   - Use browser DevTools to inspect network request headers
   - Look for `X-Parse-Application-Id` and `X-Parse-REST-API-Key`
   - Check JavaScript files for embedded configuration

2. **Test API Requests:**
   - Use curl/Postman to replicate Parse API calls
   - Try different query parameters
   - Test authentication requirements

3. **Document Query Syntax:**
   - Understand Parse query language
   - Test filtering by date, location, club
   - Test pagination (skip/limit)

4. **Find Regatta ID Pattern:**
   - Determine if IDs are sequential or random
   - Check if there's a way to list all regatta IDs

5. **Map Object Relationships:**
   - Regattas → Clubs
   - Regattas → Documents
   - Regattas → Entries
   - Entries → Sailors

## Conclusion

The ClubSpot racing website uses a Parse Server backend with clean REST-like APIs. The best approach for scraping is to:

1. **Extract Parse API credentials** from the page source or network requests
2. **Use the Parse API directly** for clean JSON data
3. **Build URL patterns** to access individual regatta pages if needed

The data is structured and accessible, but requires understanding the Parse API query syntax and having the correct authentication headers.
