# ClubSpot Racing Parse Server API Discovery Report

## Executive Summary

This document details the Parse Server API configuration and structure used by the ClubSpot Racing platform (https://racing.theclubspot.com/).

## Parse Server Configuration

### Server Details
- **Base URL**: `https://theclubspot.com/parse/`
- **Application ID**: `myclubspot2017`
- **Parse SDK Source**: `https://racing.theclubspot.com/parse-sdk-js`
- **Health Check**: `https://theclubspot.com/parse/health` → Returns `{"status":"ok"}`

### Environment-Specific URLs
The Parse initialization code (from `common.min.js`) shows different server URLs based on environment:

```javascript
Parse.initialize("myclubspot2017");
if(window.location.href.includes("localhost") || 
   window.location.href.includes("lvh.me") || 
   window.location.href.includes("localtest")) {
    Parse.serverURL = "http://localhost:8080/parse"
} else if(window.location.href.includes("primarytest.theclubspot.com")) {
    Parse.serverURL = "https://primarytest.theclubspot.com/parse"
} else {
    Parse.serverURL = "https://theclubspot.com/parse"
}
```

## API Endpoints

### Main Endpoints Observed

1. **Regattas Endpoint**
   - URL: `POST https://theclubspot.com/parse/classes/regattas`
   - Purpose: Query regatta events
   
2. **Clubs Endpoint**
   - URL: `POST https://theclubspot.com/parse/classes/clubs`
   - Purpose: Query sailing clubs/organizations

## Required Headers

All Parse API requests require the following headers:

```
X-Parse-Application-Id: myclubspot2017
Content-Type: application/json
```

## Request/Response Structure

### Example Request Format (POST to /parse/classes/regattas)
```json
{
  "limit": 24,
  "skip": 0,
  "keys": ["name", "startDate", "endDate", "club", "regattaLogoURL"],
  "include": ["club"],
  "where": {
    "archived": {
      "$ne": true
    },
    "startDate": {
      "$gte": {
        "__type": "Date",
        "iso": "2026-03-12T00:00:00.000Z"
      }
    }
  },
  "order": "startDate"
}
```

### Parse Query Parameters

The API uses Parse Query syntax with the following common parameters:
- `limit`: Number of results to return (default appears to be 24)
- `skip`: Number of results to skip (for pagination)
- `keys`: Array of field names to return
- `include`: Array of pointer fields to include (e.g., populate club data)
- `where`: Query constraints using Parse query operators
- `order`: Sort field (prefix with `-` for descending)

### Parse Query Operators
- `$ne`: Not equal to
- `$gte`: Greater than or equal to
- `$lte`: Less than or equal to
- `$gt`: Greater than
- `$lt`: Less than
- `$in`: Contained in array
- `$nin`: Not contained in array
- `$exists`: Field exists
- `$regex`: Regular expression match

## Data Structure

### Regatta Object Fields (Observed)
Based on the page display and API structure:
- `objectId`: Unique identifier (Parse default)
- `name`: Regatta name
- `startDate`: Start date (Parse Date type)
- `endDate`: End date (Parse Date type)
- `club`: Pointer to clubs table
- `regattaLogoURL`: URL to regatta logo image
- `location`: Location string
- `archived`: Boolean indicating if regatta is archived
- `createdAt`: Creation timestamp (Parse default)
- `updatedAt`: Update timestamp (Parse default)

### Club Object Fields (Observed)
- `objectId`: Unique identifier
- `name`: Club name
- `burgeeURL`: URL to club burgee (flag) image
- `archived`: Boolean

## API Security & Access Control

### Security Rules Observed

1. **Regattas must be linked to a club**
   - Error code: 141
   - Message: "All regattas must be linked to a club"
   - Implication: Cannot query regattas without proper club relationship

2. **Admin operations require master key**
   - Error code: 141
   - Message: "You can only change the support_admin via master key"
   - Implication: Some operations are restricted to server-side master key access

3. **Public API Access**
   - The REST API does not allow unauthenticated direct queries
   - The website appears to use server-side rendering or has specific ACLs configured
   - Direct REST API calls without proper authentication/session will fail

## Network Request Examples

### Actual Network Requests Captured

From page load, the following requests were observed:

1. **Initial Regattas Query**
   ```
   POST https://theclubspot.com/parse/classes/regattas
   Status: 200 OK
   Headers:
     X-Parse-Application-Id: myclubspot2017
     Content-Type: application/json
   ```

2. **Clubs Query**
   ```
   POST https://theclubspot.com/parse/classes/clubs
   Status: 200 OK
   Headers:
     X-Parse-Application-Id: myclubspot2017
     Content-Type: application/json
   ```

## CDN Assets

Images and static assets are served from CloudFront:
- **Primary CDN**: `https://d282wvk2qi4wzk.cloudfront.net/`
- **Legacy S3**: `https://myclubspot.s3-us-west-2.amazonaws.com/`

Examples:
- Regatta logos: `https://d282wvk2qi4wzk.cloudfront.net/[fileId]_regattaLogo_[timestamp]`
- Club burgees: `https://d282wvk2qi4wzk.cloudfront.net/[fileId]_burgee_[timestamp]`

## Attempting Direct API Access

### Working Endpoints (No Auth Required)
```bash
# Health check
curl https://theclubspot.com/parse/health
# Returns: {"status":"ok"}
```

### Protected Endpoints
```powershell
# Attempting to query regattas
$headers = @{
    'X-Parse-Application-Id' = 'myclubspot2017'
    'Content-Type' = 'application/json'
}
$body = @{ 'limit' = 5 } | ConvertTo-Json

Invoke-RestMethod -Uri 'https://theclubspot.com/parse/classes/regattas' `
    -Method POST -Headers $headers -Body $body

# Error: {"code":141,"error":"All regattas must be linked to a club"}
```

## Implementation Notes for Scraping/API Integration

### Recommended Approach

Since direct REST API access is restricted, consider these approaches:

1. **Server-Side Rendering Extraction**
   - The page appears to load regatta data on initial page load
   - Parse the HTML/JavaScript state to extract initial data
   - Look for embedded JSON in script tags or Vue.js component data

2. **Parse JavaScript SDK**
   - Use the Parse JavaScript SDK with the same Application ID
   - May still face ACL restrictions but worth attempting
   - Initialize with: `Parse.initialize("myclubspot2017", undefined, undefined)`
   - Set server URL: `Parse.serverURL = "https://theclubspot.com/parse"`

3. **Browser Automation**
   - Use Selenium, Puppeteer, or similar to capture actual API responses
   - Monitor network traffic while page loads
   - Extract data from intercepted XHR/Fetch requests

4. **Contact ClubSpot**
   - For legitimate use cases, contact support@theclubspot.com
   - They may provide proper API access or data export options

## Parse Server Version Detection

Based on the SDK and API behavior:
- Parse Server appears to be a relatively recent version (2020+)
- Supports modern Parse Query syntax
- Uses standard Parse REST API conventions
- Enforces ACLs and Cloud Code validations

## Additional Resources

- **ClubSpot Support**: support@theclubspot.com
- **Main Platform**: https://theclubspot.com/
- **Racing Hub**: https://racing.theclubspot.com/
- **Parse Documentation**: https://docs.parseplatform.org/

## Appendix: Console Logs

From browser console, the following Parse-related logs were observed:
```
parse-sdk-js:14 Refused to get unsafe header "access-control-expose-headers"
```

This indicates CORS headers are configured but some headers are not exposed to client-side JavaScript.

---

**Report Generated**: March 12, 2026  
**Source**: https://racing.theclubspot.com/  
**Method**: Browser inspection, network monitoring, JavaScript source analysis
