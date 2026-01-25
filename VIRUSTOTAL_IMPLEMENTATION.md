# 🛡️ VirusTotal API Implementation Guide

This document explains how the VirusTotal API is integrated into the PhishScan Chrome extension and how to configure it.

## 📋 Table of Contents

1. [Overview](#overview)
2. [Getting Your API Key](#getting-your-api-key)
3. [Implementation Details](#implementation-details)
4. [API Integration Architecture](#api-integration-architecture)
5. [Code Structure](#code-structure)
6. [Testing and Verification](#testing-and-verification)

## 🔍 Overview

The PhishScan extension uses VirusTotal's URL Report API to check URLs in real-time against 70+ antivirus engines. This provides comprehensive threat detection with detailed analysis results.

### Key Features Implemented:

- ✅ Real-time URL scanning using VirusTotal API
- ✅ Detailed analysis including detection ratios, threat labels, and engine results
- ✅ Visual feedback on webpages (red borders for malicious, green checkmarks for safe)
- ✅ Automatic shortened URL resolution and checking
- ✅ Comprehensive popup UI showing scan statistics and detailed reports
- ✅ Manual URL checking capability
- ✅ Rate limit handling

## 🔑 Getting Your API Key

### Step 1: Create a VirusTotal Account

1. Go to [VirusTotal](https://www.virustotal.com/gui/join-us)
2. Sign up for a free account or sign in if you already have one

### Step 2: Get Your API Key

1. After logging in, click on your profile/username in the top right
2. Navigate to **API Key** section
3. Copy your API key (it will look like: `a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0`)

### Step 3: Add API Key to Extension

1. Open `background.js` in your code editor
2. Find the `API_CONFIG` object (around line 21-32)
3. Paste your API key in the `virusTotal.key` field:

```javascript
const API_CONFIG = {
  virusTotal: {
    key: 'YOUR_API_KEY_HERE', // ← Paste your key here
    url: 'https://www.virustotal.com/vtapi/v2/url/report',
    quota: 500 // Free tier: 500 requests/day
  }
};
```

### Free Tier Limits

- **500 requests per day** (resets at midnight UTC)
- Rate limit: 4 requests per minute
- The extension handles rate limits gracefully with fallback to OpenPhish database

## 🏗️ Implementation Details

### API Endpoint

```
POST https://www.virustotal.com/vtapi/v2/url/report
```

### Request Format

```javascript
const formData = new FormData();
formData.append('apikey', API_CONFIG.virusTotal.key);
formData.append('resource', url); // The URL to check
```

### Response Structure

The VirusTotal API returns detailed JSON data including:

- `response_code`: Status code (0 = not found, 1 = found)
- `positives`: Number of engines that detected threats
- `total`: Total number of engines
- `scans`: Detailed results from each antivirus engine
- `threats`: Threat labels and categories
- `scan_date`: Timestamp of last scan
- `permalink`: Link to full VirusTotal report

## 📁 API Integration Architecture

### File Structure

```
phishscan-extension/
├── background.js          # Handles VirusTotal API calls
├── content.js             # Scans pages and highlights URLs
├── popup.js               # Displays results and detailed analysis
├── popup.html             # Extension popup UI
└── popup.css              # Modern styling
```

### Data Flow

```
1. Content Script (content.js)
   ↓ Detects URLs on webpage
   ↓
2. Background Script (background.js)
   ↓ Makes VirusTotal API call
   ↓
3. VirusTotal API
   ↓ Returns detailed analysis
   ↓
4. Content Script
   ↓ Highlights malicious/safe URLs
   ↓ Stores results
   ↓
5. Popup (popup.js)
   ↓ Displays statistics and detailed analysis
```

### Key Functions

#### `checkVirusTotal(url)` in `background.js`

This is the main function that communicates with VirusTotal API:

```javascript
async function checkVirusTotal(url) {
  // 1. Validates API key
  // 2. Makes POST request to VirusTotal
  // 3. Parses detailed response
  // 4. Extracts detection data, threat labels, engine results
  // 5. Returns comprehensive analysis object
}
```

**Returns:**
```javascript
{
  malicious: true/false,
  positives: 2,           // Engines that detected threat
  total: 93,             // Total engines
  detectionRate: 2.2,    // Percentage
  scanDate: 1234567890,  // Unix timestamp
  threatLabels: [...],   // Threat categories
  detectedBy: [...],     // Which engines detected it
  scanDetails: {...},    // Full engine results
  permalink: "..."       // VirusTotal report link
}
```

#### `checkUrlWithAPI(url)` in `content.js`

This function orchestrates URL checking:

```javascript
async function checkUrlWithAPI(url) {
  // 1. Normalizes URL
  // 2. Resolves shortened URLs if needed
  // 3. Calls VirusTotal via background script
  // 4. Returns result with VirusTotal data
}
```

#### Visual Highlighting Functions

**`highlightElement()`** - Marks malicious URLs:
- Red border and background
- Warning icon ⚠️
- Detailed tooltip with VirusTotal data

**`markCleanElement()`** - Marks safe URLs:
- Green checkmark ✅
- Tooltip showing verification status
- Subtle visual indicator

## 💻 Code Structure

### Background Script (`background.js`)

**Location:** Lines 151-289

**Key Features:**
- API key validation
- Error handling (rate limits, timeouts, network errors)
- Detailed response parsing
- Threat label extraction
- Engine result processing

**Message Handler:**
```javascript
case 'CHECK_VIRUSTOTAL':
  checkVirusTotal(request.url).then(result => {
    sendResponse(result);
  });
  return true; // Keep channel open for async
```

### Content Script (`content.js`)

**Key Functions:**
- `checkUrlWithAPI()` - Main URL checking orchestrator
- `highlightElement()` - Visual feedback for malicious URLs
- `markCleanElement()` - Visual feedback for safe URLs
- `setupShortenedUrlTooltip()` - Shows expanded URL on hover

**Storage:**
- Stores scan results in `chrome.storage.local`
- Tracks: `phishscan_found`, `phishscan_clean`, `phishscan_total_scanned`

### Popup Script (`popup.js`)

**Features:**
- Real-time status updates
- Statistics display (total scanned, malicious count, safe count)
- Manual URL checker
- Detailed analysis modal
- Summary table of recent scans

**Key Functions:**
- `handleManualCheck()` - Checks URLs manually
- `showDetailedAnalysisModal()` - Displays VirusTotal report
- `updateStatusAndList()` - Updates UI with scan results

## 🧪 Testing and Verification

### Step 1: Load Extension

1. Open Chrome and go to `chrome://extensions/`
2. Enable "Developer mode" (top right)
3. Click "Load unpacked"
4. Select the extension folder

### Step 2: Verify API Key Configuration

1. Open browser console (F12)
2. Check for API key validation messages
3. Look for: `"VirusTotal API key configured"` or error messages

### Step 3: Test on Demo Page

1. Open `demo.html` in your browser
2. Click the PhishScan extension icon
3. Verify:
   - URLs are being scanned
   - Malicious URLs show red borders
   - Safe URLs show green checkmarks
   - Statistics display correctly

### Step 4: Test Manual URL Checker

1. Open extension popup
2. Enter a URL in "Check URL Manually" field
3. Click "Check"
4. Verify detailed analysis modal appears

### Step 5: Verify Rate Limiting

- The extension respects 500 requests/day limit
- When rate limited, falls back to OpenPhish database
- Shows appropriate error messages

### Expected Console Output

When working correctly, you should see:

```
Checking URL with VirusTotal: https://example.com
VirusTotal detailed result: {malicious: false, positives: 0, total: 93, ...}
URL verified clean by VirusTotal: https://example.com
```

## 🐛 Troubleshooting

### Issue: "API key not configured"

**Solution:** Add your VirusTotal API key to `background.js`

### Issue: "API rate limit exceeded"

**Solution:** 
- You've hit the 500 requests/day limit
- Wait until midnight UTC for reset
- Extension will use OpenPhish database as fallback

### Issue: URLs not being scanned

**Check:**
1. Extension is enabled (toggle in popup)
2. API key is correctly configured
3. Browser console for error messages
4. Network tab to verify API calls

### Issue: No visual highlighting

**Check:**
1. Content script is running (check console)
2. URLs are being detected
3. VirusTotal responses are valid
4. Check for JavaScript errors

## 📊 API Response Examples

### Malicious URL Response

```json
{
  "response_code": 1,
  "positives": 8,
  "total": 93,
  "scan_date": "2024-01-15 10:30:00",
  "permalink": "https://www.virustotal.com/...",
  "threats": [
    {"category": "phishing", "label": "phishing"}
  ],
  "scans": {
    "engine1": {"detected": true, "result": "malicious"},
    "engine2": {"detected": false, "result": "clean"}
  }
}
```

### Clean URL Response

```json
{
  "response_code": 1,
  "positives": 0,
  "total": 93,
  "scan_date": "2024-01-15 10:30:00",
  "permalink": "https://www.virustotal.com/...",
  "scans": {
    "engine1": {"detected": false, "result": "clean"},
    "engine2": {"detected": false, "result": "clean"}
  }
}
```

## 🔒 Security Considerations

1. **API Key Storage**: API key is stored in source code. For production, consider:
   - OAuth flow for user API keys
   - Encrypted storage
   - Server-side proxy for API calls

2. **Rate Limiting**: Extension handles rate limits gracefully:
   - Respects 500/day limit
   - Falls back to OpenPhish database
   - Shows user-friendly error messages

3. **Privacy**: 
   - URLs are only sent to VirusTotal API
   - No user tracking or analytics
   - All processing is client-side

## 📚 Additional Resources

- [VirusTotal API Documentation](https://developers.virustotal.com/reference)
- [VirusTotal URL Report API](https://developers.virustotal.com/reference/url-report)
- [Chrome Extension Manifest V3](https://developer.chrome.com/docs/extensions/mv3/)

## 🤝 Support

If you encounter issues:

1. Check browser console for error messages
2. Verify API key is correct
3. Check VirusTotal API status
4. Review this implementation guide

---

**Last Updated:** January 2024
**Extension Version:** 1.0 with VirusTotal Integration
