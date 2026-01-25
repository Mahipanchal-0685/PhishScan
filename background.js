// Background script for PhishScan extension
// Manages phishing database and API configurations

// =============================================================================
// API CONFIGURATION
// =============================================================================
// IMPORTANT: Add your VirusTotal API key below to enable real-time URL scanning
//
// To get your VirusTotal API key:
// 1. Go to https://www.virustotal.com/gui/join-us
// 2. Create a free account (or sign in)
// 3. Go to your profile settings
// 4. Copy your API key
// 5. Paste it below in the 'key' field
//
// Free Tier Limits:
// - VirusTotal: 500 requests/day
// - Google Safe Browsing: 10,000 requests/day (optional)
// =============================================================================

const API_CONFIG = {
    safeBrowsing: {
        key: '', // OPTIONAL: Google Safe Browsing API key
        // Get your API key from: https://console.cloud.google.com/apis/credentials
    },
    virusTotal: {
        key: '4c3b7733c95ac9ffefe8965fd95d83e575281227abb60be29d8fcb059d7da406', // REQUIRED: Add your VirusTotal API key here
        // ⚠️ REQUIRED FOR URL SCANNING - Get from: https://www.virustotal.com/gui/join-us
        url: 'https://www.virustotal.com/vtapi/v2/url/report',
        quota: 500 // Free tier: 500 requests/day
    }
};

// OpenPhish feed URL
const FEED_URL = 'https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt';

// Test phishing URLs for fallback
const TEST_PHISHING_URLS = [
    'auspostac.world',
    'auspostac.world/index.html',
    'meta-maskloig.godaddysites.com',
    'litebluelogin-gov.com',
    'netflix-web.vercel.app',
    'connect-ledger-login.typedream.app',
    'walletconnect-website.vercel.app',
    'mettusmask_lodin.godaddysites.com',
    'schwabprotection.com',
    'coinbaselogindesk.blogspot.com.ee',
    'kreken_x_logins.godaddysites.com',
    'sgbybabit.cc',
    'upohold-logiinus.godaddysites.com',
    'trezoriosuite.m-pages.com',
    'gnnnin_1o-giin.godaddysites.com',
    'publictrezzorstart.m-pages.com',
    'steamcomunnitty.cc',
    'bradescard.express-k.com',
    'help-extension-coinbase-chrome.typedream.app',
    'ebays.663shoppingsvip.xyz',
    'secure-id-controll.com',
    'gemminnees_usaloogaan.godaddysites.com',
    'private-user-support-center.io.vn',
    'amazon-clone-amber-mu.vercel.app',
    'meta_-mask_-logi.godaddysites.com',
    'trezor.en-safewallets.com'
];

// Cache for phishing URLs
let phishingUrls = new Set();
let lastFetchTime = 0;
const CACHE_DURATION = 30 * 60 * 1000; // 30 minutes

// URL shortener services to resolve
const URL_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'v.gd', 'ow.ly', 'buff.ly',
    'adf.ly', 'sh.st', 'adfly.com', 'shorte.st', 'shorten.me', 'shorturl.com',
    'tiny.cc', 'short.to', 'snipurl.com', 'shorturl.com', 'tr.im', 'snipr.com',
    'shortlinks.co', 'shorten.me', 'shorturl.com', 'tiny.cc', 'short.to',
    'snipurl.com', 'shorturl.com', 'tr.im', 'snipr.com', 'shortlinks.co'
];

// Fetch phishing URLs from OpenPhish feed
async function fetchPhishingUrls() {
    try {
        console.log('Fetching phishing URLs from OpenPhish feed...');
        const response = await fetch(FEED_URL);

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const text = await response.text();
        console.log('Raw feed response length:', text.length);
        console.log('First 500 characters of feed:', text.substring(0, 500));

        const urls = text.split('\n').filter(url => url.trim() !== '');
        console.log('Filtered URLs count:', urls.length);
        console.log('Sample URLs from feed:', urls.slice(0, 10));

        // Clear and update the cache
        phishingUrls.clear();
        urls.forEach(url => phishingUrls.add(url.trim()));

        console.log(`Fetched ${phishingUrls.size} phishing URLs from OpenPhish feed`);
        lastFetchTime = Date.now();

        return Array.from(phishingUrls);
    } catch (error) {
        console.error('Error fetching phishing URLs:', error);
        console.log('Using test URLs as fallback due to fetch error');
        // Return test URLs as fallback
        return TEST_PHISHING_URLS;
    }
}

// Initialize phishing cache
async function initializePhishingCache() {
    if (Date.now() - lastFetchTime > CACHE_DURATION) {
        const urls = await fetchPhishingUrls();
        if (urls.length === 0) {
            console.log('No URLs fetched, using test URLs as fallback');
            phishingUrls.clear();
            TEST_PHISHING_URLS.forEach(url => phishingUrls.add(url));
            console.log(`Loaded ${phishingUrls.size} test URLs as fallback`);
        }
    }
}

// Check if a URL is a shortened URL
function isShortenedURL(url) {
    try {
        const urlObj = new URL(url);
        const hostname = urlObj.hostname.toLowerCase().replace(/^www\./, '');
        return URL_SHORTENERS.some(shortener => hostname === shortener);
    } catch (e) {
        return false;
    }
}

// Resolve shortened URL using HEAD request
async function resolveShortenedURL(url) {
    try {
        console.log('Resolving shortened URL:', url);

        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 5000); // 5 second timeout

        const response = await fetch(url, {
            method: 'HEAD',
            redirect: 'follow',
            signal: controller.signal
        });

        clearTimeout(timeoutId);

        if (response.ok && response.url !== url) {
            console.log('Resolved shortened URL:', url, '→', response.url);
            return response.url;
        }

        return url; // Return original if no redirect
    } catch (error) {
        console.error('Error resolving shortened URL:', url, error);
        return url; // Return original on error
    }
}

// Simple in-memory VT result cache to avoid hammering the API
const VT_CACHE_TTL_MS = 90 * 1000; // 90 seconds
// Require at least this many VirusTotal positives before we flag as malicious
const VT_MIN_POSITIVES_FOR_MALICIOUS = 2;
const vtCache = new Map(); // key: url, value: { timestamp, data }

// Check URL with VirusTotal API - Enhanced with detailed analysis
async function checkVirusTotal(url) {
    if (!API_CONFIG.virusTotal.key || API_CONFIG.virusTotal.key.trim() === '') {
        return {
            malicious: false,
            reason: 'VirusTotal API key not configured',
            error: 'API_KEY_MISSING'
        };
    }

    try {
        console.log('Checking URL with VirusTotal:', url);

        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 5000); // 5 second timeout for detailed checks

        // Cache: return recent result if available
        const cached = vtCache.get(url);
        if (cached && (Date.now() - cached.timestamp) < VT_CACHE_TTL_MS) {
            return cached.data;
        }

        const formData = new FormData();
        formData.append('apikey', API_CONFIG.virusTotal.key);
        formData.append('resource', url); // VirusTotal API parameter for URLs
        // Note: 'resource' is the standard parameter for URL report API
        // Alternative: You can also use 'url' parameter, both work
        // Ask VT to submit the URL if no report exists
        formData.append('scan', '1');

        const response = await fetch(API_CONFIG.virusTotal.url, {
            method: 'POST',
            body: formData,
            signal: controller.signal
        });

        clearTimeout(timeoutId);

        if (response.ok) {
            const data = await response.json();

            if (data.response_code === 1) {
                const positives = data.positives || 0;
                const total = data.total || 0;
                const scanDate = data.scan_date;
                const firstSubmission = data.first_submission_date || null;
                const lastSubmission = data.last_submission_date || null;
                const permalink = data.permalink || null;

                // Extract detailed scan results from scans object first
                const scans = data.scans || {};

                // Extract threat labels/categories
                // Note: VirusTotal URL report API may not always include 'threats' field
                // Threat information is typically in the 'scans' object results
                const threats = data.threats || [];
                const categories = threats.map(t => t.category || '').filter(c => c);
                const threatLabels = threats.map(t => t.label || '').filter(l => l);

                // Also extract threat categories from scan results if available
                const scanThreats = [];
                for (const [engine, result] of Object.entries(scans)) {
                    if (result.result && result.result !== 'clean' && result.result !== 'unrated') {
                        scanThreats.push(result.result);
                    }
                }
                // Combine with existing threat labels
                const allThreatLabels = [...new Set([...threatLabels, ...scanThreats])];
                const scanDetails = {};
                const detectedBy = [];

                for (const [engine, result] of Object.entries(scans)) {
                    scanDetails[engine] = {
                        detected: result.detected || false,
                        result: result.result || 'clean',
                        version: result.version || null,
                        update: result.update || null
                    };
                    if (result.detected) {
                        detectedBy.push({
                            engine: engine,
                            result: result.result || 'malicious'
                        });
                    }
                }

                const detectionRate = total > 0 ? ((positives / total) * 100).toFixed(1) : 0;

                const hasMinorDetections = positives > 0 && positives < VT_MIN_POSITIVES_FOR_MALICIOUS;
                const isMalicious = positives >= VT_MIN_POSITIVES_FOR_MALICIOUS;

                const result = {
                    malicious: isMalicious,
                    reason: isMalicious
                        ? `VirusTotal: ${positives}/${total} engines detected (${detectionRate}%)`
                        : hasMinorDetections
                            ? `VirusTotal: ${positives}/${total} engines flagged (below malicious threshold of ${VT_MIN_POSITIVES_FOR_MALICIOUS})`
                            : `VirusTotal: Clean (0/${total} engines detected)`,
                    positives: positives,
                    total: total,
                    detectionRate: parseFloat(detectionRate),
                    minorDetections: hasMinorDetections,
                    vtThreshold: VT_MIN_POSITIVES_FOR_MALICIOUS,
                    scanDate: scanDate,
                    firstSubmission: firstSubmission,
                    lastSubmission: lastSubmission,
                    permalink: permalink,
                    categories: categories,
                    threatLabels: allThreatLabels,
                    detectedBy: detectedBy,
                    scanDetails: scanDetails,
                    // Additional metadata
                    resource: data.resource || url,
                    responseCode: data.response_code,
                    verboseMsg: data.verbose_msg || ''
                };

                console.log('VirusTotal detailed result:', result);
                vtCache.set(url, { timestamp: Date.now(), data: result });
                return result;
            } else if (data.response_code === 0) {
                // URL not in database - submit it for scanning
                try {
                    const submitForm = new FormData();
                    submitForm.append('apikey', API_CONFIG.virusTotal.key);
                    submitForm.append('url', url);
                    const submitResp = await fetch('https://www.virustotal.com/vtapi/v2/url/scan', {
                        method: 'POST',
                        body: submitForm
                    });
                    if (submitResp.ok) {
                        const submitData = await submitResp.json().catch(() => ({}));
                        return {
                            malicious: false,
                            reason: 'Submitted to VirusTotal for scanning. Check again in ~30-90s.',
                            responseCode: 0,
                            submitted: true,
                            scanId: submitData.scan_id || null,
                            permalink: submitData.permalink || null,
                            verboseMsg: 'URL submitted for analysis'
                        };
                    }
                } catch (e) {
                    console.warn('VirusTotal submit failed:', e);
                }
                // Fallback if submission failed
                const notFound = {
                    malicious: false,
                    reason: 'VirusTotal: URL not found in database (not scanned yet)',
                    responseCode: 0,
                    submitted: false,
                    verboseMsg: data.verbose_msg || 'URL not in database'
                };
                vtCache.set(url, { timestamp: Date.now(), data: notFound });
                return notFound;
            } else {
                const unknown = {
                    malicious: false,
                    reason: `VirusTotal: ${data.verbose_msg || 'Unknown response code'}`,
                    responseCode: data.response_code
                };
                vtCache.set(url, { timestamp: Date.now(), data: unknown });
                return unknown;
            }
        } else if (response.status === 429) {
            console.warn('VirusTotal API rate limit exceeded');
            const rateLimited = {
                malicious: false,
                reason: 'VirusTotal: API rate limit exceeded',
                rateLimited: true,
                error: 'RATE_LIMIT'
            };
            vtCache.set(url, { timestamp: Date.now(), data: rateLimited });
            return rateLimited;
        } else {
            const errorText = await response.text().catch(() => 'Unknown error');
            console.error('VirusTotal API error:', response.status, errorText);
            const httpErr = {
                malicious: false,
                reason: `VirusTotal: API error (${response.status})`,
                error: `HTTP_${response.status}`
            };
            vtCache.set(url, { timestamp: Date.now(), data: httpErr });
            return httpErr;
        }
    } catch (error) {
        console.error('VirusTotal API error:', error);
        if (error.name === 'AbortError') {
            const timeout = {
                malicious: false,
                reason: 'VirusTotal: Request timeout',
                error: 'TIMEOUT'
            };
            vtCache.set(url, { timestamp: Date.now(), data: timeout });
            return timeout;
        }
        const netErr = {
            malicious: false,
            reason: 'VirusTotal: Network error',
            error: 'NETWORK_ERROR'
        };
        vtCache.set(url, { timestamp: Date.now(), data: netErr });
        return netErr;
    }
}

// Message listener for communication with content scripts and popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    console.log('Background received message:', request.type);

    switch (request.type) {
        case 'GET_PHISH_FEED':
            // Return cached phishing URLs
            sendResponse({ phishingList: Array.from(phishingUrls) });
            break;

        case 'GET_TOGGLE_STATE':
            // Get toggle state from storage
            chrome.storage.sync.get(['phishscan_enabled'], (result) => {
                sendResponse({ enabled: result.phishscan_enabled !== false });
            });
            return true; // Keep message channel open for async response

        case 'SET_TOGGLE_STATE':
            // Set toggle state in storage
            chrome.storage.sync.set({ phishscan_enabled: request.enabled }, () => {
                sendResponse({ success: true });
            });
            return true; // Keep message channel open for async response

        case 'GET_SAFE_BROWSING_KEY':
            // Return Google Safe Browsing API key
            sendResponse({ key: API_CONFIG.safeBrowsing.key });
            break;

        case 'GET_VIRUSTOTAL_KEY':
            // Return VirusTotal API key
            sendResponse({ key: API_CONFIG.virusTotal.key });
            break;

        case 'CHECK_VIRUSTOTAL':
            // Check URL with VirusTotal API
            checkVirusTotal(request.url).then(result => {
                sendResponse(result);
            });
            return true; // Keep message channel open for async response

        case 'RESOLVE_SHORTENED_URL':
            // Resolve shortened URL
            resolveShortenedURL(request.url).then(resolvedUrl => {
                sendResponse({ resolvedUrl: resolvedUrl });
            });
            return true; // Keep message channel open for async response

        case 'IS_SHORTENED_URL':
            // Check if URL is shortened
            const isShortened = isShortenedURL(request.url);
            sendResponse({ isShortened: isShortened });
            break;

        default:
            sendResponse({ error: 'Unknown message type' });
    }
});

// Initialize on startup
initializePhishingCache();

// Set up periodic refresh of phishing database
setInterval(initializePhishingCache, CACHE_DURATION);

// Handle extension installation
chrome.runtime.onInstalled.addListener(() => {
    console.log('PhishScan extension installed');
    ensureDetectionDefaultOn();
    initializePhishingCache();
});

// Ensure detection starts enabled by default
async function ensureDetectionDefaultOn() {
    try {
        const { phishscan_enabled } = await chrome.storage.sync.get(['phishscan_enabled']);
        if (phishscan_enabled === undefined) {
            await chrome.storage.sync.set({ phishscan_enabled: true });
            console.log('PhishScan detection set to ON by default');
        }
    } catch (e) {
        console.debug('Could not set default detection state', e);
    }
}

// Also enforce default ON when the browser starts
chrome.runtime.onStartup.addListener(() => {
    ensureDetectionDefaultOn();
});

// ---------------------------------------------------------------------------
// Automatic rescans when the user switches tabs or completes navigation
// ---------------------------------------------------------------------------
async function triggerScanOnTab(tabId) {
    try {
        // Respect the user toggle; skip if disabled
        const { phishscan_enabled } = await chrome.storage.sync.get(['phishscan_enabled']);
        if (phishscan_enabled === false) return;

        // Nudge the content script to rescan this tab
        chrome.tabs.sendMessage(tabId, { type: 'FORCE_SCAN' }, () => {
            // Ignore errors when no receiver (e.g., chrome pages or inactive tabs)
            if (chrome.runtime.lastError) {
                // Useful for debugging but not fatal
                console.debug('FORCE_SCAN sendMessage skipped:', chrome.runtime.lastError.message);
            }
        });
    } catch (e) {
        console.debug('Unable to trigger scan on tab', tabId, e);
    }
}

// Re-scan when the active tab changes
chrome.tabs.onActivated.addListener(({ tabId }) => {
    triggerScanOnTab(tabId);
});

// Re-scan when navigation finishes on a tab
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
    if (changeInfo.status === 'complete') {
        triggerScanOnTab(tabId);
    }
});