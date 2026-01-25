// Prevent multiple executions of this script
if (window.phishScanLoaded) {
    console.log('PhishScan already loaded, skipping...');
} else {
    window.phishScanLoaded = true;

    // Configuration
    const SCAN_BATCH_SIZE = 6; // Batch size for API calls (balanced speed)
    const SCAN_DELAY = 150; // ms between batches
    const DEBOUNCE_DELAY = 1000; // ms for DOM change debouncing
    const API_TIMEOUT = 7000; // 7 second timeout for API calls
    const MAX_LINKS_PER_PAGE = 30; // Hard cap on links to scan per page
    const MAX_FORMS_PER_PAGE = 5; // Hard cap on forms to scan per page

    // Cache for processed URLs to avoid re-scanning
    const processedUrls = new Set();
    let scanInProgress = false;
    let observer = null;
    let rateLimitReached = false;

    // Test phishing URLs for demonstration (including some real ones from the feed)
    const TEST_PHISHING_URLS = [
        'example-phishing-site.com',
        'fake-login-page.com',
        'malicious-download.net',
        'fake-phishing-form.com',
        'phishing-test.com',
        'malicious-site.org',
        'fake-bank-login.com',
        'steal-password.net',
        'fake-paypal.com',
        'malware-download.com',
        'auspostac.world',
        'auspostac.world/index.html',
        'fake-auspost.com',
        'phishing-auspost.net',
        'malicious-auspost.org',
        // Real URLs from the OpenPhish feed for testing
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
        'netflix-web.vercel.app',
        'meta_-mask_-logi.godaddysites.com',
        'trezor.en-safewallets.com'
    ];

    // Safe domains that should never be flagged
    const SAFE_DOMAINS = [
        'google.com', 'google.co.uk', 'google.ca', 'google.com.au',
        'microsoft.com', 'microsoft.co.uk', 'microsoft.ca',
        'github.com', 'github.io', 'githubusercontent.com',
        'apple.com', 'icloud.com', 'me.com',
        'amazon.com', 'amazon.co.uk', 'amazon.ca', 'amazon.com.au',
        'facebook.com', 'instagram.com', 'twitter.com', 'x.com',
        'linkedin.com', 'youtube.com', 'reddit.com',
        'stackoverflow.com', 'wikipedia.org', 'wikimedia.org',
        'mozilla.org', 'firefox.com', 'chrome.com',
        'cloudflare.com', 'fastly.com', 'akamai.com',
        'wordpress.com', 'tumblr.com', 'medium.com',
        'netflix.com', 'spotify.com', 'discord.com',
        'slack.com', 'zoom.us', 'teams.microsoft.com',
        'dropbox.com', 'box.com', 'onedrive.live.com',
        'paypal.com', 'stripe.com', 'square.com',
        'bankofamerica.com', 'wellsfargo.com', 'chase.com',
        'usps.com', 'fedex.com', 'ups.com',
        'weather.com', 'accuweather.com', 'weather.gov',
        'irs.gov', 'ssa.gov', 'usps.gov',
        'whitehouse.gov', 'congress.gov', 'supremecourt.gov'
    ];

    // Suspicious Patterns for Fallback Logic
    const IP_REGEX = /^(http|https):\/\/(\d{1,3}\.){3}\d{1,3}/;
    const SUSPICIOUS_KEYWORDS = ['login', 'signin', 'verify', 'update', 'secure', 'account', 'banking', 'wallet', 'confirm', 'pay', 'bonus', 'free', 'gift', 'prize'];
    const SUSPICIOUS_TLDS = ['.xyz', '.top', '.club', '.info', '.site', '.live', '.gq', '.tk', '.ml', '.ga', '.cf', '.buzz', '.cn']; // Common abuse TLDs

    // Heuristic Risk Scoring
    function calculateRiskScore(url) {
        let score = 0;
        const reasons = [];
        const normalizedUrl = normalizeUrl(url);
        const urlObj = new URL(normalizedUrl);
        const hostname = urlObj.hostname.toLowerCase();

        // 1. Check for IP-based URL
        if (IP_REGEX.test(url)) {
            score += 50;
            reasons.push('IP-based URL detected (high risk)');
        }

        // 2. Check for suspicious keywords in hostname or path
        let keywordCount = 0;
        SUSPICIOUS_KEYWORDS.forEach(keyword => {
            if (normalizedUrl.includes(keyword)) {
                keywordCount++;
            }
        });
        if (keywordCount > 0) {
            score += 10 * keywordCount;
            reasons.push(`Contains suspicious keywords (${keywordCount})`);
        }

        // 3. Check for suspicious TLDs
        const isSuspiciousTLD = SUSPICIOUS_TLDS.some(tld => hostname.endsWith(tld));
        if (isSuspiciousTLD) {
            score += 20;
            reasons.push('Suspicious Top-Level Domain (TLD)');
        }

        // 4. URL Length (Extremely long URLs are often phishing)
        if (url.length > 75) {
            score += 10;
            reasons.push('Unusually long URL');
        }

        // 5. Subdomain count
        const dotCount = (hostname.match(/\./g) || []).length;
        if (dotCount > 3) {
            score += 15;
            reasons.push(' Excessive subdomains');
        }

        return { score, reasons };
    }


    // Track URL scan results for tooltips and display
    const urlScanResults = new Map();

    function highlightElement(el, reason = '', isShortened = false, resolvedUrl = null, virustotalData = null) {
        if (el.hasAttribute('data-phishscan-malicious')) return; // Already highlighted as malicious

        // Remove any existing clean markers
        if (el.hasAttribute('data-phishscan-clean')) {
            el.removeAttribute('data-phishscan-clean');
            const existingIndicator = el.querySelector('.phishscan-clean-indicator');
            if (existingIndicator) existingIndicator.remove();
        }

        el.style.border = '2px solid #dc3545';
        el.style.backgroundColor = '#ffe6e6';
        el.setAttribute('data-phishscan-malicious', 'true');
        el.classList.add('phishscan-malicious-link');

        // Build tooltip text using translations
        let tooltipText = `${t('maliciousConfirmed')}\n\n${t('detection')}: ${reason}`;

        if (isShortened && resolvedUrl) {
            tooltipText += `\n\n${t('shortenedUrl')}:\n${t('original')}: ${el.href}\n${t('expanded')}: ${resolvedUrl}`;
        }

        if (virustotalData) {
            if (virustotalData.positives !== undefined) {
                tooltipText += `\n\n${t('vtAnalysis')}:\n• ${virustotalData.positives}/${virustotalData.total} ${t('enginesDetected')}`;
            }

            if (virustotalData.scanDate) {
                tooltipText += `\n${t('lastScan')}: ${new Date(virustotalData.scanDate * 1000).toLocaleDateString()}`;
            }

            if (virustotalData.permalink) {
                tooltipText += `\n${t('clickToView')}`;
            }
        }

        tooltipText += `\n\n${t('warningMsg')}`;

        // Set native tooltip
        el.title = tooltipText;

        // Add visual warning indicator
        const warningIcon = document.createElement('span');
        warningIcon.className = 'phishscan-malicious-indicator';
        warningIcon.textContent = '⚠️';
        warningIcon.style.marginLeft = '5px';
        warningIcon.style.fontSize = '12px';
        warningIcon.style.cursor = 'help';
        warningIcon.title = tooltipText;

        if (!el.querySelector('.phishscan-malicious-indicator')) {
            el.appendChild(warningIcon);
        }

        // Add click interception for safety
        el.addEventListener('click', function (e) {
            e.preventDefault();
            e.stopPropagation();
            showConfirmationModal(resolvedUrl || el.href);
        }, true);
    }

    // Multilingual translation system (Hindi, Gujarati, English)
    const translations = {
        en: {
            maliciousConfirmed: '⚠️ MALICIOUS URL CONFIRMED!',
            verifiedSafe: '✅ VERIFIED SAFE',
            detection: '🚨 DETECTION',
            riskScore: '🎯 Risk Score',
            suspiciousPatterns: '⚠️ Suspicious Patterns',
            shortenedUrl: '🔗 SHORTENED URL',
            original: 'Original',
            expanded: 'Expanded',
            vtAnalysis: '📊 VirusTotal Analysis',
            enginesDetected: 'engines detected',
            enginesFlagged: 'engines flagged',
            threatLabels: '• Threat Labels',
            newDomain: '• 🆕 NEW DOMAIN DETECTED!',
            daysOld: 'days old',
            highRisk: 'High Risk',
            lastScan: '• Last Scan',
            warningMsg: '⚠️ WARNING: This URL has been flagged as malicious. Do not click this link!',
            safeDomain: 'Safe domain (whitelisted)',
            clickToView: '• View Full Report: Click to see detailed analysis',
            expandedUrl: '🔗 Expanded URL',
            rateLimited: '⚠️ Scan incomplete: API rate limit reached.',
            threatsDetected: (count) => `⚠️ ${count} malicious link${count > 1 ? 's' : ''} detected`,
            noLinksFound: 'ℹ️ No links found on this page',
            pageSafe: (count) => `✅ Page appears safe — ${count} link${count > 1 ? 's' : ''} scanned`
        },
        hi: {
            maliciousConfirmed: '⚠️ दुर्भावनापूर्ण URL की पुष्टि की गई!',
            verifiedSafe: '✅ सत्यापित सुरक्षित',
            detection: '🚨 पहचान',
            riskScore: '🎯 जोखिम स्कोर',
            suspiciousPatterns: '⚠️ संदिग्ध पैटर्न',
            shortenedUrl: '🔗 छोटा किया गया URL',
            original: 'मूल',
            expanded: 'विस्तारित',
            vtAnalysis: '📊 VirusTotal विश्लेषण',
            enginesDetected: 'इंजन मिले',
            enginesFlagged: 'इंजन ने चेतावनी दी',
            threatLabels: '• खतरा लेबल',
            newDomain: '• 🆕 नया डोमेन मिला!',
            daysOld: 'दिन पुराना',
            highRisk: 'उच्च जोखिम',
            lastScan: '• अंतिम स्कैन',
            warningMsg: '⚠️ चेतावनी: इस URL को दुर्भावनापूर्ण के रूप में चिह्नित किया गया है। इस लिंक पर क्लिक न करें!',
            safeDomain: 'सुरक्षित डोमेन (श्वेतसूचीबद्ध)',
            clickToView: '• पूरी रिपोर्ट देखें: विस्तृत विश्लेषण देखने के लिए क्लिक करें',
            expandedUrl: '🔗 विस्तारित URL',
            rateLimited: '⚠️ स्कैन अधूरा: API दर सीमा पहुंच गई।',
            threatsDetected: (count) => `⚠️ ${count} दुर्भावनापूर्ण लिंक${count > 1 ? ' पाए गए' : ' पाया गया'}`,
            noLinksFound: 'ℹ️ इस पृष्ठ पर कोई लिंक नहीं मिला',
            pageSafe: (count) => `✅ पृष्ठ सुरक्षित लगता है — ${count} लिंक${count > 1 ? ' स्कैन किए गए' : ' स्कैन किया गया'}`
        },
        gu: {
            maliciousConfirmed: '⚠️ દુર્ભાવનાપૂર્ણ URL ની પુષ્ટિ કરી!',
            verifiedSafe: '✅ ચકાસાયેલ સુરક્ષિત',
            detection: '🚨 ઓળખ',
            riskScore: '🎯 જોખમ સ્કોર',
            suspiciousPatterns: '⚠️ શંકાસ્પદ પેટર્ન',
            shortenedUrl: '🔗 ટૂંકું કરેલું URL',
            original: 'મૂળ',
            expanded: 'વિસ્તૃત',
            vtAnalysis: '📊 VirusTotal વિશ્લેષણ',
            enginesDetected: 'એન્જિન મળ્યા',
            enginesFlagged: 'એન્જિન ચેતવણી આપી',
            threatLabels: '• ખતરાના લેબલ',
            newDomain: '• 🆕 નવું ડોમેન મળ્યું!',
            daysOld: 'દિવસ જૂનું',
            highRisk: 'ઉચ્ચ જોખમ',
            lastScan: '• છેલ્લું સ્કેન',
            warningMsg: '⚠️ ચેતવણી: આ URL ને દુર્ભાવનાપૂર્ણ તરીકે ચિહ્નિત કરવામાં આવ્યું છે. આ લિંક પર ક્લિક કરશો નહીં!',
            safeDomain: 'સુરક્ષિત ડોમેન (વ્હાઇટલિસ્ટેડ)',
            clickToView: '• સંપૂર્ણ રિપોર્ટ જુઓ: વિગતવાર વિશ્લેષણ જોવા માટે ક્લિક કરો',
            expandedUrl: '🔗 વિસ્તૃત URL',
            rateLimited: '⚠️ સ્કેન અધૂરું: API દર મર્યાદા પહોંચી ગઈ.',
            threatsDetected: (count) => `⚠️ ${count} દુર્ભાવનાપૂર્ણ લિંક${count > 1 ? ' મળી' : ' મળી'}`,
            noLinksFound: 'ℹ️ આ પૃષ્ઠ પર કોઈ લિંક મળી નથી',
            pageSafe: (count) => `✅ પૃષ્ઠ સુરક્ષિત લાગે છે — ${count} લિંક${count > 1 ? ' સ્કેન કરવામાં આવ્યા' : ' સ્કેન કરવામાં આવ્યું'}`
        }
    };

    let currentLang = 'en';
    let cachedLanguage = null; // Moved here to be near the translations object

    // Get current language from storage
    function updateLanguage() {
        chrome.storage.sync.get(['phishscan_language'], (result) => {
            if (result.phishscan_language) {
                currentLang = result.phishscan_language;
            }
        });
    }

    // Listen for language changes from popup
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
        if (request.type === 'LANGUAGE_CHANGED') {
            currentLang = request.language;
            console.log('Language updated to:', currentLang);
        }
    });

    // Call immediately
    updateLanguage();

    // Helper to get translated string
    function t(key, ...args) {
        const lang = cachedLanguage || detectLanguage(); // Use cached language if available
        const langTranslations = translations[lang] || translations.en;
        const translation = langTranslations[key];

        if (typeof translation === 'function') {
            return translation(...args);
        }
        // Fallback to English if key not found in current language
        return translation || translations.en[key];
    }

    // Detect language from storage, page, or browser
    function detectLanguage() {
        // Return cached language if available
        if (cachedLanguage) {
            return cachedLanguage;
        }

        // Check browser language as fallback
        const browserLang = navigator.language || navigator.userLanguage || 'en';
        const langCode = browserLang.split('-')[0].toLowerCase();

        // Check page language attribute
        const pageLang = document.documentElement.lang || '';
        const pageLangCode = pageLang.split('-')[0].toLowerCase();

        let detectedLang = 'en';

        // Priority: page lang > browser lang > default to English
        if (pageLangCode === 'hi' || pageLangCode === 'gu') {
            detectedLang = pageLangCode;
        } else if (langCode === 'hi' || langCode === 'gu') {
            detectedLang = langCode;
        }

        cachedLanguage = detectedLang;
        return detectedLang;
    }

    // Load language from chrome.storage
    chrome.storage.sync.get(['phishscan_language'], (result) => {
        if (result.phishscan_language && (result.phishscan_language === 'hi' || result.phishscan_language === 'gu' || result.phishscan_language === 'en')) {
            cachedLanguage = result.phishscan_language;
            // Refresh banner if it exists
            if (statusBannerEl) {
                chrome.storage.local.get(['phishscan_total_scanned', 'phishscan_found', 'phishscan_rate_limited', 'phishscan_clean'], (localResult) => {
                    updatePageStatusBanner({
                        totalScanned: localResult.phishscan_total_scanned || 0,
                        threats: (localResult.phishscan_found || []).length,
                        clean: (localResult.phishscan_clean || []).length,
                        rateLimited: localResult.phishscan_rate_limited === true
                    });
                });
            }
        }
    });

    // Enhanced URL normalization - remove tracking params and ensure proper scheme
    function normalizeUrl(url) {
        if (!url) return '';

        try {
            // Create URL object to properly parse
            let urlObj;
            try {
                urlObj = new URL(url);
            } catch (e) {
                // If URL is relative, make it absolute
                urlObj = new URL(url, window.location.href);
            }

            // Remove tracking parameters
            const trackingParams = [
                'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
                'fbclid', 'gclid', 'msclkid', 'ref', 'source', 'campaign', 'medium',
                'term', 'content', 'clickid', 'affiliate', 'partner', 'referrer'
            ];

            trackingParams.forEach(param => {
                urlObj.searchParams.delete(param);
            });

            // Ensure HTTPS scheme
            if (urlObj.protocol === 'http:') {
                urlObj.protocol = 'https:';
            }

            // Remove fragments
            urlObj.hash = '';

            // Normalize hostname (lowercase, remove www)
            urlObj.hostname = urlObj.hostname.toLowerCase().replace(/^www\./, '');

            return urlObj.toString();
        } catch (e) {
            console.error('Error normalizing URL:', url, e);
            return url;
        }
    }

    // Check if domain is in safe list
    function isSafeDomain(url) {
        try {
            const urlObj = new URL(url);
            const hostname = urlObj.hostname.toLowerCase().replace(/^www\./, '');

            // Check exact match
            if (SAFE_DOMAINS.includes(hostname)) {
                return true;
            }

            // Check subdomain matches
            for (const safeDomain of SAFE_DOMAINS) {
                if (hostname.endsWith('.' + safeDomain)) {
                    return true;
                }
            }

            return false;
        } catch (e) {
            return false;
        }
    }

    // Check if URL is shortened
    async function isShortenedURL(url) {
        try {
            const response = await chrome.runtime.sendMessage({
                type: 'IS_SHORTENED_URL',
                url: url
            });
            return response?.isShortened || false;
        } catch (e) {
            console.error('Error checking if URL is shortened:', e);
            return false;
        }
    }

    // Resolve shortened URL
    async function resolveShortenedURL(url) {
        try {
            const response = await chrome.runtime.sendMessage({
                type: 'RESOLVE_SHORTENED_URL',
                url: url
            });
            return response?.resolvedUrl || url;
        } catch (e) {
            console.error('Error resolving shortened URL:', e);
            return url;
        }
    }

    // Google Safe Browsing API check
    async function checkSafeBrowsing(url) {
        try {
            // Get API key from background script
            const apiKeyResponse = await chrome.runtime.sendMessage({ type: 'GET_SAFE_BROWSING_KEY' });
            const apiKey = apiKeyResponse?.key;

            if (!apiKey || apiKey.trim() === '') {
                console.log('No API key configured, skipping Safe Browsing check');
                return { malicious: false, reason: 'API key not configured' };
            }

            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), API_TIMEOUT);

            const response = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    client: {
                        clientId: 'phishscan-extension',
                        clientVersion: '1.0'
                    },
                    threatInfo: {
                        threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
                        platformTypes: ['ANY_PLATFORM'],
                        threatEntryTypes: ['URL'],
                        threatEntries: [{ url: url }]
                    }
                }),
                signal: controller.signal
            });

            clearTimeout(timeoutId);

            if (response.ok) {
                const data = await response.json();
                if (data.matches && data.matches.length > 0) {
                    const threat = data.matches[0];
                    return {
                        malicious: true,
                        reason: `Google Safe Browsing: ${threat.threatType}`,
                        threatType: threat.threatType,
                        platformType: threat.platformType
                    };
                }
            } else if (response.status === 429) {
                // Rate limit exceeded
                rateLimitReached = true;
                return { malicious: false, reason: 'API rate limit exceeded', rateLimited: true };
            }
        } catch (e) {
            console.error('Safe Browsing API error:', e);
            if (e.name === 'AbortError') {
                return { malicious: false, reason: 'API request timeout' };
            }
        }

        return { malicious: false, reason: 'No threats detected' };
    }

    // VirusTotal API check
    async function checkVirusTotal(url) {
        try {
            const response = await chrome.runtime.sendMessage({
                type: 'CHECK_VIRUSTOTAL',
                url: url
            });
            return response;
        } catch (e) {
            console.error('VirusTotal API error:', e);
            return { malicious: false, reason: 'VirusTotal: Network error' };
        }
    }

    // Improved fallback detection using OpenPhish database with better matching
    function checkOpenPhishDatabase(url, phishingSet) {
        if (!phishingSet || phishingSet.size === 0) {
            console.log('OpenPhish database is empty, using test URLs');
            // Fallback to test URLs if database is empty
            const testSet = new Set(TEST_PHISHING_URLS);
            return checkOpenPhishDatabaseInternal(url, testSet);
        }

        return checkOpenPhishDatabaseInternal(url, phishingSet);
    }

    function checkOpenPhishDatabaseInternal(url, phishingSet) {
        // First check if it's a safe domain
        if (isSafeDomain(url)) {
            console.log('URL is in safe domain list:', url);
            return { malicious: false, reason: 'Safe domain (whitelisted)' };
        }

        const normalizedUrl = normalizeUrl(url);
        const urlObj = new URL(normalizedUrl);
        const hostname = urlObj.hostname.toLowerCase().replace(/^www\./, '');
        const domain = hostname.split('.').slice(-2).join('.'); // Get main domain (e.g., google.com from sub.google.com)

        console.log('Checking URL against phishing database:', {
            original: url,
            normalized: normalizedUrl,
            hostname: hostname,
            domain: domain,
            databaseSize: phishingSet.size
        });

        // Check exact match first (most precise)
        if (phishingSet.has(normalizedUrl)) {
            console.log('Exact match found in phishing database');
            return { malicious: true, reason: 'Exact match in phishing database' };
        }

        // Check hostname match (more precise than domain)
        if (phishingSet.has(hostname)) {
            console.log('Hostname match found in phishing database');
            return { malicious: true, reason: 'Hostname match in phishing database' };
        }

        // Check domain match (less precise, but still good)
        if (phishingSet.has(domain)) {
            console.log('Domain match found in phishing database');
            return { malicious: true, reason: 'Domain match in phishing database' };
        }

        // Check for broader matches (more flexible)
        for (const phishingUrl of phishingSet) {
            // Check if the phishing URL contains our hostname or domain
            if (phishingUrl.includes(hostname) || phishingUrl.includes(domain)) {
                console.log('Broad match found in phishing database:', phishingUrl);
                return { malicious: true, reason: 'Broad match in phishing database' };
            }

            // Check if our URL contains the phishing URL
            if (hostname.includes(phishingUrl) || domain.includes(phishingUrl)) {
                console.log('Reverse match found in phishing database:', phishingUrl);
                return { malicious: true, reason: 'Reverse match in phishing database' };
            }
        }

        console.log('No match found in phishing database');
        return { malicious: false, reason: 'No match in phishing database' };
    }

    // Main URL checking function with Hybrid Approach (Heuristic + Local + API)
    async function checkUrlWithAPI(url) {
        if (!url) return { malicious: false, reason: 'No URL provided' };

        const normalizedUrl = normalizeUrl(url);
        console.log('Checking URL:', url, 'Normalized:', normalizedUrl);

        // 1. SAFE LIST CHECK (Fastest, Local)
        // Immediately trust known safe domains to avoid false positives and save resources
        if (isSafeDomain(normalizedUrl)) {
            return {
                malicious: false,
                reason: 'Safe domain (whitelisted)',
                originalUrl: url,
                resolvedUrl: null,
                isShortened: false,
                virustotalData: null,
                riskScore: 0
            };
        }

        // Check if already processed
        if (processedUrls.has(normalizedUrl)) {
            console.log('URL already processed:', normalizedUrl);
            return null;
        }

        processedUrls.add(normalizedUrl);

        // Check if URL is shortened
        const isShortened = await isShortenedURL(normalizedUrl);
        let finalUrl = normalizedUrl;
        let resolvedUrl = null;

        if (isShortened) {
            console.log('Detected shortened URL, resolving...');
            resolvedUrl = await resolveShortenedURL(normalizedUrl);
            finalUrl = resolvedUrl;

            if (resolvedUrl !== normalizedUrl) {
                console.log('Resolved shortened URL:', normalizedUrl, '→', resolvedUrl);

                // Check if resolved URL is already processed
                if (processedUrls.has(resolvedUrl)) {
                    console.log('Resolved URL already processed:', resolvedUrl);
                    return null;
                }
                processedUrls.add(resolvedUrl);
            }
        }

        // 2. HEURISTIC ANALYSIS (Local, Instant)
        const heuristicData = calculateRiskScore(finalUrl);
        console.log('Heuristic analysis:', finalUrl, heuristicData);

        // If risk is extremely high from heuristics alone (e.g. suspicious IP), flag it
        // But we prefer to confirm with APIs if possible.

        // 3. OPENPHISH DATABASE CHECK (Local Cache)
        // Always check this as it's efficient and catches known recent threats
        const phishingList = await getPhishFeed();
        const phishingSet = new Set(phishingList);
        const openPhishResult = checkOpenPhishDatabase(finalUrl, phishingSet);

        if (openPhishResult.malicious) {
            console.log('Found malicious URL via OpenPhish database:', finalUrl, 'Reason:', openPhishResult.reason);
            return {
                ...openPhishResult,
                originalUrl: url,
                resolvedUrl: resolvedUrl,
                isShortened: isShortened,
                riskScore: heuristicData.score,
                heuristicReasons: heuristicData.reasons
            };
        }

        // Check configuration
        const apiKeyResponse = await chrome.runtime.sendMessage({ type: 'GET_SAFE_BROWSING_KEY' });
        const virusTotalKeyResponse = await chrome.runtime.sendMessage({ type: 'GET_VIRUSTOTAL_KEY' });

        const safeBrowsingKeyConfigured = apiKeyResponse?.key && apiKeyResponse.key.trim() !== '';
        const virusTotalKeyConfigured = virusTotalKeyResponse?.key && virusTotalKeyResponse.key.trim() !== '';

        // 4. GOOGLE SAFE BROWSING (High Quota)
        // Use this if configured, as it has higher limits than VirusTotal
        if (safeBrowsingKeyConfigured) {
            const safeBrowsingResult = await checkSafeBrowsing(finalUrl);

            if (safeBrowsingResult.malicious) {
                console.log('Found malicious URL via Safe Browsing API:', finalUrl, 'Reason:', safeBrowsingResult.reason);
                return {
                    ...safeBrowsingResult,
                    originalUrl: url,
                    resolvedUrl: resolvedUrl,
                    isShortened: isShortened,
                    riskScore: heuristicData.score
                };
            }
        }

        // 5. VIRUSTOTAL (Low Quota - Hybrid Strategy)
        // Only scan if:
        // a) URL has some heuristic risk (score >= 20)
        // b) URL is shortened (often used to hide threats)
        // c) It's a new/unknown domain (we can't know this without checking, but we use heuristics effectively)
        // d) We haven't hit the rate limit flag yet

        const RISK_THRESHOLD_FOR_SCAN = 20;
        const shouldScanVT = virusTotalKeyConfigured &&
            (heuristicData.score >= RISK_THRESHOLD_FOR_SCAN || isShortened || !safeBrowsingKeyConfigured);

        let virusTotalResult = null;

        if (shouldScanVT && !rateLimitReached) {
            console.log(`Checking VirusTotal (Risk Score: ${heuristicData.score})...`);
            virusTotalResult = await checkVirusTotal(finalUrl);

            if (virusTotalResult.malicious) {
                console.log('Found malicious URL via VirusTotal:', finalUrl, 'Reason:', virusTotalResult.reason);
                return {
                    ...virusTotalResult,
                    originalUrl: url,
                    resolvedUrl: resolvedUrl,
                    isShortened: isShortened,
                    riskScore: heuristicData.score,
                    heuristicReasons: heuristicData.reasons
                };
            }

            // If VirusTotal returns rate limit error, set flag
            if (virusTotalResult.rateLimited) {
                rateLimitReached = true;
            }
        } else {
            console.log(`Skipping VirusTotal. Risk Score: ${heuristicData.score} (Threshold: ${RISK_THRESHOLD_FOR_SCAN}), Key Configured: ${virusTotalKeyConfigured}`);
        }

        // 6. FINAL VERDICT
        // If we have a high heuristic score but APIs didn't catch it (or were skipped),
        // we might still want to warn the user if it looks very suspicious.
        if (heuristicData.score >= 50) { // Very high threshold for pure heuristic block
            return {
                malicious: true,
                reason: `Suspicious patterns detected: ${heuristicData.reasons.join(', ')}`,
                originalUrl: url,
                resolvedUrl: resolvedUrl,
                isShortened: isShortened,
                riskScore: heuristicData.score,
                heuristicReasons: heuristicData.reasons,
                virustotalData: virusTotalResult
            };
        }

        // Otherwise return safe (clean)
        return {
            malicious: false,
            reason: virusTotalResult?.reason || 'No threats detected',
            originalUrl: url,
            resolvedUrl: resolvedUrl,
            isShortened: isShortened,
            virustotalData: virusTotalResult || null,
            riskScore: heuristicData.score,
            heuristicReasons: heuristicData.reasons
        };
    }

    // Mark clean/safe URLs with green checkmark
    function markCleanElement(el, reason = '', isShortened = false, resolvedUrl = null, virustotalData = null) {
        // Don't override malicious markers
        if (el.hasAttribute('data-phishscan-malicious')) return;

        // Don't mark if already marked as clean (unless we have new data)
        if (el.hasAttribute('data-phishscan-clean') && !virustotalData) return;

        el.setAttribute('data-phishscan-clean', 'true');
        el.classList.add('phishscan-clean-link');

        // Store scan result
        if (virustotalData) {
            urlScanResults.set(el.href, { type: 'clean', data: virustotalData, isShortened, resolvedUrl });
        }

        // Enhanced tooltip for clean URLs
        let tooltipText = `${t('verifiedSafe')}\n\n✓ ${reason}`;

        if (isShortened && resolvedUrl) {
            tooltipText += `\n\n${t('shortenedUrl')}:\n${t('original')}: ${el.href}\n${t('expanded')}: ${resolvedUrl}`;
        }

        if (virustotalData && virustotalData.total > 0) {
            tooltipText += `\n\n${t('vtAnalysis')}:\n• Clean: ${virustotalData.positives}/${virustotalData.total} ${t('enginesFlagged')}`;
            if (virustotalData.scanDate) {
                tooltipText += `\n${t('lastScan')}: ${new Date(virustotalData.scanDate * 1000).toLocaleDateString()}`;
            }
            if (virustotalData.permalink) {
                tooltipText += `\n${t('clickToView')}`;
            }
        }

        // Add subtle green checkmark indicator
        const checkmark = document.createElement('span');
        checkmark.className = 'phishscan-clean-indicator';
        checkmark.textContent = '✅';
        checkmark.style.marginLeft = '5px';
        checkmark.style.fontSize = '12px';
        checkmark.style.opacity = '0.7';
        checkmark.style.cursor = 'help';
        checkmark.title = tooltipText;

        // Set tooltip on the link itself
        el.title = tooltipText;

        // Only add checkmark if not already present
        if (!el.querySelector('.phishscan-clean-indicator')) {
            el.appendChild(checkmark);
        }
    }

    // Enhanced tooltip for shortened URLs on hover (works with mouseover)
    function setupShortenedUrlTooltip(el, resolvedUrl) {
        if (!resolvedUrl || resolvedUrl === el.href) return;

        el.addEventListener('mouseenter', function () {
            // Create or update tooltip
            let tooltip = document.getElementById('phishscan-url-tooltip');
            if (!tooltip) {
                tooltip = document.createElement('div');
                tooltip.id = 'phishscan-url-tooltip';
                tooltip.style.cssText = `
          position: absolute;
          background: #2d3748;
          color: white;
          padding: 8px 12px;
          border-radius: 6px;
          font-size: 12px;
          z-index: 10000;
          max-width: 400px;
          word-break: break-all;
          box-shadow: 0 4px 6px rgba(0,0,0,0.3);
          pointer-events: none;
        `;
                document.body.appendChild(tooltip);
            }

            tooltip.innerHTML = `
        <div style="font-weight: bold; margin-bottom: 4px;">${t('expandedUrl')}:</div>
        <div style="color: #90cdf4;">${resolvedUrl}</div>
      `;

            // Position tooltip near the link
            const rect = el.getBoundingClientRect();
            tooltip.style.top = (rect.bottom + window.scrollY + 5) + 'px';
            tooltip.style.left = (rect.left + window.scrollX) + 'px';
        });

        el.addEventListener('mouseleave', function () {
            const tooltip = document.getElementById('phishscan-url-tooltip');
            if (tooltip) {
                tooltip.remove();
            }
        });
    }

    // Confirmation Modal for Click Warning
    function showConfirmationModal(url) {
        // Remove existing modal if any
        const existingModal = document.getElementById('phishscan-warning-modal');
        if (existingModal) existingModal.remove();

        const modal = document.createElement('div');
        modal.id = 'phishscan-warning-modal';
        modal.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(0, 0, 0, 0.85);
      z-index: 999999;
      display: flex;
      justify-content: center;
      align-items: center;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    `;

        modal.innerHTML = `
      <div style="
        background: white;
        padding: 30px;
        border-radius: 12px;
        max-width: 500px;
        width: 90%;
        text-align: center;
        box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
        border-top: 6px solid #dc3545;
      ">
        <div style="font-size: 48px; margin-bottom: 20px;">⚠️</div>
        <h2 style="color: #dc3545; margin: 0 0 15px 0; font-size: 24px;">Security Warning</h2>
        <p style="color: #4a5568; font-size: 16px; line-height: 1.6; margin-bottom: 25px;">
          This link has been flagged as <strong>unsafe</strong> by PhishScan. It may attempt to steal your information or install malware.
        </p>
        <div style="background: #edf2f7; padding: 12px; border-radius: 6px; margin-bottom: 25px; word-break: break-all; font-family: monospace; font-size: 14px; color: #718096;">
          ${url}
        </div>
        <div style="display: flex; justify-content: center; gap: 15px;">
          <button id="phishscan-cancel-btn" style="
            background: #dc3545;
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 6px;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.2s;
            font-size: 16px;
          ">Go Back (Recommended)</button>
          <button id="phishscan-proceed-btn" style="
            background: transparent;
            color: #718096;
            border: 2px solid #cbd5e0;
            padding: 12px 24px;
            border-radius: 6px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            font-size: 16px;
          ">Proceed Anyway</button>
        </div>
      </div>
    `;

        document.body.appendChild(modal);

        document.getElementById('phishscan-cancel-btn').onclick = () => {
            modal.remove();
        };

        document.getElementById('phishscan-proceed-btn').onclick = () => {
            modal.remove();
            // Allow navigation by temporarily bypassing the listener or setting window.location
            window.location.href = url;
        };
    }

    async function getPhishFeed() {
        return new Promise((resolve) => {
            console.log('Requesting phishing feed from background script...');
            chrome.runtime.sendMessage({ type: 'GET_PHISH_FEED' }, (response) => {
                console.log('Phish feed response:', response);
                const openPhishUrls = response?.phishingList || [];
                console.log(`Received ${openPhishUrls.length} URLs from OpenPhish feed`);

                if (openPhishUrls.length === 0) {
                    console.log('OpenPhish feed is empty, will use test URLs as fallback');
                } else {
                    console.log('Sample URLs from feed:', openPhishUrls.slice(0, 5));
                }

                resolve(openPhishUrls);
            });
        });
    }

    async function getToggleState() {
        return new Promise((resolve) => {
            chrome.runtime.sendMessage({ type: 'GET_TOGGLE_STATE' }, (response) => {
                resolve(response?.enabled !== false);
            });
        });
    }

    // Enhanced batch processing for API calls (no global time cap, just gentle pacing)
    async function processBatch(elements, processFn) {
        const results = [];
        for (let i = 0; i < elements.length; i += SCAN_BATCH_SIZE) {
            const batch = elements.slice(i, i + SCAN_BATCH_SIZE);

            const batchPromises = batch.map(async (element) => {
                const result = await processFn(element);
                if (result) results.push(result);
            });

            await Promise.all(batchPromises);

            // Yield control to prevent blocking and respect API rate limits
            if (i + SCAN_BATCH_SIZE < elements.length) {
                await new Promise(resolve => setTimeout(resolve, SCAN_DELAY));
            }
        }
        return results;
    }

    // Debounced function to prevent excessive scanning
    function debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }

    // Main scanning function with enhanced detection
    async function scanPage() {
        if (scanInProgress) return;

        scanInProgress = true;

        try {
            console.log('Starting enhanced page scan with VirusTotal integration...');

            // Set scan-in-progress flag
            await chrome.storage.local.set({ phishscan_scanning: true });
            await chrome.storage.local.remove('phishscan_found');

            const enabled = await getToggleState();
            if (!enabled) {
                await chrome.storage.local.set({ phishscan_scanning: false });
                scanInProgress = false;
                return;
            }

            // Clear processed URLs for fresh scan
            processedUrls.clear();

            const found = [];
            const cleanUrls = [];
            let totalScanned = 0;

            // Get all elements to scan (capped for speed)
            const allLinks = Array.from(document.querySelectorAll('a[href]'));
            const allForms = Array.from(document.querySelectorAll('form[action]'));
            const aTags = allLinks.slice(0, MAX_LINKS_PER_PAGE);
            const formTags = allForms.slice(0, MAX_FORMS_PER_PAGE);

            console.log(`Scanning ${aTags.length}/${allLinks.length} links, ${formTags.length}/${allForms.length} forms with enhanced detection`);

            // Process links in batches
            const linkResults = await processBatch(aTags, async (a) => {
                const url = a.href;
                if (url) {
                    console.log('Processing link URL:', url);
                    totalScanned++;
                    const result = await checkUrlWithAPI(url);
                    console.log('Link check result:', url, result);

                    if (result) {
                        if (result.malicious) {
                            console.log('Found malicious link:', url, 'Reason:', result.reason);
                            highlightElement(
                                a,
                                result.reason,
                                result.isShortened,
                                result.resolvedUrl,
                                result.virustotalData || (result.positives !== undefined ? result : null)
                            );

                            // Set up tooltip for shortened URLs
                            if (result.isShortened && result.resolvedUrl) {
                                setupShortenedUrlTooltip(a, result.resolvedUrl);
                            }

                            return {
                                url: result.originalUrl || url,
                                reason: result.reason,
                                threatType: result.threatType,
                                isShortened: result.isShortened,
                                resolvedUrl: result.resolvedUrl,
                                virustotalData: result.virustotalData || (result.positives !== undefined ? result : null)
                            };
                        } else {
                            // Mark as clean if we have VirusTotal data and no minor detections
                            if (result.virustotalData && result.virustotalData.total > 0 && !result.virustotalData.minorDetections) {
                                console.log('Marking clean link:', url);
                                markCleanElement(
                                    a,
                                    result.reason,
                                    result.isShortened,
                                    result.resolvedUrl,
                                    result.virustotalData
                                );

                                // Set up tooltip for shortened URLs
                                if (result.isShortened && result.resolvedUrl) {
                                    setupShortenedUrlTooltip(a, result.resolvedUrl);
                                }

                                cleanUrls.push({
                                    url: result.originalUrl || url,
                                    reason: result.reason,
                                    virustotalData: result.virustotalData
                                });
                            }
                        }
                    }
                }
                return null;
            });

            // Process forms in batches
            const formResults = await processBatch(formTags, async (f) => {
                const url = f.action;
                if (url) {
                    console.log('Processing form action URL:', url);
                    totalScanned++;
                    const result = await checkUrlWithAPI(url);
                    console.log('Form check result:', url, result);

                    if (result && result.malicious) {
                        console.log('Found malicious form:', url, 'Reason:', result.reason);
                        highlightElement(
                            f,
                            result.reason,
                            result.isShortened,
                            result.resolvedUrl,
                            result.virustotalData || (result.positives !== undefined ? result : null)
                        );

                        return {
                            url: result.originalUrl || url,
                            reason: result.reason,
                            threatType: result.threatType,
                            isShortened: result.isShortened,
                            resolvedUrl: result.resolvedUrl,
                            virustotalData: result.virustotalData || (result.positives !== undefined ? result : null)
                        };
                    }
                }
                return null;
            });

            // Combine results
            const allResults = linkResults.filter(r => r !== null).concat(formResults.filter(r => r !== null));

            // Store results with scan statistics
            await chrome.storage.local.set({
                phishscan_found: allResults,
                phishscan_clean: cleanUrls,
                phishscan_total_scanned: totalScanned,
                phishscan_scanning: false,
                phishscan_rate_limited: rateLimitReached
            });

            // Update in-page banner so users see the result without opening the popup
            updatePageStatusBanner({
                totalScanned,
                threats: allResults.length,
                clean: cleanUrls.length,
                rateLimited: rateLimitReached
            });

            console.log(`Enhanced scan complete. Found ${allResults.length} threats:`, allResults);

            if (rateLimitReached) {
                console.warn('API rate limit reached during scan');
            }

        } catch (error) {
            console.error('Error during enhanced scan:', error);
            await chrome.storage.local.set({ phishscan_scanning: false });
        } finally {
            scanInProgress = false;
        }
    }

    // Debounced scan function for DOM changes
    const debouncedScan = debounce(scanPage, DEBOUNCE_DELAY);

    function detectLanguage() {
        // Return cached language if available
        if (cachedLanguage) {
            return cachedLanguage;
        }

        // Check browser language as fallback
        const browserLang = navigator.language || navigator.userLanguage || 'en';
        const langCode = browserLang.split('-')[0].toLowerCase();

        // Check page language attribute
        const pageLang = document.documentElement.lang || '';
        const pageLangCode = pageLang.split('-')[0].toLowerCase();

        let detectedLang = 'en';

        // Priority: page lang > browser lang > default to English
        if (pageLangCode === 'hi' || pageLangCode === 'gu') {
            detectedLang = pageLangCode;
        } else if (langCode === 'hi' || langCode === 'gu') {
            detectedLang = langCode;
        }

        cachedLanguage = detectedLang;
        return detectedLang;
    }

    // Load language from chrome.storage
    chrome.storage.sync.get(['phishscan_language'], (result) => {
        if (result.phishscan_language && (result.phishscan_language === 'hi' || result.phishscan_language === 'gu' || result.phishscan_language === 'en')) {
            cachedLanguage = result.phishscan_language;
            // Refresh banner if it exists
            if (statusBannerEl) {
                chrome.storage.local.get(['phishscan_total_scanned', 'phishscan_found', 'phishscan_rate_limited', 'phishscan_clean'], (localResult) => {
                    updatePageStatusBanner({
                        totalScanned: localResult.phishscan_total_scanned || 0,
                        threats: (localResult.phishscan_found || []).length,
                        clean: (localResult.phishscan_clean || []).length,
                        rateLimited: localResult.phishscan_rate_limited === true
                    });
                });
            }
        }
    });

    // Get translated text
    function t(key, ...args) {
        const lang = detectLanguage();
        const langTranslations = translations[lang] || translations.en;
        const translation = langTranslations[key];

        if (typeof translation === 'function') {
            return translation(...args);
        }
        return translation || translations.en[key](...args);
    }

    // In-page status banner to show overall result without needing the popup
    let statusBannerEl = null;
    function ensureStatusBanner() {
        if (statusBannerEl) return statusBannerEl;
        statusBannerEl = document.createElement('div');
        statusBannerEl.id = 'phishscan-status-banner';
        const lang = detectLanguage();
        const fontFamily = lang === 'hi' || lang === 'gu'
            ? '"Noto Sans Devanagari", "Noto Sans Gujarati", system-ui, sans-serif'
            : 'system-ui, -apple-system, sans-serif';

        statusBannerEl.style.cssText = `
      position: fixed;
      top: 12px;
      left: 50%;
      transform: translateX(-50%);
      z-index: 2147483647;
      padding: 10px 14px;
      border-radius: 10px;
      background: #1f2937;
      color: #e5e7eb;
      font-family: ${fontFamily};
      font-size: 13px;
      box-shadow: 0 10px 30px rgba(0,0,0,0.35);
      display: flex;
      align-items: center;
      gap: 8px;
      cursor: default;
      opacity: 0.95;
    `;
        document.body.appendChild(statusBannerEl);
        return statusBannerEl;
    }

    function updatePageStatusBanner({ totalScanned, threats, clean, rateLimited }) {
        const el = ensureStatusBanner();
        let text = '';
        let bg = '#1f2937';
        let border = '#4b5563';

        if (rateLimited) {
            text = t('rateLimited');
            bg = '#78350f';
            border = '#f59e0b';
        } else if (threats > 0) {
            text = t('threatsDetected', threats);
            bg = '#7f1d1d';
            border = '#ef4444';
        } else if (totalScanned === 0) {
            text = t('noLinksFound');
            bg = '#1f2937';
            border = '#4b5563';
        } else {
            text = t('pageSafe', totalScanned);
            bg = '#064e3b';
            border = '#34d399';
        }

        el.textContent = text;
        el.style.background = bg;
        el.style.border = `1px solid ${border}`;
    }

    // Initialize scanning
    function initializeScanning() {
        // Clear previous highlights
        document.querySelectorAll('[data-phishscan]').forEach(el => {
            el.removeAttribute('data-phishscan');
            el.style.border = '';
            el.style.backgroundColor = '';
            const warning = el.querySelector('span');
            if (warning) warning.remove();
        });

        // Clear processed URLs cache
        processedUrls.clear();

        // Reset rate limit flag
        rateLimitReached = false;

        // Start initial scan
        scanPage();

        // Set up DOM observer for dynamic content
        if (observer) {
            observer.disconnect();
        }

        observer = new MutationObserver((mutations) => {
            let shouldScan = false;

            for (const mutation of mutations) {
                if (mutation.type === 'childList' && mutation.addedNodes.length > 0) {
                    for (const node of mutation.addedNodes) {
                        if (node.nodeType === Node.ELEMENT_NODE) {
                            if (node.querySelector && (node.querySelector('a[href]') || node.querySelector('form[action]'))) {
                                shouldScan = true;
                                break;
                            }
                        }
                    }
                }
            }

            if (shouldScan && !rateLimitReached) {
                debouncedScan();
            }
        });

        observer.observe(document.body, {
            childList: true,
            subtree: true,
            attributes: false,
            characterData: false
        });
    }

    // Run on page load
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initializeScanning);
    } else {
        initializeScanning();
    }

    // Listen for messages from popup
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
        if (request.type === 'FORCE_SCAN') {
            initializeScanning();
            sendResponse({ success: true });
        } else if (request.type === 'LANGUAGE_CHANGED') {
            // Update cached language and refresh banner
            cachedLanguage = request.language;

            // TRIGGER RE-SCAN TO UPDATE TOOLTIPS IMMEDIATELY
            console.log('Language changed to', cachedLanguage, '- Triggering re-scan...');
            initializeScanning();

            // Refresh the banner if it exists
            if (statusBannerEl) {
                chrome.storage.local.get(['phishscan_total_scanned', 'phishscan_found', 'phishscan_rate_limited', 'phishscan_clean'], (result) => {
                    updatePageStatusBanner({
                        totalScanned: result.phishscan_total_scanned || 0,
                        threats: (result.phishscan_found || []).length,
                        clean: (result.phishscan_clean || []).length,
                        rateLimited: result.phishscan_rate_limited === true
                    });
                });
            }
            sendResponse({ success: true });
        }

    });

    // Cleanup on page unload
    window.addEventListener('beforeunload', () => {
        if (observer) {
            observer.disconnect();
        }
        processedUrls.clear();
    });
} // End of else block 