



🛡️
PhishingGuard AI
Browser Security Extension
Technical Abstract & Developer Documentation


Version 1.0.0  |  Manifest V3  |  Chrome · Firefox · Edge · Brave
2026



Technical Abstract


PhishingGuard AI is a cross-browser security extension built on the WebExtensions Manifest V3 standard, designed to protect users from phishing attacks, brand impersonation, government portal fraud, and adult content exposure. The extension operates entirely client-side — no data is transmitted to external servers — making it a privacy-preserving, real-time threat detection system deployable on Google Chrome, Mozilla Firefox, Microsoft Edge, Brave, and other Chromium-based browsers.

The core detection engine combines a heuristic scoring model with rule-based pattern analysis, originally designed to operate alongside a TensorFlow.js neural network classifier. The heuristic model extracts fifteen URL and page-level features including URL length, subdomain depth, hyphen and digit frequency, HTTPS usage, IP address usage, path complexity, password form presence, external link ratio, and brand keyword co-occurrence. These features are weighted through a calibrated coefficient vector to produce a normalized risk score in the range [0, 1]. Sites scoring above 0.7 are classified as high risk and blocked automatically.

A critical innovation of PhishingGuard AI is its Kenyan government institution impersonation detection module. Kenya has seen a sharp rise in phishing attacks targeting citizens who use government digital portals such as eCitizen, KRA iTax, HELB, NTSA TIMS, and IEBC voter registration systems. The extension maintains an authoritative whitelist of fourteen official Kenyan government domains. When a page contains institution-specific keywords in both the URL path and page body, yet the hosting domain does not appear in the official whitelist, the extension classifies the site as a government impersonation attempt and redirects the user to a dedicated warning page displaying the official domain.

Global brand impersonation detection focuses on homograph attacks — domains with a Levenshtein edit distance of exactly one character from known official domains. This strict threshold minimizes false positives while catching the most dangerous lookalike domains. Official domains for all monitored brands, including PayPal, Google, Microsoft, Safaricom, M-Pesa, Equity Bank, and KCB, are explicitly whitelisted so that users visiting the genuine site are never interrupted.

The extension architecture follows a clear separation of concerns across five JavaScript modules: the content script extracts page signals after the window load event; the background service worker performs threat analysis and manages blocking decisions; the ML engine provides heuristic scoring and impersonation detection; the IndexedDB layer maintains persistent scan history; and the configuration module centralises all domain lists, brand data, and keyword sets. The popup dashboard exposes real-time protection statistics and provides a manual domain blacklist with both one-click blocking and free-text URL input.

User experience has been carefully designed so that the extension never blocks legitimate activity. Blacklisted domains and adult content are blocked with no bypass option. Government impersonation and regular phishing blocks present a clearly structured warning page with a working Proceed Anyway button that records the bypass decision, marks the URL as exempt from further scanning in the current session, and navigates the user directly to the site without triggering a redirect loop. This session-level bypass token system is a key architectural feature that differentiates PhishingGuard AI from simpler blocking extensions.

Table of Contents
Technical Abstract	ii
Developer Documentation	1
1. Architecture Overview	1
2. Manifest V3 Configuration	1
3. Configuration Module (config.js)	2
3.1 Official Kenyan Government Whitelist	2
3.2 Brand Domains	2
4. ML / Heuristic Engine (ml.js)	3
4.1 Domain Matching Utility	3
4.2 Heuristic Feature Extraction	4
4.3 Kenyan Government Impersonation Detection	4
4.4 Brand Lookalike Detection (Homograph Attack)	6
5. Background Service Worker (background.js)	6
5.1 importScripts Module Loading	7
5.2 Bypass Token System (Prevents Redirect Loops)	7
5.3 Scan Pipeline	7
6. Content Script (content.js)	8
7. Database Layer (db.js)	9
8. Warning Page Logic (warning.js)	10
9. Block Type Reference	10
10. Installation Guide	11
Chrome / Edge / Brave / Opera	11
Firefox	11
After Installation	11
11. Adding Domains to the Blacklist	11
12. Extending the Extension	13
Adding a New Kenyan Institution	13
Replacing the ML Model	13
Developer Documentation
1. Architecture Overview


PhishingGuard AI follows the WebExtensions Manifest V3 architecture with a strict separation of responsibilities across modules. The diagram below illustrates the data flow:

File	Responsibility
manifest.json	Extension metadata, permissions, CSP, content script rules
background.js	Service worker: scan orchestration, blocking decisions, bypass tokens
content.js	Page signal extraction after full load, sends data to background
ml.js	Heuristic scoring, impersonation detection, whitelist logic
config.js	Centralised domain lists, brand data, keyword sets
db.js	IndexedDB wrapper for persistent scan history
popup.html/js	Dashboard: stats, manual blacklist, current risk display
warning.html/js	Phishing block page with Proceed Anyway and blacklist controls
model/	TF.js model topology and weights (heuristic fallback active)


2. Manifest V3 Configuration

The manifest defines all extension permissions and entry points. Key design decisions:

    • Service worker uses classic mode (no 'type: module') for importScripts compatibility
    • CSP restricts scripts to 'self' only — no external CDN sources permitted by Chrome MV3
    • declarativeNetRequest permission is included for future rule-based blocking
    • web_accessible_resources exposes warning.html and model/ to all URLs for redirect and TF.js loading

// manifest.json — critical sections
{
  "manifest_version": 3,
  "background": {
    "service_worker": "background.js"
    // No "type":"module" — required for importScripts() to work
  },
  "content_security_policy": {
    "extension_pages": "script-src 'self'; object-src 'self'"
    // Chrome MV3 blocks ALL external script sources — no CDN URLs allowed
  },
  "permissions": ["storage","tabs","scripting","activeTab","webNavigation"],
  "host_permissions": ["<all_urls>"],
  "web_accessible_resources": [{
    "resources": ["warning.html", "model/*"],
    "matches": ["<all_urls>"]
  }]
}


3. Configuration Module (config.js)

config.js is loaded first via importScripts and defines all global constants used by ml.js and background.js. There are no exports — variables become globals in the service worker scope.

3.1 Official Kenyan Government Whitelist
This object maps institution names to their authoritative domain lists. Any domain matching an entry here bypasses all analysis and is never blocked.

// config.js — Kenyan government whitelist
const OFFICIAL_KENYAN_DOMAINS = {
  "IEBC":               ["iebc.or.ke"],
  "KRA":                ["kra.go.ke", "itax.kra.go.ke"],
  "eCitizen":           ["ecitizen.go.ke"],
  "SHA":                ["sha.go.ke"],
  "HELB":               ["helb.co.ke"],
  "NTSA":               ["ntsa.go.ke"],
  "Kenya Power":        ["kplc.co.ke", "kenyapower.co.ke"],
  "NSSF":               ["nssf.or.ke"],
  "NHIF":               ["nhif.or.ke"],
  "Ministry of Education": ["education.go.ke"],
  "Kenya Police":       ["nationalpolice.go.ke"],
  "Kenya Judiciary":    ["judiciary.go.ke"],
  "Central Bank of Kenya": ["centralbank.go.ke"]
};

3.2 Brand Domains
Each brand entry pairs official domains with detection keywords. The official array is used for whitelist matching; keywords are used only for lookalike domain confirmation, not standalone detection.

// config.js — Brand domain structure (excerpt)
const BRAND_DOMAINS = {
  "PayPal": {
    official: ["paypal.com", "paypal.me"],
    keywords: ["paypal", "pay pal"]
  },
  "Safaricom": {
    official: ["safaricom.co.ke"],
    keywords: ["safaricom", "mpesa", "m-pesa", "bonga points"]
  },
  // ... 14 brands total
};


4. ML / Heuristic Engine (ml.js)

ml.js contains the entire threat analysis pipeline. It is loaded as a classic script in the service worker via importScripts. The module exposes one primary function: predict(urlStr, pageData).

4.1 Domain Matching Utility
A critical helper function handles multi-part Kenyan ccTLDs correctly. Standard root domain extraction (last 2 parts) fails for domains like itax.kra.go.ke — the function detects Kenyan suffixes and returns 3 parts instead.

// ml.js — Kenyan ccTLD-aware root domain extraction
function getRootDomain(hostname) {
  const h = hostname.replace(/^www\./, "").toLowerCase();
  const parts = h.split('.');
  const kenyanSuffixes = ["go.ke","or.ke","co.ke","ac.ke","ne.ke","sc.ke"];
  for (const suffix of kenyanSuffixes) {
    if (h.endsWith('.' + suffix) || h === suffix)
      return parts.slice(-3).join('.');  // e.g. kra.go.ke (not just go.ke)
  }
  return parts.length >= 2 ? parts.slice(-2).join('.') : h;
}

// Subdomain-aware matching
function domainMatchesOfficial(testHostname, officialDomain) {
  const test = testHostname.toLowerCase().replace(/^www\./, "");
  const official = officialDomain.toLowerCase().replace(/^www\./, "");
  // Matches exact domain OR any subdomain
  return test === official || test.endsWith('.' + official);
  // e.g. 'itax.kra.go.ke' matches 'kra.go.ke' ✓
  // e.g. 'fakekra.go.ke.evil.com' does NOT match 'kra.go.ke' ✓
}

4.2 Heuristic Feature Extraction
Fifteen features are computed from the URL and page data. These feed into a weighted linear model to produce a phishing risk score.

// ml.js — Feature extraction (condensed)
function extractFeatures(urlStr, pageData) {
  const url      = new URL(urlStr);
  const hostname = url.hostname.toLowerCase();
  const fullUrl  = urlStr.toLowerCase();

  const f0 = Math.min(urlStr.length / 200, 1);       // URL length
  const f1 = Math.min(dotCount / 10, 1);             // Dot count (subdomains)
  const f2 = Math.min(hyphenCount / 5, 1);           // Hyphens in hostname
  const f3 = digitCount / hostname.length;           // Digit ratio
  const f4 = suspiciousKeywordInURL ? 1 : 0;         // 'login','verify','secure'...
  const f5 = url.protocol === 'https:' ? 1 : 0;     // HTTPS (negative weight)
  const f6 = isIPAddress ? 1 : 0;                   // IP address as host
  const f7 = Math.min(subdomainDepth / 5, 1);        // Subdomain depth
  const f8 = Math.min(pathSlashes / 8, 1);           // URL path depth
  const f9 = url.search.length > 0 ? 1 : 0;         // Has query string
  const f11 = pageData.hasPasswordForm ? 1 : 0;      // Password input on page
  const f12 = externalLinkRatio > 0.5 ? 1 : 0;      // High external link ratio
  return [f0,f1,f2,f3,f4,f5,f6,f7,f8,f9,0,f11,f12,0,0];
}

// Weighted scoring
function heuristicScore(urlStr, pageData) {
  const features = extractFeatures(urlStr, pageData);
  const weights  = [0.05,0.08,0.10,0.12,0.15,-0.05,0.20,
                    0.08,0.04,0.04,0.00, 0.15,0.08, 0.00,0.00];
  let score = 0;
  for (let i = 0; i < features.length; i++)
    score += features[i] * weights[i];
  return Math.min(Math.max(score, 0), 1);  // Clamp to [0,1]
}

4.3 Kenyan Government Impersonation Detection
This function requires keyword evidence in BOTH the URL path AND the page body content before triggering. This dual-evidence requirement prevents false positives on news articles or legitimate pages that mention government institution names.

// ml.js — Kenyan government impersonation detection
function detectKenyanImpersonation(urlStr, hostname, pageContent) {
  // Step 1: If domain IS official, immediately return null (whitelisted)
  if (isOfficialKenyanDomain(hostname)) return null;

  const urlLower     = urlStr.toLowerCase();
  const contentLower = (pageContent || '').toLowerCase();

  for (const [institution, keywords] of Object.entries(KENYAN_INSTITUTION_KEYWORDS)) {
    const officialDomains = OFFICIAL_KENYAN_DOMAINS[institution] || [];
    if (officialDomains.length === 0) continue;

    // Step 2: Keyword must appear in BOTH the URL AND the page content
    const inUrl     = keywords.some(kw => urlLower.includes(kw.toLowerCase()));
    const inContent = keywords.some(kw => contentLower.includes(kw.toLowerCase()));

    if (inUrl && inContent) {
      // Example: URL contains 'iebc' AND page body says 'IEBC voter registration'
      // But domain is ctretz.online (not iebc.or.ke) → BLOCK
      return {
        detected: true, institution,
        officialUrl: 'https://' + officialDomains[0],
        currentDomain: getRootDomain(hostname)
      };
    }
  }
  return null;  // No impersonation detected
}

4.4 Brand Lookalike Detection (Homograph Attack)
Brand impersonation detection uses Levenshtein distance = 1 (exactly one character substitution) to identify classic homograph attacks. This strict threshold prevents false positives while catching attacks like paypai.com or paypa1.com.

// ml.js — Levenshtein distance for lookalike detection
function levenshtein(a, b) {
  // Standard dynamic programming edit distance
  const dp = Array.from({ length: a.length+1 }, (_,i) =>
    Array.from({ length: b.length+1 }, (_,j) => i===0 ? j : j===0 ? i : 0)
  );
  for (let i = 1; i <= a.length; i++)
    for (let j = 1; j <= b.length; j++)
      dp[i][j] = a[i-1]===b[j-1] ? dp[i-1][j-1]
        : 1 + Math.min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1]);
  return dp[a.length][b.length];
}

function detectBrandImpersonation(urlStr, hostname, pageContent) {
  if (isOfficialBrandDomain(hostname)) return null; // Skip if official
  const normHost = normaliseHomographs(hostname.replace(/^www\./, ''));

  for (const [brand, data] of Object.entries(BRAND_DOMAINS)) {
    if (data.official.some(d => domainMatchesOfficial(hostname, d))) continue;
    for (const official of data.official) {
      const dist = levenshtein(normHost, getRootDomain(official));
      if (dist === 1) {  // Exactly 1 char difference = homograph
        // e.g. 'paypa1.com' vs 'paypal.com' → distance = 1 → BLOCK
        return { detected: true, brand, officialUrl: 'https://'+data.official[0] };
      }
    }
  }
  return null;
}


5. Background Service Worker (background.js)

The background service worker is the central controller. It loads all modules via importScripts, manages the bypass token system, routes messages from content scripts and popup, and handles all blocking redirects.

5.1 importScripts Module Loading
Because Chrome MV3 service workers do not support ES module imports when declared without 'type: module', all files are loaded using importScripts. This makes all variables in config.js, db.js, and ml.js available as globals.

// background.js — module loading
importScripts("config.js", "db.js", "ml.js");
// After this line, all constants from config.js (OFFICIAL_KENYAN_DOMAINS,
// BRAND_DOMAINS, etc.) and all functions from ml.js (predict, isOfficialKenyanDomain,
// etc.) are available as globals in this service worker.

5.2 Bypass Token System (Prevents Redirect Loops)
When a user clicks Proceed Anyway on the warning page, the background stores the URL in a Set. All subsequent scan requests for that URL are immediately allowed, preventing the content script from re-scanning the page and redirecting the user back to the warning page.

// background.js — bypass token system
const bypassedUrls = new Set();  // In-memory, lives for the service worker lifetime

// Message handler: user clicked 'Proceed Anyway'
if (message.type === "BYPASS_NAVIGATE") {
  bypassedUrls.add(message.url);  // Mark URL as user-approved
  sendResponse({ success: true });
  // warning.js then calls window.location.replace(blockedUrl)
  // When content.js fires on the destination page, SCAN_PAGE handler checks:
}

if (message.type === "SCAN_PAGE") {
  if (bypassedUrls.has(message.url)) {
    sendResponse({ success: true, result: { shouldBlock: false } });
    return true;  // Do not scan — user already approved this URL
  }
  runScan(tabId, message.url, message.pageData)...
}

5.3 Scan Pipeline
The runScan function implements a priority-ordered threat pipeline. Each check returns early if a decision is made, so the most critical checks (whitelist, blacklist) run first with minimal overhead.

// background.js — scan pipeline (condensed)
async function runScan(tabId, urlStr, pageData) {
  const hostname = new URL(urlStr).hostname.toLowerCase();

  // Priority 1: Official Kenyan domain → always allow
  if (isOfficialKenyanDomain(hostname)) return { shouldBlock: false };

  // Priority 2: Official global brand domain → always allow
  if (isOfficialBrandDomain(hostname)) return { shouldBlock: false };

  // Priority 3: Already bypassed this session → allow
  if (bypassedUrls.has(urlStr)) return { shouldBlock: false };

  // Priority 4: User blacklist → block, no bypass
  if (await isBlacklisted(hostname)) { handleBlock(...); return; }

  // Priority 5: Full ML + heuristic analysis
  const result = predict(urlStr, pageData);
  if (result.shouldBlock) handleBlock(tabId, urlStr, hostname, result, scanType);
  return result;
}


6. Content Script (content.js)

The content script runs in the context of every web page. Its sole responsibility is to extract page signals and send them to the background for analysis. It deliberately waits for the full page load to ensure meaningful content is available before scanning.

// content.js — load-aware scan trigger
if (document.readyState === 'complete') {
  // Page already loaded (e.g. cached navigation) — short delay
  setTimeout(extractAndScan, 1500);
} else {
  // Wait for window.load (all resources including JS bundles)
  window.addEventListener('load', function onLoad() {
    window.removeEventListener('load', onLoad);
    setTimeout(extractAndScan, 800);  // Extra wait for SPA rendering
  });
}

function extractAndScan() {
  // Skip extension pages
  if (window.location.href.startsWith('chrome-extension://')) return;

  // Require real content — retry if page still loading
  const bodyText = document.body && document.body.innerText || '';
  if (bodyText.trim().length < 20) {
    setTimeout(extractAndScan, 2000);  // Single retry
    return;
  }

  chrome.runtime.sendMessage({
    type: 'SCAN_PAGE',
    url: window.location.href,
    pageData: {
      pageTitle:         document.title,
      pageContent:       bodyText.substring(0, 6000),  // Cap size
      hasPasswordForm:   !!document.querySelector("input[type='password']"),
      externalLinkRatio: calcExternalLinkRatio(),
    }
  });
}


7. Database Layer (db.js)

db.js provides a thin async wrapper over IndexedDB. All scan history is persisted locally and used to populate the popup dashboard statistics.

// db.js — IndexedDB scan record schema
// Object store: 'scanHistory'  |  keyPath: 'id' (auto-increment)

// Record structure:
const scanRecord = {
  id:           /* auto */,
  url:          'https://evil-site.com/page',
  domain:       'evil-site.com',
  detectedBrand:'IEBC',              // Institution or brand name, if impersonation
  scanResult:   'phishing',          // 'safe' | 'phishing' | 'adult' | 'blacklisted'
  mlConfidence: 0.87,                // Risk score 0-1
  userAction:   'blocked',           // 'blocked' | 'allowed' | 'bypassed'
  reason:       'High phishing risk',
  timestamp:    1712345678901        // Date.now()
};

// Stats aggregation used by popup dashboard
async function getStats() {
  const scans = await getAllScans();
  return {
    total:       scans.length,
    phishing:    scans.filter(s => s.scanResult === 'phishing').length,
    adult:       scans.filter(s => s.scanResult === 'adult').length,
    blacklisted: scans.filter(s => s.scanResult === 'blacklisted').length,
    bypassed:    scans.filter(s => s.userAction  === 'bypassed').length,
    safe:        scans.filter(s => s.scanResult  === 'safe').length
  };
}


8. Warning Page Logic (warning.js)

The warning page reads all threat context from URL query parameters set by background.js. The Proceed Anyway flow sends two messages — USER_BYPASS to record the event, and BYPASS_NAVIGATE to add the URL to the bypass token set — before using window.location.replace() to navigate without creating a browser history entry.

// warning.js — Proceed Anyway button (no redirect loop)
btnProceed.addEventListener('click', function handleProceed() {
  btnProceed.disabled = true;  // Prevent double-click
  btnProceed.textContent = '⏳ Redirecting...';

  // 1. Record bypass in scan history
  API.runtime.sendMessage({ type: 'USER_BYPASS', url: blockedUrl, ... });

  // 2. Add URL to bypass token set in background (prevents re-scan loop)
  API.runtime.sendMessage({ type: 'BYPASS_NAVIGATE', url: blockedUrl }, () => {
    // 3. Navigate using replace() — no history entry for the warning page
    window.location.replace(blockedUrl);
  });
});

// Bypass rules:
// ✅ Regular phishing block  → Proceed Anyway shown
// ✅ Govt impersonation       → Proceed Anyway shown (with strong warning)
// ❌ Adult content            → No bypass (hard block)
// ❌ User blacklist           → No bypass (hard block)


9. Block Type Reference


Block Type	Bypass Allowed?  |  Blacklist Button?  |  Govt Banner?
Regular phishing	✅ Yes            |  ✅ Yes              |  ❌ No
Brand impersonation	✅ Yes            |  ✅ Yes              |  ❌ No
Govt impersonation	✅ Yes            |  ✅ Yes              |  ✅ Yes
Adult content	❌ No             |  ❌ No               |  ❌ No
User blacklist	❌ No             |  —  (already listed) |  ❌ No


10. Installation Guide


Chrome / Edge / Brave / Opera
    1. Extract the ZIP archive to a local folder
    2. Open chrome://extensions in the browser address bar
    3. Enable Developer Mode using the toggle in the top-right corner
    4. Click Load unpacked and select the extracted phishingguard-ai-extension folder
    5. The extension icon (🛡) appears in the toolbar — pin it for easy access

Firefox
    6. Open about:debugging#/runtime/this-firefox
    7. Click Load Temporary Add-on
    8. Navigate to and select the manifest.json file inside the folder

After Installation
    • Visit any website — the extension silently scans in the background
    • Try visiting https://www.ctretz.online/iebc-or-ke-jobs to test Kenyan impersonation detection
    • Click the 🛡 icon to open the dashboard and view protection statistics
    • Use the Manage Blacklist panel to manually add domains by typing them into the input field


11. Adding Domains to the Blacklist

PhishingGuard AI provides three ways to blacklist a domain:

    9. From the warning page: click the 🚫 Blacklist This Domain button shown on any phishing or govt impersonation warning
    10. From the popup dashboard: click 🚫 Block Site to instantly blacklist the domain of the currently active tab
    11. Manual entry: open the Manage Blacklist panel in the popup and type any domain (e.g. evil-site.com) or full URL (e.g. https://evil-site.com/page) into the input field, then click Add

The input field automatically strips protocols and paths — you may paste a full URL and the extension will extract the hostname for you. Blacklisted domains are stored in chrome.storage.local and persist across browser sessions.



12. Extending the Extension

Adding a New Kenyan Institution
To add a new institution to the impersonation detection system, edit config.js and add entries to both OFFICIAL_KENYAN_DOMAINS and KENYAN_INSTITUTION_KEYWORDS:

// config.js — adding a new institution
const OFFICIAL_KENYAN_DOMAINS = {
  // ... existing entries ...
  "Kenya Ports Authority": ["kpa.co.ke"],
};

const KENYAN_INSTITUTION_KEYWORDS = {
  // ... existing entries ...
  "Kenya Ports Authority": ["KPA", "Kenya Ports Authority", "mombasa port"],
};

Replacing the ML Model
The model/ directory contains a TensorFlow.js model. To upgrade with a production-trained model: train a binary classifier on a labelled phishing dataset using the same 15 features defined in extractFeatures(), export to TF.js format using tensorflowjs_converter, and replace model.json and group1-shard1of1.bin. The heuristic engine remains as a fallback if the model fails to load.





