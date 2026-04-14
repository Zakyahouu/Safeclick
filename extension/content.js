/**
 * SafeClick — content.js
 *
 * Content script injected into every page. Responsible for:
 *  1. Extracting phishing signals from the live DOM (HTML features).
 *  2. Calling the SafeClick API with the current URL + HTML features.
 *  3. Displaying a warning banner when a threat is detected.
 *
 * Coding standard: Google JavaScript Style Guide
 * https://google.github.io/styleguide/jsguide.html
 *
 * Dependencies: config.js (loaded first via manifest.json)
 */

'use strict';

// ─── Constants ────────────────────────────────────────────────────────────────

/** @const {string} DOM element ID for the warning banner. */
const ALERT_ID = 'safeclick-sentinel-alert';

/**
 * Banner visual config keyed by risk level.
 * @const {Object<string, {border: string, bg: string, label: string, accent: string}>}
 */
const BANNER_CONFIG = {
  suspicious: {
    border: '#ffb783',
    bg:     'rgba(18,20,22,0.97)',
    label:  'CAUTION DETECTED',
    accent: '#ffb783',
  },
  dangerous: {
    border: '#ffb4ab',
    bg:     'rgba(12,14,16,0.98)',
    label:  'THREAT DETECTED',
    accent: '#ffb4ab',
  },
};

/**
 * Returns whether the URL can be scanned by the extension.
 *
 * @param {string} url Current page URL.
 * @return {boolean} True for http(s) URLs.
 */
function isScannableUrl(url) {
  return url.startsWith('http://') || url.startsWith('https://');
}

// ─── HTML feature extraction ──────────────────────────────────────────────────

/**
 * Detects hidden or invisible iframes in the page.
 * Phishing pages sometimes use zero-pixel iframes to silently redirect users.
 *
 * @param {NodeListOf<HTMLIFrameElement>} iframes All iframes on the page.
 * @return {number} 1 if a hidden iframe is found, 0 otherwise.
 */
function detectHiddenIframes(iframes) {
  for (const iframe of iframes) {
    const frameborder = iframe.getAttribute('frameborder') ?? '';
    const width       = parseInt(iframe.getAttribute('width')  ?? '999', 10);
    const height      = parseInt(iframe.getAttribute('height') ?? '999', 10);
    const style       = iframe.getAttribute('style') ?? '';

    const isZeroSize    = width <= 1 || height <= 1;
    const isNoBorder    = frameborder === '0';
    const isCssHidden   = /display\s*:\s*none|visibility\s*:\s*hidden/.test(style);

    if (isNoBorder || isZeroSize || isCssHidden) return 1;
  }
  return 0;
}

/**
 * Analyzes form action attributes (Server Form Handler — SFH).
 * Forms that submit to blank targets or external domains are red flags.
 *
 * Score meaning:
 *   0 = legitimate (relative paths, same domain)
 *   1 = suspicious (submits to a different external domain)
 *   2 = phishing   (blank action or about:blank)
 *
 * @param {NodeListOf<HTMLFormElement>} forms         All forms on the page.
 * @param {string}                     currentDomain Normalized current hostname.
 * @return {number} SFH score (0, 1, or 2).
 */
function scoreForms(forms, currentDomain) {
  if (forms.length === 0) return 0;

  let worstScore = 0;

  for (const form of forms) {
    const action = (form.getAttribute('action') ?? '').trim().toLowerCase();

    if (!action || action === 'about:blank') {
      worstScore = Math.max(worstScore, 2);
      continue;
    }

    if (action.startsWith('http') || action.startsWith('//')) {
      try {
        const normalized  = action.startsWith('//') ? 'http:' + action : action;
        const actionUrl   = new URL(normalized);
        const actionDomain = actionUrl.hostname.replace(/^www\./, '');

        if (actionDomain && actionDomain !== currentDomain) {
          worstScore = Math.max(worstScore, 1);
        }
      } catch {
        worstScore = Math.max(worstScore, 1); // Unparseable → treat as suspicious
      }
    }
    // Relative paths ("/submit", "process.php") are safe — no penalty
  }

  return worstScore;
}

/**
 * Measures the proportion of page resources (images, scripts, links)
 * loaded from domains other than the current page.
 *
 * Phishing pages often clone a real site's look by hot-linking all
 * assets from the legitimate domain while hosting only the fake form.
 *
 * Score meaning:
 *   0 = < 22% external (legitimate)
 *   1 = 22–61% external (suspicious)
 *   2 = > 61% external (phishing)
 *
 * @param {string} currentDomain Normalized current hostname.
 * @return {number} External resources ratio score (0, 1, or 2).
 */
function scoreExternalResources(currentDomain) {
  const resources = [
    ...document.querySelectorAll('img[src]'),
    ...document.querySelectorAll('script[src]'),
    ...document.querySelectorAll('link[href]'),
  ];

  if (resources.length === 0) return 0;

  let externalCount = 0;

  for (const el of resources) {
    const src = el.getAttribute('src') ?? el.getAttribute('href') ?? '';
    if (!src.startsWith('http') && !src.startsWith('//')) continue;

    try {
      const normalized  = src.startsWith('//') ? 'http:' + src : src;
      const resDomain   = new URL(normalized).hostname.replace(/^www\./, '');
      if (resDomain && resDomain !== currentDomain) externalCount++;
    } catch { /* skip malformed URLs */ }
  }

  const ratio = externalCount / resources.length;
  if (ratio >= 0.61)   return 2;
  if (ratio >= 0.22)   return 1;
  return 0;
}

/**
 * Orchestrates DOM analysis and returns all HTML-level phishing signals.
 *
 * @param {string} currentDomain Normalized current hostname (no www.).
 * @return {{has_iframe_redirection: number, sfh_score: number, external_resources_ratio: number}}
 */
function extractHtmlFeatures(currentDomain) {
  const iframes = document.querySelectorAll('iframe');
  const forms   = document.querySelectorAll('form');

  return {
    has_iframe_redirection:   detectHiddenIframes(iframes),
    sfh_score:                scoreForms(forms, currentDomain),
    external_resources_ratio: scoreExternalResources(currentDomain),
  };
}

// ─── API communication ────────────────────────────────────────────────────────

/**
 * Sends the current URL and HTML features to the SafeClick API for analysis.
 *
 * @param {string} url          The full URL of the current page.
 * @param {Object} htmlFeatures Signals extracted from the live DOM.
 * @return {Promise<?Object>}   The API response, or null on failure.
 */
async function analyzeUrl(url, htmlFeatures) {
  try {
    return await analyzeWithFallback(url, htmlFeatures);

  } catch {
    return null; // Network error or server offline — fail silently
  }
}

// ─── Warning banner ───────────────────────────────────────────────────────────

/**
 * Builds the HTML string for the threat reason list items.
 *
 * @param {string[]} reasons List of human-readable threat reasons from the API.
 * @return {string} HTML string of <li> elements, or empty string if no reasons.
 */
function buildReasonsList(reasons) {
  if (!reasons?.length) return '';

  const items = reasons.slice(0, 3).map(
    (reason) => `<li style="color:#c4c6d0;font-size:11px;line-height:1.5;padding:2px 0">${reason}</li>`
  );

  return `<ul style="list-style:none;margin:0 0 12px;padding:0">${items.join('')}</ul>`;
}

/**
 * Injects a fixed-position warning banner into the page DOM.
 * Does nothing for 'safe' pages. Removes any previous banner first.
 *
 * @param {Object} result The full API response object.
 */
function showWarningBanner(result) {
  // Remove any existing banner from a previous scan
  document.getElementById(ALERT_ID)?.remove();

  const level  = result.risk_level;
  const config = BANNER_CONFIG[level];
  if (!config) return; // 'safe' level — no banner needed

  const banner = document.createElement('div');
  banner.id = ALERT_ID;
  banner.style.cssText = `
    position: fixed;
    top: 16px;
    right: 16px;
    z-index: 2147483647;
    width: 300px;
    background: ${config.bg};
    border-left: 3px solid ${config.border};
    border-radius: 10px;
    padding: 16px 18px;
    font-family: 'Inter', 'Segoe UI', Arial, sans-serif;
    box-shadow: 0 20px 40px rgba(0,0,0,0.5);
    animation: sc-in 0.3s cubic-bezier(0.34, 1.4, 0.64, 1);
  `;

  const reasonsList = buildReasonsList(result.reasons);

  banner.innerHTML = `
    <style>
      @keyframes sc-in {
        from { opacity: 0; transform: translateX(16px) scale(0.97); }
        to   { opacity: 1; transform: translateX(0)    scale(1);    }
      }
    </style>

    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
      <div>
        <div style="font-size:9px;font-weight:700;letter-spacing:2px;color:${config.accent};margin-bottom:3px">
          ${config.label}
        </div>
        <div style="font-size:15px;font-weight:800;color:#e2e2e5;font-family:'Manrope',sans-serif">
          SafeClick
        </div>
      </div>
      <button id="sc-close-btn"
        style="background:#1e2022;border:none;color:#c4c6d0;width:28px;height:28px;
               border-radius:6px;cursor:pointer;font-size:14px;
               display:flex;align-items:center;justify-content:center">
        ×
      </button>
    </div>

    <p style="font-size:12px;color:#c4c6d0;line-height:1.5;margin-bottom:${reasonsList ? '8px' : '12px'}">
      ${result.message}
    </p>

    ${reasonsList}

    <div style="display:flex;gap:8px">
      <button id="sc-back-btn"
        style="flex:1;padding:8px;
               background:linear-gradient(135deg,#b2c5ff,#002769);
               color:#e2e2e5;border:none;border-radius:7px;cursor:pointer;
               font-size:12px;font-weight:700;font-family:'Inter',sans-serif">
        ← Go Back
      </button>
      <button id="sc-dismiss-btn"
        style="flex:1;padding:8px;background:#1e2022;color:#c4c6d0;
               border:none;border-radius:7px;cursor:pointer;font-size:12px;
               font-family:'Inter',sans-serif">
        Dismiss
      </button>
    </div>
  `;

  document.body.appendChild(banner);

  const removeBanner = () => document.getElementById(ALERT_ID)?.remove();
  banner.querySelector('#sc-close-btn')?.addEventListener('click', removeBanner);
  banner.querySelector('#sc-dismiss-btn')?.addEventListener('click', removeBanner);
  banner.querySelector('#sc-back-btn')?.addEventListener('click', () => window.history.back());
}

// ─── Entry point ──────────────────────────────────────────────────────────────

/**
 * Scans the current page and updates storage, badge, and warning banner.
 *
 * @return {Promise<?Object>} API response object, or null on failure.
 */
async function scanCurrentPage() {
  const url = window.location.href;
  if (!isScannableUrl(url)) return null;

  // Normalize current domain (remove www. prefix for consistent comparison)
  const currentDomain = location.hostname.replace(/^www\./, '');

  // Step 1: Extract DOM-level phishing signals
  const htmlFeatures = extractHtmlFeatures(currentDomain);

  // Step 2: Send URL + HTML signals to the API
  const result = await analyzeUrl(url, htmlFeatures);
  if (!result) return null; // API unreachable — fail silently

  // Step 3: Persist result for the popup and notify the background worker
  chrome.storage.local.set({last_result: result});
  chrome.runtime.sendMessage({type: 'risk_result', payload: result});

  // Step 4: Show a warning banner if the site is suspicious or dangerous
  showWarningBanner(result);

  return result;
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type !== 'scan_now') return undefined;

  scanCurrentPage()
      .then((result) => sendResponse({ok: Boolean(result), result}))
      .catch((error) => sendResponse({ok: false, error: String(error)}));

  return true;
});

scanCurrentPage();
