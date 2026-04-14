/**
 * SafeClick — config.js
 *
 * Central configuration file. This is the ONLY file you need to edit
 * to change how the extension connects to the backend.
 *
 * Coding standard: Google JavaScript Style Guide
 * https://google.github.io/styleguide/jsguide.html
 *
 * ─── HOW TO SWITCH MODES ────────────────────────────────────────────────────
 *
 *  MODE 1 — Cloud (recommended for demos and public use):
 *    Set SAFECLICK_MODE = 'cloud'
 *    Set CLOUD_API_URLS = your deployed backend URLs in priority order
 *
 *  MODE 2 — Local machine (for development or offline backup):
 *    Set SAFECLICK_MODE = 'local'
 *    Make sure the backend is running: uvicorn main:app --reload
 *
 * ────────────────────────────────────────────────────────────────────────────
 */

'use strict';

/**
 * @enum {string}
 * Available operating modes for the extension backend connection.
 */
const Mode = {
  CLOUD: 'cloud',
  LOCAL: 'local',
};

// ─── EDIT THIS SECTION ────────────────────────────────────────────────────────

/** @type {Mode} Active mode — switch between 'cloud' and 'local'. */
const SAFECLICK_MODE = Mode.CLOUD;

/** @type {string[]} Cloud backends in priority order (first one is preferred). */
const CLOUD_API_URLS = [
  'https://safeclick-production.up.railway.app',
  'https://safeclick-f8yg.onrender.com',
];

// ─── DO NOT EDIT BELOW THIS LINE ─────────────────────────────────────────────

/** @type {string} Local backend URL (used when mode = 'local'). */
const LOCAL_API_URL = 'http://localhost:8000';

/**
 * Normalizes an API base URL by trimming whitespace and trailing slash.
 *
 * @param {string} url Raw URL value.
 * @return {string} Normalized URL string.
 */
function normalizeApiUrl(url) {
  return String(url ?? '').trim().replace(/\/$/, '');
}

/**
 * Returns a de-duplicated list of valid URLs while preserving order.
 *
 * @param {string[]} urls Candidate URLs.
 * @return {string[]} Unique normalized URLs.
 */
function uniqueUrls(urls) {
  const seen = new Set();
  const out  = [];

  for (const raw of urls) {
    const normalized = normalizeApiUrl(raw);
    if (!normalized || seen.has(normalized)) continue;
    seen.add(normalized);
    out.push(normalized);
  }

  return out;
}

/**
 * Returns configured API URLs based on active mode.
 *
 * @return {string[]} Candidate API base URLs in priority order.
 */
function getConfiguredApiUrls() {
  if (SAFECLICK_MODE === Mode.CLOUD) return uniqueUrls(CLOUD_API_URLS);
  return uniqueUrls([LOCAL_API_URL]);
}

/**
 * Backward-compatible helper that returns the current top-priority URL.
 *
 * @return {string} Top-priority API base URL.
 */
function getApiUrl() {
  return getConfiguredApiUrls()[0] ?? normalizeApiUrl(LOCAL_API_URL);
}

/**
 * Resolves API candidates from config plus optional user overrides.
 * In cloud mode, it prefers the last healthy backend when available.
 *
 * @return {Promise<string[]>} Ordered list of API base URLs to try.
 */
async function resolveApiCandidates() {
  const defaults = getConfiguredApiUrls();

  if (SAFECLICK_MODE === Mode.LOCAL) return defaults;

  return new Promise((resolve) => {
    chrome.storage.sync.get({
      api_base: '',
      api_base_secondary: '',
      preferred_api_base: '',
    }, (items) => {
      const candidates = uniqueUrls([
        items.preferred_api_base,
        items.api_base,
        items.api_base_secondary,
        ...defaults,
      ]);

      resolve(candidates.length ? candidates : defaults);
    });
  });
}

/**
 * Legacy helper retained for compatibility.
 *
 * @return {Promise<string>} The first API candidate URL.
 */
async function resolveApiBase() {
  const candidates = await resolveApiCandidates();
  return candidates[0] ?? getApiUrl();
}

/**
 * Calls /analyze with automatic backend failover.
 * Tries each configured candidate in order until one succeeds.
 *
 * @param {string} url URL to analyze.
 * @param {?Object} htmlFeatures Optional DOM feature payload.
 * @return {Promise<Object>} Analysis response JSON.
 */
async function analyzeWithFallback(url, htmlFeatures = null) {
  const payload = htmlFeatures == null ? {url} : {url, html_features: htmlFeatures};
  const candidates = await resolveApiCandidates();
  let lastError = null;

  for (const apiBase of candidates) {
    try {
      const response = await fetch(`${apiBase}/analyze`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        lastError = new Error(`Backend ${apiBase} returned HTTP ${response.status}`);
        continue;
      }

      const data = await response.json();
      chrome.storage.sync.set({preferred_api_base: apiBase});
      return data;

    } catch (error) {
      lastError = error;
    }
  }

  throw lastError ?? new Error('All configured backends are unavailable.');
}
