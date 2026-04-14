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
 *    Set CLOUD_API_URL  = your deployed backend URL (e.g. Render, Railway)
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

// ─── EDIT THESE TWO LINES ────────────────────────────────────────────────────

/** @type {Mode} Active mode — switch between 'cloud' and 'local'. */
const SAFECLICK_MODE = Mode.CLOUD;

/** @type {string} Your deployed cloud backend URL (used when mode = 'cloud'). */
const CLOUD_API_URL = 'https://your-app.onrender.com'; // <-- replace with your URL

// ─── DO NOT EDIT BELOW THIS LINE ─────────────────────────────────────────────

/** @type {string} Local backend URL (used when mode = 'local'). */
const LOCAL_API_URL = 'http://localhost:8000';

/**
 * Returns the active API base URL based on the current mode.
 * Strips any trailing slash to prevent double-slash in request paths.
 *
 * @return {string} The resolved API base URL.
 */
function getApiUrl() {
  const url = SAFECLICK_MODE === Mode.CLOUD ? CLOUD_API_URL : LOCAL_API_URL;
  return url.replace(/\/$/, '');
}

/**
 * Reads the user-saved API override from Chrome storage.
 * Falls back to the config-defined URL if no override is stored.
 *
 * Use this in content scripts and popups so the user's manual setting
 * always takes precedence over the hardcoded config.
 *
 * @return {Promise<string>} Resolves to the final API base URL.
 */
async function resolveApiBase() {
  return new Promise((resolve) => {
    chrome.storage.sync.get({api_base: getApiUrl()}, (items) => {
      resolve(items.api_base.replace(/\/$/, ''));
    });
  });
}
