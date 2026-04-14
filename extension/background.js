/**
 * SafeClick — background.js
 *
 * Service worker that manages the extension badge and listens for
 * risk result messages from content scripts.
 *
 * Coding standard: Google JavaScript Style Guide
 * https://google.github.io/styleguide/jsguide.html
 */

'use strict';

// ─── Constants ────────────────────────────────────────────────────────────────

/**
 * Badge colors keyed by risk level.
 * @const {Object<string, string>}
 */
const BADGE_COLORS = {
  safe:       '#22c55e',
  suspicious: '#f59e0b',
  dangerous:  '#ef4444',
  checking:   '#6b7280',
};

/**
 * Badge text labels keyed by risk level.
 * @const {Object<string, string>}
 */
const BADGE_LABELS = {
  safe:       '✓',
  suspicious: '!',
  dangerous:  '✕',
};

// ─── Badge helpers ────────────────────────────────────────────────────────────

/**
 * Updates the extension action badge for a specific tab.
 *
 * @param {number} tabId  The Chrome tab ID to update.
 * @param {string} level  Risk level key ('safe'|'suspicious'|'dangerous'|'checking').
 * @param {string} text   Text to display on the badge.
 */
function setBadge(tabId, level, text) {
  chrome.action.setBadgeText({ tabId, text });
  chrome.action.setBadgeBackgroundColor({
    tabId,
    color: BADGE_COLORS[level] ?? BADGE_COLORS.checking,
  });
}

// ─── Event listeners ──────────────────────────────────────────────────────────

/**
 * When a tab finishes loading, reset the badge to the "checking" state
 * so the user always sees that a scan is in progress.
 */
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status !== 'complete') return;
  setBadge(tabId, 'checking', '...');
});

/**
 * Listen for risk results sent by content.js after each page scan.
 * Updates the badge to reflect the detected risk level.
 */
chrome.runtime.onMessage.addListener((message, sender) => {
  if (message.type !== 'risk_result') return;

  const tabId = sender.tab?.id;
  if (!tabId) return;

  const level = message.payload?.risk_level;
  const text  = BADGE_LABELS[level] ?? '';

  setBadge(tabId, level, text);
});
