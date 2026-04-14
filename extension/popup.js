/**
 * SafeClick — popup.js
 *
 * Controls the extension popup UI across three tabs:
 *  - Dashboard: scans the active tab and shows the risk result.
 *  - Training:  phishing detection quiz for user education.
 *  - Reports:   community-flagged threats and historical statistics.
 *
 * Coding standard: Google JavaScript Style Guide
 * https://google.github.io/styleguide/jsguide.html
 *
 * Dependencies: config.js (loaded first via popup.html)
 */

'use strict';

// ─── Constants ────────────────────────────────────────────────────────────────

/** @const {number} Maximum scan history entries to keep. */
const MAX_HISTORY = 6;

/**
 * Known legitimate domains for "Did you mean?" suggestions.
 * Key = keyword to detect in a suspicious URL, value = real domain.
 * @const {Object<string, string>}
 */
const KNOWN_DOMAINS = {
  paypal:        'paypal.com',
  amazon:        'amazon.com',
  apple:         'apple.com',
  google:        'google.com',
  microsoft:     'microsoft.com',
  netflix:       'netflix.com',
  facebook:      'facebook.com',
  instagram:     'instagram.com',
  twitter:       'twitter.com',
  ebay:          'ebay.com',
  bankofamerica: 'bankofamerica.com',
  chase:         'chase.com',
};

/**
 * Training quiz questions with expected answers and explanations.
 * @const {Array<{url: string, answer: string, explain: string}>}
 */
const QUIZ_QUESTIONS = [
  {
    url:     'https://github.com/user/project',
    answer:  'safe',
    explain: 'Legitimate GitHub URL — HTTPS, trusted domain, clean path.',
  },
  {
    url:     'http://paypal-login-verify-account.tk/signin',
    answer:  'phishing',
    explain: 'HTTP only, fake domain mimicking PayPal, suspicious .tk TLD.',
  },
  {
    url:     'https://accounts.google.com/signin',
    answer:  'safe',
    explain: 'Real Google sign-in — HTTPS, official google.com subdomain.',
  },
  {
    url:     'http://192.168.1.1/banking/update/credentials',
    answer:  'phishing',
    explain: 'Raw IP address instead of domain — a classic phishing red flag.',
  },
  {
    url:     'https://www.amazon.com/dp/B09G9FPHY6',
    answer:  'safe',
    explain: 'Legitimate Amazon product page — HTTPS, real domain, clean URL.',
  },
  {
    url:     'http://apple-id-suspended-verify-now.ml/confirm',
    answer:  'phishing',
    explain: 'Fear tactic, fake domain, HTTP, suspicious .ml extension.',
  },
];

/** @const {number} Gauge arc total length in SVG stroke units. */
const GAUGE_ARC_LENGTH = 145;

// ─── DOM element references ───────────────────────────────────────────────────
// Cached once at startup to avoid repeated querySelector calls.

const el = {
  // Hero / scan section
  heroCard:       document.getElementById('hero-card'),
  heroHeadline:   document.getElementById('hero-headline'),
  heroSub:        document.getElementById('hero-sub'),
  statusOverline: document.getElementById('status-overline'),
  trendingBanner: document.getElementById('trending-banner'),

  // Risk gauge
  riskCard:   document.getElementById('risk-card'),
  gaugeArc:   document.getElementById('gauge-arc'),
  gaugePct:   document.getElementById('gauge-pct'),
  gaugeLvl:   document.getElementById('gauge-lvl'),

  // Metadata
  metaSite: document.getElementById('meta-site'),
  metaCert: document.getElementById('meta-cert'),
  metaKw:   document.getElementById('meta-kw'),
  metaSub:  document.getElementById('meta-sub'),

  // Supporting cards
  suggCard:    document.getElementById('suggestion-card'),
  suggUrl:     document.getElementById('suggestion-url'),
  reasonsCard: document.getElementById('reasons-card'),
  threatList:  document.getElementById('threat-list'),

  // Report section
  reportRow:   document.getElementById('report-row'),
  btnReport:   document.getElementById('btn-report'),
  reportCount: document.getElementById('report-count'),

  // Feed and stats
  feedList:    document.getElementById('feed-list'),
  statChecked: document.getElementById('stat-checked'),
  statBlocked: document.getElementById('stat-blocked'),
  statSafe:    document.getElementById('stat-safe'),
  btnRecheck:  document.getElementById('btn-recheck'),
};

// ─── Tab navigation ───────────────────────────────────────────────────────────

/**
 * Activates the clicked tab and its corresponding content panel.
 * Triggers loadThreats() when the Reports tab is selected.
 */
document.querySelectorAll('.tab').forEach((btn) => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach((t) => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach((c) => c.classList.remove('active'));

    btn.classList.add('active');
    document.getElementById(`tab-${btn.dataset.tab}`).classList.add('active');

    if (btn.dataset.tab === 'threats') loadThreats();
  });
});

// ─── Dashboard — hero state ───────────────────────────────────────────────────

/**
 * State definitions for the hero card header area.
 * @const {Object<string, {overline: string, headline: string, sub: string}>}
 */
const HERO_STATES = {
  safe: {
    overline: 'CURRENT STATUS',
    headline: `Your digital perimeter is <span class="accent">Protected.</span>`,
    sub:      'No threats detected on this page.',
  },
  suspicious: {
    overline: 'CAUTION DETECTED',
    headline: `Proceed with <span class="accent-warn">Caution.</span>`,
    sub:      'This site shows suspicious characteristics.',
  },
  dangerous: {
    overline: 'THREAT DETECTED',
    headline: `Phishing site <span class="accent-err">Blocked.</span>`,
    sub:      'Do NOT enter any personal information here.',
  },
  checking: {
    overline: 'SCANNING',
    headline: 'Analyzing...',
    sub:      'Checking current page for threats.',
  },
};

/**
 * Updates the hero card to reflect the current risk level.
 *
 * @param {string} level Risk level ('safe'|'suspicious'|'dangerous'|'checking').
 */
function setHeroState(level) {
  el.heroCard.className = `hero-card ${level}`;

  const state = HERO_STATES[level] ?? HERO_STATES.checking;
  el.statusOverline.textContent = state.overline;
  el.heroHeadline.innerHTML     = state.headline;
  el.heroSub.textContent        = state.sub;
}

// ─── Dashboard — risk gauge ───────────────────────────────────────────────────

/**
 * Gauge color per risk level.
 * @const {Object<string, string>}
 */
const GAUGE_COLORS = {safe: '#4ae183', suspicious: '#ffb783', dangerous: '#ffb4ab'};

/**
 * Gauge label per risk level.
 * @const {Object<string, string>}
 */
const GAUGE_LABELS = {safe: 'LOW RISK', suspicious: 'MEDIUM RISK', dangerous: 'HIGH RISK'};

/**
 * Animates the semi-circular risk gauge to the given score.
 *
 * @param {number} score Normalized risk score between 0 and 1.
 * @param {string} level Risk level key for color and label.
 */
function animateGauge(score, level) {
  const clampedScore = Math.min(Math.max(score, 0), 1);
  const dashOffset   = GAUGE_ARC_LENGTH - clampedScore * GAUGE_ARC_LENGTH;
  const color        = GAUGE_COLORS[level] ?? GAUGE_COLORS.safe;

  el.gaugeArc.style.transition       = 'stroke-dashoffset 1s ease, stroke 0.4s';
  el.gaugeArc.style.strokeDashoffset = dashOffset;
  el.gaugeArc.style.stroke           = color;
  el.gaugePct.style.color            = color;
  el.gaugeLvl.style.color            = color;
  el.gaugeLvl.textContent            = GAUGE_LABELS[level] ?? 'LOW RISK';

  // Animate the percentage counter from 0 to target
  const targetPct = Math.round(clampedScore * 100);
  let   current   = 0;
  const timer = setInterval(() => {
    current = Math.min(current + Math.max(1, Math.ceil(targetPct / 30)), targetPct);
    el.gaugePct.textContent = current + '%';
    if (current >= targetPct) clearInterval(timer);
  }, 30);
}

// ─── Dashboard — metadata panel ───────────────────────────────────────────────

/**
 * Populates the metadata panel below the gauge with URL and feature data.
 *
 * @param {?Object} features Feature dict returned by the API.
 * @param {string}  url      The scanned URL.
 */
function renderMetadata(features, url) {
  try {
    const domain = new URL(url).hostname;
    el.metaSite.textContent = domain.length > 22 ? domain.slice(0, 22) + '…' : domain;
    el.metaSite.className   = 'risk-val';
  } catch {
    el.metaSite.textContent = '—';
  }

  if (features) {
    const certOk = features.has_https;
    el.metaCert.textContent = certOk ? 'Valid' : 'Missing';
    el.metaCert.className   = `risk-val ${certOk ? 'ok' : 'bad'}`;

    const kwCount = features.phishing_words ?? 0;
    el.metaKw.textContent = kwCount;
    el.metaKw.className   = `risk-val ${kwCount > 0 ? 'bad' : 'ok'}`;

    const subCount = features.subdomain_count ?? 0;
    el.metaSub.textContent = subCount;
    el.metaSub.className   = `risk-val ${subCount > 2 ? 'bad' : 'ok'}`;
  }

  el.riskCard.style.display = 'block';
}

// ─── Dashboard — threat reasons ───────────────────────────────────────────────

/**
 * Renders the list of human-readable threat reasons from the API.
 *
 * @param {string[]} reasons Array of threat description strings.
 */
function renderReasons(reasons) {
  if (!reasons?.length) return;

  el.threatList.innerHTML = reasons.map(
    (reason) => `
      <li class="threat-item">
        <span class="threat-dot"></span>
        <span>${reason}</span>
      </li>`
  ).join('');

  el.reasonsCard.style.display = 'block';
}

// ─── Dashboard — "Did you mean?" suggestion ───────────────────────────────────

/**
 * Checks if the suspicious URL appears to impersonate a known brand,
 * then suggests the real domain to the user.
 *
 * @param {string} url The suspicious URL being scanned.
 */
function renderSuggestion(url) {
  const lowerUrl = url.toLowerCase();

  for (const [keyword, realDomain] of Object.entries(KNOWN_DOMAINS)) {
    if (lowerUrl.includes(keyword) && !lowerUrl.includes(realDomain)) {
      el.suggUrl.textContent = realDomain;
      el.suggUrl.onclick     = () => chrome.tabs.create({url: `https://${realDomain}`});
      el.suggCard.style.display = 'flex';
      return;
    }
  }
}

// ─── Dashboard — trending banner ──────────────────────────────────────────────

/**
 * Shows the "Trending Threat" banner if the current domain has been
 * reported by multiple users locally.
 *
 * @param {string} url The current page URL.
 */
function checkTrending(url) {
  let domain;
  try { domain = new URL(url).hostname; } catch { return; }

  chrome.storage.local.get('reports', (data) => {
    if ((data.reports?.[domain] ?? 0) >= 2) {
      el.trendingBanner.style.display = 'flex';
    }
  });
}

// ─── Dashboard — report button ────────────────────────────────────────────────

/**
 * Wires up the "Report this Site" button and loads any existing report count.
 *
 * @param {string} url   The current page URL.
 * @param {string} level The detected risk level.
 */
function setupReportButton(url, level) {
  let domain;
  try { domain = new URL(url).hostname; } catch { return; }

  el.reportRow.style.display = 'flex';

  // Show existing report count if already reported
  chrome.storage.local.get('reports', (data) => {
    const count = data.reports?.[domain] ?? 0;
    if (count > 0) {
      el.reportCount.textContent = `${count} report${count > 1 ? 's' : ''}`;
      el.btnReport.textContent   = 'Reported';
      el.btnReport.classList.add('reported');
    }
  });

  el.btnReport.onclick = () => {
    chrome.storage.local.get(['reports', 'community_reports'], (data) => {
      // Increment domain report count
      const reports     = data.reports ?? {};
      reports[domain]   = (reports[domain] ?? 0) + 1;

      // Add or update entry in the community reports list
      const communityList = data.community_reports ?? [];
      const existing      = communityList.find((r) => r.domain === domain);

      if (existing) {
        existing.count++;
        existing.last = Date.now();
      } else {
        communityList.unshift({domain, count: 1, level, last: Date.now()});
      }

      chrome.storage.local.set({
        reports,
        community_reports: communityList.slice(0, 20),
      });

      el.reportCount.textContent = `${reports[domain]} report${reports[domain] > 1 ? 's' : ''}`;
      el.btnReport.textContent   = 'Reported';
      el.btnReport.classList.add('reported');

      if (reports[domain] >= 2) el.trendingBanner.style.display = 'flex';
    });
  };
}

// ─── Dashboard — scan history feed ───────────────────────────────────────────

/**
 * Loads and renders the scan history feed from local storage.
 */
function loadFeed() {
  chrome.storage.local.get('history', (data) => {
    const history = data.history ?? [];
    if (!history.length) return;

    const icons = {safe: '✓', suspicious: '⚠', dangerous: '✕'};

    el.feedList.innerHTML = history.map(
      (item) => `
        <li class="feed-item">
          <div class="feed-icon ${item.level}">${icons[item.level] ?? ''}</div>
          <div class="feed-body">
            <div class="feed-domain">${item.domain}</div>
            <div class="feed-meta">${timeAgo(item.time)} · ${item.level === 'safe' ? 'Automated Check' : 'Manual Trigger'}</div>
          </div>
          <span class="chip ${item.level}">${item.level.toUpperCase()}</span>
        </li>`
    ).join('');
  });
}

/**
 * Saves the current scan result to local history, deduplicating by domain.
 *
 * @param {string} url   The scanned URL.
 * @param {string} level The detected risk level.
 * @param {number} score The risk score (0–1).
 */
function saveHistory(url, level, score) {
  let domain;
  try { domain = new URL(url).hostname; } catch { domain = url.slice(0, 30); }

  chrome.storage.local.get('history', (data) => {
    const history = [
      {domain, level, score, time: Date.now()},
      ...(data.history ?? []).filter((x) => x.domain !== domain),
    ].slice(0, MAX_HISTORY);

    chrome.storage.local.set({history}, loadFeed);
  });
}

// ─── Dashboard — statistics ───────────────────────────────────────────────────

/**
 * Reads scan statistics from local storage and updates the stats row UI.
 */
function loadStats() {
  chrome.storage.local.get(['checked', 'blocked', 'safe_count'], (data) => {
    el.statChecked.textContent = data.checked    ?? 0;
    el.statBlocked.textContent = data.blocked    ?? 0;
    el.statSafe.textContent    = data.safe_count ?? 0;
  });
}

/**
 * Increments the appropriate scan statistics counters in local storage.
 *
 * @param {string} level The detected risk level of the completed scan.
 */
function updateStats(level) {
  chrome.storage.local.get(['checked', 'blocked', 'safe_count'], (data) => {
    chrome.storage.local.set({
      checked:    (data.checked    ?? 0) + 1,
      blocked:    (data.blocked    ?? 0) + (level !== 'safe' ? 1 : 0),
      safe_count: (data.safe_count ?? 0) + (level === 'safe' ? 1 : 0),
    }, loadStats);
  });
}

// ─── Dashboard — scan flow ────────────────────────────────────────────────────

/**
 * Resets all dashboard UI elements to their initial "scanning" state.
 */
function resetScanUI() {
  setHeroState('checking');
  el.trendingBanner.style.display    = 'none';
  el.riskCard.style.display          = 'none';
  el.suggCard.style.display          = 'none';
  el.reasonsCard.style.display       = 'none';
  el.reportRow.style.display         = 'none';
  el.btnReport.className             = 'btn-report';
  el.btnReport.textContent           = 'Report this Site';
  el.reportCount.textContent         = '';
  el.gaugeArc.style.strokeDashoffset = GAUGE_ARC_LENGTH;
  el.gaugePct.textContent            = '0%';
}

/**
 * Returns whether a URL is scannable by the extension.
 *
 * @param {string} url Candidate URL.
 * @return {boolean} True for http(s) URLs.
 */
function isScannableUrl(url) {
  return url.startsWith('http://') || url.startsWith('https://');
}

/**
 * Shows a clear state for tabs that cannot be scanned.
 *
 * @param {string} message Additional guidance text.
 */
function showUnsupportedTabState(message) {
  el.heroHeadline.textContent = 'Unsupported Tab';
  el.heroSub.textContent      = message;
}

/**
 * Applies one completed scan result to the dashboard UI and counters.
 *
 * @param {Object} result API response payload.
 * @param {string} scannedUrl URL that was scanned.
 */
function applyScanResult(result, scannedUrl) {
  const {risk_level: level, risk_score: score, features, reasons} = result;

  setHeroState(level);
  animateGauge(score ?? 0, level);
  renderMetadata(features, scannedUrl);
  renderReasons(reasons);

  if (level === 'dangerous') renderSuggestion(scannedUrl);

  checkTrending(scannedUrl);
  setupReportButton(scannedUrl, level);
  saveHistory(scannedUrl, level, score ?? 0);
  updateStats(level);
}

/**
 * Requests a fresh scan from the content script running in the active tab.
 *
 * @param {number} tabId Active tab ID.
 * @return {Promise<?Object>} API result object, or null if content script is unavailable.
 */
async function requestContentRescan(tabId) {
  try {
    const response = await chrome.tabs.sendMessage(tabId, {type: 'scan_now'});
    if (!response?.ok || !response.result) return null;
    return response.result;
  } catch {
    return null;
  }
}

/**
 * Fallback scan path when content scripts are unavailable.
 * Sends URL-only payload directly to the API.
 *
 * @param {string} url URL to analyze.
 * @return {Promise<Object>} API response payload.
 */
async function fetchUrlOnlyScan(url) {
  const apiBase  = await resolveApiBase();
  const response = await fetch(`${apiBase}/analyze`, {
    method:  'POST',
    headers: {'Content-Type': 'application/json'},
    body:    JSON.stringify({url}),
  });

  if (!response.ok) throw new Error('API returned non-OK status');
  return await response.json();
}

/**
 * Fetches the active tab URL, runs a scan, and updates the full UI.
 * Prefers content-script rescans (URL + DOM signals), with URL-only fallback.
 */
async function checkCurrentTab() {
  resetScanUI();

  const [tab] = await chrome.tabs.query({active: true, currentWindow: true});
  if (!tab?.url) {
    showUnsupportedTabState('No active page found to scan.');
    return;
  }

  if (!isScannableUrl(tab.url)) {
    showUnsupportedTabState('Open any website that starts with http:// or https://');
    return;
  }

  try {
    const contentResult = tab.id ? await requestContentRescan(tab.id) : null;
    const result = contentResult ?? await fetchUrlOnlyScan(tab.url);
    applyScanResult(result, tab.url);

  } catch {
    el.heroHeadline.textContent = 'Server Offline';
    el.heroSub.textContent      = 'Cloud mode: check your backend URL in config.js. Local mode: run uvicorn main:app --reload';
  }
}

// ─── Training tab ─────────────────────────────────────────────────────────────

/** @type {number} Current quiz question index. */
let quizIndex = 0;

/** @type {number} Current quiz score. */
let quizScore = 0;

/** @type {Array<{url: string, correct: boolean, answer: string}>} Answered questions. */
let quizAnswers = [];

/**
 * Shows a named training screen and hides all others.
 *
 * @param {string} screenId Element ID of the screen to show.
 */
function showTrainScreen(screenId) {
  ['train-intro', 'train-quiz', 'train-result'].forEach((id) => {
    document.getElementById(id).style.display = 'none';
  });
  document.getElementById(screenId).style.display = 'flex';
}

/**
 * Loads and renders the previous quiz score history chips.
 */
function loadScoreHistory() {
  chrome.storage.local.get('quiz_history', (data) => {
    const history = data.quiz_history ?? [];
    const row     = document.getElementById('score-chips');

    if (!history.length) {
      row.innerHTML = '<span class="score-empty">No attempts yet</span>';
      return;
    }

    row.innerHTML = history.slice(0, 5).map((score) => {
      const cls = score >= 5 ? 'good' : score >= 3 ? 'mid' : 'bad';
      return `<span class="score-chip ${cls}">${score}/6</span>`;
    }).join('');
  });
}

/**
 * Renders the current quiz question.
 */
function loadQuestion() {
  const question   = QUIZ_QUESTIONS[quizIndex];
  const progressPct = Math.round((quizIndex / QUIZ_QUESTIONS.length) * 100);

  document.getElementById('quiz-fill').style.width       = progressPct + '%';
  document.getElementById('quiz-step').textContent       = `Question ${quizIndex + 1} / ${QUIZ_QUESTIONS.length}`;
  document.getElementById('quiz-score-live').textContent = `Score: ${quizScore}`;
  document.getElementById('quiz-url').textContent        = question.url;
  document.getElementById('feedback-card').style.display = 'none';

  const btnSafe  = document.getElementById('choice-safe');
  const btnPhish = document.getElementById('choice-phish');
  btnSafe.disabled  = false;
  btnPhish.disabled = false;
  btnSafe.onclick   = () => submitAnswer('safe',     question);
  btnPhish.onclick  = () => submitAnswer('phishing', question);
}

/**
 * Processes the user's quiz answer and shows feedback.
 *
 * @param {string} choice   The user's choice ('safe' or 'phishing').
 * @param {Object} question The current question object.
 */
function submitAnswer(choice, question) {
  const isCorrect = choice === question.answer;
  if (isCorrect) quizScore++;

  quizAnswers.push({url: question.url, correct: isCorrect, answer: question.answer});

  document.getElementById('choice-safe').disabled  = true;
  document.getElementById('choice-phish').disabled = true;

  const feedback = document.getElementById('feedback-card');
  feedback.className = `feedback-card ${isCorrect ? 'correct' : 'wrong'}`;
  feedback.style.display = 'flex';

  document.getElementById('feedback-icon').textContent       = isCorrect ? '✓' : '✕';
  document.getElementById('quiz-score-live').textContent     = `Score: ${quizScore}`;
  document.getElementById('feedback-text').textContent       = isCorrect
    ? `Correct! ${question.explain}`
    : `Wrong. ${question.explain}`;
}

document.getElementById('btn-next').addEventListener('click', () => {
  quizIndex++;
  if (quizIndex >= QUIZ_QUESTIONS.length) {
    showQuizResult();
  } else {
    loadQuestion();
  }
});

/**
 * Renders the final quiz result screen.
 */
function showQuizResult() {
  showTrainScreen('train-result');
  document.getElementById('result-num').textContent = quizScore;

  const pct   = quizScore / QUIZ_QUESTIONS.length;
  const color = pct >= 0.8 ? 'var(--secondary)' : pct >= 0.5 ? 'var(--tertiary)' : 'var(--error)';

  document.getElementById('result-ring').style.borderColor = color;
  document.getElementById('result-num').style.color        = color;

  const titles = ['Keep practicing!', 'Getting there!', 'Good job!', 'Great job!', 'Excellent!', 'Perfect!', 'Perfect!'];
  const descs  = [
    'Phishing can be tricky. Review the explanations and try again.',
    'You got some right! More practice will sharpen your instincts.',
    'Solid effort. You\'re developing a good eye for threats.',
    'Well done! Most phishing attempts won\'t fool you.',
    'Impressive — you can spot sophisticated phishing attempts.',
    'Outstanding! You\'re operating at cybersecurity professional level.',
  ];

  document.getElementById('result-title').textContent = titles[quizScore];
  document.getElementById('result-desc').textContent  = descs[Math.min(quizScore, descs.length - 1)];

  document.getElementById('breakdown').innerHTML = quizAnswers.map(
    (a) => `
      <div class="bd-item">
        <span class="bd-dot" style="background:${a.correct ? 'var(--secondary)' : 'var(--error)'}"></span>
        <span class="bd-url">${a.url}</span>
        <span class="bd-verdict" style="color:${a.correct ? 'var(--secondary)' : 'var(--error)'}">
          ${a.correct ? '✓' : '✕ ' + a.answer}
        </span>
      </div>`
  ).join('');

  chrome.storage.local.get('quiz_history', (data) => {
    const history = data.quiz_history ?? [];
    chrome.storage.local.set({quiz_history: [quizScore, ...history].slice(0, 10)});
  });
}

document.getElementById('btn-start-train').addEventListener('click', () => {
  quizIndex   = 0;
  quizScore   = 0;
  quizAnswers = [];
  showTrainScreen('train-quiz');
  loadQuestion();
});

document.getElementById('btn-retry').addEventListener('click', () => {
  loadScoreHistory();
  showTrainScreen('train-intro');
});

// ─── Reports tab ──────────────────────────────────────────────────────────────

/**
 * Loads community-reported threats and personal scan statistics
 * into the Reports tab UI.
 */
function loadThreats() {
  chrome.storage.local.get(['community_reports', 'checked', 'blocked', 'safe_count'], (data) => {
    const checked = data.checked    ?? 0;
    const blocked = data.blocked    ?? 0;
    const safe    = data.safe_count ?? 0;
    const total   = checked || 1;

    document.getElementById('ps-checked').textContent  = checked;
    document.getElementById('ps-blocked').textContent  = blocked;
    document.getElementById('ps-attempts').textContent = blocked;
    document.getElementById('safe-pct').textContent    = Math.round((safe / total) * 100) + '%';

    const reports  = data.community_reports ?? [];
    const listEl   = document.getElementById('threats-list');

    if (!reports.length) {
      listEl.innerHTML = '<li class="feed-empty" style="padding:16px">No reports yet — use the Report button on the Dashboard.</li>';
      return;
    }

    listEl.innerHTML = reports.map(
      (r) => `
        <li class="threat-card">
          <div class="threat-card-top">
            <span class="threat-domain">${r.domain}</span>
            <span class="chip dangerous">${r.count} report${r.count > 1 ? 's' : ''}</span>
          </div>
          <div class="threat-meta-txt">${r.level} · ${timeAgo(r.last)}</div>
        </li>`
    ).join('');
  });
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Converts a Unix timestamp to a human-readable relative time string.
 *
 * @param {number} timestamp Unix timestamp in milliseconds.
 * @return {string} e.g. "just now", "5m ago", "2h ago", "3d ago".
 */
function timeAgo(timestamp) {
  const minutes = Math.floor((Date.now() - timestamp) / 60000);
  if (minutes < 1)  return 'just now';
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24)   return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

// ─── Initialization ───────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  loadStats();
  loadFeed();
  loadScoreHistory();
  checkCurrentTab();
  el.btnRecheck.addEventListener('click', checkCurrentTab);
});
