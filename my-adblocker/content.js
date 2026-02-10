const STYLE_ID = 'adblocker-cosmetic';
const HIDDEN_ATTR = 'data-adblocker-hidden';
const ANTI_DETECTION_STYLE_ID = 'adblocker-anti-detection';
const ANTI_DETECTION_HIDDEN_ATTR = 'data-adblocker-anti-detection-hidden';
const SURROGATE_MODE_DEFAULT = 'safe';

const ANTI_DETECTION_SELECTORS_BY_DOMAIN = Object.freeze({
  'forbes.com': Object.freeze({
    caseId: 'AD-001',
    safe: Object.freeze([
      '#adblock-modal',
      '.adblock-modal',
      '[id*="forbes-adblock"]',
      '[class*="forbes-adblock"]',
      '[data-forbes-adblock]'
    ]),
    strict: Object.freeze([
      '[id*="adblock"]',
      '[class*="adblock"]',
      '[data-adblock]'
    ])
  }),
  'sourceforge.net': Object.freeze({
    caseId: 'AD-002',
    safe: Object.freeze([
      '#adblock_message',
      '#adblocker-message',
      '.adblock-warning',
      '[data-test="adblock-warning"]',
      '[id*="sourceforge-adblock"]'
    ]),
    strict: Object.freeze([
      '[id*="adblock"]',
      '[class*="adblock"]',
      '[data-adblock]'
    ])
  })
});

const SELECTORS_BY_RISK = Object.freeze({
  safe: [
    '.ad-banner',
    '.ad-container',
    '.ad-wrapper',
    '.ad-unit',
    '.ad-slot',
    '.ad-box',
    '.advert-banner',
    '.advert-container',
    '.banner-ad',
    '.sidebar-ad',
    '.footer-ad',
    '.header-ad',
    '.native-ad',
    '.in-article-ad',
    '.interstitial-ad',
    '.dfp-ad',
    '.gpt-ad',
    '#ad-slot',
    '#google_ads',
    '#ad-container',
    '#ad-wrapper',
    '#ad-banner',
    '#leaderboard-ad',
    '#sidebar-ad',
    '#footer-ad',
    '[id^="div-gpt-ad"]',
    '[id^="google_ads_"]',
    '[data-ad-slot]',
    '[data-ad-client]',
    '[data-google-query-id]',
    'ins.adsbygoogle',
    'amp-ad',
    'amp-embed',
    'iframe[src*="doubleclick"]',
    'iframe[id*="google_ads"]',
    'iframe[name*="google_ads"]',
    'ytd-ad-slot-renderer',
    'ytd-promoted-sparkles-web-renderer',
    'ytd-display-ad-renderer',
    'ytd-in-feed-ad-layout-renderer'
  ],
  medium: [
    '.ad-banner',
    '.ad-container',
    '.advertisement',
    '.ad-block',
    '.advert',
    '.sponsored',
    '.sponsored-content',
    '.sponsored-post',
    '#advert',
    '#ads',
    '[data-ad]',
    '[aria-label*="advertisement" i]',
    '[aria-label*="sponsored" i]',
    '[data-testid="placementTracking"]',
    '[data-ad-preview]',
    '.x-sponsored'
  ],
  aggressive: [
    '[class*="sponsored"]',
    '[class*="advertisement"]',
    'iframe[src*="ads"]',
    'aside[class*="ad"]',
    'section[class*="ad"]'
  ]
});

const FRAGILE_SELECTOR_EXCLUSIONS = Object.freeze({
  'amazon.com': ['.sponsored', '[class*="sponsored"]'],
  'github.com': ['.sponsored'],
  'linkedin.com': ['.sponsored-content'],
  'nytimes.com': ['.advertisement'],
  'wikipedia.org': ['.advertisement'],
  'weather.com': ['.ad-container'],
  'reddit.com': ['[data-testid="placementTracking"]'],
  'x.com': ['.x-sponsored'],
  'youtube.com': ['#ads', 'ytd-in-feed-ad-layout-renderer'],
  'cnn.com': ['.advert-banner']
});

let observer = null;
let debounceTimer = null;
let processedNodes = new WeakSet();
let antiDetectionProcessedNodes = new WeakSet();
let activeSelectors = [];
let activeAntiDetectionSelectors = [];
let isCosmeticEnabled = true;
let isAntiDetectionEnabled = false;

function isObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function getCurrentHostname() {
  try {
    const hostname = new URL(window.location.href).hostname.toLowerCase();
    return hostname.startsWith('www.') ? hostname.slice(4) : hostname;
  } catch (_) {
    return null;
  }
}

function getHostnameHierarchy(hostname) {
  if (!hostname) return [];

  const domains = [];
  let current = hostname;
  while (current) {
    domains.push(current);
    const dotIndex = current.indexOf('.');
    if (dotIndex === -1) break;
    current = current.slice(dotIndex + 1);
  }

  return domains;
}

function getDomainConfig(domainSettings, hostname) {
  if (!isObject(domainSettings) || !hostname) return null;

  for (const domain of getHostnameHierarchy(hostname)) {
    if (isObject(domainSettings[domain])) {
      return domainSettings[domain];
    }
  }

  return null;
}

function normalizeHostnameValue(rawValue) {
  if (typeof rawValue !== 'string') return null;
  const trimmed = rawValue.trim().toLowerCase();
  if (!trimmed) return null;
  return trimmed.startsWith('www.') ? trimmed.slice(4) : trimmed;
}

function sanitizeSurrogateMode(rawMode) {
  if (typeof rawMode !== 'string') return SURROGATE_MODE_DEFAULT;
  const normalized = rawMode.trim().toLowerCase();
  return normalized === 'off' || normalized === 'safe' || normalized === 'strict'
    ? normalized
    : SURROGATE_MODE_DEFAULT;
}

function getAntiDetectionConfig(hostname) {
  for (const domain of getHostnameHierarchy(hostname)) {
    const config = ANTI_DETECTION_SELECTORS_BY_DOMAIN[domain];
    if (isObject(config)) {
      return config;
    }
  }

  return null;
}

function isHostnameWhitelisted(hostname, whitelist) {
  if (!hostname || !Array.isArray(whitelist)) return false;

  const hostnameHierarchy = new Set(getHostnameHierarchy(hostname));
  for (const entry of whitelist) {
    const normalized = normalizeHostnameValue(entry);
    if (!normalized) continue;
    if (hostnameHierarchy.has(normalized)) {
      return true;
    }
  }

  return false;
}

function getExcludedSelectors(hostname) {
  const blocked = new Set();

  for (const domain of getHostnameHierarchy(hostname)) {
    const exclusions = FRAGILE_SELECTOR_EXCLUSIONS[domain];
    if (!Array.isArray(exclusions)) continue;
    for (const selector of exclusions) {
      blocked.add(selector);
    }
  }

  return blocked;
}

function getSelectorsForMode(strictModeEnabled) {
  const selectors = SELECTORS_BY_RISK.safe.concat(SELECTORS_BY_RISK.medium);
  if (strictModeEnabled) {
    selectors.push(...SELECTORS_BY_RISK.aggressive);
  }
  return selectors;
}

function buildActiveSelectors(strictModeEnabled, hostname) {
  const excludedSelectors = getExcludedSelectors(hostname);
  const selectors = getSelectorsForMode(strictModeEnabled);
  const deduped = [];
  const seen = new Set();

  for (const selector of selectors) {
    if (excludedSelectors.has(selector) || seen.has(selector)) {
      continue;
    }
    seen.add(selector);
    deduped.push(selector);
  }

  return deduped;
}

function buildAntiDetectionSelectors(state) {
  if (!state.enabled || !state.networkBlockingEnabled) return [];
  if (state.isWhitelisted) return [];
  if (!state.surrogatesEnabled || !state.antiDetectionEnabled) return [];
  if (state.surrogateMode === 'off') return [];
  if (state.siteFixSurrogates === false) return [];
  if (state.siteFixAntiDetection !== true) return [];

  const config = getAntiDetectionConfig(state.hostname);
  if (!config) return [];

  const selectors = [...config.safe];
  const strictHooksEnabled =
    state.surrogateMode === 'strict' &&
    (state.siteFixStrict === true || state.siteStrictness === 'strict');
  if (strictHooksEnabled) {
    selectors.push(...config.strict);
  }

  const deduped = [];
  const seen = new Set();
  for (const selector of selectors) {
    if (typeof selector !== 'string' || !selector.trim() || seen.has(selector)) {
      continue;
    }
    seen.add(selector);
    deduped.push(selector);
  }

  return deduped;
}

function buildStyleText(selectors) {
  return selectors
    .map(
      (selector) =>
        `${selector}{display:none!important;visibility:hidden!important;opacity:0!important;` +
        'height:0!important;overflow:hidden!important;margin:0!important;padding:0!important;' +
        'pointer-events:none!important}'
    )
    .join('');
}

function ensureStyle(selectors) {
  if (!document.documentElement) return;

  let style = document.getElementById(STYLE_ID);
  if (!style) {
    style = document.createElement('style');
    style.id = STYLE_ID;
    document.documentElement.appendChild(style);
  }
  style.textContent = buildStyleText(selectors);
}

function removeStyle() {
  const style = document.getElementById(STYLE_ID);
  if (style) {
    style.remove();
  }
}

function ensureAntiDetectionStyle(selectors) {
  if (!document.documentElement) return;

  let style = document.getElementById(ANTI_DETECTION_STYLE_ID);
  if (!style) {
    style = document.createElement('style');
    style.id = ANTI_DETECTION_STYLE_ID;
    document.documentElement.appendChild(style);
  }
  style.textContent = buildStyleText(selectors);
}

function removeAntiDetectionStyle() {
  const style = document.getElementById(ANTI_DETECTION_STYLE_ID);
  if (style) {
    style.remove();
  }
}

function applyHiddenStyles(element) {
  element.setAttribute(HIDDEN_ATTR, '1');
  element.style.setProperty('display', 'none', 'important');
  element.style.setProperty('visibility', 'hidden', 'important');
  element.style.setProperty('opacity', '0', 'important');
  element.style.setProperty('height', '0', 'important');
  element.style.setProperty('overflow', 'hidden', 'important');
  element.style.setProperty('margin', '0', 'important');
  element.style.setProperty('padding', '0', 'important');
  element.style.setProperty('pointer-events', 'none', 'important');
}

function applyAntiDetectionHiddenStyles(element) {
  element.setAttribute(ANTI_DETECTION_HIDDEN_ATTR, '1');
  element.style.setProperty('display', 'none', 'important');
  element.style.setProperty('visibility', 'hidden', 'important');
  element.style.setProperty('opacity', '0', 'important');
  element.style.setProperty('height', '0', 'important');
  element.style.setProperty('overflow', 'hidden', 'important');
  element.style.setProperty('margin', '0', 'important');
  element.style.setProperty('padding', '0', 'important');
  element.style.setProperty('pointer-events', 'none', 'important');
}

function clearHiddenStyles() {
  const hiddenElements = document.querySelectorAll(`[${HIDDEN_ATTR}="1"]`);
  for (const element of hiddenElements) {
    element.style.removeProperty('display');
    element.style.removeProperty('visibility');
    element.style.removeProperty('opacity');
    element.style.removeProperty('height');
    element.style.removeProperty('overflow');
    element.style.removeProperty('margin');
    element.style.removeProperty('padding');
    element.style.removeProperty('pointer-events');
    element.removeAttribute(HIDDEN_ATTR);
  }
  processedNodes = new WeakSet();
}

function clearAntiDetectionHiddenStyles() {
  const hiddenElements = document.querySelectorAll(`[${ANTI_DETECTION_HIDDEN_ATTR}="1"]`);
  for (const element of hiddenElements) {
    element.style.removeProperty('display');
    element.style.removeProperty('visibility');
    element.style.removeProperty('opacity');
    element.style.removeProperty('height');
    element.style.removeProperty('overflow');
    element.style.removeProperty('margin');
    element.style.removeProperty('padding');
    element.style.removeProperty('pointer-events');
    element.removeAttribute(ANTI_DETECTION_HIDDEN_ATTR);
  }
  antiDetectionProcessedNodes = new WeakSet();
}

function hideElements(root = document) {
  if (!isCosmeticEnabled) return;

  for (const selector of activeSelectors) {
    let matches = [];
    try {
      matches = root.querySelectorAll(selector);
    } catch (_) {
      continue;
    }

    for (const element of matches) {
      if (processedNodes.has(element)) continue;
      processedNodes.add(element);
      applyHiddenStyles(element);
    }
  }
}

function hideAntiDetectionElements(root = document) {
  if (!isAntiDetectionEnabled) return;

  for (const selector of activeAntiDetectionSelectors) {
    let matches = [];
    try {
      matches = root.querySelectorAll(selector);
    } catch (_) {
      continue;
    }

    for (const element of matches) {
      if (antiDetectionProcessedNodes.has(element)) continue;
      antiDetectionProcessedNodes.add(element);
      applyAntiDetectionHiddenStyles(element);
    }
  }
}

function runHidePass() {
  try {
    hideElements(document);
  } catch (err) {
    console.error('[AdBlocker] hide pass failed:', err.message);
  }
}

function runAntiDetectionPass() {
  try {
    hideAntiDetectionElements(document);
  } catch (err) {
    console.error('[AdBlocker] anti-detection pass failed:', err.message);
  }
}

function runMutationPass() {
  runHidePass();
  runAntiDetectionPass();
}

function stopObserver() {
  if (observer) {
    observer.disconnect();
    observer = null;
  }
  if (debounceTimer) {
    clearTimeout(debounceTimer);
    debounceTimer = null;
  }
}

function startObserver() {
  if (observer || !document.documentElement || (!isCosmeticEnabled && !isAntiDetectionEnabled)) {
    return;
  }

  observer = new MutationObserver(() => {
    if (debounceTimer) return;

    debounceTimer = setTimeout(() => {
      debounceTimer = null;
      if (typeof requestIdleCallback === 'function') {
        requestIdleCallback(runMutationPass);
      } else {
        runMutationPass();
      }
    }, 100);
  });

  observer.observe(document.documentElement, {
    childList: true,
    subtree: true
  });
}

function applyCosmeticState(state) {
  const strictModeEnabled = state.strictModeEnabled || state.siteStrictness === 'strict';
  activeSelectors = buildActiveSelectors(strictModeEnabled, state.hostname);
  activeAntiDetectionSelectors = buildAntiDetectionSelectors(state);

  isCosmeticEnabled = state.enabled && state.cosmeticFilteringEnabled && state.siteCosmeticEnabled;
  isAntiDetectionEnabled = activeAntiDetectionSelectors.length > 0;

  if (!isCosmeticEnabled) {
    removeStyle();
    clearHiddenStyles();
  } else {
    ensureStyle(activeSelectors);
    runHidePass();
  }

  if (!isAntiDetectionEnabled) {
    removeAntiDetectionStyle();
    clearAntiDetectionHiddenStyles();
  } else {
    ensureAntiDetectionStyle(activeAntiDetectionSelectors);
    runAntiDetectionPass();
  }

  if (!isCosmeticEnabled && !isAntiDetectionEnabled) {
    stopObserver();
    return;
  }

  startObserver();
}

async function loadStateFromStorage() {
  const data = await chrome.storage.local.get([
    'enabled',
    'networkBlockingEnabled',
    'cosmeticFilteringEnabled',
    'strictModeEnabled',
    'surrogatesEnabled',
    'antiDetectionEnabled',
    'surrogateMode',
    'domainSettings',
    'siteFixes',
    'whitelist'
  ]);

  const hostname = getCurrentHostname();
  const domainSettings = isObject(data.domainSettings) ? data.domainSettings : {};
  const siteFixes = isObject(data.siteFixes) ? data.siteFixes : {};
  const domainConfig = getDomainConfig(domainSettings, hostname);
  const siteFix = getDomainConfig(siteFixes, hostname);
  const isWhitelisted = isHostnameWhitelisted(hostname, data.whitelist);

  applyCosmeticState({
    enabled: data.enabled ?? true,
    networkBlockingEnabled: data.networkBlockingEnabled ?? (data.enabled ?? true),
    cosmeticFilteringEnabled: data.cosmeticFilteringEnabled ?? true,
    strictModeEnabled: data.strictModeEnabled ?? false,
    surrogatesEnabled: data.surrogatesEnabled ?? true,
    antiDetectionEnabled: data.antiDetectionEnabled ?? true,
    surrogateMode: sanitizeSurrogateMode(data.surrogateMode),
    siteCosmeticEnabled: !isWhitelisted && domainConfig?.cosmetic !== false,
    siteFixSurrogates: siteFix?.surrogates,
    siteFixAntiDetection: siteFix?.antiDetection,
    siteFixStrict: siteFix?.strict,
    siteStrictness: domainConfig?.strictness,
    isWhitelisted,
    hostname
  });
}

function initStorageListener() {
  chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName !== 'local') return;

    if (
      changes.enabled ||
      changes.networkBlockingEnabled ||
      changes.cosmeticFilteringEnabled ||
      changes.strictModeEnabled ||
      changes.surrogatesEnabled ||
      changes.antiDetectionEnabled ||
      changes.surrogateMode ||
      changes.domainSettings ||
      changes.siteFixes ||
      changes.whitelist
    ) {
      loadStateFromStorage().catch((err) => {
        console.error('[AdBlocker] failed to reload cosmetic state:', err.message);
      });
    }
  });
}

function initMessageListener() {
  chrome.runtime.onMessage.addListener((message) => {
    if (!isObject(message)) return;
    if (message.type !== 'stateUpdated') return;

    loadStateFromStorage().catch((err) => {
      console.error('[AdBlocker] failed to handle state update message:', err.message);
    });
  });
}

// Safe mode defaults to ON immediately, then storage settings refine behavior.
applyCosmeticState({
  enabled: true,
  networkBlockingEnabled: true,
  cosmeticFilteringEnabled: true,
  strictModeEnabled: false,
  surrogatesEnabled: true,
  antiDetectionEnabled: true,
  surrogateMode: SURROGATE_MODE_DEFAULT,
  siteCosmeticEnabled: true,
  siteFixSurrogates: true,
  siteFixAntiDetection: false,
  siteFixStrict: false,
  siteStrictness: 'balanced',
  isWhitelisted: false,
  hostname: getCurrentHostname()
});

loadStateFromStorage().catch((err) => {
  console.error('[AdBlocker] initial state load failed:', err.message);
});

initStorageListener();
initMessageListener();
