const STYLE_ID = 'adblocker-cosmetic';
const HIDDEN_ATTR = 'data-adblocker-hidden';

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
let activeSelectors = [];
let isCosmeticEnabled = true;

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

function runHidePass() {
  try {
    hideElements(document);
  } catch (err) {
    console.error('[AdBlocker] hide pass failed:', err.message);
  }
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
  if (observer || !document.documentElement || !isCosmeticEnabled) return;

  observer = new MutationObserver(() => {
    if (debounceTimer) return;

    debounceTimer = setTimeout(() => {
      debounceTimer = null;
      if (typeof requestIdleCallback === 'function') {
        requestIdleCallback(runHidePass);
      } else {
        runHidePass();
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

  isCosmeticEnabled = state.enabled && state.cosmeticFilteringEnabled && state.siteCosmeticEnabled;

  if (!isCosmeticEnabled) {
    stopObserver();
    removeStyle();
    clearHiddenStyles();
    return;
  }

  ensureStyle(activeSelectors);
  runHidePass();
  startObserver();
}

async function loadStateFromStorage() {
  const data = await chrome.storage.local.get([
    'enabled',
    'cosmeticFilteringEnabled',
    'strictModeEnabled',
    'domainSettings'
  ]);

  const hostname = getCurrentHostname();
  const domainSettings = isObject(data.domainSettings) ? data.domainSettings : {};
  const domainConfig = getDomainConfig(domainSettings, hostname);

  applyCosmeticState({
    enabled: data.enabled ?? true,
    cosmeticFilteringEnabled: data.cosmeticFilteringEnabled ?? true,
    strictModeEnabled: data.strictModeEnabled ?? false,
    siteCosmeticEnabled: domainConfig?.cosmetic !== false,
    siteStrictness: domainConfig?.strictness,
    hostname
  });
}

function initStorageListener() {
  chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName !== 'local') return;

    if (
      changes.enabled ||
      changes.cosmeticFilteringEnabled ||
      changes.strictModeEnabled ||
      changes.domainSettings
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
  cosmeticFilteringEnabled: true,
  strictModeEnabled: false,
  siteCosmeticEnabled: true,
  siteStrictness: 'balanced',
  hostname: getCurrentHostname()
});

loadStateFromStorage().catch((err) => {
  console.error('[AdBlocker] initial state load failed:', err.message);
});

initStorageListener();
initMessageListener();
