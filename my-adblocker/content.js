// Content script - cosmetic filtering
// Runs at document_start to catch ads before render
/*
cosmetic filtering - js file that chrome injects into every webpage
its job is to hide elements visually,
elements that slip through network blocking
*/

// ── Ad selectors ────────────────────────────────────────────────────
const AD_SELECTORS = [
  // Class-based
  '.ad-banner', '.ad-container', '.advertisement', '.ad-wrapper',
  '.ad-unit', '.ad-slot', '.ad-block', '.ad-box',
  '.advert', '.advert-banner', '.advert-container',
  '.sponsored', '.sponsored-content', '.sponsored-post',
  '.banner-ad', '.sidebar-ad', '.footer-ad', '.header-ad',
  '.native-ad', '.in-article-ad', '.interstitial-ad',
  '.dfp-ad', '.gpt-ad',

  // ID-based
  '#ad-slot', '#google_ads', '#ad-container',
  '#ad-wrapper', '#advert', '#ads', '#ad-banner',
  '#leaderboard-ad', '#sidebar-ad', '#footer-ad',
  '[id^="div-gpt-ad"]',

  // Attribute-based
  '[id^="google_ads_"]',
  '[class*="sponsored"]', '[class*="advertisement"]',
  '[data-ad]', '[data-ad-slot]', '[data-ad-client]',
  '[data-google-query-id]',
  '[aria-label*="advertisement" i]',
  '[aria-label*="sponsored" i]',

  // Semantic/Tag-based
  'ins.adsbygoogle', 'amp-ad', 'amp-embed',
  'iframe[src*="ads"]', 'iframe[src*="doubleclick"]',
  'iframe[id*="google_ads"]', 'iframe[name*="google_ads"]',
  'aside[class*="ad"]', 'section[class*="ad"]',

  // Social/Native Ads
  '[data-testid="placementTracking"]',
  '[data-ad-preview]',
  '.x-sponsored',
  'ytd-ad-slot-renderer',
  'ytd-promoted-sparkles-web-renderer',
  'ytd-display-ad-renderer',
  'ytd-in-feed-ad-layout-renderer'
];

// ── CSS injection (fast initial blocking) ───────────────────────────
const style = document.createElement('style');
style.id = 'adblocker-cosmetic';
style.textContent = AD_SELECTORS.map(s =>
  `${s}{display:none!important;visibility:hidden!important;opacity:0!important;` +
  `height:0!important;overflow:hidden!important;margin:0!important;padding:0!important;` +
  `pointer-events:none!important}`
).join('');
document.documentElement.appendChild(style);

// ── Direct element hiding ───────────────────────────────────────────
const processedNodes = new WeakSet();

function hideElements(root) {
  for (const selector of AD_SELECTORS) {
    let elements;
    try {
      elements = (root || document).querySelectorAll(selector);
    } catch (e) {
      continue;
    }
    for (const el of elements) {
      if (processedNodes.has(el)) continue;
      processedNodes.add(el);
      el.style.setProperty('display', 'none', 'important');
      el.style.setProperty('visibility', 'hidden', 'important');
      el.style.setProperty('opacity', '0', 'important');
      el.style.setProperty('height', '0', 'important');
      el.style.setProperty('overflow', 'hidden', 'important');
      el.style.setProperty('margin', '0', 'important');
      el.style.setProperty('padding', '0', 'important');
      el.style.setProperty('pointer-events', 'none', 'important');
    }
  }
}

// Run immediately at document_start
hideElements(document);

// ── MutationObserver (catch dynamically injected ads) ───────────────
let debounceTimer = null;

const observer = new MutationObserver((mutations) => {
  if (debounceTimer) return;
  debounceTimer = setTimeout(() => {
    debounceTimer = null;
    if (typeof requestIdleCallback === 'function') {
      requestIdleCallback(() => hideElements(document));
    } else {
      hideElements(document);
    }
  }, 100);
});

// Observe as early as possible (document_start means documentElement exists)
observer.observe(document.documentElement, {
  childList: true,
  subtree: true
});
