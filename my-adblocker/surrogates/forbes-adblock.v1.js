(() => {
  'use strict';

  // AD-001 surrogate: intentionally minimal no-op replacement for Forbes anti-adblock detector.
  const store = (window.__myAdblockerSurrogates = window.__myAdblockerSurrogates || {});
  store['AD-001'] = {
    loadedAt: Date.now(),
    version: '1.0.0'
  };
})();
