(() => {
  'use strict';

  // AD-002 surrogate: intentionally minimal no-op replacement for SourceForge anti-adblock detector.
  const store = (window.__myAdblockerSurrogates = window.__myAdblockerSurrogates || {});
  store['AD-002'] = {
    loadedAt: Date.now(),
    version: '1.0.0'
  };
})();
