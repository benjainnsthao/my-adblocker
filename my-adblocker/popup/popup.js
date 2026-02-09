const state = {
  isBusy: false,
  activeTab: null,
  popupState: null
};

let pauseTicker = null;

const elements = {
  status: document.getElementById('status'),
  globalToggle: document.getElementById('global-toggle'),
  domain: document.getElementById('current-domain'),
  whitelistToggle: document.getElementById('whitelist-toggle'),
  tabCounter: document.getElementById('tab-counter'),
  sessionCounter: document.getElementById('session-counter'),
  lifetimeCounter: document.getElementById('lifetime-counter'),
  quickPause: document.getElementById('quick-pause'),
  pauseStatus: document.getElementById('pause-status'),
  reportIssue: document.getElementById('report-issue')
};

function isObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function normalizeDomainFromUrl(rawUrl) {
  if (typeof rawUrl !== 'string') return null;

  try {
    const parsed = new URL(rawUrl);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return null;
    }

    let hostname = parsed.hostname.toLowerCase();
    if (hostname.startsWith('www.')) {
      hostname = hostname.slice(4);
    }

    return hostname || null;
  } catch (_) {
    return null;
  }
}

function formatCount(value) {
  const numeric = Number.isFinite(value) ? Math.max(0, Math.trunc(value)) : 0;
  return numeric.toLocaleString();
}

function formatRemainingSeconds(ms) {
  const seconds = Math.max(0, Math.ceil(ms / 1000));
  return `${seconds}s`;
}

function setStatus(message, tone = 'info') {
  elements.status.textContent = message || '';
  elements.status.setAttribute('data-tone', tone);
}

function sendMessage(message) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(message, (response) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message || 'Runtime error'));
        return;
      }

      if (!isObject(response)) {
        reject(new Error('Invalid response from background'));
        return;
      }

      if (response.error) {
        reject(new Error(response.error));
        return;
      }

      resolve(response);
    });
  });
}

function queryActiveTab() {
  return new Promise((resolve, reject) => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message || 'Failed to query active tab'));
        return;
      }
      resolve(Array.isArray(tabs) ? tabs[0] || null : null);
    });
  });
}

function getCurrentDomain() {
  return normalizeDomainFromUrl(state.activeTab?.url);
}

function getPopupQuickPauseState() {
  const quickPause = state.popupState?.quickPause;
  return isObject(quickPause)
    ? quickPause
    : {
        active: false,
        pausedUntil: null,
        remainingMs: 0
      };
}

function updatePauseStatusText() {
  const quickPause = getPopupQuickPauseState();

  if (!quickPause.active || !Number.isFinite(quickPause.pausedUntil)) {
    const enabled = state.popupState?.enabled ?? true;
    elements.pauseStatus.textContent = enabled
      ? 'Temporarily disable blocking for troubleshooting.'
      : 'Enable blocking to use quick pause.';
    return;
  }

  const remainingMs = Math.max(0, quickPause.pausedUntil - Date.now());
  quickPause.remainingMs = remainingMs;
  quickPause.active = remainingMs > 0;

  if (!quickPause.active) {
    elements.pauseStatus.textContent = 'Quick pause complete. Restoring state...';
    if (!state.isBusy) {
      withBusy(async () => {
        await refreshState();
        setStatus('Quick pause ended and state was restored.', 'success');
      });
    }
    return;
  }

  elements.pauseStatus.textContent = `Blocking resumes in ${formatRemainingSeconds(remainingMs)}.`;
}

function syncPauseTicker() {
  const quickPause = getPopupQuickPauseState();
  const shouldRun = quickPause.active && Number.isFinite(quickPause.pausedUntil);

  if (shouldRun && !pauseTicker) {
    pauseTicker = setInterval(() => {
      render();
    }, 1000);
    return;
  }

  if (!shouldRun && pauseTicker) {
    clearInterval(pauseTicker);
    pauseTicker = null;
  }
}

function render() {
  const popupState = state.popupState || {};
  const stats = isObject(popupState.stats) ? popupState.stats : {};
  const currentDomain = getCurrentDomain();
  const quickPause = getPopupQuickPauseState();

  elements.globalToggle.checked = popupState.enabled ?? true;
  elements.globalToggle.disabled = state.isBusy;

  elements.domain.textContent = currentDomain || 'Unavailable on this page';

  const domainAvailable = Boolean(currentDomain);
  const whitelisted = popupState.isCurrentDomainWhitelisted === true;
  elements.whitelistToggle.disabled = state.isBusy || !domainAvailable;
  elements.whitelistToggle.textContent = domainAvailable
    ? whitelisted
      ? 'Remove from Whitelist'
      : 'Whitelist This Site'
    : 'Whitelist Unavailable';

  elements.tabCounter.textContent = formatCount(stats.tabBlocked);
  elements.sessionCounter.textContent = formatCount(stats.sessionBlocked);
  elements.lifetimeCounter.textContent = formatCount(stats.totalBlocked);

  const quickPauseActive = quickPause.active && Number.isFinite(quickPause.pausedUntil);
  elements.quickPause.disabled = state.isBusy || quickPauseActive || !(popupState.enabled ?? true);
  elements.quickPause.textContent = quickPauseActive
    ? `Paused (${formatRemainingSeconds(Math.max(0, quickPause.pausedUntil - Date.now()))})`
    : 'Quick Pause (30s)';

  const hasUrl = typeof state.activeTab?.url === 'string' && state.activeTab.url.length > 0;
  elements.reportIssue.disabled = state.isBusy || !domainAvailable || !hasUrl;

  updatePauseStatusText();
  syncPauseTicker();
}

async function refreshState() {
  state.activeTab = await queryActiveTab();
  const domain = getCurrentDomain();
  const tabId = Number.isInteger(state.activeTab?.id) ? state.activeTab.id : null;

  state.popupState = await sendMessage({
    type: 'getPopupState',
    domain,
    tabId
  });
}

async function withBusy(task) {
  if (state.isBusy) return;
  state.isBusy = true;
  render();

  try {
    await task();
  } catch (err) {
    setStatus(err.message || 'Request failed', 'error');
  } finally {
    state.isBusy = false;
    render();
  }
}

async function onGlobalToggleChange() {
  const nextEnabled = elements.globalToggle.checked;

  await withBusy(async () => {
    await sendMessage({ type: 'setEnabled', enabled: nextEnabled });
    await refreshState();
    setStatus(nextEnabled ? 'Blocking enabled.' : 'Blocking disabled.', 'success');
  });
}

async function onWhitelistToggleClick() {
  const domain = getCurrentDomain();
  if (!domain) {
    setStatus('Whitelist control is unavailable for this page.', 'error');
    return;
  }

  const remove = state.popupState?.isCurrentDomainWhitelisted === true;

  await withBusy(async () => {
    await sendMessage({
      type: remove ? 'removeFromWhitelist' : 'addToWhitelist',
      domain
    });
    await refreshState();
    setStatus(remove ? `Removed ${domain} from whitelist.` : `Whitelisted ${domain}.`, 'success');
  });
}

async function onQuickPauseClick() {
  await withBusy(async () => {
    const result = await sendMessage({ type: 'startQuickPause' });
    await refreshState();
    if (result.active) {
      setStatus('Quick pause started for 30 seconds.', 'success');
      return;
    }
    setStatus('Quick pause request completed.', 'info');
  });
}

async function onReportIssueClick() {
  const domain = getCurrentDomain();
  if (!domain) {
    setStatus('Issue reports require a valid website tab.', 'error');
    return;
  }

  const tabId = Number.isInteger(state.activeTab?.id) ? state.activeTab.id : null;

  await withBusy(async () => {
    await sendMessage({
      type: 'reportSiteIssue',
      domain,
      url: state.activeTab?.url,
      title: state.activeTab?.title || '',
      tabId
    });
    setStatus('Site issue report saved locally.', 'success');
  });
}

function bindEvents() {
  elements.globalToggle.addEventListener('change', onGlobalToggleChange);
  elements.whitelistToggle.addEventListener('click', onWhitelistToggleClick);
  elements.quickPause.addEventListener('click', onQuickPauseClick);
  elements.reportIssue.addEventListener('click', onReportIssueClick);
}

async function init() {
  bindEvents();
  setStatus('Loading state...', 'info');

  await withBusy(async () => {
    await refreshState();
    setStatus('Ready.', 'info');
  });
}

document.addEventListener('DOMContentLoaded', () => {
  init().catch((err) => {
    setStatus(err.message || 'Popup failed to initialize', 'error');
    render();
  });
});

window.addEventListener('unload', () => {
  if (pauseTicker) {
    clearInterval(pauseTicker);
    pauseTicker = null;
  }
});
