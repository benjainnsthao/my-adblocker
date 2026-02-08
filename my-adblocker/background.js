const RULESET_IDS = ['ads', 'tracking', 'annoyances'];
const STORAGE_SCHEMA_VERSION = 1;
const WHITELIST_RULE_ID_START = 5000;
const WHITELIST_RULE_ID_END = 5999;
const tabBlockedCounts = new Map();

const WHITELIST_FRAME_RESOURCE_TYPES = ['main_frame', 'sub_frame'];

function isObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function deepEqual(a, b) {
  return JSON.stringify(a) === JSON.stringify(b);
}

function createDefaultStats() {
  return {
    totalBlocked: 0,
    sessionBlocked: 0,
    lastReset: new Date().toISOString()
  };
}

function sanitizeStats(rawStats) {
  const stats = isObject(rawStats) ? rawStats : {};
  return {
    totalBlocked: Number.isFinite(stats.totalBlocked) ? stats.totalBlocked : 0,
    sessionBlocked: Number.isFinite(stats.sessionBlocked) ? stats.sessionBlocked : 0,
    lastReset: typeof stats.lastReset === 'string' ? stats.lastReset : new Date().toISOString()
  };
}

function sanitizeErrorLog(rawErrorLog) {
  if (!Array.isArray(rawErrorLog)) return [];

  return rawErrorLog
    .slice(-50)
    .map((entry) => {
      if (!isObject(entry)) return null;
      return {
        context: typeof entry.context === 'string' ? entry.context : 'unknown',
        message: typeof entry.message === 'string' ? entry.message : 'Unknown error',
        timestamp: Number.isFinite(entry.timestamp) ? entry.timestamp : Date.now()
      };
    })
    .filter(Boolean);
}

function normalizeDomain(rawDomain) {
  if (typeof rawDomain !== 'string') return null;

  let value = rawDomain.trim().toLowerCase();
  if (!value) return null;

  if (!value.includes('://')) {
    value = value.replace(/^[a-z]+:\/\//, '');
    value = value.split('/')[0];
    value = value.split('?')[0];
    value = value.split('#')[0];
  } else {
    try {
      value = new URL(value).hostname;
    } catch (_) {
      return null;
    }
  }

  value = value.replace(/\.$/, '');
  if (value.startsWith('www.')) {
    value = value.slice(4);
  }

  const host = value.split(':')[0];
  const isLocalhost = host === 'localhost';
  const isIpv4 = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host);
  const isDomain = /^[a-z0-9-]+(?:\.[a-z0-9-]+)+$/.test(host);

  if (!isLocalhost && !isIpv4 && !isDomain) {
    return null;
  }

  return host;
}

function sanitizeWhitelist(rawWhitelist) {
  if (!Array.isArray(rawWhitelist)) return [];

  const normalized = [];
  const seen = new Set();

  for (const item of rawWhitelist) {
    const domain = normalizeDomain(item);
    if (!domain || seen.has(domain)) continue;
    seen.add(domain);
    normalized.push(domain);
  }

  return normalized;
}

function sanitizeDomainSettings(rawDomainSettings) {
  if (!isObject(rawDomainSettings)) return {};

  const normalized = {};
  for (const [rawDomain, rawConfig] of Object.entries(rawDomainSettings)) {
    const domain = normalizeDomain(rawDomain);
    if (!domain || !isObject(rawConfig)) continue;

    const nextConfig = {};
    if (typeof rawConfig.cosmetic === 'boolean') {
      nextConfig.cosmetic = rawConfig.cosmetic;
    }
    if (typeof rawConfig.network === 'boolean') {
      nextConfig.network = rawConfig.network;
    }
    if (rawConfig.strictness === 'balanced' || rawConfig.strictness === 'strict') {
      nextConfig.strictness = rawConfig.strictness;
    }

    normalized[domain] = nextConfig;
  }

  return normalized;
}

function getDomainFromSender(sender) {
  const candidate = sender?.tab?.url || sender?.url;
  if (!candidate) return null;

  try {
    return normalizeDomain(new URL(candidate).hostname);
  } catch (_) {
    return null;
  }
}

async function logError(context, error) {
  try {
    const data = await chrome.storage.local.get('errorLog');
    const errorLog = sanitizeErrorLog(data.errorLog);
    errorLog.push({
      context,
      message: error?.message || String(error),
      timestamp: Date.now()
    });
    await chrome.storage.local.set({ errorLog: errorLog.slice(-50) });
  } catch (_) {
    // Ignore logging failures.
  }
}

async function migrateStorage() {
  const current = await chrome.storage.local.get(null);
  const updates = {};

  const enabled = typeof current.enabled === 'boolean' ? current.enabled : true;
  if (current.enabled !== enabled) {
    updates.enabled = enabled;
  }

  const networkBlockingEnabled =
    typeof current.networkBlockingEnabled === 'boolean'
      ? current.networkBlockingEnabled
      : enabled;
  if (current.networkBlockingEnabled !== networkBlockingEnabled) {
    updates.networkBlockingEnabled = networkBlockingEnabled;
  }

  const cosmeticFilteringEnabled =
    typeof current.cosmeticFilteringEnabled === 'boolean'
      ? current.cosmeticFilteringEnabled
      : enabled;
  if (current.cosmeticFilteringEnabled !== cosmeticFilteringEnabled) {
    updates.cosmeticFilteringEnabled = cosmeticFilteringEnabled;
  }

  const strictModeEnabled = typeof current.strictModeEnabled === 'boolean' ? current.strictModeEnabled : false;
  if (current.strictModeEnabled !== strictModeEnabled) {
    updates.strictModeEnabled = strictModeEnabled;
  }

  const whitelist = sanitizeWhitelist(current.whitelist);
  if (!deepEqual(current.whitelist, whitelist)) {
    updates.whitelist = whitelist;
  }

  const domainSettings = sanitizeDomainSettings(current.domainSettings);
  if (!deepEqual(current.domainSettings, domainSettings)) {
    updates.domainSettings = domainSettings;
  }

  const stats = sanitizeStats(current.stats);
  if (!deepEqual(current.stats, stats)) {
    updates.stats = stats;
  }

  const errorLog = sanitizeErrorLog(current.errorLog);
  if (!deepEqual(current.errorLog, errorLog)) {
    updates.errorLog = errorLog;
  }

  if (current.schemaVersion !== STORAGE_SCHEMA_VERSION) {
    updates.schemaVersion = STORAGE_SCHEMA_VERSION;
  }

  if (Object.keys(updates).length > 0) {
    await chrome.storage.local.set(updates);
  }
}

async function resetSessionBlockedCounter() {
  const data = await chrome.storage.local.get('stats');
  const stats = sanitizeStats(data.stats);
  stats.sessionBlocked = 0;
  stats.lastReset = new Date().toISOString();
  await chrome.storage.local.set({ stats });
}

async function applyPersistedRulesetState() {
  const data = await chrome.storage.local.get(['enabled', 'networkBlockingEnabled']);
  const enabled = data.enabled ?? true;
  const networkBlockingEnabled = data.networkBlockingEnabled ?? enabled;

  if (networkBlockingEnabled) {
    await chrome.declarativeNetRequest.updateEnabledRulesets({ enableRulesetIds: RULESET_IDS });
  } else {
    await chrome.declarativeNetRequest.updateEnabledRulesets({ disableRulesetIds: RULESET_IDS });
  }
}

async function updateWhitelistRules(whitelist) {
  const existing = await chrome.declarativeNetRequest.getDynamicRules();
  const removeRuleIds = existing
    .filter((rule) => rule.id >= WHITELIST_RULE_ID_START && rule.id <= WHITELIST_RULE_ID_END)
    .map((rule) => rule.id);

  const maxWhitelistEntries = WHITELIST_RULE_ID_END - WHITELIST_RULE_ID_START + 1;
  const effectiveWhitelist = whitelist.slice(0, maxWhitelistEntries);

  const addRules = effectiveWhitelist.map((domain, index) => ({
    id: WHITELIST_RULE_ID_START + index,
    priority: 5,
    action: { type: 'allowAllRequests' },
    condition: {
      requestDomains: [domain],
      resourceTypes: WHITELIST_FRAME_RESOURCE_TYPES
    }
  }));

  await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds, addRules });
}

async function syncWhitelistRulesWithStorage() {
  const data = await chrome.storage.local.get('whitelist');
  const whitelist = sanitizeWhitelist(data.whitelist);

  if (!deepEqual(data.whitelist, whitelist)) {
    await chrome.storage.local.set({ whitelist });
  }

  await updateWhitelistRules(whitelist);
}

async function setEnabled(enabled) {
  await chrome.storage.local.set({
    enabled,
    networkBlockingEnabled: enabled,
    cosmeticFilteringEnabled: enabled
  });

  if (enabled) {
    await chrome.declarativeNetRequest.updateEnabledRulesets({ enableRulesetIds: RULESET_IDS });
  } else {
    await chrome.declarativeNetRequest.updateEnabledRulesets({ disableRulesetIds: RULESET_IDS });
  }
}

async function getStateForSender(sender) {
  const data = await chrome.storage.local.get([
    'enabled',
    'networkBlockingEnabled',
    'cosmeticFilteringEnabled',
    'strictModeEnabled',
    'whitelist',
    'domainSettings'
  ]);

  const domainSettings = sanitizeDomainSettings(data.domainSettings);
  const currentDomain = getDomainFromSender(sender);

  return {
    enabled: data.enabled ?? true,
    networkBlockingEnabled: data.networkBlockingEnabled ?? (data.enabled ?? true),
    cosmeticFilteringEnabled: data.cosmeticFilteringEnabled ?? (data.enabled ?? true),
    strictModeEnabled: data.strictModeEnabled ?? false,
    whitelist: sanitizeWhitelist(data.whitelist),
    domainSettings,
    currentDomain,
    currentDomainSettings: currentDomain ? (domainSettings[currentDomain] || null) : null
  };
}

async function setSiteCosmetic(domain, enabled) {
  const data = await chrome.storage.local.get('domainSettings');
  const domainSettings = sanitizeDomainSettings(data.domainSettings);
  const current = isObject(domainSettings[domain]) ? domainSettings[domain] : {};
  current.cosmetic = enabled;
  domainSettings[domain] = current;
  await chrome.storage.local.set({ domainSettings });
  return { domain, settings: current };
}

chrome.runtime.onInstalled.addListener(async () => {
  try {
    await migrateStorage();
    await resetSessionBlockedCounter();
    await applyPersistedRulesetState();
    await syncWhitelistRulesWithStorage();
    await chrome.action.setBadgeBackgroundColor({ color: '#666' });
  } catch (err) {
    await logError('onInstalled', err);
  }
});

chrome.runtime.onStartup.addListener(async () => {
  try {
    await migrateStorage();
    await resetSessionBlockedCounter();
    await applyPersistedRulesetState();
    await syncWhitelistRulesWithStorage();
  } catch (err) {
    await logError('onStartup', err);
  }
});

chrome.declarativeNetRequest.onRuleMatchedDebug.addListener(async (info) => {
  try {
    const tabId = info?.request?.tabId;
    if (!Number.isInteger(tabId) || tabId < 0) return;

    const nextCount = (tabBlockedCounts.get(tabId) || 0) + 1;
    tabBlockedCounts.set(tabId, nextCount);
    await chrome.action.setBadgeText({ tabId, text: String(nextCount) });

    const data = await chrome.storage.local.get('stats');
    const stats = sanitizeStats(data.stats);
    stats.totalBlocked += 1;
    stats.sessionBlocked += 1;
    await chrome.storage.local.set({ stats });
  } catch (err) {
    await logError('onRuleMatchedDebug', err);
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  tabBlockedCounts.delete(tabId);
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === 'loading') {
    tabBlockedCounts.set(tabId, 0);
    chrome.action.setBadgeText({ tabId, text: '' }).catch(() => {});
  }
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const type = isObject(message) && typeof message.type === 'string' ? message.type : 'invalid';

  handleMessage(message, sender)
    .then(sendResponse)
    .catch(async (err) => {
      await logError(`onMessage:${type}`, err);
      sendResponse({ error: err?.message || 'Unknown error' });
    });

  return true;
});

async function handleMessage(message, sender) {
  if (!isObject(message) || typeof message.type !== 'string') {
    return { error: 'Invalid message payload' };
  }

  switch (message.type) {
    case 'getState': {
      return getStateForSender(sender);
    }

    case 'toggleEnabled': {
      const data = await chrome.storage.local.get('enabled');
      const newEnabledState = !(data.enabled ?? true);
      await setEnabled(newEnabledState);
      return {
        enabled: newEnabledState,
        networkBlockingEnabled: newEnabledState,
        cosmeticFilteringEnabled: newEnabledState
      };
    }

    case 'setCosmeticFiltering': {
      if (typeof message.enabled !== 'boolean') {
        return { error: 'setCosmeticFiltering requires boolean "enabled"' };
      }
      await chrome.storage.local.set({ cosmeticFilteringEnabled: message.enabled });
      return { cosmeticFilteringEnabled: message.enabled };
    }

    case 'setStrictMode': {
      if (typeof message.enabled !== 'boolean') {
        return { error: 'setStrictMode requires boolean "enabled"' };
      }
      await chrome.storage.local.set({ strictModeEnabled: message.enabled });
      return { strictModeEnabled: message.enabled };
    }

    case 'setSiteCosmetic': {
      if (typeof message.enabled !== 'boolean') {
        return { error: 'setSiteCosmetic requires boolean "enabled"' };
      }

      const domain = normalizeDomain(message.domain) || getDomainFromSender(sender);
      if (!domain) {
        return { error: 'setSiteCosmetic requires a valid domain' };
      }

      return setSiteCosmetic(domain, message.enabled);
    }

    case 'addToWhitelist': {
      const domain = normalizeDomain(message.domain) || getDomainFromSender(sender);
      if (!domain) {
        return { error: 'addToWhitelist requires a valid domain' };
      }

      const data = await chrome.storage.local.get('whitelist');
      const whitelist = sanitizeWhitelist(data.whitelist);
      if (!whitelist.includes(domain)) {
        whitelist.push(domain);
        await chrome.storage.local.set({ whitelist });
        await updateWhitelistRules(whitelist);
      }

      return { whitelist };
    }

    case 'removeFromWhitelist': {
      const domain = normalizeDomain(message.domain) || getDomainFromSender(sender);
      if (!domain) {
        return { error: 'removeFromWhitelist requires a valid domain' };
      }

      const data = await chrome.storage.local.get('whitelist');
      const whitelist = sanitizeWhitelist(data.whitelist).filter((item) => item !== domain);
      await chrome.storage.local.set({ whitelist });
      await updateWhitelistRules(whitelist);
      return { whitelist };
    }

    case 'getStats': {
      const data = await chrome.storage.local.get('stats');
      const stats = sanitizeStats(data.stats);
      const tabId = sender?.tab?.id;
      stats.tabBlocked = Number.isInteger(tabId) ? (tabBlockedCounts.get(tabId) || 0) : 0;
      return stats;
    }

    case 'getErrorLog': {
      const data = await chrome.storage.local.get('errorLog');
      return { errorLog: sanitizeErrorLog(data.errorLog) };
    }

    case 'clearErrorLog': {
      await chrome.storage.local.set({ errorLog: [] });
      return { success: true };
    }

    default:
      return { error: 'Unknown message type' };
  }
}
