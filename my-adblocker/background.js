const RULESET_IDS = ['ads', 'tracking', 'annoyances'];
const STORAGE_SCHEMA_VERSION = 1;
const WHITELIST_RULE_ID_START = 5000;
const WHITELIST_RULE_ID_END = 5999;
const MAX_WHITELIST_ENTRIES = WHITELIST_RULE_ID_END - WHITELIST_RULE_ID_START + 1;
const MAX_DOMAIN_SETTINGS_ENTRIES = 500;
const MAX_ERROR_LOG_ENTRIES = 50;
const MAX_ERROR_CONTEXT_LENGTH = 80;
const MAX_ERROR_MESSAGE_LENGTH = 500;
const MAX_DOMAIN_LENGTH = 253;
const tabBlockedCounts = new Map();

const WHITELIST_FRAME_RESOURCE_TYPES = ['main_frame', 'sub_frame'];

function isObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function deepEqual(a, b) {
  return JSON.stringify(a) === JSON.stringify(b);
}

function nowIsoString() {
  return new Date().toISOString();
}

function clampNonNegativeInt(value, fallback = 0) {
  if (!Number.isFinite(value)) return fallback;
  return Math.max(0, Math.trunc(value));
}

function sanitizeText(value, fallback, maxLength) {
  if (typeof value !== 'string') return fallback;
  const trimmed = value.trim();
  if (!trimmed) return fallback;
  return trimmed.slice(0, maxLength);
}

function createDefaultStats() {
  const now = nowIsoString();
  return {
    releaseSafe: {
      settingsMutationCount: 0,
      whitelistEntryCount: 0,
      domainOverrideCount: 0,
      lastConfigChange: now
    },
    debugApprox: {
      totalBlocked: 0,
      sessionBlocked: 0,
      lastReset: now,
      source: 'declarativeNetRequest.onRuleMatchedDebug',
      isApproximate: true
    }
  };
}

function sanitizeStats(rawStats) {
  const stats = isObject(rawStats) ? rawStats : {};
  const defaults = createDefaultStats();
  const releaseSafe = isObject(stats.releaseSafe) ? stats.releaseSafe : {};
  const debugApprox = isObject(stats.debugApprox) ? stats.debugApprox : {};

  const legacyTotalBlocked = Number.isFinite(stats.totalBlocked)
    ? clampNonNegativeInt(stats.totalBlocked, 0)
    : defaults.debugApprox.totalBlocked;
  const legacySessionBlocked = Number.isFinite(stats.sessionBlocked)
    ? clampNonNegativeInt(stats.sessionBlocked, 0)
    : defaults.debugApprox.sessionBlocked;
  const legacyLastReset =
    typeof stats.lastReset === 'string' ? stats.lastReset : defaults.debugApprox.lastReset;

  return {
    releaseSafe: {
      settingsMutationCount: clampNonNegativeInt(
        releaseSafe.settingsMutationCount,
        defaults.releaseSafe.settingsMutationCount
      ),
      whitelistEntryCount: clampNonNegativeInt(
        releaseSafe.whitelistEntryCount,
        defaults.releaseSafe.whitelistEntryCount
      ),
      domainOverrideCount: clampNonNegativeInt(
        releaseSafe.domainOverrideCount,
        defaults.releaseSafe.domainOverrideCount
      ),
      lastConfigChange:
        typeof releaseSafe.lastConfigChange === 'string'
          ? releaseSafe.lastConfigChange
          : defaults.releaseSafe.lastConfigChange
    },
    debugApprox: {
      totalBlocked: clampNonNegativeInt(debugApprox.totalBlocked, legacyTotalBlocked),
      sessionBlocked: clampNonNegativeInt(debugApprox.sessionBlocked, legacySessionBlocked),
      lastReset: typeof debugApprox.lastReset === 'string' ? debugApprox.lastReset : legacyLastReset,
      source:
        typeof debugApprox.source === 'string' ? debugApprox.source : defaults.debugApprox.source,
      isApproximate: true
    }
  };
}

function sanitizeErrorLog(rawErrorLog) {
  if (!Array.isArray(rawErrorLog)) return [];

  return rawErrorLog
    .slice(-MAX_ERROR_LOG_ENTRIES)
    .map((entry) => {
      if (!isObject(entry)) return null;
      return {
        context: sanitizeText(entry.context, 'unknown', MAX_ERROR_CONTEXT_LENGTH),
        message: sanitizeText(entry.message, 'Unknown error', MAX_ERROR_MESSAGE_LENGTH),
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
  if (!host || host.length > MAX_DOMAIN_LENGTH) {
    return null;
  }

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

    if (normalized.length >= MAX_WHITELIST_ENTRIES) {
      break;
    }
  }

  return normalized;
}

function sanitizeDomainSettings(rawDomainSettings) {
  if (!isObject(rawDomainSettings)) return {};

  const normalized = {};
  const seen = new Set();

  for (const [rawDomain, rawConfig] of Object.entries(rawDomainSettings)) {
    if (Object.keys(normalized).length >= MAX_DOMAIN_SETTINGS_ENTRIES) {
      break;
    }

    const domain = normalizeDomain(rawDomain);
    if (!domain || !isObject(rawConfig) || seen.has(domain)) continue;
    seen.add(domain);

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
    if (Object.keys(nextConfig).length === 0) {
      continue;
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

async function refreshReleaseSafeStats(options = {}) {
  const incrementMutation = options.incrementMutation === true;
  const data = await chrome.storage.local.get(['stats', 'whitelist', 'domainSettings']);
  const stats = sanitizeStats(data.stats);
  const whitelist = sanitizeWhitelist(data.whitelist);
  const domainSettings = sanitizeDomainSettings(data.domainSettings);

  const nextStats = {
    releaseSafe: {
      settingsMutationCount:
        stats.releaseSafe.settingsMutationCount + (incrementMutation ? 1 : 0),
      whitelistEntryCount: whitelist.length,
      domainOverrideCount: Object.keys(domainSettings).length,
      lastConfigChange: incrementMutation ? nowIsoString() : stats.releaseSafe.lastConfigChange
    },
    debugApprox: stats.debugApprox
  };

  const updates = {};
  if (!deepEqual(data.whitelist, whitelist)) {
    updates.whitelist = whitelist;
  }
  if (!deepEqual(data.domainSettings, domainSettings)) {
    updates.domainSettings = domainSettings;
  }
  if (!deepEqual(data.stats, nextStats)) {
    updates.stats = nextStats;
  }

  if (Object.keys(updates).length > 0) {
    await chrome.storage.local.set(updates);
  }

  return nextStats;
}

async function logError(context, error) {
  try {
    const data = await chrome.storage.local.get('errorLog');
    const errorLog = sanitizeErrorLog(data.errorLog);
    errorLog.push({
      context: sanitizeText(context, 'unknown', MAX_ERROR_CONTEXT_LENGTH),
      message: sanitizeText(error?.message || String(error), 'Unknown error', MAX_ERROR_MESSAGE_LENGTH),
      timestamp: Date.now()
    });
    await chrome.storage.local.set({ errorLog: errorLog.slice(-MAX_ERROR_LOG_ENTRIES) });
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
    typeof current.networkBlockingEnabled === 'boolean' ? current.networkBlockingEnabled : enabled;
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

  const strictModeEnabled =
    typeof current.strictModeEnabled === 'boolean' ? current.strictModeEnabled : false;
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
  stats.debugApprox.sessionBlocked = 0;
  stats.debugApprox.lastReset = nowIsoString();
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

  const effectiveWhitelist = whitelist.slice(0, MAX_WHITELIST_ENTRIES);
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

  await refreshReleaseSafeStats({ incrementMutation: true });
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
    currentDomainSettings: currentDomain ? domainSettings[currentDomain] || null : null
  };
}

async function setSiteCosmetic(domain, enabled) {
  const data = await chrome.storage.local.get('domainSettings');
  const domainSettings = sanitizeDomainSettings(data.domainSettings);
  const hasExistingDomain = isObject(domainSettings[domain]);
  if (!hasExistingDomain && Object.keys(domainSettings).length >= MAX_DOMAIN_SETTINGS_ENTRIES) {
    return {
      error: `setSiteCosmetic rejected: domainSettings limit (${MAX_DOMAIN_SETTINGS_ENTRIES}) reached`
    };
  }

  const current = hasExistingDomain ? domainSettings[domain] : {};
  if (current.cosmetic === enabled) {
    return { domain, settings: current };
  }

  current.cosmetic = enabled;
  domainSettings[domain] = current;
  await chrome.storage.local.set({ domainSettings });
  await refreshReleaseSafeStats({ incrementMutation: true });
  return { domain, settings: current };
}

chrome.runtime.onInstalled.addListener(async () => {
  try {
    await migrateStorage();
    await resetSessionBlockedCounter();
    await applyPersistedRulesetState();
    await syncWhitelistRulesWithStorage();
    await refreshReleaseSafeStats();
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
    await refreshReleaseSafeStats();
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
    stats.debugApprox.totalBlocked += 1;
    stats.debugApprox.sessionBlocked += 1;
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

      const data = await chrome.storage.local.get('cosmeticFilteringEnabled');
      const currentValue = data.cosmeticFilteringEnabled ?? true;
      if (currentValue !== message.enabled) {
        await chrome.storage.local.set({ cosmeticFilteringEnabled: message.enabled });
        await refreshReleaseSafeStats({ incrementMutation: true });
      }

      return { cosmeticFilteringEnabled: message.enabled };
    }

    case 'setStrictMode': {
      if (typeof message.enabled !== 'boolean') {
        return { error: 'setStrictMode requires boolean "enabled"' };
      }

      const data = await chrome.storage.local.get('strictModeEnabled');
      const currentValue = data.strictModeEnabled ?? false;
      if (currentValue !== message.enabled) {
        await chrome.storage.local.set({ strictModeEnabled: message.enabled });
        await refreshReleaseSafeStats({ incrementMutation: true });
      }

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
      if (whitelist.includes(domain)) {
        return { whitelist };
      }

      if (whitelist.length >= MAX_WHITELIST_ENTRIES) {
        return {
          error: `addToWhitelist rejected: whitelist limit (${MAX_WHITELIST_ENTRIES}) reached`
        };
      }

      whitelist.push(domain);
      await chrome.storage.local.set({ whitelist });
      await updateWhitelistRules(whitelist);
      await refreshReleaseSafeStats({ incrementMutation: true });

      return { whitelist };
    }

    case 'removeFromWhitelist': {
      const domain = normalizeDomain(message.domain) || getDomainFromSender(sender);
      if (!domain) {
        return { error: 'removeFromWhitelist requires a valid domain' };
      }

      const data = await chrome.storage.local.get('whitelist');
      const currentWhitelist = sanitizeWhitelist(data.whitelist);
      const whitelist = currentWhitelist.filter((item) => item !== domain);
      if (whitelist.length === currentWhitelist.length) {
        return { whitelist };
      }

      await chrome.storage.local.set({ whitelist });
      await updateWhitelistRules(whitelist);
      await refreshReleaseSafeStats({ incrementMutation: true });

      return { whitelist };
    }

    case 'getStats': {
      const data = await chrome.storage.local.get('stats');
      const stats = sanitizeStats(data.stats);
      const tabId = sender?.tab?.id;
      const tabBlocked = Number.isInteger(tabId) ? tabBlockedCounts.get(tabId) || 0 : 0;

      return {
        releaseSafe: stats.releaseSafe,
        debugApprox: {
          ...stats.debugApprox,
          tabBlocked
        },
        totalBlocked: stats.debugApprox.totalBlocked,
        sessionBlocked: stats.debugApprox.sessionBlocked,
        tabBlocked,
        isApproximate: true
      };
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
