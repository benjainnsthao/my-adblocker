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
const MAX_REPORT_URL_LENGTH = 2048;
const MAX_REPORT_TITLE_LENGTH = 160;
const MAX_REPORT_NOTE_LENGTH = 500;
const MAX_SITE_ISSUE_REPORT_ENTRIES = 100;
const QUICK_PAUSE_DURATION_MS = 30 * 1000;
const QUICK_PAUSE_ALARM_NAME = 'quickPauseResume';
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

function sanitizeReportUrl(rawUrl) {
  if (typeof rawUrl !== 'string') return null;
  const value = rawUrl.trim();
  if (!value) return null;

  try {
    const parsed = new URL(value);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return null;
    }
    return parsed.toString().slice(0, MAX_REPORT_URL_LENGTH);
  } catch (_) {
    return null;
  }
}

function sanitizeSiteIssueReports(rawReports) {
  if (!Array.isArray(rawReports)) return [];

  return rawReports
    .slice(-MAX_SITE_ISSUE_REPORT_ENTRIES)
    .map((entry) => {
      if (!isObject(entry)) return null;

      const id = sanitizeText(entry.id, '', 64);
      const createdAt =
        typeof entry.createdAt === 'string' ? entry.createdAt : nowIsoString();
      const domain = normalizeDomain(entry.domain);
      const url = sanitizeReportUrl(entry.url);
      const title = sanitizeText(entry.title, '', MAX_REPORT_TITLE_LENGTH);
      const note = sanitizeText(entry.note, '', MAX_REPORT_NOTE_LENGTH);

      const state = isObject(entry.state) ? entry.state : {};
      const stats = isObject(entry.stats) ? entry.stats : {};

      if (!id || !domain || !url) return null;

      return {
        id,
        createdAt,
        domain,
        url,
        title,
        note,
        state: {
          enabled: state.enabled === true,
          networkBlockingEnabled: state.networkBlockingEnabled === true,
          cosmeticFilteringEnabled: state.cosmeticFilteringEnabled === true,
          strictModeEnabled: state.strictModeEnabled === true,
          isWhitelisted: state.isWhitelisted === true
        },
        stats: {
          tabBlocked: clampNonNegativeInt(stats.tabBlocked, 0),
          sessionBlocked: clampNonNegativeInt(stats.sessionBlocked, 0),
          totalBlocked: clampNonNegativeInt(stats.totalBlocked, 0),
          isApproximate: true
        }
      };
    })
    .filter(Boolean);
}

function sanitizeQuickPause(rawQuickPause) {
  if (!isObject(rawQuickPause)) return null;

  const pausedUntil = Number.isFinite(rawQuickPause.pausedUntil)
    ? Math.trunc(rawQuickPause.pausedUntil)
    : 0;
  if (pausedUntil <= 0) return null;

  return {
    pausedUntil,
    resumeEnabled: rawQuickPause.resumeEnabled !== false,
    resumeNetworkBlockingEnabled: rawQuickPause.resumeNetworkBlockingEnabled !== false,
    resumeCosmeticFilteringEnabled: rawQuickPause.resumeCosmeticFilteringEnabled !== false
  };
}

function toQuickPauseStatus(rawQuickPause) {
  const quickPause = sanitizeQuickPause(rawQuickPause);
  if (!quickPause) {
    return {
      active: false,
      pausedUntil: null,
      remainingMs: 0
    };
  }

  const remainingMs = Math.max(0, quickPause.pausedUntil - Date.now());
  return {
    active: remainingMs > 0,
    pausedUntil: quickPause.pausedUntil,
    remainingMs
  };
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

function getDomainFromUrl(rawUrl) {
  if (typeof rawUrl !== 'string') return null;
  try {
    return normalizeDomain(new URL(rawUrl).hostname);
  } catch (_) {
    return null;
  }
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

  return getDomainFromUrl(candidate);
}

function resolveTabId(rawTabId, sender) {
  if (Number.isInteger(rawTabId) && rawTabId >= 0) {
    return rawTabId;
  }
  if (Number.isInteger(sender?.tab?.id) && sender.tab.id >= 0) {
    return sender.tab.id;
  }
  return null;
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

  const quickPause = sanitizeQuickPause(current.quickPause);
  if (!deepEqual(current.quickPause, quickPause)) {
    updates.quickPause = quickPause;
  }

  const siteIssueReports = sanitizeSiteIssueReports(current.siteIssueReports);
  if (!deepEqual(current.siteIssueReports, siteIssueReports)) {
    updates.siteIssueReports = siteIssueReports;
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

  await syncNetworkRulesetState(networkBlockingEnabled);
}

async function syncNetworkRulesetState(networkBlockingEnabled) {
  if (networkBlockingEnabled) {
    await chrome.declarativeNetRequest.updateEnabledRulesets({ enableRulesetIds: RULESET_IDS });
    return;
  }

  await chrome.declarativeNetRequest.updateEnabledRulesets({ disableRulesetIds: RULESET_IDS });
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

async function clearQuickPauseState() {
  await chrome.alarms.clear(QUICK_PAUSE_ALARM_NAME);
  await chrome.storage.local.set({ quickPause: null });
}

async function setEnabled(enabled, options = {}) {
  const incrementMutation = options.incrementMutation !== false;
  const cancelQuickPause = options.cancelQuickPause !== false;

  if (cancelQuickPause) {
    await clearQuickPauseState();
  }

  await chrome.storage.local.set({
    enabled,
    networkBlockingEnabled: enabled,
    cosmeticFilteringEnabled: enabled
  });

  await syncNetworkRulesetState(enabled);

  if (incrementMutation) {
    await refreshReleaseSafeStats({ incrementMutation: true });
  }
}

async function resumeQuickPause(options = {}) {
  const force = options.force === true;
  const incrementMutation = options.incrementMutation !== false;
  const data = await chrome.storage.local.get('quickPause');
  const quickPause = sanitizeQuickPause(data.quickPause);

  if (!quickPause) {
    await chrome.alarms.clear(QUICK_PAUSE_ALARM_NAME);
    if (data.quickPause !== null) {
      await chrome.storage.local.set({ quickPause: null });
    }
    return { resumed: false, ...toQuickPauseStatus(null) };
  }

  if (!force && quickPause.pausedUntil > Date.now()) {
    await chrome.alarms.create(QUICK_PAUSE_ALARM_NAME, { when: quickPause.pausedUntil });
    return { resumed: false, ...toQuickPauseStatus(quickPause) };
  }

  await chrome.storage.local.set({
    quickPause: null,
    enabled: quickPause.resumeEnabled,
    networkBlockingEnabled: quickPause.resumeNetworkBlockingEnabled,
    cosmeticFilteringEnabled: quickPause.resumeCosmeticFilteringEnabled
  });
  await chrome.alarms.clear(QUICK_PAUSE_ALARM_NAME);
  await syncNetworkRulesetState(quickPause.resumeNetworkBlockingEnabled);
  if (incrementMutation) {
    await refreshReleaseSafeStats({ incrementMutation: true });
  }

  return {
    resumed: true,
    ...toQuickPauseStatus(null),
    enabled: quickPause.resumeEnabled,
    networkBlockingEnabled: quickPause.resumeNetworkBlockingEnabled,
    cosmeticFilteringEnabled: quickPause.resumeCosmeticFilteringEnabled
  };
}

async function syncQuickPauseLifecycle() {
  const data = await chrome.storage.local.get('quickPause');
  const quickPause = sanitizeQuickPause(data.quickPause);

  if (!quickPause) {
    await chrome.alarms.clear(QUICK_PAUSE_ALARM_NAME);
    if (data.quickPause !== null) {
      await chrome.storage.local.set({ quickPause: null });
    }
    return toQuickPauseStatus(null);
  }

  if (quickPause.pausedUntil <= Date.now()) {
    const resumeResult = await resumeQuickPause({ force: true });
    return {
      active: false,
      pausedUntil: resumeResult.pausedUntil,
      remainingMs: resumeResult.remainingMs
    };
  }

  await chrome.alarms.create(QUICK_PAUSE_ALARM_NAME, { when: quickPause.pausedUntil });
  return toQuickPauseStatus(quickPause);
}

async function getQuickPauseStatus() {
  const status = await syncQuickPauseLifecycle();
  return status;
}

async function startQuickPause() {
  const existingStatus = await syncQuickPauseLifecycle();
  if (existingStatus.active) {
    return existingStatus;
  }

  const data = await chrome.storage.local.get([
    'enabled',
    'networkBlockingEnabled',
    'cosmeticFilteringEnabled'
  ]);
  const enabled = data.enabled ?? true;
  const networkBlockingEnabled = data.networkBlockingEnabled ?? enabled;
  const cosmeticFilteringEnabled = data.cosmeticFilteringEnabled ?? enabled;

  if (!enabled && !networkBlockingEnabled && !cosmeticFilteringEnabled) {
    return { error: 'Quick pause requires blocker to be enabled' };
  }

  const quickPause = {
    pausedUntil: Date.now() + QUICK_PAUSE_DURATION_MS,
    resumeEnabled: enabled,
    resumeNetworkBlockingEnabled: networkBlockingEnabled,
    resumeCosmeticFilteringEnabled: cosmeticFilteringEnabled
  };

  await chrome.storage.local.set({
    quickPause,
    enabled: false,
    networkBlockingEnabled: false,
    cosmeticFilteringEnabled: false
  });
  await syncNetworkRulesetState(false);
  await chrome.alarms.create(QUICK_PAUSE_ALARM_NAME, { when: quickPause.pausedUntil });
  await refreshReleaseSafeStats({ incrementMutation: true });

  return toQuickPauseStatus(quickPause);
}

async function getStateForDomain(currentDomain) {
  const data = await chrome.storage.local.get([
    'enabled',
    'networkBlockingEnabled',
    'cosmeticFilteringEnabled',
    'strictModeEnabled',
    'whitelist',
    'domainSettings',
    'quickPause'
  ]);

  const domainSettings = sanitizeDomainSettings(data.domainSettings);
  const whitelist = sanitizeWhitelist(data.whitelist);
  const normalizedDomain = normalizeDomain(currentDomain);
  const quickPause = toQuickPauseStatus(data.quickPause);

  return {
    enabled: data.enabled ?? true,
    networkBlockingEnabled: data.networkBlockingEnabled ?? (data.enabled ?? true),
    cosmeticFilteringEnabled: data.cosmeticFilteringEnabled ?? (data.enabled ?? true),
    strictModeEnabled: data.strictModeEnabled ?? false,
    whitelist,
    domainSettings,
    currentDomain: normalizedDomain,
    currentDomainSettings: normalizedDomain ? domainSettings[normalizedDomain] || null : null,
    isCurrentDomainWhitelisted: normalizedDomain ? whitelist.includes(normalizedDomain) : false,
    quickPause
  };
}

async function getStateForSender(sender) {
  return getStateForDomain(getDomainFromSender(sender));
}

async function getStatsForTab(tabId) {
  const data = await chrome.storage.local.get('stats');
  const stats = sanitizeStats(data.stats);
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

function createSiteIssueReportId() {
  const randomSuffix = Math.random().toString(36).slice(2, 8);
  return `${Date.now()}-${randomSuffix}`;
}

async function createSiteIssueReport(input, sender) {
  const payload = isObject(input) ? input : {};
  const domain =
    normalizeDomain(payload.domain) ||
    getDomainFromUrl(payload.url) ||
    getDomainFromSender(sender);
  if (!domain) {
    return { error: 'reportSiteIssue requires a valid domain' };
  }

  const url = sanitizeReportUrl(payload.url) || sanitizeReportUrl(sender?.tab?.url);
  if (!url) {
    return { error: 'reportSiteIssue requires a valid http(s) URL' };
  }

  const titleSource =
    typeof payload.title === 'string' ? payload.title : sender?.tab?.title;
  const noteSource = typeof payload.note === 'string' ? payload.note : '';
  const tabId = resolveTabId(payload.tabId, sender);

  const [state, statsResult] = await Promise.all([
    getStateForDomain(domain),
    getStatsForTab(tabId)
  ]);

  const report = {
    id: createSiteIssueReportId(),
    createdAt: nowIsoString(),
    domain,
    url,
    title: sanitizeText(titleSource, '', MAX_REPORT_TITLE_LENGTH),
    note: sanitizeText(noteSource, '', MAX_REPORT_NOTE_LENGTH),
    state: {
      enabled: state.enabled,
      networkBlockingEnabled: state.networkBlockingEnabled,
      cosmeticFilteringEnabled: state.cosmeticFilteringEnabled,
      strictModeEnabled: state.strictModeEnabled,
      isWhitelisted: state.isCurrentDomainWhitelisted
    },
    stats: {
      tabBlocked: statsResult.tabBlocked,
      sessionBlocked: statsResult.sessionBlocked,
      totalBlocked: statsResult.totalBlocked,
      isApproximate: true
    }
  };

  const data = await chrome.storage.local.get('siteIssueReports');
  const reports = sanitizeSiteIssueReports(data.siteIssueReports);
  reports.push(report);
  const nextReports = reports.slice(-MAX_SITE_ISSUE_REPORT_ENTRIES);
  await chrome.storage.local.set({ siteIssueReports: nextReports });

  return {
    success: true,
    reportId: report.id,
    storedCount: nextReports.length
  };
}

chrome.runtime.onInstalled.addListener(async () => {
  try {
    await migrateStorage();
    await resetSessionBlockedCounter();
    await applyPersistedRulesetState();
    await syncWhitelistRulesWithStorage();
    await syncQuickPauseLifecycle();
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
    await syncQuickPauseLifecycle();
    await refreshReleaseSafeStats();
  } catch (err) {
    await logError('onStartup', err);
  }
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (!alarm || alarm.name !== QUICK_PAUSE_ALARM_NAME) return;
  resumeQuickPause({ force: true }).catch((err) => {
    logError('quickPause:alarm', err);
  });
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

  if (message.type !== 'startQuickPause') {
    await syncQuickPauseLifecycle();
  }

  switch (message.type) {
    case 'getState': {
      const domain = normalizeDomain(message.domain) || getDomainFromSender(sender);
      return getStateForDomain(domain);
    }

    case 'getPopupState': {
      const domain = normalizeDomain(message.domain) || getDomainFromSender(sender);
      const tabId = resolveTabId(message.tabId, sender);
      const [state, stats] = await Promise.all([
        getStateForDomain(domain),
        getStatsForTab(tabId)
      ]);
      return {
        enabled: state.enabled,
        networkBlockingEnabled: state.networkBlockingEnabled,
        cosmeticFilteringEnabled: state.cosmeticFilteringEnabled,
        strictModeEnabled: state.strictModeEnabled,
        currentDomain: state.currentDomain,
        currentDomainSettings: state.currentDomainSettings,
        isCurrentDomainWhitelisted: state.isCurrentDomainWhitelisted,
        quickPause: state.quickPause,
        stats
      };
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

    case 'setEnabled': {
      if (typeof message.enabled !== 'boolean') {
        return { error: 'setEnabled requires boolean "enabled"' };
      }

      await setEnabled(message.enabled, {
        incrementMutation: true,
        cancelQuickPause: true
      });
      return {
        enabled: message.enabled,
        networkBlockingEnabled: message.enabled,
        cosmeticFilteringEnabled: message.enabled
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

    case 'startQuickPause': {
      return startQuickPause();
    }

    case 'resumeQuickPause': {
      return resumeQuickPause({ force: true });
    }

    case 'getQuickPauseStatus': {
      return getQuickPauseStatus();
    }

    case 'reportSiteIssue': {
      return createSiteIssueReport(message, sender);
    }

    case 'getStats': {
      const tabId = resolveTabId(message.tabId, sender);
      return getStatsForTab(tabId);
    }

    case 'getSiteIssueReports': {
      const data = await chrome.storage.local.get('siteIssueReports');
      return { siteIssueReports: sanitizeSiteIssueReports(data.siteIssueReports) };
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
