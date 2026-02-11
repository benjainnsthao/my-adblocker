const CORE_RULESET_IDS = ['ads', 'tracking', 'annoyances'];
const SURROGATE_RULESET_ID = 'surrogates';
const ALL_RULESET_IDS = [...CORE_RULESET_IDS, SURROGATE_RULESET_ID];
const STORAGE_SCHEMA_VERSION = 2;
const WHITELIST_RULE_ID_START = 5000;
const WHITELIST_RULE_ID_END = 5999;
const MAX_WHITELIST_ENTRIES = WHITELIST_RULE_ID_END - WHITELIST_RULE_ID_START + 1;
const MAX_DOMAIN_SETTINGS_ENTRIES = 500;
const MAX_SITE_FIX_ENTRIES = 200;
const MAX_ERROR_LOG_ENTRIES = 50;
const MAX_ERROR_CONTEXT_LENGTH = 80;
const MAX_ERROR_MESSAGE_LENGTH = 500;
const MAX_DOMAIN_LENGTH = 253;
const MAX_REPORT_URL_LENGTH = 2048;
const MAX_REPORT_TITLE_LENGTH = 160;
const MAX_REPORT_NOTE_LENGTH = 500;
const MAX_SITE_ISSUE_REPORT_ENTRIES = 100;
const MAX_BREAKAGE_REPORT_ENTRIES = 100;
const MAX_BREAKAGE_CASE_ID_LENGTH = 32;
const MAX_ERROR_VALUE_PREVIEW_LENGTH = 120;
const QUICK_PAUSE_DURATION_MS = 30 * 1000;
const QUICK_PAUSE_ALARM_NAME = 'quickPauseResume';
const tabBlockedCounts = new Map();

const WHITELIST_FRAME_RESOURCE_TYPES = ['main_frame', 'sub_frame'];
const WHITELIST_RULE_PRIORITY = 6;
const SURROGATE_MODE_DEFAULT = 'safe';
const SURROGATE_MODE_VALUES = ['off', 'safe', 'strict'];
const SITE_FIX_PATCH_KEYS = ['surrogates', 'antiDetection', 'strict'];
const BREAKAGE_MITIGATION_VALUES = ['surrogate', 'exception', 'no-fix', 'needs-investigation'];
const DEFAULT_SITE_FIXES = Object.freeze({
  'forbes.com': Object.freeze({
    surrogates: true,
    antiDetection: false,
    strict: false
  }),
  'sourceforge.net': Object.freeze({
    surrogates: true,
    antiDetection: false,
    strict: false
  })
});

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

function formatInvalidValue(value) {
  let candidate = '';

  if (typeof value === 'string') {
    candidate = value;
  } else {
    try {
      candidate = JSON.stringify(value);
    } catch (_) {
      candidate = String(value);
    }
  }

  return sanitizeText(candidate, 'invalid', MAX_ERROR_VALUE_PREVIEW_LENGTH);
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

function sanitizeBreakageCaseId(rawCaseId) {
  const caseId = sanitizeText(rawCaseId, '', MAX_BREAKAGE_CASE_ID_LENGTH);
  if (!caseId) return null;

  const normalized = caseId.toUpperCase();
  return /^[A-Z]{2,10}-[0-9]{1,6}$/.test(normalized) ? normalized : null;
}

function normalizeBreakageMitigation(rawMitigation) {
  if (typeof rawMitigation !== 'string') return null;
  const normalized = rawMitigation.trim().toLowerCase();
  return BREAKAGE_MITIGATION_VALUES.includes(normalized) ? normalized : null;
}

function sanitizeBreakageMitigation(rawMitigation) {
  return normalizeBreakageMitigation(rawMitigation) || 'needs-investigation';
}

function sanitizeBreakageReports(rawReports) {
  if (!Array.isArray(rawReports)) return [];

  return rawReports
    .slice(-MAX_BREAKAGE_REPORT_ENTRIES)
    .map((entry) => {
      if (!isObject(entry)) return null;

      const caseId = sanitizeBreakageCaseId(entry.caseId);
      const domain = normalizeDomain(entry.domain);
      const detectorUrl = sanitizeReportUrl(entry.detectorUrl);
      const timestamp = Number.isFinite(entry.timestamp)
        ? Math.max(0, Math.trunc(entry.timestamp))
        : Date.now();

      if (!caseId || !domain || !detectorUrl) return null;

      return {
        caseId,
        domain,
        detectorUrl,
        mitigation: sanitizeBreakageMitigation(entry.mitigation),
        timestamp
      };
    })
    .filter(Boolean);
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

function sanitizeSurrogateMode(rawMode) {
  if (typeof rawMode !== 'string') return SURROGATE_MODE_DEFAULT;
  const normalized = rawMode.trim().toLowerCase();
  return SURROGATE_MODE_VALUES.includes(normalized) ? normalized : SURROGATE_MODE_DEFAULT;
}

function sanitizeSiteFixes(rawSiteFixes) {
  if (!isObject(rawSiteFixes)) return {};

  const normalized = {};
  const seen = new Set();

  for (const [rawDomain, rawConfig] of Object.entries(rawSiteFixes)) {
    if (Object.keys(normalized).length >= MAX_SITE_FIX_ENTRIES) {
      break;
    }

    const domain = normalizeDomain(rawDomain);
    if (!domain || !isObject(rawConfig) || seen.has(domain)) continue;
    seen.add(domain);

    const nextConfig = {};
    if (typeof rawConfig.surrogates === 'boolean') {
      nextConfig.surrogates = rawConfig.surrogates;
    }
    if (typeof rawConfig.antiDetection === 'boolean') {
      nextConfig.antiDetection = rawConfig.antiDetection;
    }
    if (typeof rawConfig.strict === 'boolean') {
      nextConfig.strict = rawConfig.strict;
    }
    if (Object.keys(nextConfig).length === 0) {
      continue;
    }

    normalized[domain] = nextConfig;
  }

  return normalized;
}

function getDomainHierarchy(domain) {
  if (!domain) return [];

  const hierarchy = [];
  let current = domain;
  while (current) {
    hierarchy.push(current);
    const dotIndex = current.indexOf('.');
    if (dotIndex === -1) break;
    current = current.slice(dotIndex + 1);
  }

  return hierarchy;
}

function getDomainValueForHost(domainMap, domain) {
  if (!isObject(domainMap) || !domain) return null;

  for (const candidate of getDomainHierarchy(domain)) {
    if (Object.prototype.hasOwnProperty.call(domainMap, candidate)) {
      return domainMap[candidate];
    }
  }

  return null;
}

function isDomainWhitelisted(domain, whitelist) {
  if (!domain || !Array.isArray(whitelist)) return false;
  const normalizedWhitelist = new Set(whitelist);
  for (const candidate of getDomainHierarchy(domain)) {
    if (normalizedWhitelist.has(candidate)) {
      return true;
    }
  }
  return false;
}

function getEffectiveSurrogatesEnabled(surrogatesEnabled, surrogateMode) {
  return surrogatesEnabled && sanitizeSurrogateMode(surrogateMode) !== 'off';
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

function getSenderUrl(sender) {
  const candidate = sender?.tab?.url || sender?.url;
  return typeof candidate === 'string' ? candidate : null;
}

function getUrlIssue(rawUrl) {
  if (typeof rawUrl !== 'string') return null;
  const value = rawUrl.trim();
  if (!value) return null;

  try {
    const parsed = new URL(value);
    if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
      return null;
    }
    return `unsupported URL protocol "${parsed.protocol}"`;
  } catch (_) {
    return 'malformed URL';
  }
}

function resolveDomainForAction(rawDomain, sender, actionName) {
  if (rawDomain !== undefined && rawDomain !== null) {
    const normalized = normalizeDomain(rawDomain);
    if (normalized) {
      return { domain: normalized };
    }

    return {
      error: `${actionName} rejected: malformed domain "${formatInvalidValue(rawDomain)}"`
    };
  }

  const senderDomain = getDomainFromSender(sender);
  if (senderDomain) {
    return { domain: senderDomain };
  }

  const senderUrl = getSenderUrl(sender);
  const urlIssue = getUrlIssue(senderUrl);
  if (urlIssue) {
    return {
      error: `${actionName} requires an http(s) page URL; ${urlIssue}`
    };
  }

  return { error: `${actionName} requires a valid domain` };
}

function resolveHttpUrlForAction(rawUrl, sender, actionName, fieldName) {
  if (rawUrl !== undefined && rawUrl !== null) {
    const normalized = sanitizeReportUrl(rawUrl);
    if (normalized) {
      return { url: normalized };
    }

    return {
      error: `${actionName} rejected: invalid ${fieldName}; expected http(s) URL`
    };
  }

  const senderUrl = getSenderUrl(sender);
  const normalizedSenderUrl = sanitizeReportUrl(senderUrl);
  if (normalizedSenderUrl) {
    return { url: normalizedSenderUrl };
  }

  const urlIssue = getUrlIssue(senderUrl);
  if (urlIssue) {
    return {
      error: `${actionName} requires an http(s) ${fieldName}; ${urlIssue}`
    };
  }

  return { error: `${actionName} requires a valid http(s) ${fieldName}` };
}

function validateBooleanPayload(actionName, rawValue, keyName = 'enabled') {
  if (typeof rawValue !== 'boolean') {
    return { error: `${actionName} requires boolean "${keyName}"` };
  }
  return { value: rawValue };
}

function validateSurrogateModePayload(rawMode) {
  if (typeof rawMode !== 'string') {
    return { error: 'setSurrogateMode requires string "mode"' };
  }

  const normalizedMode = sanitizeSurrogateMode(rawMode);
  if (normalizedMode !== rawMode.trim().toLowerCase()) {
    return { error: 'setSurrogateMode mode must be one of: off, safe, strict' };
  }

  return { mode: normalizedMode };
}

async function refreshReleaseSafeStats(options = {}) {
  const incrementMutation = options.incrementMutation === true;
  const data = await chrome.storage.local.get(['stats', 'whitelist', 'domainSettings', 'siteFixes']);
  const stats = sanitizeStats(data.stats);
  const whitelist = sanitizeWhitelist(data.whitelist);
  const domainSettings = sanitizeDomainSettings(data.domainSettings);
  const siteFixes = sanitizeSiteFixes(data.siteFixes);

  const nextStats = {
    releaseSafe: {
      settingsMutationCount:
        stats.releaseSafe.settingsMutationCount + (incrementMutation ? 1 : 0),
      whitelistEntryCount: whitelist.length,
      domainOverrideCount: Object.keys(domainSettings).length + Object.keys(siteFixes).length,
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
  if (!deepEqual(data.siteFixes, siteFixes)) {
    updates.siteFixes = siteFixes;
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

  const surrogatesEnabled =
    typeof current.surrogatesEnabled === 'boolean' ? current.surrogatesEnabled : true;
  if (current.surrogatesEnabled !== surrogatesEnabled) {
    updates.surrogatesEnabled = surrogatesEnabled;
  }

  const antiDetectionEnabled =
    typeof current.antiDetectionEnabled === 'boolean' ? current.antiDetectionEnabled : true;
  if (current.antiDetectionEnabled !== antiDetectionEnabled) {
    updates.antiDetectionEnabled = antiDetectionEnabled;
  }

  const surrogateMode = sanitizeSurrogateMode(current.surrogateMode);
  if (current.surrogateMode !== surrogateMode) {
    updates.surrogateMode = surrogateMode;
  }

  const whitelist = sanitizeWhitelist(current.whitelist);
  if (!deepEqual(current.whitelist, whitelist)) {
    updates.whitelist = whitelist;
  }

  const domainSettings = sanitizeDomainSettings(current.domainSettings);
  if (!deepEqual(current.domainSettings, domainSettings)) {
    updates.domainSettings = domainSettings;
  }

  const siteFixes = sanitizeSiteFixes({
    ...DEFAULT_SITE_FIXES,
    ...(isObject(current.siteFixes) ? current.siteFixes : {})
  });
  if (!deepEqual(current.siteFixes, siteFixes)) {
    updates.siteFixes = siteFixes;
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

  const breakageReports = sanitizeBreakageReports(current.breakageReports);
  if (!deepEqual(current.breakageReports, breakageReports)) {
    updates.breakageReports = breakageReports;
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
  const data = await chrome.storage.local.get([
    'enabled',
    'networkBlockingEnabled',
    'surrogatesEnabled',
    'surrogateMode'
  ]);
  const enabled = data.enabled ?? true;
  const networkBlockingEnabled = data.networkBlockingEnabled ?? enabled;
  const surrogatesEnabled = data.surrogatesEnabled ?? true;
  const surrogateMode = sanitizeSurrogateMode(data.surrogateMode);

  await syncNetworkRulesetState(
    networkBlockingEnabled,
    getEffectiveSurrogatesEnabled(surrogatesEnabled, surrogateMode)
  );
}

function buildRulesetStateUpdate(networkBlockingEnabled, surrogatesEnabled) {
  if (!networkBlockingEnabled) {
    return {
      enableRulesetIds: [],
      disableRulesetIds: ALL_RULESET_IDS
    };
  }

  if (surrogatesEnabled) {
    return {
      enableRulesetIds: ALL_RULESET_IDS,
      disableRulesetIds: []
    };
  }

  return {
    enableRulesetIds: CORE_RULESET_IDS,
    disableRulesetIds: [SURROGATE_RULESET_ID]
  };
}

async function syncNetworkRulesetState(networkBlockingEnabled, surrogatesEnabled = true) {
  const { enableRulesetIds, disableRulesetIds } = buildRulesetStateUpdate(
    networkBlockingEnabled,
    surrogatesEnabled
  );

  if (enableRulesetIds.length === 0 && disableRulesetIds.length === 0) {
    return;
  }

  await chrome.declarativeNetRequest.updateEnabledRulesets({
    enableRulesetIds,
    disableRulesetIds
  });
}

async function updateWhitelistRules(whitelist) {
  const existing = await chrome.declarativeNetRequest.getDynamicRules();
  const removeRuleIds = existing
    .filter((rule) => rule.id >= WHITELIST_RULE_ID_START && rule.id <= WHITELIST_RULE_ID_END)
    .map((rule) => rule.id);

  const effectiveWhitelist = whitelist.slice(0, MAX_WHITELIST_ENTRIES);
  const addRules = effectiveWhitelist.map((domain, index) => ({
    id: WHITELIST_RULE_ID_START + index,
    priority: WHITELIST_RULE_PRIORITY,
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

  const state = await chrome.storage.local.get(['surrogatesEnabled', 'surrogateMode']);
  const surrogatesEnabled = state.surrogatesEnabled ?? true;
  const surrogateMode = sanitizeSurrogateMode(state.surrogateMode);
  await syncNetworkRulesetState(
    enabled,
    getEffectiveSurrogatesEnabled(surrogatesEnabled, surrogateMode)
  );

  if (incrementMutation) {
    await refreshReleaseSafeStats({ incrementMutation: true });
  }
}

async function resumeQuickPause(options = {}) {
  const force = options.force === true;
  const incrementMutation = options.incrementMutation !== false;
  const data = await chrome.storage.local.get(['quickPause', 'surrogatesEnabled', 'surrogateMode']);
  const quickPause = sanitizeQuickPause(data.quickPause);
  const surrogatesEnabled = data.surrogatesEnabled ?? true;
  const surrogateMode = sanitizeSurrogateMode(data.surrogateMode);

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
  await syncNetworkRulesetState(
    quickPause.resumeNetworkBlockingEnabled,
    getEffectiveSurrogatesEnabled(surrogatesEnabled, surrogateMode)
  );
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
    'cosmeticFilteringEnabled',
    'surrogatesEnabled',
    'surrogateMode'
  ]);
  const enabled = data.enabled ?? true;
  const networkBlockingEnabled = data.networkBlockingEnabled ?? enabled;
  const cosmeticFilteringEnabled = data.cosmeticFilteringEnabled ?? enabled;
  const surrogatesEnabled = data.surrogatesEnabled ?? true;
  const surrogateMode = sanitizeSurrogateMode(data.surrogateMode);

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
  await syncNetworkRulesetState(
    false,
    getEffectiveSurrogatesEnabled(surrogatesEnabled, surrogateMode)
  );
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
    'surrogatesEnabled',
    'antiDetectionEnabled',
    'surrogateMode',
    'whitelist',
    'domainSettings',
    'siteFixes',
    'quickPause'
  ]);

  const domainSettings = sanitizeDomainSettings(data.domainSettings);
  const siteFixes = sanitizeSiteFixes(data.siteFixes);
  const whitelist = sanitizeWhitelist(data.whitelist);
  const normalizedDomain = normalizeDomain(currentDomain);
  const surrogateMode = sanitizeSurrogateMode(data.surrogateMode);
  const surrogatesEnabled = data.surrogatesEnabled ?? true;
  const antiDetectionEnabled = data.antiDetectionEnabled ?? true;
  const isCurrentDomainWhitelisted = normalizedDomain
    ? isDomainWhitelisted(normalizedDomain, whitelist)
    : false;
  const currentDomainSettings = normalizedDomain
    ? getDomainValueForHost(domainSettings, normalizedDomain)
    : null;
  const currentSiteFix = normalizedDomain && !isCurrentDomainWhitelisted
    ? getDomainValueForHost(siteFixes, normalizedDomain)
    : null;
  const quickPause = toQuickPauseStatus(data.quickPause);

  return {
    enabled: data.enabled ?? true,
    networkBlockingEnabled: data.networkBlockingEnabled ?? (data.enabled ?? true),
    cosmeticFilteringEnabled: data.cosmeticFilteringEnabled ?? (data.enabled ?? true),
    strictModeEnabled: data.strictModeEnabled ?? false,
    surrogatesEnabled,
    antiDetectionEnabled,
    surrogateMode,
    effectiveSurrogatesEnabled: getEffectiveSurrogatesEnabled(surrogatesEnabled, surrogateMode),
    whitelist,
    domainSettings,
    siteFixes,
    currentDomain: normalizedDomain,
    currentDomainSettings,
    currentSiteFix,
    isCurrentDomainWhitelisted,
    isCurrentDomainSurrogateBypassed:
      isCurrentDomainWhitelisted || currentSiteFix?.surrogates === false,
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

async function setAntiDetectionEnabled(enabled) {
  const data = await chrome.storage.local.get('antiDetectionEnabled');
  const currentValue = data.antiDetectionEnabled ?? true;

  if (currentValue !== enabled) {
    await chrome.storage.local.set({ antiDetectionEnabled: enabled });
    await refreshReleaseSafeStats({ incrementMutation: true });
  }

  return { antiDetectionEnabled: enabled };
}

async function setSurrogateMode(mode) {
  const normalizedMode = sanitizeSurrogateMode(mode);
  const data = await chrome.storage.local.get([
    'surrogateMode',
    'surrogatesEnabled',
    'enabled',
    'networkBlockingEnabled'
  ]);
  const currentMode = sanitizeSurrogateMode(data.surrogateMode);
  const surrogatesEnabled = data.surrogatesEnabled ?? true;
  const effectiveNetworkBlockingEnabled = data.networkBlockingEnabled ?? (data.enabled ?? true);
  const effectiveSurrogateRulesEnabled = getEffectiveSurrogatesEnabled(
    surrogatesEnabled,
    normalizedMode
  );

  if (currentMode !== normalizedMode) {
    await chrome.storage.local.set({ surrogateMode: normalizedMode });
    await refreshReleaseSafeStats({ incrementMutation: true });
  }

  await syncNetworkRulesetState(effectiveNetworkBlockingEnabled, effectiveSurrogateRulesEnabled);
  return {
    surrogateMode: normalizedMode,
    effectiveSurrogateRulesEnabled
  };
}

function sanitizeSiteFixPatch(rawPatch) {
  if (!isObject(rawPatch)) {
    return { error: 'setSiteFix requires object "siteFix"' };
  }

  const patch = {};
  for (const [key, value] of Object.entries(rawPatch)) {
    if (!SITE_FIX_PATCH_KEYS.includes(key)) {
      return { error: `setSiteFix rejected unknown field "${key}"` };
    }
    if (typeof value !== 'boolean') {
      return { error: `setSiteFix requires boolean "${key}" when provided` };
    }
    patch[key] = value;
  }

  return { patch };
}

function validateSiteFixConfig(domain, siteFix) {
  const hasApprovedMapping = Boolean(getDomainValueForHost(DEFAULT_SITE_FIXES, domain));
  if (!hasApprovedMapping) {
    return {
      error: `setSiteFix rejected: "${domain}" has no approved surrogate mapping`
    };
  }

  if (siteFix.antiDetection === true && siteFix.surrogates === false) {
    return {
      error: 'setSiteFix rejected: antiDetection cannot be true when surrogates is false'
    };
  }

  if (siteFix.strict === true && siteFix.antiDetection !== true) {
    return {
      error: 'setSiteFix rejected: strict requires antiDetection to be true'
    };
  }

  return null;
}

async function setSiteFix(domain, rawPatch) {
  const patchResult = sanitizeSiteFixPatch(rawPatch);
  if (patchResult.error) {
    return { error: patchResult.error };
  }
  const patch = patchResult.patch;

  const data = await chrome.storage.local.get('siteFixes');
  const siteFixes = sanitizeSiteFixes(data.siteFixes);
  const hasExistingDomain = isObject(siteFixes[domain]);

  if (Object.keys(patch).length === 0) {
    if (!hasExistingDomain) {
      return { domain, siteFix: null };
    }
    delete siteFixes[domain];
    await chrome.storage.local.set({ siteFixes });
    await refreshReleaseSafeStats({ incrementMutation: true });
    return { domain, siteFix: null };
  }

  if (!hasExistingDomain && Object.keys(siteFixes).length >= MAX_SITE_FIX_ENTRIES) {
    return {
      error: `setSiteFix rejected: siteFixes limit (${MAX_SITE_FIX_ENTRIES}) reached`
    };
  }

  const nextSiteFix = {
    ...(hasExistingDomain ? siteFixes[domain] : {}),
    ...patch
  };

  const validation = validateSiteFixConfig(domain, nextSiteFix);
  if (validation?.error) {
    return { error: validation.error };
  }

  siteFixes[domain] = nextSiteFix;
  await chrome.storage.local.set({ siteFixes });
  await refreshReleaseSafeStats({ incrementMutation: true });
  return { domain, siteFix: nextSiteFix };
}

async function setSurrogatesEnabled(enabled) {
  const data = await chrome.storage.local.get([
    'surrogatesEnabled',
    'enabled',
    'networkBlockingEnabled',
    'surrogateMode'
  ]);
  const currentValue = data.surrogatesEnabled ?? true;
  const effectiveNetworkBlockingEnabled = data.networkBlockingEnabled ?? (data.enabled ?? true);
  const surrogateMode = sanitizeSurrogateMode(data.surrogateMode);

  if (currentValue !== enabled) {
    await chrome.storage.local.set({ surrogatesEnabled: enabled });
    await refreshReleaseSafeStats({ incrementMutation: true });
  }

  await syncNetworkRulesetState(
    effectiveNetworkBlockingEnabled,
    getEffectiveSurrogatesEnabled(enabled, surrogateMode)
  );
  return {
    surrogatesEnabled: enabled,
    effectiveSurrogateRulesEnabled: getEffectiveSurrogatesEnabled(enabled, surrogateMode)
  };
}

function createSiteIssueReportId() {
  const randomSuffix = Math.random().toString(36).slice(2, 8);
  return `${Date.now()}-${randomSuffix}`;
}

function validateBreakageMitigationInput(rawMitigation) {
  if (rawMitigation === undefined || rawMitigation === null || rawMitigation === '') {
    return { mitigation: 'needs-investigation' };
  }

  const mitigation = normalizeBreakageMitigation(rawMitigation);
  if (!mitigation) {
    return {
      error:
        'reportBreakage mitigation must be one of: surrogate, exception, no-fix, needs-investigation'
    };
  }

  return { mitigation };
}

async function appendBreakageReport(report) {
  const sanitizedEntries = sanitizeBreakageReports([report]);
  const sanitizedReport = sanitizedEntries[0];
  if (!sanitizedReport) {
    return { error: 'reportBreakage payload failed sanitization' };
  }

  const data = await chrome.storage.local.get('breakageReports');
  const reports = sanitizeBreakageReports(data.breakageReports);
  reports.push(sanitizedReport);
  const nextReports = reports.slice(-MAX_BREAKAGE_REPORT_ENTRIES);
  await chrome.storage.local.set({ breakageReports: nextReports });

  return { storedCount: nextReports.length };
}

async function createBreakageReport(input, sender) {
  const payload = isObject(input) ? input : {};
  const caseId = sanitizeBreakageCaseId(payload.caseId);
  if (!caseId) {
    return { error: 'reportBreakage requires caseId formatted like "AD-001"' };
  }

  const detectorUrlResult = resolveHttpUrlForAction(
    payload.detectorUrl,
    sender,
    'reportBreakage',
    'detectorUrl'
  );
  if (detectorUrlResult.error) {
    return { error: detectorUrlResult.error };
  }
  const detectorUrl = detectorUrlResult.url;

  let domain = null;
  if (payload.domain !== undefined && payload.domain !== null) {
    const domainResult = resolveDomainForAction(payload.domain, sender, 'reportBreakage');
    if (domainResult.error) {
      return { error: domainResult.error };
    }
    domain = domainResult.domain;
  } else {
    domain = getDomainFromUrl(detectorUrl) || getDomainFromSender(sender);
  }

  if (!domain) {
    return { error: 'reportBreakage requires a valid domain' };
  }

  const mitigationResult = validateBreakageMitigationInput(payload.mitigation);
  if (mitigationResult.error) {
    return { error: mitigationResult.error };
  }

  const result = await appendBreakageReport({
    caseId,
    domain,
    detectorUrl,
    mitigation: mitigationResult.mitigation,
    timestamp: Date.now()
  });
  if (result.error) {
    return { error: result.error };
  }

  return {
    success: true,
    caseId,
    storedCount: result.storedCount
  };
}

function buildRollbackSiteFixes(rawSiteFixes) {
  const currentSiteFixes = sanitizeSiteFixes(rawSiteFixes);
  const nextSiteFixes = {};

  for (const [domain, config] of Object.entries(currentSiteFixes)) {
    nextSiteFixes[domain] = {
      ...config,
      antiDetection: false,
      strict: false
    };
  }

  return nextSiteFixes;
}

async function runFeatureRollback() {
  const data = await chrome.storage.local.get([
    'enabled',
    'networkBlockingEnabled',
    'surrogatesEnabled',
    'antiDetectionEnabled',
    'surrogateMode',
    'siteFixes'
  ]);
  const effectiveNetworkBlockingEnabled = data.networkBlockingEnabled ?? (data.enabled ?? true);
  const nextSiteFixes = buildRollbackSiteFixes(data.siteFixes);
  const updates = {};

  if ((data.surrogatesEnabled ?? true) !== false) {
    updates.surrogatesEnabled = false;
  }
  if ((data.antiDetectionEnabled ?? true) !== false) {
    updates.antiDetectionEnabled = false;
  }
  if (sanitizeSurrogateMode(data.surrogateMode) !== 'off') {
    updates.surrogateMode = 'off';
  }
  if (!deepEqual(data.siteFixes, nextSiteFixes)) {
    updates.siteFixes = nextSiteFixes;
  }

  const rollbackApplied = Object.keys(updates).length > 0;
  if (rollbackApplied) {
    await chrome.storage.local.set(updates);
    await refreshReleaseSafeStats({ incrementMutation: true });
  }

  await syncNetworkRulesetState(effectiveNetworkBlockingEnabled, false);

  return {
    success: true,
    rollbackApplied,
    surrogatesEnabled: false,
    antiDetectionEnabled: false,
    surrogateMode: 'off',
    effectiveSurrogateRulesEnabled: false,
    siteFixesTouched: Object.keys(nextSiteFixes).length
  };
}

async function createSiteIssueReport(input, sender) {
  const payload = isObject(input) ? input : {};
  const urlResult = resolveHttpUrlForAction(payload.url, sender, 'reportSiteIssue', 'url');
  if (urlResult.error) {
    return { error: urlResult.error };
  }
  const url = urlResult.url;

  let domain = null;
  if (payload.domain !== undefined && payload.domain !== null) {
    const domainResult = resolveDomainForAction(payload.domain, sender, 'reportSiteIssue');
    if (domainResult.error) {
      return { error: domainResult.error };
    }
    domain = domainResult.domain;
  } else {
    domain = getDomainFromUrl(url) || getDomainFromSender(sender);
  }

  if (!domain) {
    return { error: 'reportSiteIssue requires a valid domain' };
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
        surrogatesEnabled: state.surrogatesEnabled,
        antiDetectionEnabled: state.antiDetectionEnabled,
        surrogateMode: state.surrogateMode,
        effectiveSurrogatesEnabled: state.effectiveSurrogatesEnabled,
        currentDomain: state.currentDomain,
        currentDomainSettings: state.currentDomainSettings,
        currentSiteFix: state.currentSiteFix,
        isCurrentDomainWhitelisted: state.isCurrentDomainWhitelisted,
        isCurrentDomainSurrogateBypassed: state.isCurrentDomainSurrogateBypassed,
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
      const enabledPayload = validateBooleanPayload('setEnabled', message.enabled);
      if (enabledPayload.error) {
        return { error: enabledPayload.error };
      }

      await setEnabled(enabledPayload.value, {
        incrementMutation: true,
        cancelQuickPause: true
      });
      return {
        enabled: enabledPayload.value,
        networkBlockingEnabled: enabledPayload.value,
        cosmeticFilteringEnabled: enabledPayload.value
      };
    }

    case 'setCosmeticFiltering': {
      const enabledPayload = validateBooleanPayload('setCosmeticFiltering', message.enabled);
      if (enabledPayload.error) {
        return { error: enabledPayload.error };
      }

      const data = await chrome.storage.local.get('cosmeticFilteringEnabled');
      const currentValue = data.cosmeticFilteringEnabled ?? true;
      if (currentValue !== enabledPayload.value) {
        await chrome.storage.local.set({ cosmeticFilteringEnabled: enabledPayload.value });
        await refreshReleaseSafeStats({ incrementMutation: true });
      }

      return { cosmeticFilteringEnabled: enabledPayload.value };
    }

    case 'setStrictMode': {
      const enabledPayload = validateBooleanPayload('setStrictMode', message.enabled);
      if (enabledPayload.error) {
        return { error: enabledPayload.error };
      }

      const data = await chrome.storage.local.get('strictModeEnabled');
      const currentValue = data.strictModeEnabled ?? false;
      if (currentValue !== enabledPayload.value) {
        await chrome.storage.local.set({ strictModeEnabled: enabledPayload.value });
        await refreshReleaseSafeStats({ incrementMutation: true });
      }

      return { strictModeEnabled: enabledPayload.value };
    }

    case 'setAntiDetectionEnabled': {
      const enabledPayload = validateBooleanPayload('setAntiDetectionEnabled', message.enabled);
      if (enabledPayload.error) {
        return { error: enabledPayload.error };
      }

      return setAntiDetectionEnabled(enabledPayload.value);
    }

    case 'setSurrogateMode': {
      const modePayload = validateSurrogateModePayload(message.mode);
      if (modePayload.error) {
        return { error: modePayload.error };
      }

      return setSurrogateMode(modePayload.mode);
    }

    case 'setSurrogatesEnabled': {
      const enabledPayload = validateBooleanPayload('setSurrogatesEnabled', message.enabled);
      if (enabledPayload.error) {
        return { error: enabledPayload.error };
      }

      return setSurrogatesEnabled(enabledPayload.value);
    }

    case 'runFeatureRollback': {
      return runFeatureRollback();
    }

    case 'setSiteCosmetic': {
      const enabledPayload = validateBooleanPayload('setSiteCosmetic', message.enabled);
      if (enabledPayload.error) {
        return { error: enabledPayload.error };
      }

      const domainResult = resolveDomainForAction(message.domain, sender, 'setSiteCosmetic');
      if (domainResult.error) {
        return { error: domainResult.error };
      }

      return setSiteCosmetic(domainResult.domain, enabledPayload.value);
    }

    case 'setSiteFix': {
      const domainResult = resolveDomainForAction(message.domain, sender, 'setSiteFix');
      if (domainResult.error) {
        return { error: domainResult.error };
      }

      return setSiteFix(domainResult.domain, message.siteFix);
    }

    case 'addToWhitelist': {
      const domainResult = resolveDomainForAction(message.domain, sender, 'addToWhitelist');
      if (domainResult.error) {
        return { error: domainResult.error };
      }
      const domain = domainResult.domain;

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
      const domainResult = resolveDomainForAction(message.domain, sender, 'removeFromWhitelist');
      if (domainResult.error) {
        return { error: domainResult.error };
      }
      const domain = domainResult.domain;

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

    case 'reportBreakage': {
      return createBreakageReport(message, sender);
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

    case 'getBreakageReports': {
      const data = await chrome.storage.local.get('breakageReports');
      return { breakageReports: sanitizeBreakageReports(data.breakageReports) };
    }

    case 'clearErrorLog': {
      await chrome.storage.local.set({ errorLog: [] });
      return { success: true };
    }

    case 'clearBreakageReports': {
      await chrome.storage.local.set({ breakageReports: [] });
      return { success: true };
    }

    default:
      return { error: 'Unknown message type' };
  }
}
