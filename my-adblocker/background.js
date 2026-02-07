// Service worker - background logic
/*
keeps track of how many ads were blocked
updates badge number on the extension icon
listens for messages from other parts of the extension (like the popup or content script)
*/

// ── Per-tab blocked counts ──────────────────────────────────────────
const tabBlockedCounts = new Map();

// ── Error logging ───────────────────────────────────────────────────
async function logError(context, error) {
  try {
    const data = await chrome.storage.local.get('errorLog');
    const errors = data.errorLog || [];
    errors.push({ context, message: error.message, timestamp: Date.now() });
    await chrome.storage.local.set({ errorLog: errors.slice(-50) });
  } catch (_) {
    // Can't do much if storage itself fails
  }
}

// ── Initialize on install ───────────────────────────────────────────
chrome.runtime.onInstalled.addListener(async (details) => {
  try {
    if (details.reason === 'install') {
      await chrome.storage.local.set({
        enabled: true,
        whitelist: [],
        stats: { totalBlocked: 0, sessionBlocked: 0 },
        errorLog: []
      });
    }
    // Set initial badge style
    await chrome.action.setBadgeBackgroundColor({ color: '#666' });
  } catch (err) {
    await logError('onInstalled', err);
  }
});

// ── Track blocked requests ──────────────────────────────────────────
chrome.declarativeNetRequest.onRuleMatchedDebug.addListener(async (info) => {
  try {
    const tabId = info.request.tabId;
    if (tabId < 0) return; // Ignore non-tab requests

    // Increment per-tab count
    const count = (tabBlockedCounts.get(tabId) || 0) + 1;
    tabBlockedCounts.set(tabId, count);

    // Update badge for this tab
    await chrome.action.setBadgeText({ text: String(count), tabId });

    // Increment persistent stats
    const data = await chrome.storage.local.get('stats');
    const stats = data.stats || { totalBlocked: 0, sessionBlocked: 0 };
    stats.totalBlocked++;
    stats.sessionBlocked++;
    await chrome.storage.local.set({ stats });
  } catch (err) {
    await logError('onRuleMatchedDebug', err);
  }
});

// ── Clean up tab data when tabs close ───────────────────────────────
chrome.tabs.onRemoved.addListener((tabId) => {
  tabBlockedCounts.delete(tabId);
});

// Reset per-tab count on navigation
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === 'loading') {
    tabBlockedCounts.set(tabId, 0);
    chrome.action.setBadgeText({ text: '', tabId }).catch(() => {});
  }
});

// ── Whitelist: manage dynamic allow-rules ───────────────────────────
async function updateWhitelistRules(whitelist) {
  try {
    // Remove all existing dynamic rules first
    const existing = await chrome.declarativeNetRequest.getDynamicRules();
    const removeIds = existing.map(r => r.id);

    // Build allow-rules for each whitelisted domain (ID range 5000+)
    const addRules = whitelist.map((domain, i) => ({
      id: 5000 + i,
      priority: 5,
      action: { type: 'allow' },
      condition: {
        requestDomains: [domain],
        resourceTypes: [
          'main_frame', 'sub_frame', 'stylesheet', 'script',
          'image', 'font', 'object', 'xmlhttprequest', 'ping',
          'media', 'websocket', 'other'
        ]
      }
    }));

    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: removeIds,
      addRules
    });
  } catch (err) {
    await logError('updateWhitelistRules', err);
  }
}

// ── Toggle extension enabled/disabled ───────────────────────────────
async function setEnabled(enabled) {
  await chrome.storage.local.set({ enabled });

  // Enable or disable all static rulesets
  const rulesetIds = ['ads', 'tracking', 'annoyances'];
  if (enabled) {
    await chrome.declarativeNetRequest.updateEnabledRulesets({
      enableRulesetIds: rulesetIds
    });
  } else {
    await chrome.declarativeNetRequest.updateEnabledRulesets({
      disableRulesetIds: rulesetIds
    });
  }
}

// ── Message handling ────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  handleMessage(message, sender).then(sendResponse).catch(async (err) => {
    await logError('onMessage:' + message.type, err);
    sendResponse({ error: err.message });
  });
  return true; // Keep channel open for async response
});

async function handleMessage(message, sender) {
  switch (message.type) {
    case 'getState': {
      const data = await chrome.storage.local.get(['enabled', 'whitelist']);
      return {
        enabled: data.enabled ?? true,
        whitelist: data.whitelist || []
      };
    }

    case 'toggleEnabled': {
      const data = await chrome.storage.local.get('enabled');
      const newState = !(data.enabled ?? true);
      await setEnabled(newState);
      return { enabled: newState };
    }

    case 'addToWhitelist': {
      const domain = message.domain;
      if (!domain) return { error: 'No domain provided' };
      const data = await chrome.storage.local.get('whitelist');
      const whitelist = data.whitelist || [];
      if (!whitelist.includes(domain)) {
        whitelist.push(domain);
        await chrome.storage.local.set({ whitelist });
        await updateWhitelistRules(whitelist);
      }
      return { whitelist };
    }

    case 'removeFromWhitelist': {
      const domain = message.domain;
      if (!domain) return { error: 'No domain provided' };
      const data = await chrome.storage.local.get('whitelist');
      let whitelist = data.whitelist || [];
      whitelist = whitelist.filter(d => d !== domain);
      await chrome.storage.local.set({ whitelist });
      await updateWhitelistRules(whitelist);
      return { whitelist };
    }

    case 'getStats': {
      const data = await chrome.storage.local.get('stats');
      const stats = data.stats || { totalBlocked: 0, sessionBlocked: 0 };
      const tabId = sender.tab?.id;
      stats.tabBlocked = tabId ? (tabBlockedCounts.get(tabId) || 0) : 0;
      return stats;
    }

    default:
      return { error: 'Unknown message type' };
  }
}
