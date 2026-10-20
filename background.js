// Phish Guard - background service worker (Manifest V3)
// Flow: navigation -> URL -> feature extraction -> ML model -> threat intel -> risk engine -> warning.
import { extractFeatures, hostOf } from "./lib/features.js";
import { loadModel, predictProba } from "./lib/model.js";
import { loadBlocklist, isBlocklisted, lookups } from "./lib/intel.js";
import { computeRisk } from "./lib/risk.js";

const DEFAULTS = { threshold: 61, onlineLookups: false, trusted: [] };
const getSettings = () => chrome.storage.local.get(DEFAULTS);

export async function analyze(url, signals = {}) {
  let u;
  try { u = new URL(url); } catch { return { applicable: false, url }; }
  if (u.protocol !== "http:" && u.protocol !== "https:") return { applicable: false, url };

  const settings = await getSettings();
  const host = hostOf(url);

  if (settings.trusted.includes(host)) {
    return {
      applicable: true, trusted: true, url, host, score: 0, level: "safe", levelLabel: "Safe",
      color: "#22a559", reasons: ["You marked this site as trusted"], signals,
    };
  }

  const model = await loadModel();
  const features = extractFeatures(url);
  const prob = predictProba(model, features);
  const blocklisted = isBlocklisted(host, await loadBlocklist());
  const intel = settings.onlineLookups ? await lookups(host) : null;
  const risk = computeRisk({ url, features, prob, blocklisted, intel, signals });

  return {
    applicable: true, trusted: false, url, host, prob, features, intel, signals, blocklisted,
    modelMeta: model.meta || null, ...risk,
  };
}

// ---- per-tab state (session storage survives service-worker restarts) ----
const tabKey = (id) => `tab:${id}`;
const saveTabResult = (tabId, r) => chrome.storage.session.set({ [tabKey(tabId)]: r });
async function getTabResult(tabId) {
  const o = await chrome.storage.session.get(tabKey(tabId));
  return o[tabKey(tabId)];
}

async function updateBadge(tabId, r) {
  try {
    if (!r.applicable) return chrome.action.setBadgeText({ tabId, text: "" });
    await chrome.action.setBadgeText({ tabId, text: String(r.score) });
    await chrome.action.setBadgeBackgroundColor({ tabId, color: r.color });
  } catch { /* tab may have closed */ }
}

async function maybeNotify(tabId, r) {
  if (!r.applicable || r.trusted) return;
  const { threshold } = await getSettings();
  if (r.score < threshold) return;
  const key = `notified:${tabId}`;
  const prev = (await chrome.storage.session.get(key))[key];
  if (prev === r.url) return; // one notification per page load
  await chrome.storage.session.set({ [key]: r.url });
  chrome.notifications.create(`pg-${tabId}-${Date.now()}`, {
    type: "basic",
    iconUrl: "icons/icon128.png",
    title: `Phish Guard: ${r.levelLabel} risk (${r.score}/100)`,
    message: `${r.host}\n${r.reasons.slice(0, 3).join("\n")}`,
    priority: 2,
  });
}

async function process(tabId, url, signals) {
  const prev = await getTabResult(tabId);
  const sig = { ...(prev && prev.url === url ? prev.signals : {}), ...signals };
  const r = await analyze(url, sig);
  await saveTabResult(tabId, r);
  await updateBadge(tabId, r);
  await maybeNotify(tabId, r);
  return r;
}

// ---- navigation hooks ----
const onNav = (d) => { if (d.frameId === 0) process(d.tabId, d.url, {}).catch(console.error); };
chrome.webNavigation.onCommitted.addListener(onNav);
chrome.webNavigation.onHistoryStateUpdated.addListener(onNav);
chrome.tabs.onRemoved.addListener((tabId) => chrome.storage.session.remove([tabKey(tabId), `notified:${tabId}`]));

// ---- messages from content script and popup ----
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    switch (msg.type) {
      case "PAGE_READY": { // content script: page loaded, here are page signals
        if (!sender.tab || sender.frameId !== 0) return sendResponse(null);
        const r = await process(sender.tab.id, sender.url || msg.url, msg.signals || {});
        const { threshold } = await getSettings();
        return sendResponse({ show: r.applicable && !r.trusted && r.score >= threshold, result: r });
      }
      case "ANALYZE": { // popup: analyze the active tab
        const cached = msg.tabId != null ? await getTabResult(msg.tabId) : null;
        if (cached && cached.url === msg.url && !msg.force) return sendResponse(cached);
        const r = msg.tabId != null ? await process(msg.tabId, msg.url, {}) : await analyze(msg.url);
        return sendResponse(r);
      }
      case "TRUST":
      case "UNTRUST": {
        const { trusted } = await getSettings();
        const set = new Set(trusted);
        msg.type === "TRUST" ? set.add(msg.host) : set.delete(msg.host);
        await chrome.storage.local.set({ trusted: [...set] });
        return sendResponse({ ok: true });
      }
      default: return sendResponse(null);
    }
  })().catch((e) => { console.error(e); sendResponse(null); });
  return true; // async response
});
