const $ = (id) => document.getElementById(id);
const ORIGINS = ["https://dns.google/*", "https://rdap.org/*"];
let current = null; // { tabId, url, result }

const FEATURE_LABELS = {
  url_length: "URL length", domain_length: "Domain length", num_dots: "Dots", num_hyphens: "Hyphens",
  num_digits: "Digits", num_special_chars: "Special characters", num_subdomains: "Subdomains",
  has_ip_address: "IP address as host", has_at_symbol: "'@' symbol", uses_https: "HTTPS",
  suspicious_word_count: "Suspicious words", num_percent_encoded: "Encoded characters (%XX)",
  has_punycode: "Punycode (xn--)",
};
const YESNO = new Set(["has_ip_address", "has_at_symbol", "uses_https", "has_punycode"]);

function row(k, v) {
  const tr = document.createElement("tr");
  const a = document.createElement("td"); a.textContent = k;
  const b = document.createElement("td"); b.textContent = v;
  tr.append(a, b);
  return tr;
}

function render(r) {
  $("loading").hidden = true;
  if (!r || !r.applicable) { $("na").hidden = false; $("result").hidden = true; return; }
  $("na").hidden = true; $("result").hidden = false;

  $("score").textContent = r.score;
  $("gauge").style.setProperty("--p", r.score);
  $("gauge").style.setProperty("--c", r.color);
  $("pill").textContent = r.levelLabel;
  $("pill").style.background = r.color;
  $("host").textContent = r.host;
  $("prob").textContent = r.trusted ? "Trusted by you" : `ML phishing probability: ${(r.prob * 100).toFixed(1)}%`;

  const warn = $("modelWarn");
  if (r.modelMeta && r.modelMeta.placeholder) {
    warn.hidden = false;
    warn.textContent = "Demo model in use (trained on synthetic data). Replace model/model.json with the file from your Colab training for real results.";
  } else warn.hidden = true;

  const ul = $("reasons"); ul.replaceChildren();
  r.reasons.forEach((t) => { const li = document.createElement("li"); li.textContent = t; ul.append(li); });

  const tbl = $("features"); tbl.replaceChildren();
  if (r.features) {
    for (const [k, label] of Object.entries(FEATURE_LABELS)) {
      const v = r.features[k];
      tbl.append(row(label, YESNO.has(k) ? (v ? "yes" : "no") : v));
    }
  }

  const intel = $("intel"); intel.replaceChildren();
  const lines = [];
  lines.push(r.blocklisted ? "Local blocklist: MATCH" : "Local blocklist: no match");
  if (r.intel) {
    lines.push(r.intel.registered ? `Registered: ${r.intel.registered} (${r.intel.ageDays} days ago)` : "Registration date: unavailable");
    lines.push(r.intel.dnsRecords != null ? `DNS: ${r.intel.dnsRecords} A record(s), min TTL ${r.intel.dnsMinTtl}s` : "DNS: unavailable");
  } else lines.push("Online lookups are off.");
  lines.forEach((t) => { const p = document.createElement("div"); p.textContent = t; intel.append(p); });

  $("trustBtn").textContent = r.trusted ? "Remove from trusted sites" : "Trust this site";
}

async function analyze(force = false) {
  $("loading").hidden = false;
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.url) return render(null);
  const r = await chrome.runtime.sendMessage({ type: "ANALYZE", tabId: tab.id, url: tab.url, force });
  current = { tabId: tab.id, url: tab.url, result: r };
  render(r);
}

async function init() {
  const s = await chrome.storage.local.get({ threshold: 61, onlineLookups: false });
  $("threshold").value = String(s.threshold);
  $("lookups").checked = s.onlineLookups;

  $("threshold").addEventListener("change", async () => {
    await chrome.storage.local.set({ threshold: Number($("threshold").value) });
  });

  $("lookups").addEventListener("change", async () => {
    if ($("lookups").checked) {
      // must be called directly inside the user gesture
      const ok = await chrome.permissions.request({ origins: ORIGINS });
      if (!ok) { $("lookups").checked = false; return; }
    }
    await chrome.storage.local.set({ onlineLookups: $("lookups").checked });
    analyze(true);
  });

  $("trustBtn").addEventListener("click", async () => {
    const r = current && current.result;
    if (!r || !r.host) return;
    await chrome.runtime.sendMessage({ type: r.trusted ? "UNTRUST" : "TRUST", host: r.host });
    analyze(true);
  });

  analyze();
}
init();
