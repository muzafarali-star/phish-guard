// URL feature extraction. Mirrors extract_features() in train_phishing_model.py / the Colab notebook
// EXACTLY - if you change one side, change the other and retrain, or predictions will drift.

export const SUSPICIOUS_WORDS = [
  "login", "signin", "sign-in", "verify", "verification", "account", "update",
  "secure", "security", "banking", "bank", "confirm", "password", "passwd",
  "paypal", "ebay", "amazon", "apple", "microsoft", "webscr", "wallet",
  "suspend", "suspended", "unlock", "billing", "invoice", "payment",
  "support", "alert", "authenticate", "recover", "credential", "free", "bonus",
];

const TWO_LEVEL_TLDS = new Set([
  "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
  "co.in", "net.in", "org.in", "co.jp", "com.br", "com.cn", "com.mx",
  "co.nz", "co.za", "com.sg", "com.tr", "com.ar", "com.hk",
]);

const IPV4_RE = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const HEX_IP_RE = /^0x[0-9a-f]+$/i;

// Same host/scheme parsing rules as Python's urllib.parse.urlparse(...).hostname
function parseUrl(url) {
  const full = url.includes("://") ? url : "http://" + url;
  const m = /^([A-Za-z][A-Za-z0-9+.\-]*):\/\/([^\/?#]*)/.exec(full);
  if (!m) return { scheme: "", host: "" };
  const netloc = m[2];
  let hostinfo = netloc.slice(netloc.lastIndexOf("@") + 1);
  let host;
  if (hostinfo.includes("[")) {
    hostinfo = hostinfo.slice(hostinfo.indexOf("[") + 1);
    host = hostinfo.split("]")[0];
  } else {
    host = hostinfo.split(":")[0];
  }
  return { scheme: m[1].toLowerCase(), host: host.toLowerCase() };
}

export function hostOf(url) {
  return parseUrl(String(url).trim()).host;
}

export function registeredDomain(host) {
  const labels = host.split(".").filter(Boolean);
  if (IPV4_RE.test(host) || HEX_IP_RE.test(host) || host.includes(":")) return host;
  const suffixLen = TWO_LEVEL_TLDS.has(labels.slice(-2).join(".")) ? 2 : 1;
  return labels.slice(-(suffixLen + 1)).join(".");
}

export function matchedSuspiciousWords(url) {
  const lower = String(url).toLowerCase();
  return SUSPICIOUS_WORDS.filter((w) => lower.includes(w));
}

const count = (s, sub) => s.split(sub).length - 1;

export function extractFeatures(rawUrl) {
  const url = String(rawUrl).trim();
  const { scheme, host } = parseUrl(url);
  const chars = Array.from(url); // code points, like Python's len()
  const lower = url.toLowerCase();
  const labels = host.split(".").filter(Boolean);

  let numSubdomains;
  if (IPV4_RE.test(host) || HEX_IP_RE.test(host) || host.includes(":")) {
    numSubdomains = 0;
  } else {
    const suffixLen = TWO_LEVEL_TLDS.has(labels.slice(-2).join(".")) ? 2 : 1;
    numSubdomains = Math.max(0, labels.length - (suffixLen + 1));
  }

  const pct = url.match(/%[0-9a-fA-F]{2}/g) || [];

  return {
    url_length: chars.length,
    domain_length: Array.from(host).length,
    num_dots: count(url, "."),
    num_hyphens: count(url, "-"),
    num_digits: chars.filter((c) => c >= "0" && c <= "9").length,
    num_special_chars: chars.filter((c) => !/[\p{L}\p{N}]/u.test(c)).length,
    num_subdomains: numSubdomains,
    has_ip_address: Number(IPV4_RE.test(host) || HEX_IP_RE.test(host) || host.startsWith("[") || host.includes(":")),
    has_at_symbol: Number(url.includes("@")),
    uses_https: Number(scheme === "https"),
    suspicious_word_count: SUSPICIOUS_WORDS.reduce((n, w) => n + count(lower, w), 0),
    num_percent_encoded: pct.length,
    has_url_encoding: Number(pct.length > 0),
    percent_encoded_ratio: (3 * pct.length) / Math.max(1, chars.length),
    has_punycode: Number(host.includes("xn--")),
    has_hex_or_unicode_chars: Number(chars.some((c) => c.codePointAt(0) > 127)),
  };
}
