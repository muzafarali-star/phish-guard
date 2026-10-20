// Threat intelligence.
//  - Local blocklist (data/blocklist.json): always on, fully offline.
//  - Optional online lookups (OFF by default, user opts in from the popup):
//      * RDAP via rdap.org  -> domain registration date (WHOIS successor)
//      * DNS via dns.google -> A-record count and TTL (informational)
//    These send the site's domain name to those services.
import { registeredDomain } from "./features.js";

let blocklist = null;
export async function loadBlocklist() {
  if (blocklist) return blocklist;
  try {
    const res = await fetch(chrome.runtime.getURL("data/blocklist.json"));
    const j = await res.json();
    blocklist = (j.domains || []).map((d) => String(d).toLowerCase());
  } catch { blocklist = []; }
  return blocklist;
}

export function isBlocklisted(host, list) {
  return list.some((d) => host === d || host.endsWith("." + d));
}

const cache = new Map(); // domain -> {t, data}
const TTL_MS = 6 * 60 * 60 * 1000;

async function getJson(url, timeoutMs = 4000, accept = "application/json") {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { signal: ctl.signal, headers: { Accept: accept }, credentials: "omit" });
    if (!res.ok) return null;
    return await res.json();
  } catch { return null; } finally { clearTimeout(timer); }
}

export async function lookups(host) {
  const domain = registeredDomain(host);
  if (/^[\d.]+$/.test(domain) || domain.includes(":")) return {}; // IPs have no registration data
  const hit = cache.get(domain);
  if (hit && Date.now() - hit.t < TTL_MS) return hit.data;

  const [rdap, dns] = await Promise.all([
    getJson(`https://rdap.org/domain/${encodeURIComponent(domain)}`, 4000, "application/rdap+json"),
    getJson(`https://dns.google/resolve?name=${encodeURIComponent(host)}&type=A`),
  ]);

  const data = {};
  const reg = rdap?.events?.find((e) => e.eventAction === "registration");
  if (reg?.eventDate) {
    const days = Math.floor((Date.now() - Date.parse(reg.eventDate)) / 86400000);
    if (Number.isFinite(days)) { data.ageDays = Math.max(0, days); data.registered = reg.eventDate.slice(0, 10); }
  }
  if (dns?.Answer?.length) {
    const a = dns.Answer.filter((r) => r.type === 1);
    data.dnsRecords = a.length;
    if (a.length) data.dnsMinTtl = Math.min(...a.map((r) => r.TTL));
  }
  cache.set(domain, { t: Date.now(), data });
  return data;
}
