// Risk engine: combines the ML probability with threat-intel and page signals -> 0-100 score,
// level (Safe/Low/Medium/High/Critical) and human-readable reasons.
import { matchedSuspiciousWords } from "./features.js";

export const LEVELS = [
  { key: "safe",     label: "Safe",     max: 20,  color: "#22a559" },
  { key: "low",      label: "Low",      max: 40,  color: "#e6b800" },
  { key: "medium",   label: "Medium",   max: 60,  color: "#ff9f1a" },
  { key: "high",     label: "High",     max: 80,  color: "#f0541e" },
  { key: "critical", label: "Critical", max: 100, color: "#d90429" },
];

export function levelFor(score) {
  return LEVELS.find((l) => score <= l.max) || LEVELS[LEVELS.length - 1];
}

// Tunable weights (points added on top of the ML score, which is probability * 100)
const W = { age7: 25, age30: 15, age90: 5, passwordOnHttp: 10 };

export function computeRisk({ url, features: f, prob, blocklisted, intel, signals }) {
  let score = prob * 100;
  const reasons = [];

  if (blocklisted) {
    score = 100;
    reasons.push("Domain is on the known-malicious list");
  }

  if (prob >= 0.5) reasons.push(`High ML phishing probability (${Math.round(prob * 100)}%)`);

  if (f.has_ip_address) reasons.push("Suspicious URL structure: raw IP address instead of a domain name");
  if (f.has_at_symbol) reasons.push("Suspicious URL structure: contains '@', which can hide the real destination");
  if (f.num_dots >= 5 || f.num_hyphens >= 4 || f.domain_length > 30) {
    reasons.push(`Suspicious URL structure: ${f.num_dots} dots, ${f.num_hyphens} hyphens, domain length ${f.domain_length}`);
  }
  if (f.num_subdomains >= 3) reasons.push(`Unusual number of subdomains (${f.num_subdomains})`);

  const words = matchedSuspiciousWords(url);
  if (f.suspicious_word_count >= 2 || (words.length >= 1 && prob >= 0.5)) {
    reasons.push(`Suspicious keywords in URL: ${words.slice(0, 5).join(", ")}`);
  }
  if (!f.uses_https) reasons.push("Connection is not encrypted (no HTTPS)");
  if (f.url_length > 75) reasons.push(`Very long URL (${f.url_length} characters)`);
  if (f.num_percent_encoded >= 3 || f.has_punycode || f.has_hex_or_unicode_chars) {
    reasons.push("URL contains encoded or look-alike characters");
  }

  if (signals && signals.hasPassword && !f.uses_https) {
    score += W.passwordOnHttp;
    reasons.push("Page asks for a password over an unencrypted (HTTP) connection");
  }

  if (intel && typeof intel.ageDays === "number") {
    const d = intel.ageDays;
    const add = d < 7 ? W.age7 : d < 30 ? W.age30 : d < 90 ? W.age90 : 0;
    if (add) {
      score += add;
      reasons.push(`Domain was registered only ${d} day${d === 1 ? "" : "s"} ago`);
    }
  }

  score = Math.max(0, Math.min(100, Math.round(score)));
  if (!reasons.length) reasons.push("No suspicious characteristics found in the URL");
  const level = levelFor(score);
  return { score, level: level.key, levelLabel: level.label, color: level.color, reasons };
}
