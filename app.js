const $ = (id) => document.getElementById(id);

const SUSPICIOUS_WORDS = [
  "login", "signin", "sign-in", "verify", "verification", "account", "update",
  "secure", "security", "banking", "bank", "confirm", "password", "paypal",
  "wallet", "suspend", "suspended", "unlock", "billing", "invoice", "payment",
  "support", "alert", "authenticate", "recover", "credential", "free", "bonus"
];

function parseInput(raw) {
  const trimmed = raw.trim();
  if (!trimmed) throw new Error("Enter a URL to scan.");
  let url;
  try {
    url = new URL(/^[a-zA-Z][a-zA-Z\d+.-]*:\/\//.test(trimmed) ? trimmed : `http://${trimmed}`);
  } catch {
    throw new Error("That URL doesn't look valid. Try something like https://example.com.");
  }
  if (!["http:", "https:"].includes(url.protocol)) {
    throw new Error("For this demo, enter a URL beginning with http:// or https://.");
  }
  if (!url.hostname || !url.hostname.includes(".") && url.hostname !== "localhost") {
    throw new Error("Enter a complete hostname, such as example.com.");
  }
  return url;
}

function analyze(raw) {
  const u = parseInput(raw);
  const full = `${u.hostname}${u.pathname}${u.search}${u.hash}`.toLowerCase();
  const host = u.hostname.toLowerCase();
  const isIPv4 = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(host);
  const words = SUSPICIOUS_WORDS.filter(w => full.includes(w));
  const subdomains = isIPv4 ? 0 : Math.max(0, host.split(".").length - 2);
  const dots = (full.match(/\./g) || []).length;
  const hyphens = (full.match(/-/g) || []).length;
  const atSymbol = raw.includes("@");
  const longUrl = raw.length > 75;
  const nonHttps = u.protocol !== "https:";
  const encoded = /%[0-9a-f]{2}/i.test(full);
  const punycode = host.includes("xn--");

  // Educational heuristic only. This is not the project's trained Random Forest model.
  let score = 5;
  const reasons = [];
  const add = (points, reason) => { score += points; reasons.push(reason); };
  if (isIPv4) add(30, "The hostname is a raw IP address rather than a conventional domain.");
  if (atSymbol) add(25, "The URL contains '@', which can obscure the apparent destination.");
  if (nonHttps) add(10, "The URL uses HTTP rather than HTTPS.");
  if (words.length) add(Math.min(24, words.length * 8), `Potentially deceptive terms appear in the URL: ${words.slice(0, 5).join(", ")}.`);
  if (subdomains >= 3) add(12, `The hostname has several subdomain levels (${subdomains}).`);
  if (dots >= 5 || hyphens >= 4) add(10, "The URL contains an unusually high number of dots or hyphens.");
  if (host.length > 30) add(8, "The hostname is unusually long.");
  if (longUrl) add(8, "The URL is unusually long.");
  if (encoded || punycode) add(12, "The URL contains encoded or punycode characters that deserve closer inspection.");
  score = Math.max(0, Math.min(100, score));
  if (!reasons.length) reasons.push("No warning signs from this demo's simple URL checks were detected.");
  const level = score <= 20 ? ["Low", "#6ce5d2"] : score <= 40 ? ["Guarded", "#e6c76b"] : score <= 60 ? ["Medium", "#ffad66"] : score <= 80 ? ["High", "#ff7c70"] : ["Critical", "#ff4d6d"];
  return {
    host: u.hostname,
    score,
    level: level[0],
    color: level[1],
    reasons,
    indicators: [
      ["Protocol", u.protocol.replace(":", "").toUpperCase()],
      ["URL length", `${raw.trim().length} chars`],
      ["IP address host", isIPv4 ? "Yes" : "No"],
      ["HTTPS", nonHttps ? "No" : "Yes"],
      ["Subdomain levels", String(subdomains)],
      ["Suspicious terms", String(words.length)],
      ["@ symbol", atSymbol ? "Present" : "Absent"],
      ["Encoded / punycode", encoded || punycode ? "Present" : "Not detected"]
    ]
  };
}

function render(result) {
  $("result").hidden = false;
  $("score").textContent = result.score;
  $("scoreRing").style.setProperty("--score", result.score);
  $("scoreRing").style.setProperty("--ring", result.color);
  $("levelBadge").textContent = result.level;
  $("levelBadge").style.background = result.color;
  $("levelBadge").style.color = "#08111b";
  $("resultTitle").textContent = result.score > 60 ? "Exercise caution" : result.score > 30 ? "Review this URL carefully" : "Few warning signs detected";
  $("summary").textContent = "This result is based on visible URL patterns only.";
  $("host").textContent = result.host;
  $("reasons").replaceChildren();
  result.reasons.forEach(text => {
    const li = document.createElement("li");
    li.textContent = text;
    $("reasons").append(li);
  });
  $("features").replaceChildren();
  result.indicators.forEach(([label, value]) => {
    const card = document.createElement("div");
    card.className = "feature";
    const name = document.createElement("span");
    name.textContent = label;
    const val = document.createElement("strong");
    val.textContent = value;
    card.append(name, val);
    $("features").append(card);
  });
  $("result").scrollIntoView({ behavior: "smooth", block: "start" });
}

function scan() {
  $("error").hidden = true;
  try {
    render(analyze($("urlInput").value));
  } catch (e) {
    $("error").textContent = e.message;
    $("error").hidden = false;
    $("result").hidden = true;
  }
}

$("scanBtn").addEventListener("click", scan);
$("urlInput").addEventListener("keydown", e => { if (e.key === "Enter") scan(); });
document.querySelectorAll(".example").forEach(btn => {
  btn.addEventListener("click", () => {
    $("urlInput").value = btn.dataset.url;
    scan();
  });
});
