// Phish Guard - content script.
// 1) Reports a minimal page signal (is there a password field?) to the background worker.
// 2) Shows an in-page warning banner when the background says the page is risky.
// Only the URL and that one boolean leave the page; no page content is collected.
(() => {
  if (window.top !== window) return;

  const hasPassword = () => !!document.querySelector('input[type="password"]');
  let banner = null;

  function el(tag, props = {}, ...kids) {
    const n = document.createElement(tag);
    Object.assign(n, props);
    kids.forEach((k) => n.append(k));
    return n;
  }

  function showBanner(r) {
    if (banner) return;
    const host = el("div");
    host.id = "phish-guard-banner";
    host.style.cssText = "all:initial;position:fixed;top:0;left:0;right:0;z-index:2147483647;";
    const root = host.attachShadow({ mode: "closed" });

    const style = el("style");
    style.textContent = `
      .bar{font:14px/1.45 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;color:#fff;background:${r.color};
           padding:12px 16px;box-shadow:0 2px 12px rgba(0,0,0,.35);display:flex;gap:16px;align-items:flex-start}
      .main{flex:1;min-width:0} h1{font-size:15px;margin:0 0 4px;font-weight:700}
      ul{margin:4px 0 0;padding-left:18px} li{margin:1px 0}
      .btns{display:flex;gap:8px;flex-wrap:wrap}
      button{font:inherit;font-weight:600;border:0;border-radius:6px;padding:6px 12px;cursor:pointer;background:#fff;color:#222}
      button.ghost{background:rgba(255,255,255,.2);color:#fff}`;

    const reasons = el("ul");
    r.reasons.slice(0, 4).forEach((t) => reasons.append(el("li", { textContent: t })));

    const leave = el("button", { textContent: "Leave this page" });
    leave.onclick = () => (history.length > 1 ? history.back() : (location.href = "about:blank"));
    const dismiss = el("button", { className: "ghost", textContent: "Dismiss" });
    dismiss.onclick = () => { host.remove(); banner = null; };
    const trust = el("button", { className: "ghost", textContent: "Trust this site" });
    trust.onclick = () => {
      chrome.runtime.sendMessage({ type: "TRUST", host: r.host }, () => { host.remove(); banner = null; });
    };

    root.append(style, el("div", { className: "bar" },
      el("div", { className: "main" },
        el("h1", { textContent: `\u26A0 Phish Guard: ${r.levelLabel} risk (${r.score}/100) \u2013 this page may be a phishing site` }),
        el("div", { textContent: "Don't enter passwords, card numbers or other personal information here." }),
        reasons),
      el("div", { className: "btns" }, leave, dismiss, trust)));

    (document.documentElement || document.body).append(host);
    banner = host;
  }

  function report() {
    chrome.runtime.sendMessage(
      { type: "PAGE_READY", url: location.href, signals: { hasPassword: hasPassword() } },
      (resp) => {
        if (chrome.runtime.lastError || !resp) return;
        if (resp.show) showBanner(resp.result);
      }
    );
  }

  report();
  // Login forms are often rendered late by JavaScript - check once more.
  if (!hasPassword()) setTimeout(() => { if (hasPassword()) report(); }, 3000);
})();
