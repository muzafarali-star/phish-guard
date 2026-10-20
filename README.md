# Phish Guard - AI-Powered Phishing Website Detection (Chrome / Edge, Manifest V3)

## Install (Chrome or Edge)
1. Open `chrome://extensions` (Edge: `edge://extensions`) and turn on **Developer mode**.
2. Click **Load unpacked** and select this `phish-guard` folder.
3. Visit a page - the toolbar badge shows the 0-100 risk score; click the icon for details.

## IMPORTANT: replace the demo model
`model/model.json` is a **placeholder trained on synthetic data** so the extension runs out of the box.
Run `phish_guard_training.ipynb` in Google Colab, download the `model.json` it produces, and overwrite
`model/model.json`. Then press the reload icon on the extension card. The popup's "demo model" warning
disappears automatically for a real model.

## How it maps to the project spec
| Spec component | File |
|---|---|
| manifest.json (Manifest V3) | `manifest.json` |
| Background service worker | `background.js` |
| Popup interface | `popup/popup.html`, `popup.css`, `popup.js` |
| Content script (in-page warning banner) | `content.js` |
| JavaScript detection logic (URL features) | `lib/features.js` |
| ML model / resources (Random Forest in JS) | `lib/model.js`, `model/model.json` |
| Threat intelligence | `lib/intel.js`, `data/blocklist.json` |
| Risk engine (0-100, Safe/Low/Medium/High/Critical) | `lib/risk.js` |
| User warning + reasons | notification (`background.js`) + banner (`content.js`) |

Flow: Browser -> Extension -> URL feature extraction -> ML model -> Threat intelligence -> Risk engine -> Warning/Dashboard.

## Risk score
`score = ML phishing probability x 100`, then adjusted: blocklisted domain -> 100; domain younger than
7 / 30 / 90 days -> +25 / +15 / +5 (needs online lookups); password field on an HTTP page -> +10. Capped at 0-100.
Levels: 0-20 Safe, 21-40 Low, 41-60 Medium, 61-80 High, 81-100 Critical. Weights are in `lib/risk.js`.
A warning (notification + banner) appears when the score reaches your chosen threshold (default 61 = High).

## Privacy
- URL analysis and the model run **locally**; nothing is sent anywhere by default.
- The content script sends the page URL and one boolean (is there a password field) to the extension's own
  background worker only.
- **Online threat-intel lookups are off by default.** If you enable them in the popup (the browser asks for
  permission), the site's domain name is sent to `rdap.org` (registration date) and `dns.google` (DNS info).

## Limitations (be honest in your report)
- **SSL/TLS certificate info** is not available to Manifest V3 extensions in Chrome/Edge, so it is not used.
- **DNS info** is shown but does not change the score. **WHOIS** is done via RDAP (works for most, not all, TLDs).
- `data/blocklist.json` ships **empty**; add known-malicious domains or hook up a feed.
- A URL-only model can be fooled (new look-alike domains, legit sites on odd URLs) - expect false positives and
  negatives. Use "Trust this site" for false alarms. Evaluate on fresh URLs you collect yourself.
- `lib/features.js` must stay identical to the Python feature code used for training; if you change features,
  retrain and replace `model.json`.
