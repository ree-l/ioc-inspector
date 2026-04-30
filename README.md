<div align="center">

# 🔍 IOC Inspector

**Multi-source URL & IP threat intelligence lookup for security professionals.**

A fast, minimalist Chrome / Edge extension that queries 6 threat intel APIs in parallel — plus quick-link to 8 more lookup sites that don't offer public APIs.

[![Chrome Web Store](https://img.shields.io/badge/Chrome-Install-2547D0?logo=googlechrome&logoColor=white)](#) · [![Edge Add-ons](https://img.shields.io/badge/Edge-Install-0078D4?logo=microsoftedge&logoColor=white)](#) · [![License: MIT](https://img.shields.io/badge/License-MIT-0F8782.svg)](LICENSE)

[Install](#install) · [Features](#features) · [Privacy](#privacy) · [API keys](#free-api-keys)

</div>

---

## Features

**API-based sources (queried in parallel):**

| Source | Free? | Limits |
|---|---|---|
| VirusTotal | API key | 4 req/min, 500/day |
| AbuseIPDB | API key (IP only) | 1,000/day |
| URLScan.io | No key | ~1,000/day |
| AlienVault OTX | No key | ~10,000/hr |
| abuse.ch ThreatFox | API key | Generous |
| abuse.ch URLHaus | API key (same as above) | Generous |

**Manual lookup sources** (one-click open in new tab):

Cisco Talos · IPVoid / URLVoid · MXToolBox · CrowdSec · RST Cloud · ThreatBook · IBM X-Force Exchange · Scamalytics

**Workflow tools:**

- 🚦 Color-coded verdicts (clean / suspicious / malicious)
- 🌓 Light & dark themes (turquoise / forest green)
- 🕘 Last 10 searches cached — re-view without burning API quota
- 🚀 "OPEN ALL" button launches every manual lookup in background tabs
- 📋 Export as formatted text, PNG, or PDF
- 🖱️ Right-click context menu: highlight any URL/IP → "Inspect with IOC Inspector"
- 🌐 Auto-fills with the current tab's hostname

---

## Install

**Stable releases:**
- 🟦 Chrome Web Store: _link will appear here once approved_
- 🟪 Microsoft Edge Add-ons: _link will appear here once approved_

**Manual install (developer mode):**
1. [Download the latest release ZIP](../../releases/latest)
2. Unzip
3. `chrome://extensions/` → Developer mode → Load unpacked → select unzipped folder
4. Pin to toolbar

---

## Free API keys

All keys are free. Register and paste them into the extension's settings page:

- **VirusTotal:** [virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey)
- **AbuseIPDB:** [abuseipdb.com/account/api](https://www.abuseipdb.com/account/api)
- **abuse.ch (ThreatFox + URLHaus):** [auth.abuse.ch](https://auth.abuse.ch) — one key for both sources

URLScan.io and AlienVault OTX work without keys.

---

## Privacy

- ✅ **No analytics**, no telemetry, no tracking
- ✅ **No third-party servers** — API calls go directly from your browser to the threat intel providers
- ✅ **Bring your own keys** — never harvested, never shared
- ✅ **Open source** — read the code yourself

Full [Privacy Policy](https://ree-l.github.io/ioc-inspector/privacy.html).

---

## Roadmap

- [ ] Web version (GitHub Pages + serverless proxy) for environments where extensions aren't allowed
- [ ] Hash lookup support (MD5 / SHA256)
- [ ] Bulk indicator scanning
- [ ] Customizable verdict thresholds
- [ ] Firefox version

---

## Development

```bash
git clone https://github.com/ree-l/ioc-inspector
cd ioc-inspector
# Load `ioc-inspector` folder via chrome://extensions Developer mode
```

PRs welcome. Open an issue first for substantial changes.

---

<div align="center">

Built by **RYMANTECH** for security professionals.

Released under the [MIT License](LICENSE).

</div>
