// ── Service definitions ──────────────────────────────────────────────────
const ALL_SERVICES = [
  // API-based
  { key: "virustotal", name: "VirusTotal",     needsKey: true,  type: "api" },
  { key: "abuseipdb",  name: "AbuseIPDB",      needsKey: true,  type: "api", ipOnly: true },
  { key: "urlscan",    name: "URLScan.io",     needsKey: false, type: "api" },
  { key: "otx",        name: "AlienVault OTX", needsKey: false, type: "api" },
  { key: "threatfox",  name: "ThreatFox",      needsKey: true,  type: "api", keyName: "abusech" },
  { key: "urlhaus",    name: "URLHaus",        needsKey: true,  type: "api", keyName: "abusech" },

  // Manual links
  { key: "talos",       name: "Cisco Talos",         type: "manual" },
  { key: "ipvoid",      name: "IPVoid / URLVoid",    type: "manual" },
  { key: "mxtool",      name: "MXToolBox",           type: "manual" },
  { key: "crowdsec",    name: "CrowdSec",            type: "manual" },
  { key: "rstcloud",    name: "RST Cloud",           type: "manual" },
  { key: "threatbook",  name: "ThreatBook",          type: "manual" },
  { key: "xforce",      name: "X-Force Exchange",    type: "manual" },
  { key: "scamalytics", name: "Scamalytics", type: "manual", ipOnly: true },
];

const isIP = (s) => /^(\d{1,3}\.){3}\d{1,3}$/.test(s.trim());

// Storage keys
const LAST_SEARCH_KEY = "last_search";
const RECENTS_KEY = "recent_searches";
const ENABLED_KEY = "enabled_services";
const THEME_KEY = "theme";
const MAX_RECENTS = 10;

// ── DOM refs ──────────────────────────────────────────────────────────────
const $input    = document.getElementById("indicator");
const $btn      = document.getElementById("scan-btn");
const $clearBtn = document.getElementById("clear-btn");
const $copyInputBtn = document.getElementById("copy-input-btn");
const $recentsBtn = document.getElementById("recents-btn");
const $recents  = document.getElementById("recents-dropdown");
const $results  = document.getElementById("results");
const $hint     = document.getElementById("type-hint");
const $options  = document.getElementById("open-options");
const $toolbar  = document.getElementById("results-toolbar");
const $meta     = document.getElementById("results-meta");
const $copyBtn  = document.getElementById("copy-btn");
const $openManualBtn = document.getElementById("open-manual-btn");
const $pngBtn   = document.getElementById("png-btn");
const $pdfBtn   = document.getElementById("pdf-btn");
const $themeBtn = document.getElementById("theme-toggle");

// ── State ─────────────────────────────────────────────────────────────────
let currentResults = null;
let currentIndicator = "";
let currentTimestamp = 0;
let enabledServices = null;
let SERVICES = ALL_SERVICES;

// ── SVG icons (Edge-style) ────────────────────────────────────────────────
const ICONS = {
  // Two stacked papers — Microsoft Edge / Office "Copy" style
  copy: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V6a2 2 0 0 1 2-2h9"/></svg>`,
  check: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>`,
  sun: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"/></svg>`,
  moon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>`,
};

// ── Init ──────────────────────────────────────────────────────────────────
$copyInputBtn.innerHTML = ICONS.copy;
$copyBtn.innerHTML = ICONS.copy + '<span>COPY</span>';
// Set theme icon immediately (defaults to moon = "go to dark"); applyTheme()
// will update it once we read the stored preference.
$themeBtn.innerHTML = ICONS.moon;
$themeBtn.title = "Switch to dark mode";

$options.addEventListener("click", (e) => { e.preventDefault(); chrome.runtime.openOptionsPage(); });
$input.addEventListener("input", onInputChange);
$input.addEventListener("keydown", (e) => {
  if (e.key === "Enter") run();
  if (e.key === "Escape") hideRecents();
});
$btn.addEventListener("click", run);
$clearBtn.addEventListener("click", clearAll);
$copyInputBtn.addEventListener("click", copyInputValue);
$recentsBtn.addEventListener("click", toggleRecents);
$copyBtn.addEventListener("click", copyAllResults);
$pngBtn.addEventListener("click", exportPNG);
$pdfBtn.addEventListener("click", exportPDF);
$openManualBtn.addEventListener("click", openAllManual);
$themeBtn.addEventListener("click", toggleTheme);

// Hide recents on outside click
document.addEventListener("click", (e) => {
  if (!$recents.contains(e.target) && e.target !== $recentsBtn) hideRecents();
});

(async () => {
  // Load theme
  const themeData = await chrome.storage.sync.get(THEME_KEY);
  applyTheme(themeData[THEME_KEY] || "light");

  // Load enabled services
  const cfg = await chrome.storage.sync.get(ENABLED_KEY);
  enabledServices = cfg[ENABLED_KEY] || null;
  SERVICES = enabledServices
    ? ALL_SERVICES.filter(s => enabledServices.includes(s.key))
    : ALL_SERVICES;

  updateSubtitle();

  // Pre-fill priority: pending_lookup > last_search > current tab hostname
  const { pending_lookup } = await chrome.storage.local.get("pending_lookup");
  if (pending_lookup) {
    $input.value = pending_lookup;
    await chrome.storage.local.remove("pending_lookup");
    onInputChange();
    setTimeout(() => run(), 100);
    return;
  }

  const stored = await chrome.storage.local.get(LAST_SEARCH_KEY);
  const last = stored[LAST_SEARCH_KEY];
  if (last && last.indicator) {
    $input.value = last.indicator;
    onInputChange();
    if (last.results && last.timestamp) {
      restoreResults(last);
      return;
    }
  }

  chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
    if (tab?.url) {
      try {
        const url = new URL(tab.url);
        if (!["chrome:", "edge:", "about:", "chrome-extension:"].includes(url.protocol)) {
          if (!$input.value) { $input.value = url.hostname; $input.select(); onInputChange(); }
        }
      } catch {}
    }
  });
})();

function applyTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);
  $themeBtn.innerHTML = theme === "dark" ? ICONS.sun : ICONS.moon;
  $themeBtn.title = theme === "dark" ? "Switch to light mode" : "Switch to dark mode";
}
async function toggleTheme() {
  const current = document.documentElement.getAttribute("data-theme") || "light";
  const next = current === "light" ? "dark" : "light";
  applyTheme(next);
  await chrome.storage.sync.set({ [THEME_KEY]: next });
}

function updateSubtitle() {
  const sub = document.getElementById("subtitle");
  const apiCount = SERVICES.filter(s => s.type === "api").length;
  const manualCount = SERVICES.filter(s => s.type === "manual").length;
  sub.textContent = `${apiCount} API source${apiCount===1?"":"s"} · ${manualCount} manual lookup${manualCount===1?"":"s"}`;
}

function onInputChange() {
  const v = $input.value.trim();
  $copyInputBtn.hidden = !v;
  if (!v) { $hint.innerHTML = ""; return; }
  const ip = isIP(v);
  $hint.innerHTML = `type: <span class="type-value">${ip ? "IPv4 address" : "URL / domain"}</span>` +
    (!ip ? ` <span class="type-note">· some IP-only sources skipped</span>` : "");
}

async function copyInputValue() {
  const v = $input.value.trim();
  if (!v) return;
  try {
    await navigator.clipboard.writeText(v);
    $copyInputBtn.innerHTML = ICONS.check;
    $copyInputBtn.classList.add("copied");
    setTimeout(() => { $copyInputBtn.innerHTML = ICONS.copy; $copyInputBtn.classList.remove("copied"); }, 1200);
  } catch {}
}

function clearAll() {
  $input.value = ""; $hint.innerHTML = "";
  $results.innerHTML = ""; $toolbar.hidden = true;
  $copyInputBtn.hidden = true;
  currentResults = null; currentIndicator = ""; currentTimestamp = 0;
  chrome.storage.local.remove(LAST_SEARCH_KEY);
  $input.focus();
}

// ── Recents ───────────────────────────────────────────────────────────────
function toggleRecents() { if (!$recents.hidden) hideRecents(); else showRecents(); }
function hideRecents() { $recents.hidden = true; }

async function showRecents() {
  const data = await chrome.storage.local.get(RECENTS_KEY);
  const items = data[RECENTS_KEY] || [];

  $recents.innerHTML = `
    <div class="recents-dropdown-header">
      <span>recent searches · ${items.length}/${MAX_RECENTS}</span>
      ${items.length ? '<button id="recents-clear">clear all</button>' : ""}
    </div>
    ${items.length === 0
      ? '<div class="recents-empty">no recent searches yet</div>'
      : items.map((item, idx) => {
          const verdictDots = computeVerdictDots(item.results);
          return `
            <div class="recent-item" data-idx="${idx}">
              <div class="recent-item-main">
                <span class="recent-item-target">${escapeHtml(item.indicator)}</span>
                <span class="recent-item-meta">${formatAge(item.timestamp)} · ${isIP(item.indicator) ? "IP" : "URL/domain"}</span>
              </div>
              <div class="recent-verdict-summary">${verdictDots}</div>
            </div>
          `;
        }).join("")
    }
  `;
  $recents.hidden = false;

  $recents.querySelectorAll(".recent-item").forEach(el => {
    el.addEventListener("click", () => loadRecent(items[+el.dataset.idx]));
  });
  const clearBtn = document.getElementById("recents-clear");
  if (clearBtn) {
    clearBtn.addEventListener("click", async (e) => {
      e.stopPropagation();
      await chrome.storage.local.remove(RECENTS_KEY);
      hideRecents();
    });
  }
}

function computeVerdictDots(results) {
  if (!results) return "";
  return SERVICES.filter(s => s.type === "api").map(svc => {
    const r = results[svc.key];
    if (!r || r.skipped) return "";
    const v = r.error ? "unknown" : (r.data?.verdict || "unknown");
    return `<span class="mini-dot ${v}" title="${svc.name}: ${v}"></span>`;
  }).join("");
}

function formatAge(timestamp) {
  const min = Math.floor((Date.now() - timestamp) / 60000);
  if (min < 1) return "just now";
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h ago`;
  return `${Math.floor(hr / 24)}d ago`;
}

async function loadRecent(item) {
  hideRecents();
  $input.value = item.indicator;
  onInputChange();
  restoreResults(item);
}

async function pushToRecents(indicator, results, timestamp) {
  const data = await chrome.storage.local.get(RECENTS_KEY);
  let recents = data[RECENTS_KEY] || [];
  recents = recents.filter(r => r.indicator !== indicator);
  recents.unshift({ indicator, results, timestamp });
  if (recents.length > MAX_RECENTS) recents = recents.slice(0, MAX_RECENTS);
  await chrome.storage.local.set({ [RECENTS_KEY]: recents });
}

// ── Run ───────────────────────────────────────────────────────────────────
async function run() {
  const indicator = $input.value.trim();
  if (!indicator) return;
  hideRecents();

  $btn.disabled = true;
  $btn.textContent = "SCANNING...";
  $results.innerHTML = "";
  $toolbar.hidden = true;
  currentResults = {};
  currentIndicator = indicator;
  currentTimestamp = Date.now();

  const { virustotal_key = "", abuseipdb_key = "", abusech_key = "" } = await chrome.storage.sync.get([
    "virustotal_key", "abuseipdb_key", "abusech_key"
  ]);
  const keys = {
    virustotal: virustotal_key,
    abuseipdb: abuseipdb_key,
    threatfox: abusech_key,
    urlhaus: abusech_key,
  };

  if (!virustotal_key && SERVICES.some(s => s.key === "virustotal")) {
    showWarning("VirusTotal API key not set. Click ⚙ settings to add one (free).");
  }

  const ip = isIP(indicator);

  // Render placeholder cards
  const cards = {};
  for (const svc of SERVICES) {
    const card = renderPlaceholder(svc);
    cards[svc.key] = card;
    $results.appendChild(card);
  }

  // Manual services: render link immediately
  for (const svc of SERVICES.filter(s => s.type === "manual")) {
    if (svc.ipOnly && !ip) {
      const $status = cards[svc.key].querySelector(".svc-status");
      $status.innerHTML = `<span class="skip-text">IP only</span>`;
      currentResults[svc.key] = { skipped: "IP only", manual: true };
    } else {
      renderManual(cards[svc.key], svc, indicator, ip);
      currentResults[svc.key] = { manual: true };
    }
  }

  // API queries in parallel
  await Promise.all(SERVICES.filter(s => s.type === "api").map(async (svc) => {
    try {
      if (svc.ipOnly && !ip) {
        updateCard(cards[svc.key], svc, indicator, { skip: "URLs not supported" });
        currentResults[svc.key] = { skipped: "URLs not supported" };
        return;
      }
      if (svc.needsKey && !keys[svc.key]) {
        updateCard(cards[svc.key], svc, indicator, { skip: "no API key" });
        currentResults[svc.key] = { skipped: "no API key" };
        return;
      }

      const data = await queryService(svc.key, indicator, ip, keys[svc.key]);
      updateCard(cards[svc.key], svc, indicator, { data });
      currentResults[svc.key] = { data };
    } catch (e) {
      const errMsg = e.message || "request failed";
      updateCard(cards[svc.key], svc, indicator, { error: errMsg });
      currentResults[svc.key] = { error: errMsg };
    }
  }));

  $btn.disabled = false;
  $btn.textContent = "SCAN";

  $toolbar.hidden = false;
  $meta.innerHTML = `results · <span class="target">${escapeHtml(indicator)}</span>`;

  // Show "OPEN ALL" only if there are usable manual links
  const hasUsableManual = SERVICES.some(s => s.type === "manual" && (!s.ipOnly || ip));
  $openManualBtn.hidden = !hasUsableManual;

  await chrome.storage.local.set({
    [LAST_SEARCH_KEY]: { indicator, results: currentResults, timestamp: currentTimestamp },
  });
  await pushToRecents(indicator, currentResults, currentTimestamp);
}

function showWarning(msg) {
  const div = document.createElement("div");
  div.className = "global-error";
  div.textContent = "⚠ " + msg;
  $results.appendChild(div);
}

// ── Restore ───────────────────────────────────────────────────────────────
function restoreResults(stored) {
  currentIndicator = stored.indicator;
  currentResults = stored.results;
  currentTimestamp = stored.timestamp;

  $results.innerHTML = "";
  $toolbar.hidden = false;
  $meta.innerHTML = `last scan · <span class="target">${escapeHtml(stored.indicator)}</span> · ${formatAge(stored.timestamp)}`;

  const ip = isIP(stored.indicator);
  for (const svc of SERVICES) {
    const card = renderPlaceholder(svc);
    $results.appendChild(card);
    const r = stored.results[svc.key];
    if (svc.type === "manual") {
      if (svc.ipOnly && !ip) {
        card.querySelector(".svc-status").innerHTML = `<span class="skip-text">IP only</span>`;
      } else {
        renderManual(card, svc, stored.indicator, ip);
      }
    } else if (!r) updateCard(card, svc, stored.indicator, { skip: "(not run)" });
    else if (r.skipped) updateCard(card, svc, stored.indicator, { skip: r.skipped });
    else if (r.error) updateCard(card, svc, stored.indicator, { error: r.error });
    else if (r.data) updateCard(card, svc, stored.indicator, { data: r.data });
  }

  const hasUsableManual = SERVICES.some(s => s.type === "manual" && (!s.ipOnly || ip));
  $openManualBtn.hidden = !hasUsableManual;
}

// ── Rendering ─────────────────────────────────────────────────────────────
function renderPlaceholder(svc) {
  const card = document.createElement("div");
  card.className = "result-card";
  const manualBadge = svc.type === "manual" ? '<span class="svc-badge-manual">manual</span>' : "";
  card.innerHTML = `
    <div class="result-header">
      <div class="svc-name">
        <div class="svc-bar ${svc.key}"></div>
        <span class="svc-label">${svc.name}</span>
        ${manualBadge}
      </div>
      <div class="svc-status">
        ${svc.type === "api" ? `<span class="spinner ${svc.key}"></span>` : ""}
      </div>
    </div>
    <div class="result-body"></div>
  `;
  return card;
}

function renderManual(card, svc, indicator, isIpAddr) {
  const $status = card.querySelector(".svc-status");
  const target = isIpAddr ? indicator : indicator.replace(/^https?:\/\//, "").split("/")[0];
  const link = manualLinkFor(svc.key, target, isIpAddr);
  const pasteNeeded = needsManualPaste(svc.key, isIpAddr);

  if (pasteNeeded) {
    // Use a plain href as a fallback for accessibility (right-click "Open in
    // new tab" still works), but intercept normal clicks: we need to copy to
    // the clipboard BEFORE the tab opens, otherwise the popup loses focus
    // and the clipboard write fails silently.
    $status.innerHTML = `<a class="manual-link manual-link-paste" href="${escapeHtml(link)}" target="_blank" rel="noreferrer" title="Indicator copied to clipboard — paste it once the page loads">open + copy ↗</a>`;
    $status.querySelector("a").addEventListener("click", async (e) => {
      // Allow modifier-key opens (Ctrl/Cmd/Shift/middle-click) to behave normally.
      if (e.metaKey || e.ctrlKey || e.shiftKey || e.button === 1) return;
      e.preventDefault();
      try { await navigator.clipboard.writeText(target); } catch {}
      chrome.tabs.create({ url: link, active: true });
    });
  } else {
    $status.innerHTML = `<a class="manual-link" href="${escapeHtml(link)}" target="_blank" rel="noreferrer">open ↗</a>`;
  }
}

// Some sites don't support URL-parameter deeplinking (their search uses POST
// forms). For those, we copy the indicator to clipboard so the user can just
// paste it once the page loads.
function needsManualPaste(key, isIpAddr) {
  // IPVoid's IP blacklist check uses a POST form — query params are ignored.
  if (key === "ipvoid" && isIpAddr) return true;
  return false;
}

function manualLinkFor(key, target, isIpAddr) {
  switch (key) {
    case "talos":
      return `https://talosintelligence.com/reputation_center/lookup?search=${encodeURIComponent(target)}`;
    case "ipvoid":
      return isIpAddr
        ? `https://www.ipvoid.com/ip-blacklist-check/`
        : `https://www.urlvoid.com/scan/${encodeURIComponent(target)}/`;
    case "mxtool":
      return isIpAddr
        ? `https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a${encodeURIComponent(target)}&run=toolpage`
        : `https://mxtoolbox.com/SuperTool.aspx?action=mx%3a${encodeURIComponent(target)}&run=toolpage`;
    case "crowdsec":
      return isIpAddr
        ? `https://app.crowdsec.net/cti/${encodeURIComponent(target)}`
        : `https://app.crowdsec.net/cti?q=${encodeURIComponent(target)}`;
    case "rstcloud":
      return `https://www.rstcloud.com/ioc-lookup-results/?search=${encodeURIComponent(target)}`;
    case "threatbook":
      return isIpAddr
        ? `https://threatbook.io/ip/${encodeURIComponent(target)}`
        : `https://threatbook.io/domain/${encodeURIComponent(target)}`;
    case "xforce":
      return isIpAddr
        ? `https://exchange.xforce.ibmcloud.com/ip/${encodeURIComponent(target)}`
        : `https://exchange.xforce.ibmcloud.com/url/${encodeURIComponent(target)}`;
    case "scamalytics":
      return `https://scamalytics.com/ip/${encodeURIComponent(target)}`;
  }
  return "#";
}

function updateCard(card, svc, indicator, { data, error, skip }) {
  const $status = card.querySelector(".svc-status");
  const $body   = card.querySelector(".result-body");

  if (error) {
    $status.innerHTML = `<span class="error-text" title="${escapeHtml(error)}">${escapeHtml(error)}</span>`;
    return;
  }
  if (skip) {
    $status.innerHTML = `<span class="skip-text">${escapeHtml(skip)}</span>`;
    return;
  }

  const verdict = data.verdict || "unknown";
  card.classList.add("expandable", `verdict-${verdict}`);

  $status.innerHTML = `
    <span class="dot ${verdict}"></span>
    <span class="chip ${verdict}">${verdict}</span>
    <span class="chevron">▼</span>
  `;

  const rows = (data.details || []).filter(([, v]) => v != null && v !== "");
  $body.innerHTML = rows.map(([label, value]) => `
    <div class="detail-row">
      <span class="detail-label">${escapeHtml(label)}</span>
      <span class="detail-value">${escapeHtml(String(value))}</span>
    </div>
  `).join("") + (data.link ? `
    <a class="report-link" href="${escapeHtml(data.link)}" target="_blank" rel="noreferrer">
      → view full report
    </a>
  ` : "");

  card.querySelector(".result-header").addEventListener("click", () => {
    card.classList.toggle("open");
    const chev = card.querySelector(".chevron");
    if (chev) chev.textContent = card.classList.contains("open") ? "▲" : "▼";
  });
}

// ── Open all manual lookups in background tabs ───────────────────────────
async function openAllManual() {
  if (!currentIndicator) return;
  const ip = isIP(currentIndicator);
  const target = ip ? currentIndicator : currentIndicator.replace(/^https?:\/\//, "").split("/")[0];

  const manualSvcs = SERVICES.filter(s => s.type === "manual" && (!s.ipOnly || ip));
  if (manualSvcs.length === 0) return;

  // If any paste-needed source is included, copy the indicator to clipboard
  // so the user can paste it into those forms after they load.
  const anyPasteNeeded = manualSvcs.some(s => needsManualPaste(s.key, ip));
  if (anyPasteNeeded) {
    try { await navigator.clipboard.writeText(target); } catch {}
  }

  for (const svc of manualSvcs) {
    const url = manualLinkFor(svc.key, target, ip);
    chrome.tabs.create({ url, active: false });
  }
  flashButton($openManualBtn, `✓ ${manualSvcs.length} TABS`);
}

// ── Copy / Export ─────────────────────────────────────────────────────────
function buildTextReport() {
  if (!currentResults || !currentIndicator) return "";

  const lines = [];
  lines.push(`IOC INSPECTOR REPORT`);
  lines.push(`====================`);
  lines.push(`Indicator: ${currentIndicator}`);
  lines.push(`Type: ${isIP(currentIndicator) ? "IPv4 address" : "URL / domain"}`);
  lines.push(`Scanned: ${new Date(currentTimestamp).toLocaleString()}`);
  lines.push(``);

  // Only API services in the report body
  for (const svc of SERVICES.filter(s => s.type === "api")) {
    const r = currentResults[svc.key];
    lines.push(`── ${svc.name} ${"─".repeat(Math.max(0, 36 - svc.name.length))}`);
    if (!r) lines.push(`  (no data)`);
    else if (r.skipped) lines.push(`  Skipped: ${r.skipped}`);
    else if (r.error) lines.push(`  Error: ${r.error}`);
    else if (r.data) {
      lines.push(`  Verdict: ${(r.data.verdict || "unknown").toUpperCase()}`);
      const rows = (r.data.details || []).filter(([, v]) => v != null && v !== "");
      for (const [label, value] of rows) {
        lines.push(`  ${label.padEnd(18)} ${value}`);
      }
      if (r.data.link) lines.push(`  Report: ${r.data.link}`);
    }
    lines.push(``);
  }
  return lines.join("\n");
}

async function copyAllResults() {
  const text = buildTextReport();
  if (!text) return;
  try {
    await navigator.clipboard.writeText(text);
    flashButton($copyBtn, "✓ COPIED");
  } catch {
    flashButton($copyBtn, "✗ FAILED");
  }
}

function flashButton(btn, msg) {
  const orig = btn.innerHTML;
  btn.innerHTML = msg;
  btn.classList.add("flash");
  setTimeout(() => { btn.innerHTML = orig; btn.classList.remove("flash"); }, 1500);
}

// PNG: render via Canvas, exclude manual services
async function exportPNG() {
  if (!currentResults || !currentIndicator) return;
  flashButton($pngBtn, "...");
  try {
    const canvas = await renderReportCanvas();
    const url = canvas.toDataURL("image/png");
    triggerDownload(url, `ioc-${sanitize(currentIndicator)}-${Date.now()}.png`);
    flashButton($pngBtn, "✓ SAVED");
  } catch (e) {
    console.error("PNG export failed", e);
    flashButton($pngBtn, "✗");
  }
}

// PDF: open print-ready HTML in new tab, exclude manual services
async function exportPDF() {
  if (!currentResults || !currentIndicator) return;
  try {
    const html = buildPrintableHTML();
    const blob = new Blob([html], { type: "text/html" });
    const url = URL.createObjectURL(blob);
    chrome.tabs.create({ url });
    flashButton($pdfBtn, "OPENED");
  } catch (e) {
    console.error("PDF export failed", e);
    flashButton($pdfBtn, "✗");
  }
}

function sanitize(s) {
  return String(s).replace(/[^a-z0-9]+/gi, "-").toLowerCase().slice(0, 40);
}
function triggerDownload(href, filename) {
  const a = document.createElement("a");
  a.href = href; a.download = filename;
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
}

// ── Native Canvas PNG renderer ────────────────────────────────────────────
async function renderReportCanvas() {
  const W = 800;
  const padding = 40;

  // Only API blocks in PNG
  const blocks = computeReportBlocks().filter(b => !b.manual);

  const lineHeight = 20;
  const sectionGap = 16;
  let H = padding;
  H += 60 + 30 + sectionGap;
  for (const blk of blocks) {
    H += 32;
    H += blk.lines.length * lineHeight;
    H += sectionGap;
  }
  H += 40; // footer + brand
  H += padding;

  const dpr = 2;
  const canvas = document.createElement("canvas");
  canvas.width = W * dpr;
  canvas.height = H * dpr;
  const ctx = canvas.getContext("2d");
  ctx.scale(dpr, dpr);

  // Use the ACTIVE theme colors for export
  const styles = getComputedStyle(document.documentElement);
  const c = (k, fallback) => (styles.getPropertyValue(k).trim() || fallback);

  const COL = {
    bg: c("--bg", "#FAFAF7"),
    text: c("--text", "#1F2937"),
    muted: c("--text-muted", "#64748B"),
    faint: c("--text-faint", "#94A3B8"),
    border: c("--border", "#E5E5DC"),
    accent: c("--accent", "#0F8782"),
  };

  ctx.fillStyle = COL.bg;
  ctx.fillRect(0, 0, W, H);

  let y = padding;

  ctx.fillStyle = COL.accent;
  ctx.font = "600 10px 'JetBrains Mono', monospace";
  ctx.textBaseline = "top";
  ctx.fillText("THREAT INTELLIGENCE  ·  IOC INSPECTOR REPORT", padding, y);
  y += 18;

  ctx.fillStyle = COL.text;
  ctx.font = "800 28px 'Syne', sans-serif";
  ctx.fillText(currentIndicator, padding, y);
  y += 32;

  ctx.fillStyle = COL.muted;
  ctx.font = "500 11px 'JetBrains Mono', monospace";
  const meta = `${isIP(currentIndicator) ? "IPv4 ADDRESS" : "URL / DOMAIN"}   ·   scanned: ${new Date(currentTimestamp).toLocaleString()}`;
  ctx.fillText(meta, padding, y);
  y += 24;

  ctx.strokeStyle = COL.border;
  ctx.lineWidth = 1;
  ctx.beginPath(); ctx.moveTo(padding, y); ctx.lineTo(W - padding, y); ctx.stroke();
  y += sectionGap;

  for (const blk of blocks) {
    ctx.fillStyle = blk.color;
    ctx.fillRect(padding, y + 6, 4, 18);

    ctx.fillStyle = COL.text;
    ctx.font = "700 14px 'JetBrains Mono', monospace";
    ctx.fillText(blk.name, padding + 14, y + 6);

    if (blk.verdict) {
      const cx = W - padding;
      const verdictColors = {
        malicious: { bg: c("--malicious-bg", "#FEF2F2"), fg: c("--malicious-text", "#991B1B"), border: c("--malicious-border", "#FCA5A5") },
        suspicious: { bg: c("--suspicious-bg", "#FFFBEB"), fg: c("--suspicious-text", "#92400E"), border: c("--suspicious-border", "#FDE68A") },
        clean: { bg: c("--clean-bg", "#ECFDF5"), fg: c("--clean-text", "#065F46"), border: c("--clean-border", "#A7F3D0") },
        unknown: { bg: c("--unknown-bg", "#F1F5F9"), fg: c("--unknown-text", "#475569"), border: c("--unknown-border", "#CBD5E1") },
      };
      const vc = verdictColors[blk.verdict] || verdictColors.unknown;
      const txt = blk.verdict.toUpperCase();
      ctx.font = "700 10px 'JetBrains Mono', monospace";
      const tw = ctx.measureText(txt).width + 14;
      const th = 18;
      ctx.fillStyle = vc.bg;
      ctx.strokeStyle = vc.border;
      ctx.beginPath();
      ctx.roundRect(cx - tw, y + 6, tw, th, 4);
      ctx.fill(); ctx.stroke();
      ctx.fillStyle = vc.fg;
      ctx.fillText(txt, cx - tw + 7, y + 10);
    }
    y += 32;

    ctx.font = "500 11px 'JetBrains Mono', monospace";
    for (const line of blk.lines) {
      if (line.label) {
        ctx.fillStyle = COL.muted;
        ctx.fillText(line.label, padding + 14, y);
        ctx.fillStyle = COL.text;
        ctx.fillText(String(line.value).substring(0, 80), padding + 150, y);
      } else {
        ctx.fillStyle = COL.faint;
        ctx.fillText(line.value, padding + 14, y);
      }
      y += lineHeight;
    }
    y += sectionGap;
  }

  // Footer with brand
  ctx.strokeStyle = COL.border;
  ctx.beginPath(); ctx.moveTo(padding, y); ctx.lineTo(W - padding, y); ctx.stroke();
  y += 14;
  ctx.fillStyle = COL.faint;
  ctx.font = "500 10px 'JetBrains Mono', monospace";
  ctx.fillText(`Generated ${new Date().toLocaleString()}`, padding, y);
  ctx.fillStyle = COL.accent;
  ctx.font = "700 10px 'Syne', sans-serif";
  const brand = "RYMANTECH";
  const bw = ctx.measureText(brand).width;
  ctx.fillText(brand, W - padding - bw, y);

  return canvas;
}

function computeReportBlocks() {
  const blocks = [];
  // Service-color CSS var per service key
  const colorVarMap = {
    virustotal: "--vt", abuseipdb: "--aip", urlscan: "--us", otx: "--otx",
    threatfox: "--tf", urlhaus: "--uh",
  };
  const styles = getComputedStyle(document.documentElement);

  for (const svc of SERVICES) {
    if (svc.type !== "api") continue;
    const r = currentResults[svc.key];
    const color = (styles.getPropertyValue(colorVarMap[svc.key]) || "").trim() || "#94A3B8";
    const blk = { key: svc.key, name: svc.name, color, verdict: null, lines: [], manual: false };

    if (!r) blk.lines.push({ value: "(not run)" });
    else if (r.skipped) blk.lines.push({ label: "skipped", value: r.skipped });
    else if (r.error) blk.lines.push({ label: "error", value: r.error });
    else if (r.data) {
      blk.verdict = r.data.verdict || "unknown";
      const rows = (r.data.details || []).filter(([, v]) => v != null && v !== "");
      for (const [label, value] of rows) blk.lines.push({ label, value });
      if (r.data.link) blk.lines.push({ label: "report", value: r.data.link });
    }
    blocks.push(blk);
  }
  return blocks;
}

// ── Printable HTML for PDF export ─────────────────────────────────────────
function buildPrintableHTML() {
  const blocks = computeReportBlocks();
  const styles = getComputedStyle(document.documentElement);
  const c = (k, fb) => (styles.getPropertyValue(k).trim() || fb);

  const verdictColors = {
    malicious: { bg: c("--malicious-bg","#FEF2F2"), fg: c("--malicious-text","#991B1B"), border: c("--malicious-border","#FCA5A5") },
    suspicious: { bg: c("--suspicious-bg","#FFFBEB"), fg: c("--suspicious-text","#92400E"), border: c("--suspicious-border","#FDE68A") },
    clean: { bg: c("--clean-bg","#ECFDF5"), fg: c("--clean-text","#065F46"), border: c("--clean-border","#A7F3D0") },
    unknown: { bg: c("--unknown-bg","#F1F5F9"), fg: c("--unknown-text","#475569"), border: c("--unknown-border","#CBD5E1") },
  };

  const title = `IOC Inspector Report — ${currentIndicator}`;
  const dateStr = new Date(currentTimestamp).toLocaleString();
  const bg = c("--bg","#FAFAF7");
  const text = c("--text","#1F2937");
  const muted = c("--text-muted","#64748B");
  const faint = c("--text-faint","#94A3B8");
  const border = c("--border","#E5E5DC");
  const accent = c("--accent","#0F8782");

  return `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"/><title>${escapeHtml(title)}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=Syne:wght@700;800&display=swap');
  body { font-family: 'JetBrains Mono', monospace; background: ${bg}; color: ${text}; margin: 40px; font-size: 11px; }
  .kicker { color: ${accent}; font-size: 9px; letter-spacing: 0.25em; text-transform: uppercase; font-weight: 600; }
  h1 { font-family: 'Syne', sans-serif; font-weight: 800; font-size: 28px; margin: 4px 0 6px; letter-spacing: -0.02em; }
  .meta { color: ${muted}; font-size: 10px; }
  hr { border: none; border-top: 1px solid ${border}; margin: 16px 0; }
  .block { margin-bottom: 18px; page-break-inside: avoid; }
  .block-header { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 8px; }
  .block-title { display: flex; align-items: center; gap: 10px; font-weight: 700; font-size: 13px; }
  .bar { width: 4px; height: 18px; border-radius: 2px; }
  .chip { padding: 2px 8px; font-size: 9px; letter-spacing: 0.06em; text-transform: uppercase; font-weight: 700; border-radius: 4px; border: 1px solid; }
  table { width: 100%; border-collapse: collapse; }
  td { padding: 4px 0; vertical-align: top; }
  td.label { color: ${muted}; font-weight: 500; width: 140px; }
  td.value { color: ${text}; word-break: break-all; }
  .empty { color: ${faint}; font-style: italic; }
  .print-cta { position: fixed; top: 14px; right: 14px; background: ${accent}; color: ${bg}; padding: 10px 18px; border-radius: 6px; font-family: 'Syne', sans-serif; font-weight: 700; font-size: 11px; letter-spacing: 0.08em; cursor: pointer; border: none; box-shadow: 0 2px 8px rgba(0,0,0,0.15); }
  .footer-brand { display: flex; justify-content: space-between; margin-top: 8px; font-size: 10px; color: ${faint}; }
  .footer-brand .brand { color: ${accent}; font-weight: 700; letter-spacing: 0.12em; font-family: 'Syne', sans-serif; }
  @media print { .print-cta { display: none; } body { margin: 20px; } }
</style></head><body>
<button class="print-cta" onclick="window.print()">PRINT / SAVE AS PDF</button>
<div class="kicker">THREAT INTELLIGENCE · IOC INSPECTOR REPORT</div>
<h1>${escapeHtml(currentIndicator)}</h1>
<div class="meta">${isIP(currentIndicator) ? "IPv4 address" : "URL / domain"} · scanned ${escapeHtml(dateStr)}</div>
<hr/>
${blocks.map(blk => {
  const vc = blk.verdict ? verdictColors[blk.verdict] : null;
  const chip = vc ? `<span class="chip" style="background:${vc.bg};color:${vc.fg};border-color:${vc.border}">${blk.verdict}</span>` : "";
  return `<div class="block">
    <div class="block-header">
      <div class="block-title"><span class="bar" style="background:${blk.color}"></span>${escapeHtml(blk.name)}</div>
      ${chip}
    </div>
    ${blk.lines.length === 0
      ? '<div class="empty">no data</div>'
      : `<table>${blk.lines.map(l => l.label
          ? `<tr><td class="label">${escapeHtml(l.label)}</td><td class="value">${escapeHtml(String(l.value))}</td></tr>`
          : `<tr><td colspan="2" class="empty">${escapeHtml(l.value)}</td></tr>`
        ).join("")}</table>`}
  </div>`;
}).join("")}
<hr/>
<div class="footer-brand">
  <span>Generated ${new Date().toLocaleString()}</span>
  <span class="brand">RYMANTECH</span>
</div>
</body></html>`;
}

// ── API queries ───────────────────────────────────────────────────────────
async function queryService(key, indicator, isIp, apiKey) {
  switch (key) {
    case "virustotal": return queryVirusTotal(indicator, isIp, apiKey);
    case "abuseipdb":  return queryAbuseIPDB(indicator, apiKey);
    case "urlscan":    return queryURLScan(indicator, isIp);
    case "otx":        return queryOTX(indicator, isIp);
    case "threatfox":  return queryThreatFox(indicator, apiKey);
    case "urlhaus":    return queryURLHaus(indicator, isIp, apiKey);
  }
}

async function queryVirusTotal(indicator, isIp, apiKey) {
  const endpoint = isIp
    ? `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(indicator)}`
    : `https://www.virustotal.com/api/v3/urls/${btoa(indicator).replace(/=+$/, "")}`;

  const res = await fetch(endpoint, { headers: { "x-apikey": apiKey } });
  if (res.status === 401) throw new Error("invalid API key");
  if (res.status === 429) throw new Error("rate limit (4/min)");
  if (res.status === 404) {
    return {
      verdict: "unknown",
      details: [["status", "Not found in VirusTotal"]],
      link: isIp
        ? `https://www.virustotal.com/gui/ip-address/${indicator}`
        : `https://www.virustotal.com/gui/search/${encodeURIComponent(indicator)}`,
    };
  }
  if (!res.ok) throw new Error(`HTTP ${res.status}`);

  const json = await res.json();
  const attr = json.data?.attributes || {};
  const stats = attr.last_analysis_stats || {};
  const malicious = stats.malicious || 0;
  const suspicious = stats.suspicious || 0;
  const harmless = stats.harmless || 0;
  const undetected = stats.undetected || 0;

  const verdict = malicious > 0 ? "malicious" : suspicious > 0 ? "suspicious" : "clean";

  return {
    verdict,
    details: [
      ["engines scanned", malicious + suspicious + harmless + undetected],
      ["malicious", malicious],
      ["suspicious", suspicious],
      ["harmless", harmless],
      ["undetected", undetected],
      ["reputation", attr.reputation],
      ["country", attr.country],
      ["network", attr.network],
      ["AS owner", attr.as_owner],
      ["last analysis", attr.last_analysis_date ? new Date(attr.last_analysis_date * 1000).toLocaleString() : null],
    ],
    link: isIp
      ? `https://www.virustotal.com/gui/ip-address/${indicator}`
      : `https://www.virustotal.com/gui/url/${btoa(indicator).replace(/=+$/, "")}`,
  };
}

async function queryAbuseIPDB(indicator, apiKey) {
  const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(indicator)}&maxAgeInDays=90&verbose`;
  const res = await fetch(url, { headers: { Key: apiKey, Accept: "application/json" } });
  if (res.status === 401) throw new Error("invalid API key");
  if (res.status === 429) throw new Error("rate limit hit");
  if (!res.ok) throw new Error(`HTTP ${res.status}`);

  const json = await res.json();
  const d = json.data || {};
  const score = d.abuseConfidenceScore || 0;
  const verdict = score > 50 ? "malicious" : score > 10 ? "suspicious" : "clean";

  return {
    verdict,
    details: [
      ["abuse confidence", `${score}%`],
      ["total reports", d.totalReports],
      ["distinct users", d.numDistinctUsers],
      ["country", d.countryCode],
      ["ISP", d.isp],
      ["domain", d.domain],
      ["usage type", d.usageType],
      ["tor node", d.isTor ? "Yes" : "No"],
      ["whitelisted", d.isWhitelisted ? "Yes" : "No"],
      ["last reported", d.lastReportedAt ? new Date(d.lastReportedAt).toLocaleString() : "Never"],
    ],
    link: `https://www.abuseipdb.com/check/${indicator}`,
  };
}

async function queryURLScan(indicator, isIp) {
  const domain = isIp ? indicator : indicator.replace(/^https?:\/\//, "").split("/")[0];
  const q = isIp ? `page.ip:${indicator}` : `page.domain:${domain}`;
  const url = `https://urlscan.io/api/v1/search/?q=${encodeURIComponent(q)}&size=1`;

  const res = await fetch(url);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);

  const json = await res.json();
  const result = json.results?.[0];

  if (!result) {
    return {
      verdict: "unknown",
      details: [["status", "No prior scans found"]],
      link: `https://urlscan.io/search/#${encodeURIComponent(domain)}`,
    };
  }

  const v = result.verdicts?.overall || {};
  const score = v.score || 0;
  const malicious = v.malicious || false;
  const verdict = malicious ? "malicious" : score > 30 ? "suspicious" : score > 0 ? "suspicious" : "clean";

  return {
    verdict,
    details: [
      ["overall score", score],
      ["malicious", malicious ? "Yes" : "No"],
      ["categories", (v.categories || []).join(", ") || null],
      ["domain", result.page?.domain],
      ["IP", result.page?.ip],
      ["country", result.page?.country],
      ["server", result.page?.server],
      ["AS name", result.page?.asnname],
      ["scan time", result.task?.time ? new Date(result.task.time).toLocaleString() : null],
    ],
    link: result._id ? `https://urlscan.io/result/${result._id}/` : `https://urlscan.io/search/#${encodeURIComponent(domain)}`,
  };
}

async function queryOTX(indicator, isIp) {
  const target = isIp ? indicator : indicator.replace(/^https?:\/\//, "").split("/")[0];
  const type = isIp ? "IPv4" : "domain";
  const url = `https://otx.alienvault.com/api/v1/indicators/${type}/${encodeURIComponent(target)}/general`;

  const res = await fetch(url);
  if (res.status === 404) {
    return {
      verdict: "unknown",
      details: [["status", "Not in OTX database"]],
      link: `https://otx.alienvault.com/indicator/${type === "IPv4" ? "ip" : "domain"}/${encodeURIComponent(target)}`,
    };
  }
  if (!res.ok) throw new Error(`HTTP ${res.status}`);

  const json = await res.json();
  const pulseCount = json.pulse_info?.count || 0;
  const pulses = json.pulse_info?.pulses || [];
  const reputation = json.reputation || 0;
  const topPulses = pulses.slice(0, 3).map(p => p.name).filter(Boolean);

  const verdict = pulseCount >= 5 ? "malicious"
    : pulseCount > 0 ? "suspicious"
    : reputation < 0 ? "suspicious"
    : "clean";

  return {
    verdict,
    details: [
      ["pulse count", pulseCount],
      ["reputation", reputation || 0],
      ["country", json.country_name],
      ["city", json.city],
      ["ASN", json.asn],
      ["top threats", topPulses.join("; ") || null],
    ],
    link: `https://otx.alienvault.com/indicator/${type === "IPv4" ? "ip" : "domain"}/${encodeURIComponent(target)}`,
  };
}

async function queryThreatFox(indicator, authKey) {
  const target = indicator.trim().replace(/^https?:\/\//, "").split("/")[0];

  const headers = { "Content-Type": "application/json" };
  if (authKey) headers["Auth-Key"] = authKey;

  const res = await fetch("https://threatfox-api.abuse.ch/api/v1/", {
    method: "POST",
    headers,
    body: JSON.stringify({ query: "search_ioc", search_term: target }),
  });
  if (res.status === 401) throw new Error("Auth-Key required");
  if (!res.ok) throw new Error(`HTTP ${res.status}`);

  const json = await res.json();
  if (json.query_status === "no_result") {
    return {
      verdict: "clean",
      details: [["status", "Not in ThreatFox malware IOC database"]],
      link: `https://threatfox.abuse.ch/browse.php?search=ioc%3A${encodeURIComponent(target)}`,
    };
  }
  if (json.query_status === "illegal_auth") throw new Error("invalid Auth-Key");
  if (json.query_status !== "ok") throw new Error(json.query_status || "query failed");

  const hits = json.data || [];
  const first = hits[0] || {};
  const malwareNames = [...new Set(hits.map(h => h.malware_printable).filter(Boolean))];
  const threatTypes = [...new Set(hits.map(h => h.threat_type).filter(Boolean))];

  return {
    verdict: "malicious",
    details: [
      ["IOC matches", hits.length],
      ["malware family", malwareNames.slice(0, 3).join(", ") || null],
      ["threat type", threatTypes.join(", ") || null],
      ["confidence", first.confidence_level != null ? `${first.confidence_level}%` : null],
      ["first seen", first.first_seen],
      ["last seen", first.last_seen],
      ["tags", (first.tags || []).join(", ") || null],
    ],
    link: `https://threatfox.abuse.ch/browse.php?search=ioc%3A${encodeURIComponent(target)}`,
  };
}

// URLHaus — uses the same abuse.ch Auth-Key as ThreatFox
async function queryURLHaus(indicator, isIp, authKey) {
  const target = indicator.trim().replace(/^https?:\/\//, "").split("/")[0];

  const headers = { "Content-Type": "application/x-www-form-urlencoded" };
  if (authKey) headers["Auth-Key"] = authKey;

  // URLHaus has separate host vs URL endpoints. For IPs and bare domains, use host endpoint.
  const body = `host=${encodeURIComponent(target)}`;
  const res = await fetch("https://urlhaus-api.abuse.ch/v1/host/", {
    method: "POST",
    headers,
    body,
  });
  if (res.status === 401) throw new Error("Auth-Key required");
  if (!res.ok) throw new Error(`HTTP ${res.status}`);

  const json = await res.json();
  if (json.query_status === "no_results") {
    return {
      verdict: "clean",
      details: [["status", "Not in URLHaus malware database"]],
      link: `https://urlhaus.abuse.ch/browse.php?search=${encodeURIComponent(target)}`,
    };
  }
  if (json.query_status === "invalid_auth_key") throw new Error("invalid Auth-Key");
  if (json.query_status !== "ok") throw new Error(json.query_status || "query failed");

  const urlCount = json.url_count ? parseInt(json.url_count, 10) : 0;
  const blacklists = json.blacklists || {};
  const urls = json.urls || [];
  const onlineCount = urls.filter(u => u.url_status === "online").length;
  const tags = [...new Set(urls.flatMap(u => u.tags || []))].slice(0, 6);

  const verdict = onlineCount > 0 ? "malicious"
    : urlCount > 0 ? "suspicious"
    : "clean";

  return {
    verdict,
    details: [
      ["malicious URLs", urlCount],
      ["online URLs", onlineCount],
      ["host status", json.host_status || json.hostname || null],
      ["first seen", json.firstseen],
      ["spamhaus DBL", blacklists.spamhaus_dbl],
      ["surbl", blacklists.surbl],
      ["tags", tags.join(", ") || null],
    ],
    link: json.urlhaus_reference || `https://urlhaus.abuse.ch/browse.php?search=${encodeURIComponent(target)}`,
  };
}

// ── Utils ─────────────────────────────────────────────────────────────────
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[c]);
}
