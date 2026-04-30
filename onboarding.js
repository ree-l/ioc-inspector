const SOURCES = [
  { key: "virustotal", name: "VirusTotal", color: "vt", tag: "needs-key", desc: "API · key required", default: true },
  { key: "abuseipdb",  name: "AbuseIPDB", color: "aip", tag: "needs-key", desc: "API · key required · IP only", default: true },
  { key: "urlscan",    name: "URLScan.io", color: "us", tag: "free", desc: "API · free, no key", default: true },
  { key: "otx",        name: "AlienVault OTX", color: "otx", tag: "free", desc: "API · free, no key", default: true },
  { key: "threatfox",  name: "ThreatFox", color: "tf", tag: "needs-key", desc: "API · abuse.ch Auth-Key", default: true },
  { key: "urlhaus",    name: "URLHaus", color: "uh", tag: "needs-key", desc: "API · abuse.ch Auth-Key", default: true },

  { key: "talos",       name: "Cisco Talos", color: "talos", tag: "manual", desc: "manual lookup link", default: true, badge: "manual" },
  { key: "ipvoid",      name: "IPVoid / URLVoid", color: "ipvoid", tag: "manual", desc: "manual lookup link", default: true, badge: "manual" },
  { key: "mxtool",      name: "MXToolBox", color: "mxtool", tag: "manual", desc: "manual lookup link · blacklists/MX", default: true, badge: "manual" },
  { key: "crowdsec",    name: "CrowdSec", color: "crowdsec", tag: "manual", desc: "manual lookup link · CTI", default: true, badge: "manual" },
  { key: "rstcloud",    name: "RST Cloud", color: "rstcloud", tag: "manual", desc: "manual lookup link · TI", default: false, badge: "manual" },
  { key: "threatbook",  name: "ThreatBook", color: "threatbook", tag: "manual", desc: "manual lookup link · CTI", default: true, badge: "manual" },
  { key: "xforce",      name: "X-Force Exchange", color: "xforce", tag: "manual", desc: "manual lookup link · IBM", default: true, badge: "manual" },
  { key: "scamalytics", name: "Scamalytics", color: "scamalytics", tag: "manual", desc: "manual lookup link · IP only", default: true, badge: "manual" },
];

const $grid = document.getElementById("source-grid");
const $vt = document.getElementById("virustotal_key");
const $ai = document.getElementById("abuseipdb_key");
const $ac = document.getElementById("abusech_key");
const $finish = document.getElementById("finish");
const $skip = document.getElementById("skip");
const $themeBtn = document.getElementById("theme-toggle");

const ICONS = {
  sun: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"/></svg>`,
  moon: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>`,
};

const enabled = new Set(SOURCES.filter(s => s.default).map(s => s.key));

function applyTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);
  $themeBtn.innerHTML = theme === "dark" ? ICONS.sun : ICONS.moon;
}
async function toggleTheme() {
  const current = document.documentElement.getAttribute("data-theme") || "light";
  const next = current === "light" ? "dark" : "light";
  applyTheme(next);
  await chrome.storage.sync.set({ theme: next });
}
$themeBtn.addEventListener("click", toggleTheme);

function renderSources() {
  $grid.innerHTML = SOURCES.map(s => `
    <div class="source-row ${enabled.has(s.key) ? "" : "disabled"}" data-key="${s.key}">
      <div class="source-info">
        <div class="source-bar svc-bar ${s.color}"></div>
        <div class="source-meta">
          <div class="source-name">${s.name}${s.badge ? `<span class="badge">${s.badge}</span>` : ""}</div>
          <div class="source-tag"><span class="${s.tag}">${s.desc}</span></div>
        </div>
      </div>
      <div class="toggle ${enabled.has(s.key) ? "on" : ""}"></div>
    </div>
  `).join("");

  $grid.querySelectorAll(".source-row").forEach(row => {
    row.addEventListener("click", () => {
      const key = row.dataset.key;
      if (enabled.has(key)) enabled.delete(key);
      else enabled.add(key);
      renderSources();
    });
  });
}

renderSources();

document.querySelectorAll(".toggle-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    const input = document.getElementById(btn.dataset.target);
    const isShown = input.type === "text";
    input.type = isShown ? "password" : "text";
    btn.textContent = isShown ? "show" : "hide";
  });
});

chrome.storage.sync.get(["virustotal_key","abuseipdb_key","abusech_key","enabled_services","theme"], (data) => {
  applyTheme(data.theme || "light");
  $vt.value = data.virustotal_key || "";
  $ai.value = data.abuseipdb_key || "";
  $ac.value = data.abusech_key || "";
  if (Array.isArray(data.enabled_services)) {
    enabled.clear();
    data.enabled_services.forEach(k => enabled.add(k));
    renderSources();
  }
});

async function saveAll() {
  await chrome.storage.sync.set({
    virustotal_key: $vt.value.trim(),
    abuseipdb_key: $ai.value.trim(),
    abusech_key: $ac.value.trim(),
    enabled_services: Array.from(enabled),
  });
}

$finish.addEventListener("click", async () => {
  await saveAll();
  $finish.textContent = "✓ SAVED — CLOSING...";
  setTimeout(() => window.close(), 800);
});

$skip.addEventListener("click", async () => {
  await chrome.storage.sync.set({ enabled_services: Array.from(enabled) });
  window.close();
});
