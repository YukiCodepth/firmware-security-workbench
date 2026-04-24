const demoScan = {
  file: { name: "demo-firmware.bin" },
  analysis: {
    suspicious_count: 5,
    secret_exposure_count: 1,
    cve_candidate_count: 0,
    suspicious_findings: [
      { severity: "high", offset_hex: "0x56", string: "wifi_password=demo1234" },
      { severity: "medium", offset_hex: "0x6d", string: "mqtt://broker.internal.local:1883" },
      { severity: "medium", offset_hex: "0x8f", string: "ota_update_url=http://updates.internal.local/fw.bin" },
      { severity: "medium", offset_hex: "0xd8", string: "admin_panel_enabled=true" },
      { severity: "low", offset_hex: "0xc3", string: "DEBUG: boot complete" }
    ],
    risk_dna: {
      score: 69,
      band: "high",
      fingerprint: "48f1b3013024db3635cd2440",
      tags: ["CREDS", "NET", "RULES", "FINDINGS"]
    },
    hardening_simulation: {
      projected: { score: 20, band: "low", estimated_reduction: 49 },
      actions_count: 7,
      scenarios: [
        { name: "quick-patch", projected_score: 57, projected_band: "high", reduction: 12 },
        { name: "balanced-sprint", projected_score: 29, projected_band: "low", reduction: 40 },
        { name: "aggressive-lockdown", projected_score: 14, projected_band: "low", reduction: 55 }
      ],
      actions: [
        { title: "Rotate embedded credentials and move secrets to secure storage", effort: "medium", estimated_risk_reduction: 18 },
        { title: "Enforce TLS and authenticated transport for firmware network paths", effort: "medium", estimated_risk_reduction: 14 },
        { title: "Enforce signed OTA manifests and anti-rollback controls", effort: "high", estimated_risk_reduction: 12 },
        { title: "Harden admin interfaces with least privilege and explicit authz", effort: "medium", estimated_risk_reduction: 9 }
      ]
    }
  }
};

const refs = {
  apiState: document.getElementById("api-state"),
  refreshBtn: document.getElementById("refresh-btn"),
  demoBtn: document.getElementById("demo-btn"),
  scanForm: document.getElementById("scan-form"),
  firmwareFile: document.getElementById("firmware-file"),
  fileLabel: document.getElementById("file-label"),
  minStringLength: document.getElementById("min-string-length"),
  maxStrings: document.getElementById("max-strings"),
  saveScan: document.getElementById("save-scan"),
  selectedFile: document.getElementById("selected-file"),
  riskScore: document.getElementById("risk-score"),
  riskBand: document.getElementById("risk-band"),
  riskFingerprint: document.getElementById("risk-fingerprint"),
  riskTags: document.getElementById("risk-tags"),
  metricFindings: document.getElementById("metric-findings"),
  metricSecrets: document.getElementById("metric-secrets"),
  metricCves: document.getElementById("metric-cves"),
  metricActions: document.getElementById("metric-actions"),
  projectedScore: document.getElementById("projected-score"),
  findingList: document.getElementById("finding-list"),
  scenarioList: document.getElementById("scenario-list"),
  actionList: document.getElementById("action-list")
};
const railButtons = Array.from(document.querySelectorAll(".rail-button"));

function getApiBase() {
  return "http://127.0.0.1:8000";
}

function setApiState(online) {
  refs.apiState.textContent = online ? "API online" : "API offline";
  refs.apiState.classList.toggle("good", online);
}

function safeArray(value) {
  return Array.isArray(value) ? value : [];
}

function renderScan(scan) {
  const file = scan.file || {};
  const analysis = scan.analysis || {};
  const risk = analysis.risk_dna || {};
  const hardening = analysis.hardening_simulation || {};
  const projected = hardening.projected || {};

  refs.selectedFile.textContent = file.name || "unsaved scan";
  refs.riskScore.textContent = risk.score ?? "-";
  refs.riskBand.textContent = risk.band || "-";
  refs.riskFingerprint.textContent = risk.fingerprint || "-";
  refs.riskTags.textContent = safeArray(risk.tags).join(" / ") || "BASELINE";
  refs.metricFindings.textContent = analysis.suspicious_count ?? 0;
  refs.metricSecrets.textContent = analysis.secret_exposure_count ?? 0;
  refs.metricCves.textContent = analysis.cve_candidate_count ?? 0;
  refs.metricActions.textContent = hardening.actions_count ?? 0;
  refs.projectedScore.textContent = `Projected ${projected.score ?? "-"}`;

  refs.findingList.innerHTML = "";
  for (const finding of safeArray(analysis.suspicious_findings).slice(0, 8)) {
    const li = document.createElement("li");
    li.innerHTML = `<span class="severity">${finding.severity || "info"}</span>${finding.offset_hex || "-"} ${finding.string || ""}`;
    refs.findingList.appendChild(li);
  }

  refs.scenarioList.innerHTML = "";
  for (const scenario of safeArray(hardening.scenarios).slice(0, 3)) {
    const card = document.createElement("div");
    card.className = "scenario-card";
    card.innerHTML = `<strong>${scenario.name}</strong><span class="muted">score ${scenario.projected_score} (${scenario.projected_band}), reduction ${scenario.reduction}</span>`;
    refs.scenarioList.appendChild(card);
  }

  refs.actionList.innerHTML = "";
  for (const action of safeArray(hardening.actions).slice(0, 6)) {
    const li = document.createElement("li");
    li.innerHTML = `<strong>${action.title || "Hardening action"}</strong><div class="muted">effort ${action.effort || "-"} / reduction ${action.estimated_risk_reduction || 0}</div>`;
    refs.actionList.appendChild(li);
  }
}

async function checkApi() {
  try {
    const response = await fetch(`${getApiBase()}/health`);
    setApiState(response.ok);
  } catch {
    setApiState(false);
  }
}

async function submitScan(event) {
  event.preventDefault();
  const file = refs.firmwareFile.files?.[0];
  if (!file) {
    renderScan(demoScan);
    return;
  }

  const formData = new FormData();
  formData.append("file", file);
  formData.append("min_string_length", refs.minStringLength.value || "4");
  formData.append("max_strings", refs.maxStrings.value || "2000");
  formData.append("save", refs.saveScan.checked ? "true" : "false");

  try {
    const response = await fetch(`${getApiBase()}/api/v1/scans`, {
      method: "POST",
      body: formData
    });
    if (!response.ok) {
      throw new Error(await response.text());
    }
    renderScan(await response.json());
    setApiState(true);
  } catch {
    setApiState(false);
    renderScan(demoScan);
  }
}

refs.firmwareFile.addEventListener("change", () => {
  const file = refs.firmwareFile.files?.[0];
  refs.fileLabel.textContent = file ? file.name : "Drop firmware or choose a file";
});

for (const button of railButtons) {
  button.addEventListener("click", () => {
    const targetId = button.dataset.target;
    const target = targetId ? document.getElementById(targetId) : null;
    if (target) {
      target.scrollIntoView({ behavior: "smooth", block: "start" });
    }
    for (const item of railButtons) {
      item.classList.toggle("active", item === button);
    }
  });
}

refs.scanForm.addEventListener("submit", submitScan);
refs.demoBtn.addEventListener("click", () => renderScan(demoScan));
refs.refreshBtn.addEventListener("click", checkApi);

renderScan(demoScan);
checkApi();
