const state = {
  scans: [],
  selectedScanId: null,
};

const refs = {
  scanForm: document.getElementById("scan-form"),
  firmwareFile: document.getElementById("firmware-file"),
  minStringLength: document.getElementById("min-string-length"),
  maxStrings: document.getElementById("max-strings"),
  historyLimit: document.getElementById("history-limit"),
  dbPath: document.getElementById("db-path"),
  saveScan: document.getElementById("save-scan"),
  scanStatus: document.getElementById("scan-status"),
  historyBody: document.getElementById("history-body"),
  refreshHistory: document.getElementById("refresh-history"),
  loadHistory: document.getElementById("load-history"),
  clearDetail: document.getElementById("clear-detail-btn"),
  metricFile: document.getElementById("metric-file"),
  metricType: document.getElementById("metric-type"),
  metricEntropy: document.getElementById("metric-entropy"),
  metricFindings: document.getElementById("metric-findings"),
  findingList: document.getElementById("finding-list"),
  stringsList: document.getElementById("strings-list"),
};

function setStatus(message, kind = "info") {
  refs.scanStatus.textContent = message;
  refs.scanStatus.classList.remove("error", "info");
  refs.scanStatus.classList.add(kind === "error" ? "error" : "info");
}

function getDbPath() {
  const value = refs.dbPath.value.trim();
  return value || "reports/generated/fwb_scans.sqlite3";
}

async function fetchJson(url, options = {}) {
  const response = await fetch(url, options);
  const contentType = response.headers.get("content-type") || "";
  const payload = contentType.includes("application/json")
    ? await response.json()
    : await response.text();
  if (!response.ok) {
    const detail =
      typeof payload === "object" && payload && "detail" in payload
        ? payload.detail
        : response.statusText;
    throw new Error(String(detail || "Request failed"));
  }
  return payload;
}

function renderHistoryRows() {
  refs.historyBody.innerHTML = "";
  if (state.scans.length === 0) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 5;
    cell.textContent = "No scans in history yet.";
    row.appendChild(cell);
    refs.historyBody.appendChild(row);
    return;
  }

  for (const scan of state.scans) {
    const row = document.createElement("tr");
    if (scan.id === state.selectedScanId) {
      row.classList.add("active");
    }
    row.dataset.scanId = String(scan.id);

    const ts = typeof scan.scanned_at_utc === "string" ? scan.scanned_at_utc : "";
    row.innerHTML = `
      <td>${scan.id}</td>
      <td>${ts.replace("T", " ").slice(0, 19)}</td>
      <td>${scan.type_guess || "-"}</td>
      <td>${scan.suspicious_count ?? 0}</td>
      <td>${scan.file_name || "-"}</td>
    `;
    row.addEventListener("click", async () => {
      await loadScanDetail(scan.id);
    });
    refs.historyBody.appendChild(row);
  }
}

function renderDetail(record) {
  const result = record?.result || {};
  const file = result.file || {};
  const analysis = result.analysis || {};
  const findings = Array.isArray(analysis.suspicious_findings)
    ? analysis.suspicious_findings
    : [];
  const preview = Array.isArray(analysis.strings_preview) ? analysis.strings_preview : [];

  refs.metricFile.textContent = file.name || "-";
  refs.metricType.textContent = file.type_guess || "-";
  refs.metricEntropy.textContent =
    typeof analysis.entropy === "number" ? analysis.entropy.toFixed(4) : "-";
  refs.metricFindings.textContent = String(analysis.suspicious_count ?? 0);

  refs.findingList.innerHTML = "";
  if (findings.length === 0) {
    const li = document.createElement("li");
    li.textContent = "No suspicious findings.";
    refs.findingList.appendChild(li);
  } else {
    for (const finding of findings.slice(0, 25)) {
      const li = document.createElement("li");
      const keywords = Array.isArray(finding.keywords) ? finding.keywords.join(",") : "";
      li.textContent = `[${finding.severity}/${finding.confidence}] ${finding.offset_hex} ${keywords} ${finding.string}`;
      refs.findingList.appendChild(li);
    }
  }

  refs.stringsList.innerHTML = "";
  if (preview.length === 0) {
    const li = document.createElement("li");
    li.textContent = "No strings preview available.";
    refs.stringsList.appendChild(li);
  } else {
    for (const text of preview.slice(0, 30)) {
      const li = document.createElement("li");
      li.textContent = text;
      refs.stringsList.appendChild(li);
    }
  }
}

function clearDetail() {
  state.selectedScanId = null;
  refs.metricFile.textContent = "-";
  refs.metricType.textContent = "-";
  refs.metricEntropy.textContent = "-";
  refs.metricFindings.textContent = "-";
  refs.findingList.innerHTML = "";
  refs.stringsList.innerHTML = "";
  renderHistoryRows();
}

async function loadHistory() {
  const limit = Number(refs.historyLimit.value || 20);
  const dbPath = getDbPath();
  const query = new URLSearchParams({
    limit: String(Math.max(1, Math.min(limit, 200))),
    db_path: dbPath,
  });
  const payload = await fetchJson(`/api/v1/scans?${query.toString()}`);
  state.scans = Array.isArray(payload.scans) ? payload.scans : [];
  renderHistoryRows();
}

async function loadScanDetail(scanId) {
  const dbPath = getDbPath();
  const query = new URLSearchParams({ db_path: dbPath });
  const payload = await fetchJson(`/api/v1/scans/${scanId}?${query.toString()}`);
  state.selectedScanId = scanId;
  renderHistoryRows();
  renderDetail(payload);
  setStatus(`Loaded scan #${scanId}`);
}

async function submitScan(event) {
  event.preventDefault();
  const file = refs.firmwareFile.files?.[0];
  if (!file) {
    setStatus("Pick a firmware file first.", "error");
    return;
  }

  const formData = new FormData();
  formData.append("file", file);
  formData.append("min_string_length", refs.minStringLength.value || "4");
  formData.append("max_strings", refs.maxStrings.value || "2000");
  formData.append("save", refs.saveScan.checked ? "true" : "false");
  formData.append("db_path", getDbPath());

  setStatus(`Scanning ${file.name} ...`);
  try {
    const payload = await fetchJson("/api/v1/scans", {
      method: "POST",
      body: formData,
    });

    if (payload.storage?.saved && payload.storage.scan_id) {
      setStatus(`Scan complete. Saved as #${payload.storage.scan_id}`);
      await loadHistory();
      await loadScanDetail(payload.storage.scan_id);
    } else {
      setStatus("Scan complete (not saved).");
      renderDetail({ result: payload });
    }
  } catch (error) {
    setStatus(`Scan failed: ${error.message}`, "error");
  }
}

refs.scanForm.addEventListener("submit", submitScan);
refs.refreshHistory.addEventListener("click", () => {
  loadHistory().then(() => setStatus("History refreshed."));
});
refs.loadHistory.addEventListener("click", () => {
  loadHistory().then(() => setStatus("History refreshed."));
});
refs.clearDetail.addEventListener("click", () => {
  clearDetail();
  setStatus("Detail cleared.");
});

clearDetail();
loadHistory()
  .then(() => setStatus("Dashboard ready."))
  .catch((error) => setStatus(`Unable to load history: ${error.message}`, "error"));
