const state = {
  scans: [],
  selectedScanId: null,
  selectedRecord: null,
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
  missionRiskScore: document.getElementById("mission-risk-score"),
  missionFileName: document.getElementById("mission-file-name"),
  missionSummary: document.getElementById("mission-summary"),
  metricFile: document.getElementById("metric-file"),
  metricType: document.getElementById("metric-type"),
  metricEntropy: document.getElementById("metric-entropy"),
  metricFindings: document.getElementById("metric-findings"),
  findingList: document.getElementById("finding-list"),
  stringsList: document.getElementById("strings-list"),
  assistantChat: document.getElementById("assistant-chat"),
  assistantForm: document.getElementById("assistant-form"),
  assistantInput: document.getElementById("assistant-input"),
  clearAssistant: document.getElementById("clear-assistant-btn"),
  assistChips: Array.from(document.querySelectorAll(".assist-chip")),
};

const SEVERITY_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

function setStatus(message, kind = "info") {
  refs.scanStatus.textContent = message;
  refs.scanStatus.classList.remove("error", "info");
  refs.scanStatus.classList.add(kind === "error" ? "error" : "info");
}

function getDbPath() {
  const value = refs.dbPath.value.trim();
  return value || "reports/generated/fwb_scans.sqlite3";
}

function addAssistantMessage(role, text) {
  const li = document.createElement("li");
  li.className = `assistant-msg ${role}`;
  li.textContent = `${role === "user" ? "You" : "Assistant"}: ${text}`;
  refs.assistantChat.appendChild(li);
  refs.assistantChat.scrollTop = refs.assistantChat.scrollHeight;
}

function clearAssistantMessages() {
  refs.assistantChat.innerHTML = "";
  addAssistantMessage(
    "bot",
    "Ask me about history, findings, CVEs, risk DNA, or hardening plan."
  );
}

function currentResult() {
  return state.selectedRecord?.result || null;
}

function highestSeverity(findings) {
  if (!Array.isArray(findings) || findings.length === 0) {
    return null;
  }
  let best = findings[0];
  for (const finding of findings) {
    const bestRank = SEVERITY_RANK[best.severity] ?? -1;
    const currentRank = SEVERITY_RANK[finding.severity] ?? -1;
    if (currentRank > bestRank) {
      best = finding;
    }
  }
  return best;
}

function normalizeQuestion(questionRaw) {
  return questionRaw
    .toLowerCase()
    .replace(/[^\w\s]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function hasAny(text, terms) {
  return terms.some((term) => text.includes(term));
}

function summarizeFinding(finding) {
  const keywords = Array.isArray(finding.keywords) ? finding.keywords.join(",") : "-";
  const text = String(finding.string || "").replace(/\s+/g, " ").trim();
  const snippet = text.length > 58 ? `${text.slice(0, 58)}...` : text;
  return `${finding.severity}@${finding.offset_hex} [${keywords}] ${snippet}`;
}

function severityFromQuestion(question) {
  if (question.includes("critical")) {
    return "critical";
  }
  if (question.includes("high")) {
    return "high";
  }
  if (question.includes("medium")) {
    return "medium";
  }
  if (question.includes("low")) {
    return "low";
  }
  if (question.includes("info")) {
    return "info";
  }
  return null;
}

function findingsBySeverity(findings, severity) {
  return findings.filter((finding) => finding.severity === severity);
}

function findingsAtOrAbove(findings, severity) {
  const minRank = SEVERITY_RANK[severity] ?? 0;
  return findings.filter((finding) => (SEVERITY_RANK[finding.severity] ?? -1) >= minRank);
}

function credentialFindings(analysis, findings) {
  const exposures = Array.isArray(analysis?.secret_exposures) ? analysis.secret_exposures : [];
  if (exposures.length > 0) {
    return exposures;
  }
  return findings.filter((finding) => {
    const text = String(finding.string || "").toLowerCase();
    const keywords = Array.isArray(finding.keywords)
      ? finding.keywords.map((keyword) => String(keyword).toLowerCase())
      : [];
    return (
      hasAny(text, ["password", "passwd", "token", "secret", "api_key", "apikey", "ssid"]) ||
      keywords.some((keyword) =>
        hasAny(keyword, ["password", "passwd", "token", "secret", "credential", "ssid"])
      )
    );
  });
}

function extractUrls(result, findings) {
  const endpointPreview = result?.analysis?.endpoints_preview;
  if (Array.isArray(endpointPreview) && endpointPreview.length > 0) {
    return Array.from(new Set(endpointPreview.map((item) => String(item))));
  }
  const urls = new Set();
  const regex = /\b(?:https?:\/\/|mqtt:\/\/|ws:\/\/|wss:\/\/|ftp:\/\/)[^\s"']+/gi;
  const texts = [];

  for (const finding of findings) {
    texts.push(String(finding.string || ""));
  }
  const preview = result?.analysis?.strings_preview;
  if (Array.isArray(preview)) {
    texts.push(...preview.map((entry) => String(entry)));
  }

  for (const text of texts) {
    let match = regex.exec(text);
    while (match) {
      urls.add(match[0]);
      match = regex.exec(text);
    }
    regex.lastIndex = 0;
  }

  return Array.from(urls);
}

function buildRiskDna(result, findings) {
  const analysis = result?.analysis || {};
  const dna = analysis.risk_dna;
  if (dna && typeof dna === "object") {
    return `Risk DNA ${dna.band || "-"} score=${dna.score || "-"} fingerprint=${dna.fingerprint || "-"}`;
  }
  const posture = analysis.security_posture;
  if (posture && typeof posture === "object") {
    const top = String(posture.top_severity || "-");
    const postureBand = posture.risk_level ?? "-";
    const postureScore = posture.score ?? "-";
    return `Risk DNA posture=${postureBand} score=${postureScore} top_severity=${top}`;
  }
  const top = highestSeverity(findings);
  const topRank = top ? SEVERITY_RANK[top.severity] ?? 0 : 0;
  const urls = extractUrls(result, findings);
  const creds = credentialFindings(analysis, findings);
  const hasDebug = findings.some((finding) =>
    String(finding.string || "").toLowerCase().includes("debug")
  );
  const hasOta = findings.some((finding) =>
    hasAny(String(finding.string || "").toLowerCase(), ["ota", "update", "firmware"])
  );

  const tags = [];
  if (creds.length > 0) {
    tags.push("CREDS");
  }
  if (urls.length > 0) {
    tags.push("NET");
  }
  if (hasOta) {
    tags.push("OTA");
  }
  if (hasDebug) {
    tags.push("DEBUG");
  }
  if (tags.length === 0) {
    tags.push("BASELINE");
  }

  const score = Math.min(
    100,
    findings.length * 8 + topRank * 15 + creds.length * 4 + (urls.length > 0 ? 10 : 0)
  );
  const band = score >= 75 ? "high" : score >= 45 ? "medium" : "low";
  return `Risk DNA ${tags.join("+")} | score ${score}/100 (${band})`;
}

function getHardeningSimulation(result) {
  const simulation = result?.analysis?.hardening_simulation;
  if (simulation && typeof simulation === "object") {
    return simulation;
  }
  return null;
}

function assistantReply(questionRaw) {
  const question = normalizeQuestion(questionRaw);
  const result = currentResult();
  const analysis = result?.analysis || {};
  const file = result?.file || {};
  const findings = Array.isArray(analysis.suspicious_findings)
    ? analysis.suspicious_findings
    : [];
  const asksHelp = hasAny(question, ["help", "what can you do", "commands", "examples"]);
  const asksHistory = hasAny(question, [
    "history",
    "scan history",
    "saved scans",
    "past scans",
    "previous scans",
  ]);
  const asksCount = hasAny(question, ["how many", "count", "number of", "total"]);
  const asksLatest = hasAny(question, ["latest", "recent", "newest", "last"]);
  const asksSelected = hasAny(question, ["selected", "current", "this scan"]);
  const asksSummary = hasAny(question, ["summary", "summarize", "overview", "status"]);
  const asksEntropy = question.includes("entropy");
  const asksType = hasAny(question, ["type", "format", "file type"]);
  const asksSeverity = hasAny(question, [
    "most severe",
    "top severity",
    "severity",
    "critical",
    "highest risk",
    "highest severity",
  ]);
  const asksFindings = hasAny(question, [
    "finding",
    "findings",
    "issue",
    "issues",
    "alert",
    "alerts",
    "suspicious",
    "problem",
    "problems",
  ]);
  const asksNext = hasAny(question, ["next", "what should i do", "what now", "recommend"]);
  const asksCredentials = hasAny(question, [
    "credential",
    "credentials",
    "password",
    "secret",
    "token",
    "api key",
    "apikey",
  ]);
  const asksUrls = hasAny(question, [
    "url",
    "urls",
    "endpoint",
    "endpoints",
    "link",
    "links",
    "mqtt",
    "http",
    "https",
  ]);
  const asksRiskDna = hasAny(question, ["risk dna", "dna", "risk profile", "risk fingerprint"]);
  const asksSbom = hasAny(question, [
    "sbom",
    "component",
    "components",
    "dependencies",
    "inventory",
    "cyclonedx",
  ]);
  const asksCve = hasAny(question, [
    "cve",
    "cves",
    "vulnerability",
    "vulnerabilities",
    "cvss",
  ]);
  const asksHardening = hasAny(question, [
    "hardening",
    "harden",
    "mitigation",
    "remediation",
    "fix plan",
    "action plan",
    "reduce risk",
    "secure this",
  ]);
  const asksWhatIf = hasAny(question, [
    "what if",
    "scenario",
    "scenarios",
    "quick patch",
    "balanced sprint",
    "aggressive lockdown",
  ]);
  const asksRules = hasAny(question, [
    "rule",
    "rules",
    "yara",
    "signature",
    "signatures",
    "rule match",
  ]);
  const asksAll = hasAny(question, ["all", "full", "everything"]);
  const asksThreshold = hasAny(question, ["or above", "and above", "or higher", "and higher"]);
  const requestedSeverity = severityFromQuestion(question);

  if (asksHelp) {
    return "I can answer history, selected summary, findings by severity, credentials, URLs/endpoints, YARA/rule matches, SBOM components, CVE candidates, entropy, file type, risk DNA, and hardening scenarios.";
  }
  if ((asksHistory && asksFindings) || (asksFindings && asksHistory)) {
    if (state.scans.length === 0) {
      return "No scans in history yet.";
    }
    const totalFindings = state.scans.reduce(
      (sum, scan) => sum + Number(scan.suspicious_count || 0),
      0
    );
    return `History view has ${state.scans.length} scans and ${totalFindings} total findings.`;
  }
  if (
    (asksCount && (asksHistory || question.includes("scan"))) ||
    question === "history" ||
    question === "scan history" ||
    question === "scans"
  ) {
    return `There are ${state.scans.length} scans in current history view.`;
  }
  if (asksLatest && (asksHistory || question.includes("scan"))) {
    if (state.scans.length === 0) {
      return "No scans in history yet.";
    }
    const latest = state.scans[0];
    return `Latest is scan #${latest.id}: ${latest.file_name} (${latest.type_guess}), findings=${latest.suspicious_count}.`;
  }
  if (
    (asksSelected && asksSummary) ||
    (asksSummary && !asksHistory && !asksLatest)
  ) {
    if (!result) {
      return "No scan selected. Click one from history or run a new scan.";
    }
    return `Selected ${file.name || "scan"} is ${file.type_guess || "unknown type"}, entropy ${analysis.entropy ?? "-"}, findings ${analysis.suspicious_count ?? 0}.`;
  }
  if (asksEntropy) {
    if (!result) {
      return "No selected scan yet.";
    }
    return `Selected scan entropy is ${analysis.entropy ?? "unknown"}.`;
  }
  if (asksType) {
    if (!result) {
      return "No selected scan yet.";
    }
    return `Selected file type is ${file.type_guess || "unknown"}.`;
  }
  if (asksSeverity) {
    if (!result) {
      return "No selected scan yet.";
    }
    const top = highestSeverity(findings);
    if (!top) {
      return "Selected scan has no suspicious findings.";
    }
    return `Top severity is ${top.severity} at ${top.offset_hex}, keywords ${Array.isArray(top.keywords) ? top.keywords.join(",") : "-"}.`;
  }
  if (asksCredentials) {
    if (!result) {
      return "No selected scan yet.";
    }
    const creds = credentialFindings(analysis, findings);
    if (creds.length === 0) {
      return "No credential-like findings detected in selected scan.";
    }
    if (analysis.secret_exposure_count) {
      const samples = creds
        .slice(0, 4)
        .map((entry) => `${entry.severity}@${entry.offset_hex} ${entry.indicator}`)
        .join("; ");
      return `Secret exposures: ${analysis.secret_exposure_count}. Samples: ${samples}.`;
    }
    return `Credential-like findings: ${creds.length}. ${creds.slice(0, 4).map(summarizeFinding).join("; ")}.`;
  }
  if (asksUrls) {
    if (!result) {
      return "No selected scan yet.";
    }
    const urls = extractUrls(result, findings);
    if (urls.length === 0) {
      return "No URLs/endpoints found in selected scan strings.";
    }
    return `Discovered ${urls.length} endpoint(s): ${urls.slice(0, 6).join(", ")}.`;
  }
  if (asksRiskDna) {
    if (!result) {
      return "No selected scan yet.";
    }
    return buildRiskDna(result, findings);
  }
  if (asksSbom) {
    if (!result) {
      return "No selected scan yet.";
    }
    const candidateCount = Number(analysis.component_candidate_count || 0);
    const sbomCount = Number(analysis.sbom_component_count || 0);
    if (candidateCount === 0) {
      return `SBOM has ${sbomCount} component(s) total (including firmware root), with no external component candidates detected.`;
    }
    const candidates = Array.isArray(analysis.component_candidates)
      ? analysis.component_candidates
      : [];
    const preview = candidates
      .slice(0, 5)
      .map((entry) => `${entry.name || "unknown"} ${entry.version || "?"} (${entry.confidence || "low"})`)
      .join("; ");
    return `SBOM candidates: ${candidateCount}. Total SBOM components: ${sbomCount}. Top candidates: ${preview}.`;
  }
  if (asksCve) {
    if (!result) {
      return "No selected scan yet.";
    }
    const count = Number(analysis.cve_candidate_count || 0);
    if (count === 0) {
      return "No CVE candidates matched from local catalog for selected scan.";
    }
    const confidence = analysis.cve_confidence_summary || {};
    const cves = Array.isArray(analysis.cve_candidates) ? analysis.cve_candidates : [];
    const preview = cves
      .slice(0, 5)
      .map(
        (entry) =>
          `${entry.cve_id || "UNKNOWN-CVE"} (${entry.severity || "unknown"}, ${entry.confidence || "low"})`
      )
      .join("; ");
    return `CVE candidates: ${count} (high=${confidence.high || 0}, medium=${confidence.medium || 0}, low=${confidence.low || 0}). Top: ${preview}.`;
  }
  if (asksHardening || asksWhatIf) {
    if (!result) {
      return "No selected scan yet.";
    }
    const simulation = getHardeningSimulation(result);
    if (!simulation) {
      return "Hardening simulation is not available in this scan result.";
    }
    const baseline = simulation.baseline || {};
    const projected = simulation.projected || {};
    if (asksWhatIf) {
      const scenarios = Array.isArray(simulation.scenarios) ? simulation.scenarios : [];
      if (scenarios.length === 0) {
        return "No what-if scenarios are available for this scan.";
      }
      const preview = scenarios
        .slice(0, 3)
        .map(
          (item) =>
            `${item.name}: score ${item.projected_score} (${item.projected_band}), reduction ${item.reduction}`
        )
        .join("; ");
      return `What-if scenarios from baseline ${baseline.score || "-"} (${baseline.band || "-"}): ${preview}.`;
    }

    const actions = Array.isArray(simulation.actions) ? simulation.actions : [];
    const top = actions
      .slice(0, 4)
      .map(
        (item) =>
          `${item.title || "Unnamed action"} [${item.effort || "-"}, drop ${item.estimated_risk_reduction || 0}]`
      )
      .join("; ");
    return `Hardening plan: baseline ${baseline.score || "-"} (${baseline.band || "-"}), projected ${projected.score || "-"} (${projected.band || "-"}), estimated reduction ${projected.estimated_reduction || 0}, actions ${simulation.actions_count || 0}. Top actions: ${top}.`;
  }
  if (asksRules) {
    if (!result) {
      return "No selected scan yet.";
    }
    const engine = analysis.rule_engine || "unknown";
    const matchCount = Number(analysis.rule_match_count || 0);
    if (matchCount === 0) {
      return `Rules engine (${engine}) found no matches in selected scan.`;
    }
    const matches = Array.isArray(analysis.rule_matches) ? analysis.rule_matches : [];
    const preview = matches
      .slice(0, 5)
      .map((entry) => `${entry.severity || "info"}:${entry.rule_name || "unknown_rule"}`)
      .join("; ");
    return `Rules engine (${engine}) found ${matchCount} match(es). Top matches: ${preview}.`;
  }
  if (asksFindings) {
    if (!result) {
      return "No selected scan yet. Click one from history first.";
    }
    if (findings.length === 0) {
      return "Selected scan has no suspicious findings.";
    }
    if (requestedSeverity) {
      const filtered = asksThreshold
        ? findingsAtOrAbove(findings, requestedSeverity)
        : findingsBySeverity(findings, requestedSeverity);
      if (filtered.length === 0) {
        return asksThreshold
          ? `No findings at ${requestedSeverity} severity or above in selected scan.`
          : `No ${requestedSeverity} severity findings in selected scan.`;
      }
      return `${filtered.length} ${requestedSeverity}${
        asksThreshold ? "+" : ""
      } finding(s): ${filtered.slice(0, 6).map(summarizeFinding).join("; ")}.`;
    }
    const toShow = asksAll ? findings.slice(0, 10) : findings.slice(0, 3);
    const preview = toShow.map(summarizeFinding).join("; ");
    return `Selected scan has ${findings.length} findings. ${asksAll ? "Top 10:" : "Top entries:"} ${preview}.`;
  }
  if (asksNext) {
    if (!result) {
      return "Run a scan first, then I can suggest targeted next steps.";
    }
    const count = analysis.suspicious_count ?? 0;
    if (count === 0) {
      return "Good baseline. Next: diff against previous firmware and add custom YARA rules.";
    }
    return "Next: inspect highest-severity findings, verify credentials/endpoints manually, then run firmware diff against previous version.";
  }

  return "I did not catch that yet. Try: scan history, selected summary, high findings, credentials, urls/endpoints, yara rules, sbom components, cve candidates, risk dna, hardening plan, what-if scenarios, or next steps.";
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
  state.selectedRecord = record;
  const result = record?.result || {};
  const file = result.file || {};
  const analysis = result.analysis || {};
  const riskDna = analysis.risk_dna || {};
  const findings = Array.isArray(analysis.suspicious_findings)
    ? analysis.suspicious_findings
    : [];
  const preview = Array.isArray(analysis.strings_preview) ? analysis.strings_preview : [];

  refs.missionRiskScore.textContent = riskDna.score ?? String(analysis.suspicious_count ?? "-");
  refs.missionFileName.textContent = file.name || "Selected scan";
  refs.missionSummary.textContent = `Risk ${riskDna.band || "unknown"} / entropy ${
    analysis.entropy ?? "-"
  } / findings ${analysis.suspicious_count ?? 0}`;
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
  state.selectedRecord = null;
  refs.missionRiskScore.textContent = "FWB";
  refs.missionFileName.textContent = "No scan selected";
  refs.missionSummary.textContent = "Run or select a scan to load live evidence.";
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

function askAssistant(question) {
  const clean = question.trim();
  if (!clean) {
    return;
  }
  addAssistantMessage("user", clean);
  addAssistantMessage("bot", assistantReply(clean));
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
refs.assistantForm.addEventListener("submit", (event) => {
  event.preventDefault();
  const question = refs.assistantInput.value;
  refs.assistantInput.value = "";
  askAssistant(question);
});
refs.clearAssistant.addEventListener("click", () => {
  clearAssistantMessages();
});
for (const chip of refs.assistChips) {
  chip.addEventListener("click", () => {
    const prompt = chip.dataset.ask || chip.textContent || "";
    askAssistant(prompt);
  });
}

clearDetail();
clearAssistantMessages();
loadHistory()
  .then(() => setStatus("Dashboard ready."))
  .catch((error) => setStatus(`Unable to load history: ${error.message}`, "error"));
