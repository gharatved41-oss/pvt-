/**
 * VulnTwin AI — Evidence & Threat Intelligence Dashboard
 * Pure modular JavaScript frontend interacting with FastAPI backend.
 */

(function () {
  "use strict";

  // Base API endpoint
  const API_BASE = "/api/v1";

  // Application State
  const state = {
    analyses: [],
    activeAnalysis: null,
    evidenceFilter: "all",
    searchQuery: "",
    statusFilter: "all",
    isLoadingHistory: false,
    isSubmitting: false,
  };

  // DOM Elements Cache
  const elements = {
    healthBadge: document.getElementById("system-health-badge"),
    healthText: document.getElementById("health-text"),

    submissionForm: document.getElementById("submission-form"),
    targetInput: document.getElementById("target-url-input"),
    submitBtn: document.getElementById("submit-btn"),
    submitSpinner: document.getElementById("submit-spinner"),
    submitBtnText: document.getElementById("submit-btn-text"),
    submissionError: document.getElementById("submission-error"),
    presetChips: document.querySelectorAll(".preset-chip"),

    metricTotal: document.getElementById("metric-total"),
    metricCompleted: document.getElementById("metric-completed"),
    metricPending: document.getElementById("metric-pending"),
    metricFailed: document.getElementById("metric-failed"),

    activeSection: document.getElementById("active-detail-section"),
    detailStatusBadge: document.getElementById("detail-status-badge"),
    detailTargetUrl: document.getElementById("detail-target-url"),
    detailAnalysisId: document.getElementById("detail-analysis-id"),
    detailTimestamp: document.getElementById("detail-timestamp"),
    reanalyzeBtn: document.getElementById("reanalyze-btn"),
    closeDetailBtn: document.getElementById("close-detail-btn"),

    detailRiskScore: document.getElementById("detail-risk-score"),
    detailScoreBar: document.getElementById("detail-score-bar"),
    detailRiskLevelBadge: document.getElementById("detail-risk-level-badge"),
    detailConfidenceBadge: document.getElementById("detail-confidence-badge"),
    detailConfidenceText: document.getElementById("detail-confidence-text"),

    threatOutcomePanel: document.getElementById("threat-intel-outcome-panel"),
    outcomeCategoryTag: document.getElementById("outcome-category-tag"),
    outcomeProviderName: document.getElementById("outcome-provider-name"),
    outcomeSummaryText: document.getElementById("outcome-summary-text"),

    factorsContainer: document.getElementById("contributing-factors-container"),
    factorsList: document.getElementById("factors-list"),

    evidenceCountText: document.getElementById("evidence-count-text"),
    evidenceTableBody: document.getElementById("evidence-table-body"),
    evidenceFilterChips: document.querySelectorAll(".filter-chip"),

    remediationGrid: document.getElementById("remediation-cards-grid"),

    searchInput: document.getElementById("search-input"),
    statusFilter: document.getElementById("status-filter"),
    refreshHistoryBtn: document.getElementById("refresh-history-btn"),
    retryHistoryBtn: document.getElementById("retry-history-btn"),

    historyLoading: document.getElementById("history-loading"),
    historyError: document.getElementById("history-error"),
    historyErrorMsg: document.getElementById("history-error-msg"),
    historyEmpty: document.getElementById("history-empty"),
    historyTableWrapper: document.getElementById("history-table-wrapper"),
    analysesTableBody: document.getElementById("analyses-table-body"),
  };

  // =========================================================================
  // Utility Functions
  // =========================================================================

  /**
   * Escape and sanitize string for safe DOM display (prevent XSS).
   */
  function escapeHTML(str) {
    if (!str) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  /**
   * Redact credentials from URL string so passwords are never exposed.
   */
  function sanitizeUrlForDisplay(urlStr) {
    if (!urlStr) return "";
    try {
      const url = new URL(urlStr);
      if (url.username || url.password) {
        url.password = "******";
        return url.toString();
      }
    } catch (e) {
      // If not standard URL, use regex to mask credentials
      return urlStr.replace(/:\/\/([^:]+):([^@]+)@/, "://$1:******@");
    }
    return urlStr;
  }

  /**
   * Format ISO date string into readable UTC timestamp.
   */
  function formatTimestamp(isoStr) {
    if (!isoStr) return "--";
    try {
      const date = new Date(isoStr);
      return date.toISOString().replace("T", " ").substring(0, 19) + " UTC";
    } catch (e) {
      return isoStr;
    }
  }

  // =========================================================================
  // API Client Methods
  // =========================================================================

  /**
   * Check system health connectivity.
   */
  async function checkHealth() {
    try {
      const response = await fetch(`${API_BASE}/health`);
      if (response.ok) {
        const data = await response.json();
        elements.healthBadge.className = "health-badge health-online";
        elements.healthText.textContent = `API Online (${data.status})`;
      } else {
        throw new Error(`HTTP ${response.status}`);
      }
    } catch (err) {
      elements.healthBadge.className = "health-badge health-offline";
      elements.healthText.textContent = "API Offline";
    }
  }

  /**
   * Fetch paginated analysis history from the backend.
   */
  async function loadAnalyses() {
    state.isLoadingHistory = true;
    showHistoryState("loading");

    try {
      const response = await fetch(`${API_BASE}/analyses?limit=100&offset=0`);
      if (!response.ok) {
        throw new Error(`Server returned HTTP ${response.status}`);
      }

      const data = await response.json();
      state.analyses = data.items || [];

      updateOverviewMetrics(state.analyses);
      renderAnalysesTable();

      showHistoryState(state.analyses.length > 0 ? "content" : "empty");
    } catch (err) {
      elements.historyErrorMsg.textContent = `Failed to connect to API: ${err.message}`;
      showHistoryState("error");
    } finally {
      state.isLoadingHistory = false;
    }
  }

  /**
   * Fetch complete details and evidence for a specific analysis ID.
   */
  async function fetchAnalysisDetail(analysisId) {
    try {
      const response = await fetch(`${API_BASE}/analyses/${analysisId}`);
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: Failed to retrieve analysis`);
      }
      const data = await response.json();
      state.activeAnalysis = data;
      renderActiveDetail(data);
    } catch (err) {
      alert(`Error loading analysis detail: ${err.message}`);
    }
  }

  /**
   * Trigger passive analysis pipeline on a pending analysis.
   */
  async function triggerAnalysis(analysisId) {
    try {
      const response = await fetch(`${API_BASE}/analyses/${analysisId}/analyze`, {
        method: "POST",
      });

      if (!response.ok) {
        const errData = await response.json().catch(() => ({}));
        throw new Error(errData.detail || `HTTP ${response.status}`);
      }

      const updated = await response.json();
      state.activeAnalysis = updated;
      renderActiveDetail(updated);
      await loadAnalyses(); // Refresh overview table
    } catch (err) {
      alert(`Analysis execution error: ${err.message}`);
    }
  }

  /**
   * Submit new target URL for analysis.
   */
  async function handleTargetSubmission(url) {
    hideSubmissionError();
    setSubmissionLoading(true);

    try {
      // Step 1: Create record (pending)
      const createRes = await fetch(`${API_BASE}/analyses`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: url.trim() }),
      });

      if (!createRes.ok) {
        const errJson = await createRes.json().catch(() => ({}));
        const msg = errJson.message || (errJson.details && errJson.details[0]?.msg) || `Validation error (HTTP ${createRes.status})`;
        throw new Error(msg);
      }

      const created = await createRes.json();
      elements.targetInput.value = "";

      // Step 2: Auto-trigger passive analysis
      await triggerAnalysis(created.id);
    } catch (err) {
      showSubmissionError(err.message);
    } finally {
      setSubmissionLoading(false);
    }
  }

  // =========================================================================
  // Rendering Methods
  // =========================================================================

  /**
   * Update metrics cards from analysis list.
   */
  function updateOverviewMetrics(items) {
    const total = items.length;
    const completed = items.filter((i) => i.status === "completed").length;
    const pending = items.filter((i) => i.status === "pending").length;
    const failed = items.filter((i) => i.status === "failed").length;

    elements.metricTotal.textContent = String(total);
    elements.metricCompleted.textContent = String(completed);
    elements.metricPending.textContent = String(pending);
    elements.metricFailed.textContent = String(failed);
  }

  /**
   * Render Recent Analyses history table.
   */
  function renderAnalysesTable() {
    const query = state.searchQuery.toLowerCase().trim();
    const filter = state.statusFilter;

    const filtered = state.analyses.filter((item) => {
      const matchStatus = filter === "all" || item.status === filter;
      const matchSearch =
        !query ||
        item.url.toLowerCase().includes(query) ||
        item.id.toLowerCase().includes(query);
      return matchStatus && matchSearch;
    });

    elements.analysesTableBody.innerHTML = "";

    if (filtered.length === 0) {
      const emptyRow = document.createElement("tr");
      emptyRow.innerHTML = `<td colspan="5" style="text-align:center; padding: 2rem; color: var(--text-muted);">No analyses matched your search/filter criteria.</td>`;
      elements.analysesTableBody.appendChild(emptyRow);
      return;
    }

    filtered.forEach((item) => {
      const tr = document.createElement("tr");

      const statusBadge = `<span class="status-badge status-${escapeHTML(item.status)}">${escapeHTML(item.status)}</span>`;
      const cleanUrl = sanitizeUrlForDisplay(item.url);
      const shortId = item.id.substring(0, 8) + "...";

      tr.innerHTML = `
        <td>${statusBadge}</td>
        <td class="cell-url mono" title="${escapeHTML(cleanUrl)}">${escapeHTML(cleanUrl)}</td>
        <td class="mono"><span class="code-id" title="${escapeHTML(item.id)}">${escapeHTML(shortId)}</span></td>
        <td><time datetime="${escapeHTML(item.created_at)}">${formatTimestamp(item.created_at)}</time></td>
        <td>
          <button type="button" class="btn btn-secondary btn-sm inspect-btn" data-id="${escapeHTML(item.id)}">
            View Details
          </button>
        </td>
      `;

      elements.analysesTableBody.appendChild(tr);
    });

    // Attach inspect buttons
    elements.analysesTableBody.querySelectorAll(".inspect-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        const id = btn.getAttribute("data-id");
        fetchAnalysisDetail(id);
      });
    });
  }

  /**
   * Render the active analysis details, triad metrics, factors, evidence, and remediation.
   */
  function renderActiveDetail(analysis) {
    if (!analysis) {
      elements.activeSection.hidden = true;
      return;
    }

    elements.activeSection.hidden = false;

    // Header info
    elements.detailStatusBadge.className = `status-badge status-${analysis.status}`;
    elements.detailStatusBadge.textContent = analysis.status;
    elements.detailTargetUrl.textContent = sanitizeUrlForDisplay(analysis.url);
    elements.detailAnalysisId.textContent = analysis.id;
    elements.detailTimestamp.textContent = formatTimestamp(analysis.created_at);

    // Re-analyze button toggle
    if (analysis.status === "completed") {
      elements.reanalyzeBtn.disabled = true;
      elements.reanalyzeBtn.title = "Analysis is already completed.";
    } else {
      elements.reanalyzeBtn.disabled = false;
      elements.reanalyzeBtn.title = "Run analysis pipeline";
    }

    const assessment = analysis.risk_assessment;
    const evidenceItems = analysis.evidence_items || [];

    // 1. Risk Score Card
    if (assessment) {
      const score = assessment.risk_score;
      elements.detailRiskScore.textContent = String(score);
      elements.detailScoreBar.style.width = `${score}%`;

      // Color meter based on score
      elements.detailScoreBar.className = "score-meter-fill";
      if (score > 75) elements.detailScoreBar.classList.add("meter-critical");
      else if (score > 50) elements.detailScoreBar.classList.add("meter-high");
      else if (score > 25) elements.detailScoreBar.classList.add("meter-medium");

      elements.detailRiskLevelBadge.className = `level-badge level-${assessment.risk_level}`;
      elements.detailRiskLevelBadge.textContent = assessment.risk_level.toUpperCase();

      // 2. Confidence Card
      elements.detailConfidenceBadge.className = `level-badge level-${assessment.confidence_level}`;
      elements.detailConfidenceBadge.textContent = assessment.confidence_level.toUpperCase();
      elements.detailConfidenceText.textContent = `${assessment.confidence_level.charAt(0).toUpperCase() + assessment.confidence_level.slice(1)} Confidence`;

      // 3. Contributing Factors
      renderContributingFactors(assessment.contributing_factors || []);
    } else {
      elements.detailRiskScore.textContent = "--";
      elements.detailScoreBar.style.width = "0%";
      elements.detailRiskLevelBadge.className = "level-badge level-unknown";
      elements.detailRiskLevelBadge.textContent = "PENDING";
      elements.detailConfidenceText.textContent = "Pending Evaluation";
      elements.factorsList.innerHTML = `<p style="color:var(--text-muted); font-size: 0.85rem;">Analysis pending execution. Click Re-analyze to run pipeline.</p>`;
    }

    // 4. Threat Intelligence Outcome Banner
    renderThreatOutcomeBanner(evidenceItems);

    // 5. Evidence Items Table
    renderEvidenceTable(evidenceItems);

    // 6. Remediation Guidance
    renderRemediationGuidance(analysis, evidenceItems);

    // Scroll smoothly to active section
    elements.activeSection.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  /**
   * Render Threat Intelligence outcome banner.
   */
  function renderThreatOutcomeBanner(evidenceItems) {
    const intelEvidence = evidenceItems.find(
      (e) => e.signal_name.includes("reputation") || e.signal_name.includes("threat_intel")
    );

    const panel = elements.threatOutcomePanel;
    const tag = elements.outcomeCategoryTag;
    const provider = elements.outcomeProviderName;
    const text = elements.outcomeSummaryText;

    if (!intelEvidence) {
      panel.className = "outcome-banner outcome-unknown";
      tag.textContent = "Telemetry Pending";
      provider.textContent = "Provider: None";
      text.textContent = "No threat intelligence reputation query has been executed yet for this target.";
      return;
    }

    const providerName = intelEvidence.evidence_source || "Threat Intelligence Provider";
    provider.textContent = `Provider: ${providerName}`;

    const struct = intelEvidence.structured_data || {};
    const lookupStatus = struct.lookup_status || intelEvidence.observed_value || "";

    if (intelEvidence.collection_status === "observed" && (struct.threat_verdict || "").toLowerCase() === "malicious") {
      panel.className = "outcome-banner outcome-match";
      tag.textContent = "Confirmed Malicious Match";
      text.textContent = intelEvidence.explanatory_notes || "Multi-vendor consensus flagged target as malicious.";
    } else if (intelEvidence.collection_status === "observed" && (struct.threat_verdict || "").toLowerCase() === "suspicious") {
      panel.className = "outcome-banner outcome-match";
      tag.textContent = "Suspicious Telemetry Match";
      text.textContent = intelEvidence.explanatory_notes || "Security engines flagged suspicious behavior.";
    } else if (lookupStatus === "privacy_blocked" || intelEvidence.collection_status === "skipped") {
      panel.className = "outcome-banner outcome-privacy";
      tag.textContent = "Privacy-Blocked Lookup";
      text.innerHTML = `<strong>Local Privacy Filter Applied:</strong> Target is a private/internal IP, loopback, or contains credentials. No data was sent to third parties. <em>Critical: A privacy-blocked target is NOT a confirmed clean or safe result.</em>`;
    } else if (lookupStatus === "unknown_indicator") {
      panel.className = "outcome-banner outcome-unknown";
      tag.textContent = "Unknown Indicator (Unrecorded)";
      text.innerHTML = `Target indicator was not found in the threat intelligence database (HTTP 404). <em>Critical: An unknown indicator is NOT proof that the target is safe or benign.</em>`;
    } else if (intelEvidence.collection_status === "error" || lookupStatus.startsWith("error_")) {
      panel.className = "outcome-banner outcome-error";
      tag.textContent = "Provider Unavailable / Rate Limited";
      text.textContent = intelEvidence.explanatory_notes || "Reputation query encountered a network or quota error. Pipeline safely continued.";
    } else {
      // Genuine clean no-match
      panel.className = "outcome-banner outcome-clean";
      tag.textContent = "Genuine No-Match (Clean in DB)";
      text.innerHTML = `No threat entries found in provider database. <em>Critical safety rule: The absence of a reported match does NOT certify the target is safe or benign.</em>`;
    }
  }

  /**
   * Render contributing risk factors list.
   */
  function renderContributingFactors(factors) {
    elements.factorsList.innerHTML = "";

    if (factors.length === 0) {
      elements.factorsList.innerHTML = `<p style="color:var(--text-muted); font-size:0.85rem;">No specific contributing factors recorded.</p>`;
      return;
    }

    factors.forEach((f) => {
      const item = document.createElement("div");
      item.className = "factor-item";

      let deltaClass = "delta-zero";
      let deltaPrefix = "";
      if (f.score_delta > 0) {
        deltaClass = "delta-plus";
        deltaPrefix = "+";
      } else if (f.score_delta < 0) {
        deltaClass = "delta-minus";
      }

      item.innerHTML = `
        <div class="factor-left">
          <span class="factor-name">${escapeHTML(f.signal_name)}</span>
          <span class="factor-rationale">${escapeHTML(f.rationale)}</span>
        </div>
        <div class="factor-delta ${deltaClass}">${deltaPrefix}${f.score_delta} pts</div>
      `;

      elements.factorsList.appendChild(item);
    });
  }

  /**
   * Render evidence table with filtering.
   */
  function renderEvidenceTable(items) {
    elements.evidenceCountText.textContent = `${items.length} items`;
    const filter = state.evidenceFilter;

    const filtered = items.filter((item) => {
      if (filter === "all") return true;
      return item.collection_status === filter;
    });

    elements.evidenceTableBody.innerHTML = "";

    if (filtered.length === 0) {
      const row = document.createElement("tr");
      row.innerHTML = `<td colspan="5" style="text-align:center; padding:1.5rem; color:var(--text-muted);">No evidence signals match the '${filter}' filter.</td>`;
      elements.evidenceTableBody.appendChild(row);
      return;
    }

    filtered.forEach((item) => {
      const tr = document.createElement("tr");
      const statusClass = `status-pill-${item.collection_status}`;

      tr.innerHTML = `
        <td class="mono"><strong>${escapeHTML(item.signal_name)}</strong></td>
        <td class="mono">${escapeHTML(item.observed_value || "--")}</td>
        <td>${escapeHTML(item.evidence_source)}</td>
        <td><span class="status-pill ${statusClass}">${escapeHTML(item.collection_status)}</span></td>
        <td>${escapeHTML(item.explanatory_notes || "--")}</td>
      `;

      elements.evidenceTableBody.appendChild(tr);
    });
  }

  /**
   * Render defensive remediation and hardening guidance.
   */
  function renderRemediationGuidance(analysis, evidenceItems) {
    elements.remediationGrid.innerHTML = "";

    const recommendations = [];

    // Check transport scheme
    const schemeEv = evidenceItems.find((e) => e.signal_name === "url_scheme");
    if (schemeEv && (schemeEv.observed_value || "").toLowerCase() === "http") {
      recommendations.push({
        title: "Enforce TLS Transport Encryption",
        text: "The target specifies unencrypted HTTP transport. Configure an automated redirect to HTTPS (TLS 1.3), issue valid certificates, and configure Strict-Transport-Security (HSTS) headers.",
      });
    }

    // Check sensitive auth tokens
    const tokenEv = evidenceItems.find((e) => e.signal_name === "sensitive_lexical_tokens");
    if (tokenEv && tokenEv.collection_status === "observed") {
      recommendations.push({
        title: "Harden Authentication Endpoints",
        text: `URL path specifies sensitive authentication tokens ('${escapeHTML(tokenEv.observed_value)}'). Ensure multi-factor authentication (MFA), strict rate-limiting, and brute-force defenses are active.`,
      });
    }

    // Check threat intelligence findings
    const intelEv = evidenceItems.find(
      (e) => e.signal_name.includes("reputation") || e.signal_name.includes("threat_intel")
    );
    if (intelEv) {
      const struct = intelEv.structured_data || {};
      const verdict = (struct.threat_verdict || "").toLowerCase();
      if (verdict === "malicious") {
        recommendations.push({
          title: "Investigate Corroborated IOC Telemetry",
          text: "Target indicator was flagged as malicious by multi-vendor threat engines. Audit web server logs for matching inbound traffic, inspect DNS sinkholes, and isolate related network segments.",
        });
      } else if (intelEv.collection_status === "skipped") {
        recommendations.push({
          title: "Internal Infrastructure Perimeter Defense",
          text: "Indicator represents a local loopback, RFC 1918 private address, or internal corporate domain. Verify firewall access controls and zero-trust segmentation to prevent internal network exposure.",
        });
      }
    }

    // Baseline Digital Twin guidance
    recommendations.push({
      title: "Digital Twin Verification Precaution",
      text: "Passive reputation scores do not prove active vulnerability exploitability. Do not initiate disruptive penetration tests or active exploit verification outside of an isolated containerized Digital Twin lab environment.",
    });

    recommendations.forEach((rec) => {
      const card = document.createElement("div");
      card.className = "remediation-card";
      card.innerHTML = `
        <div class="remediation-title">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          </svg>
          ${escapeHTML(rec.title)}
        </div>
        <p class="remediation-text">${escapeHTML(rec.text)}</p>
      `;
      elements.remediationGrid.appendChild(card);
    });
  }

  // =========================================================================
  // UI Helper States
  // =========================================================================

  function showHistoryState(stateName) {
    elements.historyLoading.hidden = stateName !== "loading";
    elements.historyError.hidden = stateName !== "error";
    elements.historyEmpty.hidden = stateName !== "empty";
    elements.historyTableWrapper.hidden = stateName !== "content";
  }

  function setSubmissionLoading(isLoading) {
    state.isSubmitting = isLoading;
    elements.submitBtn.disabled = isLoading;
    elements.submitSpinner.hidden = !isLoading;
    elements.submitBtnText.textContent = isLoading ? "Analyzing..." : "Submit & Analyze";
  }

  function showSubmissionError(msg) {
    elements.submissionError.textContent = msg;
    elements.submissionError.hidden = false;
  }

  function hideSubmissionError() {
    elements.submissionError.textContent = "";
    elements.submissionError.hidden = true;
  }

  // =========================================================================
  // Event Listeners & Initialization
  // =========================================================================

  function attachEventListeners() {
    // Target submission form
    elements.submissionForm.addEventListener("submit", (e) => {
      e.preventDefault();
      const val = elements.targetInput.value;
      if (val) {
        handleTargetSubmission(val);
      }
    });

    // Preset chips
    elements.presetChips.forEach((chip) => {
      chip.addEventListener("click", () => {
        const url = chip.getAttribute("data-url");
        elements.targetInput.value = url;
        handleTargetSubmission(url);
      });
    });

    // Re-analyze active button
    elements.reanalyzeBtn.addEventListener("click", () => {
      if (state.activeAnalysis && state.activeAnalysis.id) {
        triggerAnalysis(state.activeAnalysis.id);
      }
    });

    // Close detail view
    elements.closeDetailBtn.addEventListener("click", () => {
      state.activeAnalysis = null;
      elements.activeSection.hidden = true;
    });

    // Evidence table filter chips
    elements.evidenceFilterChips.forEach((chip) => {
      chip.addEventListener("click", () => {
        elements.evidenceFilterChips.forEach((c) => c.classList.remove("active"));
        chip.classList.add("active");
        state.evidenceFilter = chip.getAttribute("data-filter");
        if (state.activeAnalysis) {
          renderEvidenceTable(state.activeAnalysis.evidence_items || []);
        }
      });
    });

    // History search and filter
    elements.searchInput.addEventListener("input", (e) => {
      state.searchQuery = e.target.value;
      renderAnalysesTable();
    });

    elements.statusFilter.addEventListener("change", (e) => {
      state.statusFilter = e.target.value;
      renderAnalysesTable();
    });

    // Refresh history button
    elements.refreshHistoryBtn.addEventListener("click", () => {
      loadAnalyses();
    });

    elements.retryHistoryBtn.addEventListener("click", () => {
      loadAnalyses();
    });
  }

  // Bootstrapping
  function init() {
    attachEventListeners();
    checkHealth();
    loadAnalyses();

    // Auto health check poll every 30s
    setInterval(checkHealth, 30000);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
