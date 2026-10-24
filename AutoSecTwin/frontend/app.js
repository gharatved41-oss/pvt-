/**
 * VulnTwin AI — Integrated Security Operations & Evidence Dashboard
 * Pure modular JavaScript frontend interacting with FastAPI backend.
 * Provides unified URL reputation analysis, host OS asset management,
 * read-only OS vulnerability assessments, and explainable risk evaluation.
 */

(function () {
  "use strict";

  // Base API configuration
  const API_BASE = "/api/v1";

  // Application State
  const state = {
    // Auth & Identity
    token: sessionStorage.getItem("vulntwin_token") || "token_user_a",
    username: sessionStorage.getItem("vulntwin_username") || "Security Analyst A",
    role: sessionStorage.getItem("vulntwin_role") || "analyst",

    // Navigation
    activeTab: "dashboard",

    // URL Analysis State
    analyses: [],
    activeAnalysis: null,
    evidenceFilter: "all",
    searchQuery: "",
    statusFilter: "all",
    isLoadingHistory: false,
    isSubmitting: false,

    // OS Assets State
    assets: [],
    isLoadingAssets: false,

    // OS Assessments State
    assessments: [],
    activeAssessmentDetail: null,
    osFindingsFilter: "all",
    isLoadingAssessments: false,

    // Aggregated Findings
    allFindings: [],
    findingsSearch: "",
    findingsSeverity: "all",
  };

  // =========================================================================
  // DOM Elements Cache
  // =========================================================================
  const elements = {
    // Global Header & Auth
    healthBadge: document.getElementById("system-health-badge"),
    healthText: document.getElementById("health-text"),
    authPill: document.getElementById("auth-session-pill"),
    authUsername: document.getElementById("auth-current-username"),
    authRole: document.getElementById("auth-current-role"),
    globalAlertBanner: document.getElementById("global-alert-banner"),
    globalAlertText: document.getElementById("global-alert-text"),
    globalAlertClose: document.getElementById("global-alert-close"),

    // Navigation Tabs
    navTabs: document.querySelectorAll(".nav-tab"),
    views: {
      dashboard: document.getElementById("view-dashboard"),
      "os-assets": document.getElementById("view-os-assets"),
      "os-assessments": document.getElementById("view-os-assessments"),
      findings: document.getElementById("view-findings"),
      "url-analysis": document.getElementById("view-url-analysis"),
      settings: document.getElementById("view-settings"),
    },

    // Dashboard Overview Elements
    dashMetricAssets: document.getElementById("dash-metric-assets"),
    dashMetricAssessments: document.getElementById("dash-metric-assessments"),
    dashMetricFindings: document.getElementById("dash-metric-findings"),
    dashMetricRiskLevel: document.getElementById("dash-metric-risk-level"),
    btnRefreshDashboard: document.getElementById("btn-refresh-dashboard"),
    btnQuickNewAssessment: document.getElementById("btn-quick-new-assessment"),
    dashRecentAssessmentsBody: document.getElementById("dash-recent-assessments-body"),
    dashAssessmentsLoading: document.getElementById("dash-assessments-loading"),
    dashAssessmentsEmpty: document.getElementById("dash-assessments-empty"),
    dashSeverityBar: document.getElementById("dash-severity-bar"),
    barCrit: document.getElementById("bar-crit"),
    barHigh: document.getElementById("bar-high"),
    barMed: document.getElementById("bar-med"),
    barLow: document.getElementById("bar-low"),
    barUnrated: document.getElementById("bar-unrated"),
    countCrit: document.getElementById("count-crit"),
    countHigh: document.getElementById("count-high"),
    countMed: document.getElementById("count-med"),
    countLow: document.getElementById("count-low"),
    countUnrated: document.getElementById("count-unrated"),
    distCountCompleted: document.getElementById("dist-count-completed"),
    distCountRunning: document.getElementById("dist-count-running"),
    distCountPending: document.getElementById("dist-count-pending"),
    distCountFailed: document.getElementById("dist-count-failed"),

    // OS Assets View Elements
    registerAssetForm: document.getElementById("register-asset-form"),
    assetHostnameInput: document.getElementById("asset-hostname-input"),
    assetFamilySelect: document.getElementById("asset-family-select"),
    assetNameInput: document.getElementById("asset-name-input"),
    assetVersionInput: document.getElementById("asset-version-input"),
    assetArchSelect: document.getElementById("asset-arch-select"),
    btnSubmitAsset: document.getElementById("btn-submit-asset"),
    assetSubmitSpinner: document.getElementById("asset-submit-spinner"),
    assetSubmitBtnText: document.getElementById("asset-submit-btn-text"),
    assetRegistrationError: document.getElementById("asset-registration-error"),
    assetRegistrationSuccess: document.getElementById("asset-registration-success"),
    osAssetsTableBody: document.getElementById("os-assets-table-body"),
    assetsLoading: document.getElementById("assets-loading"),
    assetsEmpty: document.getElementById("assets-empty"),
    assetsUnauthorized: document.getElementById("assets-unauthorized"),
    assetsUnauthText: document.getElementById("assets-unauth-text"),
    btnRefreshAssets: document.getElementById("btn-refresh-assets"),

    // OS Assessments View Elements
    createAssessmentForm: document.getElementById("create-assessment-form"),
    selectAssessmentAsset: document.getElementById("select-assessment-asset"),
    btnCreateAssessment: document.getElementById("btn-create-assessment"),
    createAssessmentSpinner: document.getElementById("create-assessment-spinner"),
    createAssessmentBtnText: document.getElementById("create-assessment-btn-text"),
    assessmentLauncherError: document.getElementById("assessment-launcher-error"),
    osAssessmentsTableBody: document.getElementById("os-assessments-table-body"),
    assessmentsLoading: document.getElementById("assessments-loading"),
    assessmentsEmpty: document.getElementById("assessments-empty"),

    // OS Assessment Detail Elements
    osDetailSection: document.getElementById("os-assessment-detail-section"),
    osDetailStatusBadge: document.getElementById("os-detail-status-badge"),
    osDetailTargetHostname: document.getElementById("os-detail-target-hostname"),
    osDetailAssessmentId: document.getElementById("os-detail-assessment-id"),
    osDetailAssetId: document.getElementById("os-detail-asset-id"),
    osDetailTimestamp: document.getElementById("os-detail-timestamp"),
    btnRunAssessmentNow: document.getElementById("btn-run-assessment-now"),
    btnCloseOsDetail: document.getElementById("btn-close-os-detail"),
    osDetailRiskScore: document.getElementById("os-detail-risk-score"),
    osDetailScoreBar: document.getElementById("os-detail-score-bar"),
    osDetailRiskLevel: document.getElementById("os-detail-risk-level"),
    osDetailConfidenceBadge: document.getElementById("os-detail-confidence-badge"),
    osDetailConfidenceText: document.getElementById("os-detail-confidence-text"),
    osLimitationsContainer: document.getElementById("os-limitations-container"),
    osLimitationsList: document.getElementById("os-limitations-list"),
    osFindingsCountText: document.getElementById("os-findings-count-text"),
    osFindingsTableBody: document.getElementById("os-findings-table-body"),
    osFindingsFilterChips: document.querySelectorAll("[data-os-filter]"),
    osEvidenceCountText: document.getElementById("os-evidence-count-text"),
    osEvidenceTableBody: document.getElementById("os-evidence-table-body"),
    osRemediationGrid: document.getElementById("os-remediation-cards-grid"),

    // Findings Explorer Elements
    findingsSearchInput: document.getElementById("findings-search-input"),
    findingsSeverityFilter: document.getElementById("findings-severity-filter"),
    aggregatedFindingsEmpty: document.getElementById("aggregated-findings-empty"),
    aggregatedFindingsTableWrapper: document.getElementById("aggregated-findings-table-wrapper"),
    aggregatedFindingsBody: document.getElementById("aggregated-findings-body"),

    // URL Analysis View Elements (Preserved from Milestone 6)
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

    // Settings View Elements
    authPresetBtns: document.querySelectorAll(".auth-preset-btn"),
    customTokenInput: document.getElementById("custom-token-input"),
    btnApplyToken: document.getElementById("btn-apply-token"),
  };

  // =========================================================================
  // Utility & Security Functions
  // =========================================================================

  function escapeHTML(str) {
    if (str === null || str === undefined) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function sanitizeUrlForDisplay(urlStr) {
    if (!urlStr) return "";
    try {
      const url = new URL(urlStr);
      if (url.username || url.password) {
        url.password = "******";
        return url.toString();
      }
    } catch (e) {
      return urlStr.replace(/:\/\/([^:]+):([^@]+)@/, "://$1:******@");
    }
    return urlStr;
  }

  function formatTimestamp(isoStr) {
    if (!isoStr) return "--";
    try {
      const date = new Date(isoStr);
      return date.toISOString().replace("T", " ").substring(0, 19) + " UTC";
    } catch (e) {
      return isoStr;
    }
  }

  function showGlobalAlert(message, isError = true) {
    if (!elements.globalAlertBanner) return;
    elements.globalAlertText.textContent = message;
    elements.globalAlertBanner.hidden = false;
    elements.globalAlertBanner.className = isError ? "global-banner" : "global-banner form-success-msg";
  }

  function hideGlobalAlert() {
    if (elements.globalAlertBanner) {
      elements.globalAlertBanner.hidden = true;
    }
  }

  // =========================================================================
  // Authentication & Session Management
  // =========================================================================

  function getAuthHeaders() {
    const headers = { "Content-Type": "application/json" };
    if (state.token) {
      headers["Authorization"] = `Bearer ${state.token.trim()}`;
    }
    return headers;
  }

  function updateAuthSession(token, username, role) {
    state.token = token;
    state.username = username;
    state.role = role;

    sessionStorage.setItem("vulntwin_token", token);
    sessionStorage.setItem("vulntwin_username", username);
    sessionStorage.setItem("vulntwin_role", role);

    if (elements.authUsername) elements.authUsername.textContent = username;
    if (elements.authRole) elements.authRole.textContent = role;

    // Update settings presets highlight
    elements.authPresetBtns.forEach((btn) => {
      btn.classList.toggle("active", btn.dataset.token === token);
    });

    hideGlobalAlert();
    // Reload active view with the new identity credentials
    reloadActiveView();
  }

  // =========================================================================
  // Navigation & View Routing
  // =========================================================================

  function switchTab(tabName) {
    if (!elements.views[tabName]) return;
    state.activeTab = tabName;

    // Update tab bar buttons
    elements.navTabs.forEach((tab) => {
      tab.classList.toggle("active", tab.dataset.tab === tabName);
    });

    // Update view visibility
    Object.entries(elements.views).forEach(([name, el]) => {
      if (el) el.hidden = name !== tabName;
    });

    reloadActiveView();
  }

  function reloadActiveView() {
    switch (state.activeTab) {
      case "dashboard":
        loadDashboardOverview();
        break;
      case "os-assets":
        loadOSAssets();
        break;
      case "os-assessments":
        loadOSAssessments();
        populateAssetSelectOptions();
        break;
      case "findings":
        loadAggregatedFindings();
        break;
      case "url-analysis":
        loadHistory();
        break;
    }
  }

  // =========================================================================
  // System Health
  // =========================================================================

  async function checkHealth() {
    try {
      const response = await fetch(`${API_BASE}/health`);
      if (response.ok) {
        const data = await response.json();
        if (elements.healthBadge) {
          elements.healthBadge.className = "health-badge health-online";
          elements.healthText.textContent = `API Online (${data.status})`;
        }
      } else {
        throw new Error(`HTTP ${response.status}`);
      }
    } catch (err) {
      if (elements.healthBadge) {
        elements.healthBadge.className = "health-badge health-offline";
        elements.healthText.textContent = "API Offline";
      }
    }
  }

  // =========================================================================
  // Dashboard Overview View Logic
  // =========================================================================

  async function loadDashboardOverview() {
    if (elements.dashAssessmentsLoading) elements.dashAssessmentsLoading.hidden = false;
    if (elements.dashAssessmentsEmpty) elements.dashAssessmentsEmpty.hidden = true;

    try {
      // 1. Fetch OS Assets
      let assetCount = 0;
      try {
        const assetRes = await fetch(`${API_BASE}/os/assets`, { headers: getAuthHeaders() });
        if (assetRes.ok) {
          const assetData = await assetRes.json();
          assetCount = assetData.total || (assetData.items ? assetData.items.length : 0);
          state.assets = assetData.items || [];
        } else if (assetRes.status === 401 || assetRes.status === 403) {
          assetCount = 0;
        }
      } catch (e) {
        console.warn("Could not fetch assets:", e);
      }

      // 2. Fetch OS Assessments
      let assessments = [];
      try {
        const assessRes = await fetch(`${API_BASE}/os/assessments`, { headers: getAuthHeaders() });
        if (assessRes.ok) {
          const assessData = await assessRes.json();
          assessments = assessData.items || [];
          state.assessments = assessments;
        } else if (assessRes.status === 401 || assessRes.status === 403) {
          showGlobalAlert(`Authorization Status: HTTP ${assessRes.status} for ${state.username} (${state.role})`);
        }
      } catch (e) {
        console.warn("Could not fetch assessments:", e);
      }

      // 3. Compute Metrics
      const completedAssessments = assessments.filter((a) => a.status === "completed");
      const runningCount = assessments.filter((a) => a.status === "running").length;
      const pendingCount = assessments.filter((a) => a.status === "pending").length;
      const failedCount = assessments.filter((a) => a.status === "failed").length;

      let latestRiskLevel = "--";
      if (completedAssessments.length > 0) {
        const sorted = [...completedAssessments].sort((a, b) => new Date(b.completed_at || b.created_at) - new Date(a.completed_at || a.created_at));
        latestRiskLevel = sorted[0].risk_level ? sorted[0].risk_level.toUpperCase() : "CLEAN";
      } else if (assessments.length > 0) {
        latestRiskLevel = "PENDING";
      } else {
        latestRiskLevel = "NONE";
      }

      // 4. Fetch Findings Count from Completed Assessments
      let totalFindings = 0;
      let critCount = 0;
      let highCount = 0;
      let medCount = 0;
      let lowCount = 0;
      let unratedCount = 0;

      for (const ass of completedAssessments) {
        try {
          const findRes = await fetch(`${API_BASE}/os/assessments/${ass.id}/findings`, { headers: getAuthHeaders() });
          if (findRes.ok) {
            const findData = await findRes.json();
            totalFindings += findData.total || 0;
            critCount += findData.critical_count || 0;
            highCount += findData.high_count || 0;
            medCount += findData.medium_count || 0;
            lowCount += findData.low_count || 0;
            unratedCount += findData.unrated_count || 0;
          }
        } catch (e) {
          // ignore individual fetch errors
        }
      }

      // 5. Update UI Overview Metric Cards
      if (elements.dashMetricAssets) elements.dashMetricAssets.textContent = assetCount;
      if (elements.dashMetricAssessments) elements.dashMetricAssessments.textContent = completedAssessments.length;
      if (elements.dashMetricFindings) elements.dashMetricFindings.textContent = totalFindings;
      if (elements.dashMetricRiskLevel) {
        elements.dashMetricRiskLevel.textContent = latestRiskLevel;
        elements.dashMetricRiskLevel.className = `metric-value ${getRiskLevelColorClass(latestRiskLevel)}`;
      }

      // 6. Update Severity Distribution Bar
      if (elements.countCrit) elements.countCrit.textContent = critCount;
      if (elements.countHigh) elements.countHigh.textContent = highCount;
      if (elements.countMed) elements.countMed.textContent = medCount;
      if (elements.countLow) elements.countLow.textContent = lowCount;
      if (elements.countUnrated) elements.countUnrated.textContent = unratedCount;

      const sumSeverities = critCount + highCount + medCount + lowCount + unratedCount;
      if (sumSeverities > 0) {
        if (elements.barCrit) elements.barCrit.style.width = `${(critCount / sumSeverities) * 100}%`;
        if (elements.barHigh) elements.barHigh.style.width = `${(highCount / sumSeverities) * 100}%`;
        if (elements.barMed) elements.barMed.style.width = `${(medCount / sumSeverities) * 100}%`;
        if (elements.barLow) elements.barLow.style.width = `${(lowCount / sumSeverities) * 100}%`;
        if (elements.barUnrated) elements.barUnrated.style.width = `${(unratedCount / sumSeverities) * 100}%`;
      } else {
        if (elements.barCrit) elements.barCrit.style.width = "0%";
        if (elements.barHigh) elements.barHigh.style.width = "0%";
        if (elements.barMed) elements.barMed.style.width = "0%";
        if (elements.barLow) elements.barLow.style.width = "0%";
        if (elements.barUnrated) elements.barUnrated.style.width = "0%";
      }

      // 7. Update Status Distribution
      if (elements.distCountCompleted) elements.distCountCompleted.textContent = completedAssessments.length;
      if (elements.distCountRunning) elements.distCountRunning.textContent = runningCount;
      if (elements.distCountPending) elements.distCountPending.textContent = pendingCount;
      if (elements.distCountFailed) elements.distCountFailed.textContent = failedCount;

      // 8. Render Recent Assessments Table
      renderDashboardRecentAssessments(assessments);

    } catch (err) {
      console.error("Dashboard overview failed:", err);
    } finally {
      if (elements.dashAssessmentsLoading) elements.dashAssessmentsLoading.hidden = true;
    }
  }

  function getRiskLevelColorClass(level) {
    switch (String(level).toUpperCase()) {
      case "CRITICAL": return "color-danger";
      case "HIGH": return "color-danger";
      case "MEDIUM": return "color-warning";
      case "LOW": return "color-info";
      default: return "";
    }
  }

  function renderDashboardRecentAssessments(assessments) {
    if (!elements.dashRecentAssessmentsBody) return;
    elements.dashRecentAssessmentsBody.innerHTML = "";

    if (!assessments || assessments.length === 0) {
      if (elements.dashAssessmentsEmpty) elements.dashAssessmentsEmpty.hidden = false;
      return;
    }

    if (elements.dashAssessmentsEmpty) elements.dashAssessmentsEmpty.hidden = true;

    assessments.slice(0, 10).forEach((item) => {
      const tr = document.createElement("tr");

      const scoreDisplay = item.risk_score !== null && item.risk_score !== undefined ? `${item.risk_score}/100` : "--";
      const levelDisplay = item.risk_level ? item.risk_level.toUpperCase() : "--";
      const confidenceDisplay = item.confidence_level ? item.confidence_level.toUpperCase() : "--";
      const assetDisplay = item.asset_id ? `<span class="mono">${escapeHTML(item.asset_id.substring(0, 8))}...</span>` : "Local Host";

      tr.innerHTML = `
        <td><span class="status-badge status-${escapeHTML(item.status)}">${escapeHTML(item.status)}</span></td>
        <td><span class="mono code-id" title="${escapeHTML(item.id)}">${escapeHTML(item.id.substring(0, 8))}...</span></td>
        <td>${assetDisplay}</td>
        <td><strong>${scoreDisplay}</strong></td>
        <td><span class="level-badge level-${escapeHTML(levelDisplay.toLowerCase())}">${escapeHTML(levelDisplay)}</span></td>
        <td><span class="level-badge level-${escapeHTML(confidenceDisplay.toLowerCase())}">${escapeHTML(confidenceDisplay)}</span></td>
        <td><time class="time-muted">${formatTimestamp(item.created_at)}</time></td>
        <td>
          <button type="button" class="btn btn-secondary btn-sm" data-action="view-os-assessment" data-id="${escapeHTML(item.id)}">
            Inspect
          </button>
        </td>
      `;

      tr.querySelector('[data-action="view-os-assessment"]').addEventListener("click", () => {
        switchTab("os-assessments");
        loadAssessmentDetail(item.id);
      });

      elements.dashRecentAssessmentsBody.appendChild(tr);
    });
  }

  // =========================================================================
  // OS Assets View Logic
  // =========================================================================

  async function loadOSAssets() {
    if (elements.assetsLoading) elements.assetsLoading.hidden = false;
    if (elements.assetsEmpty) elements.assetsEmpty.hidden = true;
    if (elements.assetsUnauthorized) elements.assetsUnauthorized.hidden = true;
    if (elements.osAssetsTableBody) elements.osAssetsTableBody.innerHTML = "";

    try {
      const response = await fetch(`${API_BASE}/os/assets`, { headers: getAuthHeaders() });

      if (response.status === 401) {
        if (elements.assetsUnauthorized) {
          elements.assetsUnauthorized.hidden = false;
          elements.assetsUnauthText.textContent = "Authentication Required: Please provide a valid Bearer token in Settings.";
        }
        return;
      }

      if (response.status === 403) {
        if (elements.assetsUnauthorized) {
          elements.assetsUnauthorized.hidden = false;
          elements.assetsUnauthText.textContent = "Access Denied (403 Forbidden): Your current role is not authorized to manage OS assets.";
        }
        return;
      }

      if (!response.ok) {
        throw new Error(`Failed to load OS assets: HTTP ${response.status}`);
      }

      const data = await response.json();
      state.assets = data.items || [];

      if (state.assets.length === 0) {
        if (elements.assetsEmpty) elements.assetsEmpty.hidden = false;
        return;
      }

      renderOSAssetsTable(state.assets);
      populateAssetSelectOptions();

    } catch (err) {
      console.error("OS Assets load error:", err);
      showGlobalAlert(err.message, true);
    } finally {
      if (elements.assetsLoading) elements.assetsLoading.hidden = true;
    }
  }

  function renderOSAssetsTable(assets) {
    if (!elements.osAssetsTableBody) return;
    elements.osAssetsTableBody.innerHTML = "";

    assets.forEach((asset) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><strong class="mono">${escapeHTML(asset.hostname)}</strong></td>
        <td><span class="status-badge">${escapeHTML(asset.os_family)}</span></td>
        <td>${escapeHTML(asset.os_name)} ${escapeHTML(asset.os_version)}</td>
        <td><span class="mono">${escapeHTML(asset.architecture)}</span></td>
        <td><span class="mono code-id" title="${escapeHTML(asset.id)}">${escapeHTML(asset.id.substring(0, 8))}...</span></td>
        <td><time class="time-muted">${formatTimestamp(asset.created_at)}</time></td>
        <td>
          <button type="button" class="btn btn-primary btn-sm" data-action="assess-asset" data-id="${escapeHTML(asset.id)}">
            Assess Host
          </button>
        </td>
      `;

      tr.querySelector('[data-action="assess-asset"]').addEventListener("click", () => {
        switchTab("os-assessments");
        if (elements.selectAssessmentAsset) {
          elements.selectAssessmentAsset.value = asset.id;
        }
      });

      elements.osAssetsTableBody.appendChild(tr);
    });
  }

  async function handleRegisterAsset(e) {
    e.preventDefault();
    if (elements.assetRegistrationError) elements.assetRegistrationError.hidden = true;
    if (elements.assetRegistrationSuccess) elements.assetRegistrationSuccess.hidden = true;

    const hostname = elements.assetHostnameInput.value.trim();
    const os_family = elements.assetFamilySelect.value;
    const os_name = elements.assetNameInput.value.trim();
    const os_version = elements.assetVersionInput.value.trim();
    const architecture = elements.assetArchSelect.value;

    if (!hostname || !os_name || !os_version) {
      elements.assetRegistrationError.textContent = "Please fill in all required host profile fields.";
      elements.assetRegistrationError.hidden = false;
      return;
    }

    elements.assetSubmitSpinner.hidden = false;
    elements.assetSubmitBtnText.textContent = "Registering...";
    elements.btnSubmitAsset.disabled = true;

    // Compute deterministic 64-character hex identifier
    let hash = 0;
    for (let i = 0; i < hostname.length; i++) {
      hash = ((hash << 5) - hash) + hostname.charCodeAt(i);
      hash |= 0;
    }
    const host_identifier = Math.abs(hash).toString(16).padStart(64, "a");

    try {
      const response = await fetch(`${API_BASE}/os/assets`, {
        method: "POST",
        headers: getAuthHeaders(),
        body: JSON.stringify({ host_identifier, hostname, os_family, os_name, os_version, architecture }),
      });

      const data = await response.json();

      if (!response.ok) {
        const errorMsg = data.message || data.detail || `Registration failed (HTTP ${response.status})`;
        throw new Error(errorMsg);
      }

      elements.assetRegistrationSuccess.textContent = `Asset '${data.hostname}' registered successfully (UUID: ${data.id}).`;
      elements.assetRegistrationSuccess.hidden = false;
      elements.registerAssetForm.reset();

      // Refresh assets
      await loadOSAssets();

    } catch (err) {
      elements.assetRegistrationError.textContent = err.message;
      elements.assetRegistrationError.hidden = false;
    } finally {
      elements.assetSubmitSpinner.hidden = true;
      elements.assetSubmitBtnText.textContent = "Register Asset";
      elements.btnSubmitAsset.disabled = false;
    }
  }

  // =========================================================================
  // OS Assessments Workflow Logic
  // =========================================================================

  function populateAssetSelectOptions() {
    if (!elements.selectAssessmentAsset) return;
    const currentVal = elements.selectAssessmentAsset.value;
    elements.selectAssessmentAsset.innerHTML = '<option value="">-- Select Registered Asset --</option>';

    state.assets.forEach((asset) => {
      const opt = document.createElement("option");
      opt.value = asset.id;
      opt.textContent = `${asset.hostname} (${asset.os_name} ${asset.os_version} - ${asset.architecture})`;
      elements.selectAssessmentAsset.appendChild(opt);
    });

    if (currentVal) {
      elements.selectAssessmentAsset.value = currentVal;
    }
  }

  async function loadOSAssessments() {
    if (elements.assessmentsLoading) elements.assessmentsLoading.hidden = false;
    if (elements.assessmentsEmpty) elements.assessmentsEmpty.hidden = true;
    if (elements.osAssessmentsTableBody) elements.osAssessmentsTableBody.innerHTML = "";

    try {
      const response = await fetch(`${API_BASE}/os/assessments`, { headers: getAuthHeaders() });

      if (response.status === 401 || response.status === 403) {
        showGlobalAlert(`Authorization status: HTTP ${response.status} when listing assessments.`, true);
        return;
      }

      if (!response.ok) {
        throw new Error(`Failed to load assessments: HTTP ${response.status}`);
      }

      const data = await response.json();
      state.assessments = data.items || [];

      if (state.assessments.length === 0) {
        if (elements.assessmentsEmpty) elements.assessmentsEmpty.hidden = false;
        return;
      }

      renderOSAssessmentsTable(state.assessments);

    } catch (err) {
      console.error("OS Assessments error:", err);
    } finally {
      if (elements.assessmentsLoading) elements.assessmentsLoading.hidden = true;
    }
  }

  function renderOSAssessmentsTable(assessments) {
    if (!elements.osAssessmentsTableBody) return;
    elements.osAssessmentsTableBody.innerHTML = "";

    assessments.forEach((item) => {
      const tr = document.createElement("tr");

      const scoreVal = item.risk_score !== null && item.risk_score !== undefined ? `${item.risk_score}/100` : "--";
      const confVal = item.confidence_level ? item.confidence_level.toUpperCase() : "--";
      const assetRef = item.asset_id ? `<span class="mono">${escapeHTML(item.asset_id.substring(0, 8))}...</span>` : "Local Host";

      tr.innerHTML = `
        <td><span class="status-badge status-${escapeHTML(item.status)}">${escapeHTML(item.status)}</span></td>
        <td><span class="mono code-id" title="${escapeHTML(item.id)}">${escapeHTML(item.id.substring(0, 8))}...</span></td>
        <td>${assetRef}</td>
        <td><strong>${scoreVal}</strong></td>
        <td><span class="level-badge level-${escapeHTML(confVal.toLowerCase())}">${escapeHTML(confVal)}</span></td>
        <td><time class="time-muted">${formatTimestamp(item.created_at)}</time></td>
        <td><time class="time-muted">${formatTimestamp(item.completed_at)}</time></td>
        <td>
          <button type="button" class="btn btn-secondary btn-sm" data-action="view-os-detail" data-id="${escapeHTML(item.id)}">
            ${item.status === "completed" ? "View Findings" : "Inspect Session"}
          </button>
        </td>
      `;

      tr.querySelector('[data-action="view-os-detail"]').addEventListener("click", () => {
        loadAssessmentDetail(item.id);
      });

      elements.osAssessmentsTableBody.appendChild(tr);
    });
  }

  async function handleCreateAndStartAssessment(e) {
    e.preventDefault();
    if (elements.assessmentLauncherError) elements.assessmentLauncherError.hidden = true;

    const assetId = elements.selectAssessmentAsset.value;
    if (!assetId) {
      elements.assessmentLauncherError.textContent = "Please select a registered target asset.";
      elements.assessmentLauncherError.hidden = false;
      return;
    }

    elements.createAssessmentSpinner.hidden = false;
    elements.createAssessmentBtnText.textContent = "Initializing Session...";
    elements.btnCreateAssessment.disabled = true;

    try {
      // Step 1: Create session (POST /api/v1/os/assessments)
      const createRes = await fetch(`${API_BASE}/os/assessments`, {
        method: "POST",
        headers: getAuthHeaders(),
        body: JSON.stringify({ asset_id: assetId, assessment_type: "local_read_only" }),
      });

      const createData = await createRes.json();
      if (!createRes.ok) {
        throw new Error(createData.message || createData.detail || `Session initialization failed (HTTP ${createRes.status})`);
      }

      const assessmentId = createData.id;

      // Step 2: Run read-only assessment (POST /api/v1/os/assessments/{id}/assess)
      elements.createAssessmentBtnText.textContent = "Running Read-Only Assessment...";
      const runRes = await fetch(`${API_BASE}/os/assessments/${assessmentId}/assess`, {
        method: "POST",
        headers: getAuthHeaders(),
      });

      const runData = await runRes.json();
      if (!runRes.ok) {
        throw new Error(runData.message || runData.detail || `Assessment execution failed (HTTP ${runRes.status})`);
      }

      // Step 3: Load detail view with results
      await loadAssessmentDetail(assessmentId);
      // Reload sessions list in background
      loadOSAssessments();

    } catch (err) {
      elements.assessmentLauncherError.textContent = err.message;
      elements.assessmentLauncherError.hidden = false;
    } finally {
      elements.createAssessmentSpinner.hidden = true;
      elements.createAssessmentBtnText.textContent = "Create & Run Assessment";
      elements.btnCreateAssessment.disabled = false;
    }
  }

  async function loadAssessmentDetail(assessmentId) {
    if (!elements.osDetailSection) return;
    elements.osDetailSection.hidden = false;
    elements.osDetailSection.scrollIntoView({ behavior: "smooth" });

    // Reset view placeholders
    elements.osDetailAssessmentId.textContent = assessmentId;
    elements.osDetailStatusBadge.textContent = "Loading...";
    elements.osDetailStatusBadge.className = "status-badge status-pending";

    try {
      // 1. Fetch main assessment record
      const assRes = await fetch(`${API_BASE}/os/assessments/${assessmentId}`, { headers: getAuthHeaders() });
      if (!assRes.ok) throw new Error(`HTTP ${assRes.status}`);
      const assessment = await assRes.json();

      state.activeAssessmentDetail = assessment;

      // Populate header info
      elements.osDetailAssessmentId.textContent = assessment.id;
      elements.osDetailAssetId.textContent = assessment.asset_id || "local";
      elements.osDetailTargetHostname.textContent = assessment.asset ? assessment.asset.hostname : "Local OS Host";
      elements.osDetailTimestamp.textContent = formatTimestamp(assessment.completed_at || assessment.created_at);

      elements.osDetailStatusBadge.textContent = assessment.status;
      elements.osDetailStatusBadge.className = `status-badge status-${assessment.status}`;

      // Check run button visibility (only if pending)
      if (elements.btnRunAssessmentNow) {
        elements.btnRunAssessmentNow.hidden = assessment.status !== "pending";
        elements.btnRunAssessmentNow.onclick = async () => {
          elements.btnRunAssessmentNow.disabled = true;
          elements.btnRunAssessmentNow.textContent = "Running...";
          try {
            const runRes = await fetch(`${API_BASE}/os/assessments/${assessmentId}/assess`, {
              method: "POST",
              headers: getAuthHeaders(),
            });
            if (runRes.ok) {
              await loadAssessmentDetail(assessmentId);
            } else {
              const err = await runRes.json();
              alert(err.message || err.detail || "Run failed.");
            }
          } catch (e) {
            alert(e.message);
          } finally {
            elements.btnRunAssessmentNow.disabled = false;
            elements.btnRunAssessmentNow.textContent = "▶ Run Assessment Now";
          }
        };
      }

      // Populate Risk Triad Invariants
      const score = assessment.risk_score !== null && assessment.risk_score !== undefined ? assessment.risk_score : 0;
      elements.osDetailRiskScore.textContent = score;
      elements.osDetailScoreBar.style.width = `${Math.min(100, Math.max(0, score))}%`;

      const level = assessment.risk_level ? assessment.risk_level.toUpperCase() : "CLEAN";
      elements.osDetailRiskLevel.textContent = level;
      elements.osDetailRiskLevel.className = `level-badge level-${level.toLowerCase()}`;

      const conf = assessment.confidence_level ? assessment.confidence_level.toUpperCase() : "MEDIUM";
      elements.osDetailConfidenceBadge.textContent = conf;
      elements.osDetailConfidenceBadge.className = `level-badge level-${conf.toLowerCase()}`;
      elements.osDetailConfidenceText.textContent = `${conf} Confidence`;

      // 2. Fetch Evidence
      try {
        const evidRes = await fetch(`${API_BASE}/os/assessments/${assessmentId}/evidence`, { headers: getAuthHeaders() });
        if (evidRes.ok) {
          const evidData = await evidRes.json();
          renderOSEvidence(evidData.items || []);
        }
      } catch (e) {
        console.warn("Evidence fetch failed:", e);
      }

      // 3. Fetch Findings
      let findingsList = [];
      try {
        const findRes = await fetch(`${API_BASE}/os/assessments/${assessmentId}/findings`, { headers: getAuthHeaders() });
        if (findRes.ok) {
          const findData = await findRes.json();
          findingsList = findData.items || [];
          renderOSFindings(findingsList);
        }
      } catch (e) {
        console.warn("Findings fetch failed:", e);
      }

      // 4. Fetch Risk Explanation & Limitations
      try {
        const riskRes = await fetch(`${API_BASE}/os/assessments/${assessmentId}/risk`, { headers: getAuthHeaders() });
        if (riskRes.ok) {
          const riskData = await riskRes.json();
          renderOSLimitations(riskData.limitations || []);
        }
      } catch (e) {
        console.warn("Risk fetch failed:", e);
      }

      // 5. Fetch Remediation Guidance
      try {
        const remRes = await fetch(`${API_BASE}/os/assessments/${assessmentId}/remediation`, { headers: getAuthHeaders() });
        if (remRes.ok) {
          const remData = await remRes.json();
          renderOSRemediation(remData.recommendations || []);
        }
      } catch (e) {
        console.warn("Remediation fetch failed:", e);
      }

    } catch (err) {
      console.error("Load assessment detail error:", err);
      showGlobalAlert(`Failed to load assessment detail: ${err.message}`, true);
    }
  }

  function renderOSLimitations(limitations) {
    if (!elements.osLimitationsContainer || !elements.osLimitationsList) return;
    if (!limitations || limitations.length === 0) {
      elements.osLimitationsContainer.hidden = true;
      return;
    }

    elements.osLimitationsContainer.hidden = false;
    elements.osLimitationsList.innerHTML = "";

    limitations.forEach((item) => {
      const p = document.createElement("p");
      p.innerHTML = `• ${escapeHTML(item)}`;
      elements.osLimitationsList.appendChild(p);
    });
  }

  function renderOSFindings(findings) {
    if (!elements.osFindingsTableBody) return;
    elements.osFindingsTableBody.innerHTML = "";

    const filtered = findings.filter((f) => {
      if (state.osFindingsFilter === "all") return true;
      return String(f.severity).toLowerCase() === state.osFindingsFilter.toLowerCase();
    });

    if (elements.osFindingsCountText) {
      elements.osFindingsCountText.textContent = `${filtered.length} items`;
    }

    if (filtered.length === 0) {
      elements.osFindingsTableBody.innerHTML = `
        <tr>
          <td colspan="7" class="text-center text-muted" style="padding: 2rem;">
            No security findings matching the active filter.
          </td>
        </tr>
      `;
      return;
    }

    filtered.forEach((f) => {
      const tr = document.createElement("tr");

      const fixedStatus = f.fixed_version
        ? `<span class="tag-fixed">${escapeHTML(f.fixed_version)} (Available in vendor repo)</span>`
        : `<span class="tag-unfixed">No fix available yet</span>`;

      tr.innerHTML = `
        <td><span class="level-badge level-${escapeHTML(f.severity.toLowerCase())}">${escapeHTML(f.severity.toUpperCase())}</span></td>
        <td><strong class="mono">${escapeHTML(f.title || f.cve_id || "Finding")}</strong></td>
        <td><span class="mono">${escapeHTML(f.package_name || "--")}</span></td>
        <td><span class="mono">${escapeHTML(f.installed_version || "--")}</span></td>
        <td>${fixedStatus}</td>
        <td><span class="level-badge level-${escapeHTML(String(f.confidence).toLowerCase())}">${escapeHTML(String(f.confidence).toUpperCase())}</span></td>
        <td>
          <div>${escapeHTML(f.description || "--")}</div>
          <small class="text-muted" style="display:block; margin-top: 0.25rem;">
            <em>Host Status: Installed version observed. Fix has NOT been applied to this host.</em>
          </small>
        </td>
      `;

      elements.osFindingsTableBody.appendChild(tr);
    });
  }

  function renderOSEvidence(evidenceItems) {
    if (!elements.osEvidenceTableBody) return;
    elements.osEvidenceTableBody.innerHTML = "";

    if (elements.osEvidenceCountText) {
      elements.osEvidenceCountText.textContent = `${evidenceItems.length} items`;
    }

    if (evidenceItems.length === 0) {
      elements.osEvidenceTableBody.innerHTML = `
        <tr>
          <td colspan="5" class="text-center text-muted" style="padding: 2rem;">
            No evidence observations recorded.
          </td>
        </tr>
      `;
      return;
    }

    evidenceItems.forEach((item) => {
      const tr = document.createElement("tr");

      let valStr = "";
      if (typeof item.raw_value === "object" && item.raw_value !== null) {
        valStr = JSON.stringify(item.raw_value);
      } else {
        valStr = String(item.raw_value || "--");
      }

      tr.innerHTML = `
        <td><span class="status-badge">${escapeHTML(item.category)}</span></td>
        <td><strong class="mono">${escapeHTML(item.signal_name || item.collector_name)}</strong></td>
        <td><span class="status-badge status-${escapeHTML(item.collection_status)}">${escapeHTML(item.collection_status)}</span></td>
        <td><code class="code-id mono">${escapeHTML(valStr.length > 80 ? valStr.substring(0, 80) + "..." : valStr)}</code></td>
        <td><small class="text-muted">${escapeHTML(item.notes || "--")}</small></td>
      `;

      elements.osEvidenceTableBody.appendChild(tr);
    });
  }

  function renderOSRemediation(recommendations) {
    if (!elements.osRemediationGrid) return;
    elements.osRemediationGrid.innerHTML = "";

    if (!recommendations || recommendations.length === 0) {
      elements.osRemediationGrid.innerHTML = `
        <div class="state-container state-empty" style="grid-column: 1 / -1;">
          <p>No remediation actions required. All observed components align with baseline expectations.</p>
        </div>
      `;
      return;
    }

    recommendations.forEach((rec) => {
      const card = document.createElement("div");
      card.className = "card remediation-card";

      card.innerHTML = `
        <div class="card-header">
          <div>
            <div style="display:flex; align-items:center; gap:0.5rem; margin-bottom: 0.25rem;">
              <span class="level-badge level-${escapeHTML(String(rec.priority).toLowerCase())}">Priority: ${escapeHTML(String(rec.priority).toUpperCase())}</span>
              <span class="tag-unapplied-proposal">PROPOSED ACTION (NOT APPLIED)</span>
            </div>
            <h4>${escapeHTML(rec.title || rec.action || "Recommended Action")}</h4>
          </div>
        </div>
        <div class="card-body">
          <p class="remediation-desc">${escapeHTML(rec.description || rec.rationale || "")}</p>
          ${rec.command ? `<pre class="code-block"><code>${escapeHTML(rec.command)}</code></pre>` : ""}
          <div class="remediation-meta">
            <span class="text-muted">Target finding: <code>${escapeHTML(rec.finding_id || rec.cve_id || "--")}</code></span>
            <span class="text-muted">Effort: <strong>${escapeHTML(rec.effort || "Low")}</strong></span>
          </div>
        </div>
      `;

      elements.osRemediationGrid.appendChild(card);
    });
  }

  // =========================================================================
  // Aggregated Findings Explorer Logic
  // =========================================================================

  async function loadAggregatedFindings() {
    if (!elements.aggregatedFindingsBody) return;
    elements.aggregatedFindingsBody.innerHTML = "";

    try {
      const assessRes = await fetch(`${API_BASE}/os/assessments`, { headers: getAuthHeaders() });
      if (!assessRes.ok) return;

      const assessData = await assessRes.json();
      const completedAssessments = (assessData.items || []).filter((a) => a.status === "completed");

      const allFindings = [];
      for (const ass of completedAssessments) {
        try {
          const findRes = await fetch(`${API_BASE}/os/assessments/${ass.id}/findings`, { headers: getAuthHeaders() });
          if (findRes.ok) {
            const findData = await findRes.json();
            (findData.items || []).forEach((f) => {
              allFindings.push({ ...f, assessment_id: ass.id, asset_id: ass.asset_id });
            });
          }
        } catch (e) {
          // ignore
        }
      }

      state.allFindings = allFindings;
      renderAggregatedFindings();

    } catch (err) {
      console.error("Load aggregated findings error:", err);
    }
  }

  function renderAggregatedFindings() {
    if (!elements.aggregatedFindingsBody) return;
    elements.aggregatedFindingsBody.innerHTML = "";

    const query = state.findingsSearch.toLowerCase();
    const severity = state.findingsSeverity.toLowerCase();

    const filtered = state.allFindings.filter((f) => {
      const matchSeverity = severity === "all" || String(f.severity).toLowerCase() === severity;
      const matchQuery =
        !query ||
        String(f.title || "").toLowerCase().includes(query) ||
        String(f.cve_id || "").toLowerCase().includes(query) ||
        String(f.package_name || "").toLowerCase().includes(query);
      return matchSeverity && matchQuery;
    });

    if (filtered.length === 0) {
      elements.aggregatedFindingsEmpty.hidden = false;
      elements.aggregatedFindingsTableWrapper.hidden = true;
      return;
    }

    elements.aggregatedFindingsEmpty.hidden = true;
    elements.aggregatedFindingsTableWrapper.hidden = false;

    filtered.forEach((f) => {
      const tr = document.createElement("tr");

      const fixedStatus = f.fixed_version
        ? `<span class="tag-fixed">${escapeHTML(f.fixed_version)} (Vendor Repo)</span>`
        : `<span class="tag-unfixed">Unfixed in Vendor</span>`;

      tr.innerHTML = `
        <td><span class="level-badge level-${escapeHTML(String(f.severity).toLowerCase())}">${escapeHTML(String(f.severity).toUpperCase())}</span></td>
        <td><strong class="mono">${escapeHTML(f.cve_id || f.title || "--")}</strong></td>
        <td><span class="mono">${escapeHTML(f.package_name || "--")}</span></td>
        <td><span class="mono">${escapeHTML(f.installed_version || "--")}</span></td>
        <td>${fixedStatus}</td>
        <td><span class="mono code-id">${escapeHTML(f.assessment_id.substring(0, 8))}...</span></td>
        <td>
          <div>${escapeHTML(f.title || "--")}</div>
          <span class="tag-unapplied-proposal">Host Unpatched</span>
        </td>
      `;

      elements.aggregatedFindingsBody.appendChild(tr);
    });
  }

  // =========================================================================
  // URL Analysis & Threat Intelligence Logic (Preserved from Milestone 6)
  // =========================================================================

  async function handleTargetSubmission(e) {
    if (e) e.preventDefault();
    if (state.isSubmitting) return;

    const rawUrl = elements.targetInput.value.trim();
    if (!rawUrl) return;

    state.isSubmitting = true;
    setSubmittingState(true);
    hideSubmissionError();

    try {
      const response = await fetch(`${API_BASE}/analyses`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: rawUrl }),
      });

      const data = await response.json();

      if (!response.ok) {
        const errorMsg = data.message || data.detail || `Submission failed with HTTP ${response.status}`;
        throw new Error(errorMsg);
      }

      elements.targetInput.value = "";

      // Step 2: Trigger analyze
      const analyzeResponse = await fetch(`${API_BASE}/analyses/${data.id}/analyze`, {
        method: "POST",
      });

      if (!analyzeResponse.ok) {
        const analyzeError = await analyzeResponse.json();
        throw new Error(analyzeError.message || analyzeError.detail || "Analysis execution failed.");
      }

      await loadAnalysisDetail(data.id);
      await loadHistory();

    } catch (err) {
      showSubmissionError(err.message);
    } finally {
      state.isSubmitting = false;
      setSubmittingState(false);
    }
  }

  function setSubmittingState(submitting) {
    if (elements.submitBtn) elements.submitBtn.disabled = submitting;
    if (elements.submitSpinner) elements.submitSpinner.hidden = !submitting;
    if (elements.submitBtnText) {
      elements.submitBtnText.textContent = submitting ? "Evaluating..." : "Submit & Analyze";
    }
  }

  function showSubmissionError(msg) {
    if (elements.submissionError) {
      elements.submissionError.textContent = msg;
      elements.submissionError.hidden = false;
    }
  }

  function hideSubmissionError() {
    if (elements.submissionError) {
      elements.submissionError.hidden = true;
    }
  }

  async function loadHistory() {
    if (state.isLoadingHistory) return;
    state.isLoadingHistory = true;

    if (elements.historyLoading) elements.historyLoading.hidden = false;
    if (elements.historyError) elements.historyError.hidden = true;
    if (elements.historyEmpty) elements.historyEmpty.hidden = true;

    try {
      const response = await fetch(`${API_BASE}/analyses?limit=50`);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);

      const data = await response.json();
      state.analyses = data.items || [];

      updateMetricsSummary(state.analyses);
      filterAndRenderHistory();

    } catch (err) {
      if (elements.historyError) {
        elements.historyError.hidden = false;
        elements.historyErrorMsg.textContent = `Error fetching analysis records: ${err.message}`;
      }
    } finally {
      state.isLoadingHistory = false;
      if (elements.historyLoading) elements.historyLoading.hidden = true;
    }
  }

  function updateMetricsSummary(items) {
    const total = items.length;
    const completed = items.filter((a) => a.status === "completed").length;
    const pending = items.filter((a) => a.status === "pending").length;
    const failed = items.filter((a) => a.status === "failed").length;

    if (elements.metricTotal) elements.metricTotal.textContent = total;
    if (elements.metricCompleted) elements.metricCompleted.textContent = completed;
    if (elements.metricPending) elements.metricPending.textContent = pending;
    if (elements.metricFailed) elements.metricFailed.textContent = failed;
  }

  function filterAndRenderHistory() {
    let items = state.analyses;

    if (state.statusFilter !== "all") {
      items = items.filter((a) => a.status === state.statusFilter);
    }

    if (state.searchQuery) {
      const q = state.searchQuery.toLowerCase();
      items = items.filter((a) => {
        return (a.target_url && a.target_url.toLowerCase().includes(q)) || (a.id && a.id.toLowerCase().includes(q));
      });
    }

    renderHistoryTable(items);
  }

  function renderHistoryTable(items) {
    if (!elements.analysesTableBody) return;
    elements.analysesTableBody.innerHTML = "";

    if (items.length === 0) {
      if (elements.historyEmpty) elements.historyEmpty.hidden = false;
      return;
    }

    if (elements.historyEmpty) elements.historyEmpty.hidden = true;

    items.forEach((item) => {
      const tr = document.createElement("tr");

      tr.innerHTML = `
        <td><span class="status-badge status-${escapeHTML(item.status)}">${escapeHTML(item.status)}</span></td>
        <td><span class="mono">${escapeHTML(sanitizeUrlForDisplay(item.target_url))}</span></td>
        <td><span class="mono code-id" title="${escapeHTML(item.id)}">${escapeHTML(item.id.substring(0, 8))}...</span></td>
        <td><time class="time-muted">${formatTimestamp(item.created_at)}</time></td>
        <td>
          <button type="button" class="btn btn-secondary btn-sm" data-action="view-url" data-id="${escapeHTML(item.id)}">
            View Detail
          </button>
        </td>
      `;

      tr.querySelector('[data-action="view-url"]').addEventListener("click", () => {
        loadAnalysisDetail(item.id);
      });

      elements.analysesTableBody.appendChild(tr);
    });
  }

  async function loadAnalysisDetail(id) {
    if (elements.activeSection) elements.activeSection.hidden = false;

    try {
      const response = await fetch(`${API_BASE}/analyses/${id}`);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);

      const data = await response.json();
      state.activeAnalysis = data;
      renderActiveDetail(data);

      elements.activeSection.scrollIntoView({ behavior: "smooth" });
    } catch (err) {
      alert(`Could not load analysis detail: ${err.message}`);
    }
  }

  function renderActiveDetail(data) {
    if (!elements.activeSection) return;

    elements.detailStatusBadge.textContent = data.status;
    elements.detailStatusBadge.className = `status-badge status-${data.status}`;
    elements.detailTargetUrl.textContent = sanitizeUrlForDisplay(data.target_url);
    elements.detailAnalysisId.textContent = data.id;
    elements.detailTimestamp.textContent = formatTimestamp(data.created_at);

    const risk = data.risk_assessment;
    if (risk) {
      const score = Math.round(risk.risk_score);
      elements.detailRiskScore.textContent = score;
      elements.detailScoreBar.style.width = `${score}%`;

      const level = risk.risk_level ? risk.risk_level.toUpperCase() : "LOW";
      elements.detailRiskLevelBadge.textContent = level;
      elements.detailRiskLevelBadge.className = `level-badge level-${level.toLowerCase()}`;

      const conf = risk.confidence_level ? risk.confidence_level.toUpperCase() : "MEDIUM";
      elements.detailConfidenceBadge.textContent = conf;
      elements.detailConfidenceBadge.className = `level-badge level-${conf.toLowerCase()}`;
      elements.detailConfidenceText.textContent = `${conf} Confidence`;

      renderContributingFactors(risk.contributing_factors || []);
      renderRemediationGuidance(data.evidence_items || []);
    } else {
      elements.detailRiskScore.textContent = "--";
      elements.detailScoreBar.style.width = "0%";
      elements.detailRiskLevelBadge.textContent = "PENDING";
      elements.detailConfidenceBadge.textContent = "--";
      elements.detailConfidenceText.textContent = "Evaluation Pending";
      elements.factorsContainer.hidden = true;
    }

    renderThreatOutcomeBanner(data.threat_intel);
    renderEvidenceTable(data.evidence_items || []);
  }

  function renderContributingFactors(factors) {
    if (!elements.factorsContainer || !elements.factorsList) return;

    if (factors.length === 0) {
      elements.factorsContainer.hidden = true;
      return;
    }

    elements.factorsContainer.hidden = false;
    elements.factorsList.innerHTML = "";

    factors.forEach((f) => {
      const chip = document.createElement("div");
      chip.className = "factor-chip";
      chip.innerHTML = `
        <span class="factor-name">${escapeHTML(f.signal_name || f.factor)}</span>
        <span class="factor-weight">+${escapeHTML(f.weight_applied || f.weight || 0)}</span>
      `;
      elements.factorsList.appendChild(chip);
    });
  }

  function renderThreatOutcomeBanner(threat) {
    if (!elements.threatOutcomePanel) return;

    if (!threat) {
      elements.threatOutcomePanel.className = "outcome-banner outcome-clean";
      elements.outcomeCategoryTag.textContent = "Not Evaluated";
      elements.outcomeProviderName.textContent = "Provider: VirusTotal v3";
      elements.outcomeSummaryText.textContent = "No external threat intelligence report requested.";
      return;
    }

    if (threat.error || threat.status === "error") {
      elements.threatOutcomePanel.className = "outcome-banner outcome-threat";
      elements.outcomeCategoryTag.textContent = "Provider Lookup Error";
      elements.outcomeProviderName.textContent = `Provider: ${threat.provider || "VirusTotal v3"}`;
      elements.outcomeSummaryText.textContent = threat.error_message || "Lookup encountered a network or API issue.";
    } else if (threat.category === "threat_match" || (threat.malicious_votes && threat.malicious_votes > 0)) {
      elements.threatOutcomePanel.className = "outcome-banner outcome-threat";
      elements.outcomeCategoryTag.textContent = "Confirmed Threat Match";
      elements.outcomeProviderName.textContent = `Provider: ${threat.provider || "VirusTotal v3"}`;
      elements.outcomeSummaryText.textContent = `Target flagged by ${threat.malicious_votes || "multiple"} security vendors in public threat databases. Crucial rule: High risk score does NOT prove host exploitability.`;
    } else {
      elements.threatOutcomePanel.className = "outcome-banner outcome-clean";
      elements.outcomeCategoryTag.textContent = "Genuine No-Match";
      elements.outcomeProviderName.textContent = `Provider: ${threat.provider || "VirusTotal v3"}`;
      elements.outcomeSummaryText.textContent = "No threat records observed in provider database. Crucial safety rule: The absence of a threat entry does NOT certify target is benign.";
    }
  }

  function renderEvidenceTable(items) {
    if (!elements.evidenceTableBody) return;
    elements.evidenceTableBody.innerHTML = "";

    const filtered = items.filter((item) => {
      if (state.evidenceFilter === "all") return true;
      return item.status === state.evidenceFilter;
    });

    if (elements.evidenceCountText) {
      elements.evidenceCountText.textContent = `${filtered.length} items`;
    }

    if (filtered.length === 0) {
      elements.evidenceTableBody.innerHTML = `
        <tr>
          <td colspan="5" class="text-center text-muted" style="padding: 2rem;">
            No evidence items observed matching filter.
          </td>
        </tr>
      `;
      return;
    }

    filtered.forEach((item) => {
      const tr = document.createElement("tr");

      let valStr = "";
      if (typeof item.observed_value === "object" && item.observed_value !== null) {
        valStr = JSON.stringify(item.observed_value);
      } else {
        valStr = String(item.observed_value !== null && item.observed_value !== undefined ? item.observed_value : "--");
      }

      tr.innerHTML = `
        <td><strong class="mono">${escapeHTML(item.signal_name)}</strong></td>
        <td><code class="code-id mono">${escapeHTML(valStr.length > 60 ? valStr.substring(0, 60) + "..." : valStr)}</code></td>
        <td><span class="status-badge">${escapeHTML(item.source)}</span></td>
        <td><span class="status-badge status-${escapeHTML(item.status)}">${escapeHTML(item.status)}</span></td>
        <td><small class="text-muted">${escapeHTML(item.notes || "--")}</small></td>
      `;

      elements.evidenceTableBody.appendChild(tr);
    });
  }

  function renderRemediationGuidance(evidenceItems) {
    if (!elements.remediationGrid) return;
    elements.remediationGrid.innerHTML = "";

    const observed = evidenceItems.filter((e) => e.status === "observed");

    if (observed.length === 0) {
      elements.remediationGrid.innerHTML = `
        <div class="state-container state-empty" style="grid-column: 1 / -1;">
          <p>No actionable remediation triggers observed in syntax indicators.</p>
        </div>
      `;
      return;
    }

    observed.forEach((item) => {
      const card = document.createElement("div");
      card.className = "card remediation-card";

      card.innerHTML = `
        <div class="card-header">
          <div>
            <span class="level-badge level-medium">Defensive Proposal</span>
            <h4>Address: ${escapeHTML(item.signal_name)}</h4>
          </div>
        </div>
        <div class="card-body">
          <p class="remediation-desc">${escapeHTML(item.notes || "Harden host configuration to remediate this observation.")}</p>
          <div class="remediation-meta">
            <span class="text-muted">Evidence signal: <code>${escapeHTML(item.signal_name)}</code></span>
            <span class="tag-unapplied-proposal">UNAPPLIED PROPOSAL</span>
          </div>
        </div>
      `;

      elements.remediationGrid.appendChild(card);
    });
  }

  // =========================================================================
  // Event Bindings
  // =========================================================================

  function bindEvents() {
    // 1. Navigation Tab Switching
    elements.navTabs.forEach((tab) => {
      tab.addEventListener("click", () => switchTab(tab.dataset.tab));
    });

    // 2. Auth Session Switcher Pill
    if (elements.authPill) {
      elements.authPill.addEventListener("click", () => switchTab("settings"));
    }

    // 3. Global Alert Close
    if (elements.globalAlertClose) {
      elements.globalAlertClose.addEventListener("click", hideGlobalAlert);
    }

    // 4. Dashboard View Actions
    if (elements.btnRefreshDashboard) {
      elements.btnRefreshDashboard.addEventListener("click", loadDashboardOverview);
    }
    if (elements.btnQuickNewAssessment) {
      elements.btnQuickNewAssessment.addEventListener("click", () => {
        switchTab("os-assessments");
      });
    }

    // 5. OS Assets Form & Refresh
    if (elements.registerAssetForm) {
      elements.registerAssetForm.addEventListener("submit", handleRegisterAsset);
    }
    if (elements.btnRefreshAssets) {
      elements.btnRefreshAssets.addEventListener("click", loadOSAssets);
    }

    // 6. OS Assessment Launcher
    if (elements.createAssessmentForm) {
      elements.createAssessmentForm.addEventListener("submit", handleCreateAndStartAssessment);
    }
    if (elements.btnCloseOsDetail) {
      elements.btnCloseOsDetail.addEventListener("click", () => {
        if (elements.osDetailSection) elements.osDetailSection.hidden = true;
      });
    }

    // OS Findings Filter Chips
    elements.osFindingsFilterChips.forEach((chip) => {
      chip.addEventListener("click", () => {
        elements.osFindingsFilterChips.forEach((c) => c.classList.remove("active"));
        chip.classList.add("active");
        state.osFindingsFilter = chip.dataset.osFilter;
        if (state.activeAssessmentDetail && state.activeAssessmentDetail.findings) {
          renderOSFindings(state.activeAssessmentDetail.findings);
        }
      });
    });

    // 7. Findings Explorer Search & Filter
    if (elements.findingsSearchInput) {
      elements.findingsSearchInput.addEventListener("input", (e) => {
        state.findingsSearch = e.target.value.trim();
        renderAggregatedFindings();
      });
    }
    if (elements.findingsSeverityFilter) {
      elements.findingsSeverityFilter.addEventListener("change", (e) => {
        state.findingsSeverity = e.target.value;
        renderAggregatedFindings();
      });
    }

    // 8. URL Analysis Form & Presets
    if (elements.submissionForm) {
      elements.submissionForm.addEventListener("submit", handleTargetSubmission);
    }

    elements.presetChips.forEach((chip) => {
      chip.addEventListener("click", () => {
        if (elements.targetInput) {
          elements.targetInput.value = chip.dataset.url;
          elements.targetInput.focus();
        }
      });
    });

    if (elements.closeDetailBtn) {
      elements.closeDetailBtn.addEventListener("click", () => {
        if (elements.activeSection) elements.activeSection.hidden = true;
      });
    }

    if (elements.reanalyzeBtn) {
      elements.reanalyzeBtn.addEventListener("click", async () => {
        if (!state.activeAnalysis) return;
        elements.reanalyzeBtn.disabled = true;
        try {
          await fetch(`${API_BASE}/analyses/${state.activeAnalysis.id}/analyze`, { method: "POST" });
          await loadAnalysisDetail(state.activeAnalysis.id);
          await loadHistory();
        } finally {
          elements.reanalyzeBtn.disabled = false;
        }
      });
    }

    if (elements.refreshHistoryBtn) {
      elements.refreshHistoryBtn.addEventListener("click", loadHistory);
    }
    if (elements.retryHistoryBtn) {
      elements.retryHistoryBtn.addEventListener("click", loadHistory);
    }

    if (elements.searchInput) {
      elements.searchInput.addEventListener("input", (e) => {
        state.searchQuery = e.target.value.trim();
        filterAndRenderHistory();
      });
    }

    if (elements.statusFilter) {
      elements.statusFilter.addEventListener("change", (e) => {
        state.statusFilter = e.target.value;
        filterAndRenderHistory();
      });
    }

    elements.evidenceFilterChips.forEach((chip) => {
      chip.addEventListener("click", () => {
        elements.evidenceFilterChips.forEach((c) => c.classList.remove("active"));
        chip.classList.add("active");
        state.evidenceFilter = chip.dataset.filter;
        if (state.activeAnalysis && state.activeAnalysis.evidence_items) {
          renderEvidenceTable(state.activeAnalysis.evidence_items);
        }
      });
    });

    // 9. Auth Settings Preset Buttons
    elements.authPresetBtns.forEach((btn) => {
      btn.addEventListener("click", () => {
        updateAuthSession(btn.dataset.token, btn.dataset.name, btn.dataset.role);
      });
    });

    if (elements.btnApplyToken) {
      elements.btnApplyToken.addEventListener("click", () => {
        const val = elements.customTokenInput.value.trim();
        if (val) {
          updateAuthSession(val, "Custom Assessor", "custom");
          elements.customTokenInput.value = "";
        }
      });
    }
  }

  // =========================================================================
  // Application Bootstrap
  // =========================================================================

  function init() {
    bindEvents();
    checkHealth();

    // Set initial auth pill display
    if (elements.authUsername) elements.authUsername.textContent = state.username;
    if (elements.authRole) elements.authRole.textContent = state.role;

    // Load initial view
    loadDashboardOverview();
  }

  // Launch on DOM ready
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
