/**
 * VulnScanner — Frontend Application
 * ====================================
 * Handles:
 *   - Form submission and URL validation
 *   - API calls to the Flask backend
 *   - Loading state animations
 *   - Rendering scan results (score, cards, history)
 *   - PDF download trigger
 */

// ──────────────────────────────────────────────
//  Configuration
// ──────────────────────────────────────────────
const API_BASE = window.location.origin;

// ──────────────────────────────────────────────
//  DOM References
// ──────────────────────────────────────────────
const scanForm     = document.getElementById("scan-form");
const urlInput     = document.getElementById("url-input");
const scanBtn      = document.getElementById("scan-btn");
const errorMessage = document.getElementById("error-message");
const errorText    = document.getElementById("error-text");
const loading      = document.getElementById("loading");
const results      = document.getElementById("results");
const vulnList     = document.getElementById("vuln-list");
const historyBody  = document.getElementById("history-body");
const btnDownload  = document.getElementById("btn-download-pdf");
const btnNewScan   = document.getElementById("btn-new-scan");

// Score elements
const scoreNumber  = document.getElementById("score-number");
const scoreArc     = document.getElementById("score-arc");
const scoreGrade   = document.getElementById("score-grade");
const resultUrl    = document.getElementById("result-url");
const resultTime   = document.getElementById("result-time");
const resultTotal  = document.getElementById("result-total");
const countHigh    = document.getElementById("count-high");
const countMedium  = document.getElementById("count-medium");
const countLow     = document.getElementById("count-low");
const countInfo    = document.getElementById("count-info");

// Track the latest scan ID for PDF downloads
let currentScanId = null;

// ──────────────────────────────────────────────
//  Option Chips — Toggle active state
// ──────────────────────────────────────────────
document.querySelectorAll(".option-chip input").forEach((checkbox) => {
  checkbox.addEventListener("change", () => {
    const chip = checkbox.closest(".option-chip");
    chip.classList.toggle("option-chip--active", checkbox.checked);
  });
});

// ──────────────────────────────────────────────
//  Form Submission
// ──────────────────────────────────────────────
scanForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const url = urlInput.value.trim();

  if (!url) {
    showError("Please enter a URL to scan.");
    return;
  }

  // Gather scan options from checkboxes
  const options = {};
  document.querySelectorAll(".option-chip input").forEach((cb) => {
    options[cb.name] = cb.checked;
  });

  hideError();
  showLoading();
  hideResults();

  try {
    const response = await fetch(`${API_BASE}/api/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, options }),
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || "Scan failed.");
    }

    hideLoading();
    renderResults(data);
    loadHistory();
  } catch (err) {
    hideLoading();
    showError(err.message || "An unexpected error occurred.");
  }
});

// ──────────────────────────────────────────────
//  Loading Animation
// ──────────────────────────────────────────────
function showLoading() {
  loading.classList.add("loading-overlay--active");
  scanBtn.disabled = true;
  scanBtn.innerHTML = "<span>⏳</span><span>Scanning…</span>";
  animateLoadingSteps();
}

function hideLoading() {
  loading.classList.remove("loading-overlay--active");
  scanBtn.disabled = false;
  scanBtn.innerHTML = "<span>🔍</span><span>Scan</span>";
}

function animateLoadingSteps() {
  const steps = document.querySelectorAll(".loading-step");
  steps.forEach((s) => {
    s.classList.remove("loading-step--active", "loading-step--done");
  });

  let i = 0;
  const interval = setInterval(() => {
    if (i > 0 && i <= steps.length) {
      steps[i - 1].classList.remove("loading-step--active");
      steps[i - 1].classList.add("loading-step--done");
      steps[i - 1].textContent = steps[i - 1].textContent.replace("⏳", "✅");
    }
    if (i < steps.length) {
      steps[i].classList.add("loading-step--active");
    } else {
      clearInterval(interval);
    }
    i++;
  }, 800);
}

// ──────────────────────────────────────────────
//  Error Display
// ──────────────────────────────────────────────
function showError(msg) {
  errorText.textContent = msg;
  errorMessage.classList.add("error-message--active");
}

function hideError() {
  errorMessage.classList.remove("error-message--active");
}

// ──────────────────────────────────────────────
//  Render Results
// ──────────────────────────────────────────────
function hideResults() {
  results.classList.remove("results--active");
}

function renderResults(data) {
  currentScanId = data.id;
  results.classList.add("results--active");

  // --- Score circle animation ---
  const score = data.score || 0;
  const circumference = 2 * Math.PI * 70; // r=70
  const offset = circumference - (score / 100) * circumference;

  scoreArc.style.strokeDasharray = circumference;
  // Trigger reflow for animation
  scoreArc.style.strokeDashoffset = circumference;
  requestAnimationFrame(() => {
    scoreArc.style.strokeDashoffset = offset;
  });

  // Color the arc based on score
  let arcColor;
  if (score >= 90) arcColor = "#10b981";
  else if (score >= 75) arcColor = "#3b82f6";
  else if (score >= 60) arcColor = "#f59e0b";
  else if (score >= 40) arcColor = "#f97316";
  else arcColor = "#ef4444";
  scoreArc.style.stroke = arcColor;

  // Animate the number
  animateCounter(scoreNumber, 0, score, 1200);

  // Grade badge
  scoreGrade.textContent = data.grade || "?";
  scoreGrade.style.background = arcColor + "22";
  scoreGrade.style.color = arcColor;

  // Meta info
  resultUrl.textContent = `Target: ${data.url}`;
  resultTime.textContent = `Scan duration: ${data.scan_time}s`;
  resultTotal.textContent = `Total issues: ${data.total_vulnerabilities}`;

  // Severity counts
  const summary = data.summary || {};
  countHigh.textContent   = summary.HIGH   || 0;
  countMedium.textContent = summary.MEDIUM || 0;
  countLow.textContent    = summary.LOW    || 0;
  countInfo.textContent   = summary.INFO   || 0;

  // --- Render vulnerability cards ---
  vulnList.innerHTML = "";

  const vulns = data.vulnerabilities || [];
  if (vulns.length === 0) {
    vulnList.innerHTML = `
      <div class="no-vulns">
        <div class="no-vulns__icon">🎉</div>
        <div class="no-vulns__text">No vulnerabilities detected!</div>
      </div>
    `;
    return;
  }

  // Sort: HIGH first, then MEDIUM, LOW, INFO
  const order = { HIGH: 0, MEDIUM: 1, LOW: 2, INFO: 3 };
  vulns.sort((a, b) => (order[a.severity] ?? 4) - (order[b.severity] ?? 4));

  vulns.forEach((vuln, index) => {
    const sev = (vuln.severity || "INFO").toLowerCase();
    const card = document.createElement("div");
    card.className = `vuln-card vuln-card--${sev}`;
    card.style.animationDelay = `${index * 0.06}s`;

    card.innerHTML = `
      <div class="vuln-card__header">
        <span class="vuln-card__type">${escapeHtml(vuln.type)}</span>
        <span class="vuln-card__badge vuln-card__badge--${sev}">${vuln.severity}</span>
      </div>
      <div class="vuln-card__desc">${escapeHtml(vuln.description)}</div>
      <div class="vuln-card__fix">
        <span class="vuln-card__fix-icon">💡</span>
        <span>${escapeHtml(vuln.fix)}</span>
      </div>
    `;

    vulnList.appendChild(card);
  });

  // Scroll to results
  results.scrollIntoView({ behavior: "smooth", block: "start" });
}

// ──────────────────────────────────────────────
//  Animate Counter
// ──────────────────────────────────────────────
function animateCounter(element, start, end, duration) {
  const startTime = performance.now();
  function update(currentTime) {
    const elapsed = currentTime - startTime;
    const progress = Math.min(elapsed / duration, 1);
    // Ease-out cubic
    const eased = 1 - Math.pow(1 - progress, 3);
    const current = Math.round(start + (end - start) * eased);
    element.textContent = current;
    if (progress < 1) requestAnimationFrame(update);
  }
  requestAnimationFrame(update);
}

// ──────────────────────────────────────────────
//  Escape HTML (prevent injection in UI)
// ──────────────────────────────────────────────
function escapeHtml(text) {
  const div = document.createElement("div");
  div.textContent = text || "";
  return div.innerHTML;
}

// ──────────────────────────────────────────────
//  PDF Download
// ──────────────────────────────────────────────
btnDownload.addEventListener("click", () => {
  if (!currentScanId) return;
  window.open(`${API_BASE}/api/report/${currentScanId}`, "_blank");
});

// ──────────────────────────────────────────────
//  New Scan
// ──────────────────────────────────────────────
btnNewScan.addEventListener("click", () => {
  hideResults();
  hideError();
  urlInput.value = "";
  urlInput.focus();
  window.scrollTo({ top: 0, behavior: "smooth" });
});

// ──────────────────────────────────────────────
//  Scan History
// ──────────────────────────────────────────────
async function loadHistory() {
  try {
    const resp = await fetch(`${API_BASE}/api/history`);
    if (!resp.ok) return;
    const history = await resp.json();
    renderHistory(history);
  } catch {
    // Silently fail — history is optional
  }
}

async function checkAuthStatus() {
  try {
    const resp = await fetch(`${API_BASE}/api/auth/status`);
    const data = await resp.json();
    const nav = document.getElementById("nav-auth");
    if (data.is_logged_in) {
      nav.innerHTML = `
        <span class="user-greeting">Hi, <strong>${data.username}</strong></span>
        <button class="btn-secondary btn-sm" onclick="logout()">Logout</button>
      `;
    } else {
      nav.innerHTML = `
        <a href="login.html" class="btn-secondary btn-sm">Login</a>
        <a href="signup.html" class="btn-primary btn-sm">Sign Up</a>
      `;
    }
  } catch (err) {
    console.error("Auth status check failed", err);
  }
}

async function logout() {
  await fetch(`${API_BASE}/api/auth/logout`, { method: 'POST' });
  window.location.reload();
}

function renderHistory(history) {
  historyBody.innerHTML = "";

  if (!history || history.length === 0) {
    historyBody.innerHTML = `
      <tr>
        <td colspan="5" style="text-align:center; color: var(--text-muted);">
          No scans yet. Run your first scan above!
        </td>
      </tr>
    `;
    return;
  }

  history.forEach((scan) => {
    const row = document.createElement("tr");
    const date = new Date(scan.created_at).toLocaleString();

    let gradeColor;
    switch (scan.grade) {
      case "A": gradeColor = "#10b981"; break;
      case "B": gradeColor = "#3b82f6"; break;
      case "C": gradeColor = "#f59e0b"; break;
      case "D": gradeColor = "#f97316"; break;
      default:  gradeColor = "#ef4444"; break;
    }

    row.innerHTML = `
      <td style="font-family: var(--font-mono); font-size: 0.8rem;">${escapeHtml(scan.url)}</td>
      <td><strong>${scan.score}</strong>/100</td>
      <td><span style="color:${gradeColor}; font-weight:700;">${scan.grade}</span></td>
      <td>${scan.total_vulnerabilities}</td>
      <td style="color: var(--text-muted);">${date}</td>
    `;

    historyBody.appendChild(row);
  });
}

// ──────────────────────────────────────────────
//  Initialize
// ──────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  checkAuthStatus();
  loadHistory();
  urlInput.focus();
});
