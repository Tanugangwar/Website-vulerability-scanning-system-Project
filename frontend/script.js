const scanForm = document.getElementById('scanForm');
const scanBtn = document.getElementById('scanBtn');
const loadingOverlay = document.getElementById('loadingOverlay');
const statusMsg = document.getElementById('statusMsg');
const resultsArea = document.getElementById('resultsArea');
const vulnerabilitiesList = document.getElementById('vulnerabilitiesList');
const scoreValue = document.getElementById('scoreValue');

if (scanForm) {
    scanForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const url = document.getElementById('scanUrl').value;
        
        // Reset UI
        resultsArea.classList.remove('results--active');
        vulnerabilitiesList.innerHTML = '';
        statusMsg.style.display = 'block';
        statusMsg.innerText = 'Initializing scan...';
        if (loadingOverlay) loadingOverlay.classList.add('loading-overlay--active');
        scanBtn.disabled = true;

        // Simulate status updates
        const interval = setInterval(() => {
            const step = Math.random();
            if (step > 0.8) statusMsg.innerText = 'Checking security headers...';
            else if (step > 0.6) statusMsg.innerText = 'Analyzing HTML forms...';
            else if (step > 0.4) statusMsg.innerText = 'Checking for XSS/SQLi...';
        }, 1000);

        try {
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url })
            });

            clearInterval(interval);
            statusMsg.innerText = 'Scan complete!';

            const data = await response.json();
            
            if (data.error) {
                alert(data.error);
                statusMsg.innerText = 'Scan failed.';
            } else {
                displayResults(data);
            }
        } catch (err) {
            console.error('Scan error:', err);
            alert('An error occurred during scanning.');
            clearInterval(interval);
        } finally {
            scanBtn.disabled = false;
            setTimeout(() => {
                if (loadingOverlay) loadingOverlay.classList.remove('loading-overlay--active');
                statusMsg.style.display = 'none';
            }, 1000);
        }
    });
}

function displayResults(data) {
    resultsArea.classList.add('results--active');
    scoreValue.innerText = data.score;
    const resultUrl = document.getElementById('resultUrl');
    if (resultUrl) resultUrl.innerText = `Target: ${document.getElementById('scanUrl').value}`;
    
    // Update SVG arc
    const arc = document.getElementById('scoreArc');
    if (arc) {
        const offset = 440 - (440 * data.score) / 100;
        arc.style.strokeDashoffset = offset;
        // Color arc
        if (data.score > 80) arc.style.stroke = 'var(--accent-emerald)';
        else if (data.score > 50) arc.style.stroke = 'var(--accent-amber)';
        else arc.style.stroke = 'var(--accent-rose)';
    }

    if (data.vulnerabilities.length === 0) {
        vulnerabilitiesList.innerHTML = `
            <div class="no-vulns">
                <div class="no-vulns__icon">✅</div>
                <div class="no-vulns__text">No Vulnerabilities Found!</div>
                <p style="color: var(--text-secondary); margin-top: 10px;">The website follows security best practices.</p>
            </div>
        `;
        return;
    }

    data.vulnerabilities.forEach(vuln => {
        const severity = vuln.severity.toLowerCase();
        const card = document.createElement('div');
        card.className = `vuln-card vuln-card--${severity}`;
        card.innerHTML = `
            <div class="vuln-card__header">
                <span class="vuln-card__type">${vuln.type}</span>
                <span class="vuln-card__badge vuln-card__badge--${severity}">${vuln.severity}</span>
            </div>
            <p class="vuln-card__desc">${vuln.description}</p>
            <div class="vuln-card__fix">
                <span class="vuln-card__fix-icon">🛠️</span>
                <span>${vuln.fix}</span>
            </div>
        `;
        vulnerabilitiesList.appendChild(card);
    });
}

async function loadHistory() {
    const tableBody = document.getElementById('historyTableBody');
    if (!tableBody) return;

    try {
        const response = await fetch('/api/history');
        const history = await response.json();

        if (history.length === 0) {
            tableBody.innerHTML = '<tr><td colspan="4" style="text-align: center;">No scan history found.</td></tr>';
            return;
        }

        tableBody.innerHTML = history.map(item => `
            <tr>
                <td style="font-size: 0.85rem; color: var(--text-muted);">${new Date(item.timestamp).toLocaleString()}</td>
                <td style="font-weight: 600;">${item.url}</td>
                <td>
                    <span style="font-weight: 700; color: ${item.score > 70 ? '#10b981' : item.score > 40 ? '#f59e0b' : '#ef4444'}">
                        ${item.score}/100
                    </span>
                </td>
                <td><i class="fas fa-check-circle" style="color: #10b981;"></i> Completed</td>
            </tr>
        `).join('');
    } catch (err) {
        console.error('History load error:', err);
    }
}
