// PhishCreator Pro - Frontend JavaScript
// Enhanced with AI regeneration support and Live Traffic Analysis

let currentResultId = null;
let hasAiRegenerated = false;
let currentLiveSessionId = null;
let liveStatusInterval = null;
let currentMode = 'upload';  // 'upload', 'live', or 'ai'
let liveAnalyzerAvailable = false;

// DOM Elements - Upload Mode
const phishletFile = document.getElementById('phishletFile');
const harFile = document.getElementById('harFile');
const phishletZone = document.getElementById('phishletZone');
const harZone = document.getElementById('harZone');
const analyzeBtn = document.getElementById('analyzeBtn');
const progressSection = document.getElementById('progressSection');
const resultsSection = document.getElementById('resultsSection');
const validationSection = document.getElementById('validationSection');

// DOM Elements - Live Mode
const uploadModePanel = document.getElementById('uploadModePanel');
const liveModePanel = document.getElementById('liveModePanel');
const liveResultsSection = document.getElementById('liveResultsSection');
const liveSessionPanel = document.getElementById('liveSessionPanel');
const targetUrlInput = document.getElementById('targetUrl');
const phishletNameInput = document.getElementById('phishletName');
const headlessModeCheckbox = document.getElementById('headlessMode');
const startLiveBtn = document.getElementById('startLiveBtn');
const stopLiveBtn = document.getElementById('stopLiveBtn');
const cancelLiveBtn = document.getElementById('cancelLiveBtn');
const generatePhishletBtn = document.getElementById('generatePhishletBtn');
const downloadLiveBtn = document.getElementById('downloadLiveBtn');
const authHarFileInput = document.getElementById('authHarFile');

// DOM Elements - AI Update Mode
const aiModePanel = document.getElementById('aiModePanel');
const aiTabBtn = document.getElementById('aiTabBtn');
const aiOldPhishletFile = document.getElementById('aiOldPhishletFile');
const aiLiveYamlFile = document.getElementById('aiLiveYamlFile');
const aiHarFile = document.getElementById('aiHarFile');
const aiUpdateBtn = document.getElementById('aiUpdateBtn');
const aiEnableNote = document.getElementById('aiEnableNote');
const aiPromptPreview = document.getElementById('aiPromptPreview');
const useAICheckbox = document.getElementById('useAI');

// File Upload Handlers
function setupDragDrop(zone, fileInput) {
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        zone.addEventListener(eventName, preventDefaults, false);
    });

    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }

    ['dragenter', 'dragover'].forEach(eventName => {
        zone.addEventListener(eventName, () => zone.classList.add('drag-over'), false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
        zone.addEventListener(eventName, () => zone.classList.remove('drag-over'), false);
    });

    zone.addEventListener('drop', (e) => {
        const dt = e.dataTransfer;
        const files = dt.files;
        if (files.length > 0) {
            fileInput.files = files;
            updateFileName(fileInput);
        }
    });
}

function updateFileName(input) {
    const fileName = input.files[0]?.name;
    const fileNameSpan = input.id === 'phishletFile'
        ? document.getElementById('phishletFileName')
        : document.getElementById('harFileName');

    if (fileName) {
        fileNameSpan.textContent = `${fileName}`;
        fileNameSpan.classList.add('file-selected');
        checkFilesReady();
    }
}

function checkFilesReady() {
    const phishletReady = phishletFile.files.length > 0;
    const harReady = harFile.files.length > 0;
    analyzeBtn.disabled = !(phishletReady && harReady);
}

function updateAiFileName(input, displayId) {
    const fileName = input.files[0]?.name || '';
    const fileNameSpan = document.getElementById(displayId);
    if (fileNameSpan) {
        fileNameSpan.textContent = fileName ? `Selected: ${fileName}` : '';
        if (fileName) {
            fileNameSpan.classList.add('file-selected');
        }
    }
    checkAiFilesReady();
}

function checkAiFilesReady() {
    const aiEnabled = !!(useAICheckbox && useAICheckbox.checked);
    const oldReady = aiOldPhishletFile && aiOldPhishletFile.files.length > 0;
    const liveReady = aiLiveYamlFile && aiLiveYamlFile.files.length > 0;
    const harReady = aiHarFile && aiHarFile.files.length > 0;

    if (aiUpdateBtn) {
        aiUpdateBtn.disabled = !(aiEnabled && oldReady && liveReady && harReady);
    }

    if (aiEnableNote) {
        aiEnableNote.style.display = aiEnabled ? 'none' : 'block';
    }
}

function updateAiTabState() {
    if (!aiTabBtn) return;
    const aiEnabled = !!(useAICheckbox && useAICheckbox.checked);
    aiTabBtn.disabled = !aiEnabled;
    aiTabBtn.classList.toggle('disabled', !aiEnabled);
    checkAiFilesReady();
}

// Setup drag and drop
setupDragDrop(phishletZone, phishletFile);
setupDragDrop(harZone, harFile);

phishletFile.addEventListener('change', () => updateFileName(phishletFile));
harFile.addEventListener('change', () => updateFileName(harFile));

// Analyze Button
analyzeBtn.addEventListener('click', async () => {
    const formData = new FormData();
    formData.append('phishlet', phishletFile.files[0]);
    formData.append('har', harFile.files[0]);
    formData.append('use_ai', document.getElementById('useAI').checked);

    // Show progress
    progressSection.style.display = 'block';
    resultsSection.style.display = 'none';
    validationSection.style.display = 'none';
    hasAiRegenerated = false;

    updateProgress(10, 'Uploading files...');

    try {
        updateProgress(30, 'Analyzing phishlet structure...');

        const response = await fetch('/api/analyze', {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || 'Analysis failed');
        }

        const result = await response.json();

        updateProgress(100, 'Analysis complete!');

        setTimeout(() => {
            progressSection.style.display = 'none';
            displayResults(result);
        }, 500);

    } catch (error) {
        alert('Error: ' + error.message);
        progressSection.style.display = 'none';
    }
});

function updateProgress(percent, text) {
    document.getElementById('progressFill').style.width = percent + '%';
    document.getElementById('progressText').textContent = text;
}

function displayResults(result) {
    currentResultId = result.result_id;

    // Update stats
    document.getElementById('issuesCount').textContent = result.issues_found;
    document.getElementById('fixesCount').textContent = result.fixes_applied;

    // Display issues
    const issuesList = document.getElementById('issuesList');
    issuesList.innerHTML = '';

    if (result.issues.length === 0) {
        issuesList.innerHTML = '<p class="no-issues">No issues detected. Your phishlet looks good!</p>';
    } else {
        result.issues.forEach(issue => {
            const issueDiv = document.createElement('div');
            issueDiv.className = `issue-item ${issue.severity}`;
            issueDiv.dataset.severity = issue.severity;

            issueDiv.innerHTML = `
                <div class="issue-header">
                    <span class="issue-type">${formatIssueType(issue.type)}</span>
                    <span class="issue-badge ${issue.severity}">${issue.severity}</span>
                </div>
                <div class="issue-description">${escapeHtml(issue.description)}</div>
                ${issue.fixed ? '<div class="issue-fixed">Auto-fixed</div>' : ''}
            `;

            issuesList.appendChild(issueDiv);
        });
    }

    // Show results
    resultsSection.style.display = 'block';

    // Setup filter buttons
    setupFilters();
}

function formatIssueType(type) {
    // Convert snake_case to Title Case
    return type.split('_').map(word =>
        word.charAt(0).toUpperCase() + word.slice(1)
    ).join(' ');
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function setupFilters() {
    const filterButtons = document.querySelectorAll('.filter-btn');
    const issues = document.querySelectorAll('.issue-item');

    filterButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            // Update active button
            filterButtons.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');

            const filter = btn.dataset.filter;

            // Filter issues
            issues.forEach(issue => {
                if (filter === 'all' || issue.dataset.severity === filter) {
                    issue.style.display = 'block';
                } else {
                    issue.style.display = 'none';
                }
            });
        });
    });
}

// Download Button - Auto-Fixed Phishlet
document.getElementById('downloadBtn').addEventListener('click', () => {
    if (currentResultId) {
        window.location.href = `/api/download/${currentResultId}`;
    }
});

// Manus AI Update shortcut
document.getElementById('validateBtn').addEventListener('click', () => {
    if (!useAICheckbox || !useAICheckbox.checked) {
        alert('Enable "Use AI Analysis" in the Configuration panel to access Manus AI updates.');
        return;
    }

    switchMode('ai');
    const tabButtons = document.querySelectorAll('.tab-btn');
    tabButtons.forEach(btn => btn.classList.remove('active'));
    if (aiTabBtn) aiTabBtn.classList.add('active');

    if (aiModePanel) {
        aiModePanel.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
});

// Display Manus AI task result with link to view analysis
function displayManusTaskResult(result) {
    const validationSection = document.getElementById('validationSection');
    const validationMessage = document.getElementById('validationMessage');
    const validationLink = document.getElementById('validationLink');

    // Set the message
    validationMessage.innerHTML = `
        <div class="manus-success">
            <p class="success-message">✅ ${escapeHtml(result.message)}</p>
            ${result.task_id ? `<p class="task-id">Task ID: <code>${escapeHtml(result.task_id)}</code></p>` : ''}
        </div>
    `;

    // Set the link to view results in Manus
    const taskUrl = result.share_url || result.task_url;
    if (taskUrl) {
        validationLink.href = taskUrl;
        validationLink.style.display = 'inline-block';
        validationLink.textContent = '🔗 View Analysis in Manus AI';
    } else {
        validationLink.style.display = 'none';
    }

    validationSection.style.display = 'block';

    // Scroll to the validation section
    validationSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// Submit Manus AI Update request
async function submitAiUpdate() {
    const manusApiKey = document.getElementById('manusApiKey').value;
    const apiKey = manusApiKey.trim();

    if (!apiKey) {
        alert('Please enter your Manus API key in the configuration panel');
        document.getElementById('manusApiKey').focus();
        return;
    }

    if (!useAICheckbox || !useAICheckbox.checked) {
        alert('Enable "Use AI Analysis" in the Configuration panel before running a Manus AI update.');
        return;
    }

    if (!aiOldPhishletFile || !aiLiveYamlFile || !aiHarFile) {
        alert('AI Update inputs are missing in the UI.');
        return;
    }

    if (aiOldPhishletFile.files.length === 0 || aiLiveYamlFile.files.length === 0 || aiHarFile.files.length === 0) {
        alert('Please upload the old phishlet, live-session YAML, and HAR files.');
        return;
    }

    const formData = new FormData();
    formData.append('old_phishlet', aiOldPhishletFile.files[0]);
    formData.append('live_yaml', aiLiveYamlFile.files[0]);
    formData.append('har', aiHarFile.files[0]);
    formData.append('manus_api_key', apiKey);

    const originalText = aiUpdateBtn.innerHTML;
    aiUpdateBtn.innerHTML = '<span class="spinner"></span> Creating Manus AI Task...';
    aiUpdateBtn.disabled = true;

    try {
        const response = await fetch('/api/ai/update', {
            method: 'POST',
            body: formData
        });

        const result = await response.json();

        if (!response.ok) {
            throw new Error(result.error || 'Manus AI task creation failed');
        }

        displayManusTaskResult(result);
    } catch (error) {
        alert('Error: ' + error.message);
    } finally {
        aiUpdateBtn.innerHTML = originalText;
        checkAiFilesReady();
    }
}

// Legacy function for inline AI results (if API changes in future)
function displayAiResults(result) {
    const validationSection = document.getElementById('validationSection');
    const validationMessage = document.getElementById('validationMessage');
    const validationLink = document.getElementById('validationLink');

    // Clear and rebuild validation section
    let contentHtml = `<p class="validation-summary">${escapeHtml(result.message)}</p>`;

    // Show analysis if available
    if (result.analysis) {
        contentHtml += `
            <div class="ai-analysis">
                <h4>AI Analysis</h4>
                <div class="analysis-content">${formatAnalysis(result.analysis)}</div>
            </div>
        `;
    }

    // Show detected issues from AI
    if (result.issues && result.issues.length > 0) {
        contentHtml += `
            <div class="ai-issues">
                <h4>AI-Detected Issues</h4>
                <ul>
                    ${result.issues.map(issue => `<li>${escapeHtml(issue)}</li>`).join('')}
                </ul>
            </div>
        `;
    }

    // Show testing notes
    if (result.testing_notes) {
        contentHtml += `
            <div class="ai-testing-notes">
                <h4>Testing Recommendations</h4>
                <div class="testing-content">${formatAnalysis(result.testing_notes)}</div>
            </div>
        `;
    }

    // Download button for AI-regenerated phishlet
    if (result.has_regenerated) {
        contentHtml += `
            <div class="ai-download-section">
                <button id="downloadAiBtn" class="btn-primary btn-large">
                    Download AI-Regenerated Phishlet
                </button>
                <p class="download-note">This phishlet was completely regenerated based on your HAR traffic analysis.</p>
            </div>
        `;
    }

    validationMessage.innerHTML = contentHtml;
    validationLink.style.display = 'none';
    validationSection.style.display = 'block';

    // Add event listener for AI download button
    if (result.has_regenerated) {
        document.getElementById('downloadAiBtn').addEventListener('click', () => {
            if (currentResultId) {
                window.location.href = `/api/download/ai/${currentResultId}`;
            }
        });
    }
}

function formatAnalysis(text) {
    // Convert markdown-like formatting to HTML
    return text
        .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
        .replace(/`(.*?)`/g, '<code>$1</code>')
        .replace(/\n/g, '<br>')
        .replace(/^- /gm, '• ');
}

// ============================================================================
// MODE SWITCHING
// ============================================================================

function setupModeTabs() {
    const tabButtons = document.querySelectorAll('.tab-btn');

    tabButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            if (btn.disabled) {
                return;
            }
            const mode = btn.dataset.mode;
            switchMode(mode);

            // Update active tab
            tabButtons.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
        });
    });
}

function switchMode(mode) {
    currentMode = mode;

    // Hide all mode panels
    document.querySelectorAll('.mode-panel').forEach(panel => {
        panel.style.display = 'none';
    });

    // Show selected mode panel
    if (mode === 'upload') {
        uploadModePanel.style.display = 'block';
    } else if (mode === 'live') {
        liveModePanel.style.display = 'block';

        // Check if live analyzer is available
        if (!liveAnalyzerAvailable) {
            showLiveUnavailableMessage();
        }
    } else if (mode === 'ai') {
        aiModePanel.style.display = 'block';
    }

    // Hide results sections when switching modes
    resultsSection.style.display = 'none';
    liveResultsSection.style.display = 'none';
    validationSection.style.display = 'none';
}

function showLiveUnavailableMessage() {
    const liveForm = document.querySelector('.live-form');
    if (liveForm && !liveAnalyzerAvailable) {
        liveForm.innerHTML = `
            <div class="unavailable-message">
                <h3>Live Traffic Analyzer Not Available</h3>
                <p>The Playwright browser automation library is not installed.</p>
                <p>To enable live traffic capture, run:</p>
                <pre>pip install playwright && playwright install chromium</pre>
                <p>Then restart the PhishCreator service.</p>
            </div>
        `;
    }
}

// ============================================================================
// LIVE TRAFFIC ANALYSIS
// ============================================================================

async function startLiveSession() {
    // Some browsers don't reliably replace placeholder text on typing; ensure we clear it.
    targetUrlInput.value = targetUrlInput.value || '';
    const targetUrl = targetUrlInput.value.trim();
    const oldPhishletFile = document.getElementById('oldPhishletFile');

    if (!targetUrl) {
        alert('Please enter a target URL');
        targetUrlInput.focus();
        return;
    }

    try {
        startLiveBtn.disabled = true;
        startLiveBtn.innerHTML = '<span class="spinner"></span> Starting...';

        // Use FormData if old phishlet file is provided
        let response;
        if (oldPhishletFile && oldPhishletFile.files.length > 0) {
            const formData = new FormData();
            formData.append('target_url', targetUrl);
            formData.append('headless', headlessModeCheckbox.checked);
            formData.append('old_phishlet', oldPhishletFile.files[0]);

            response = await fetch('/api/live/start', {
                method: 'POST',
                body: formData
            });
        } else {
            response = await fetch('/api/live/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    target_url: targetUrl,
                    headless: headlessModeCheckbox.checked
                })
            });
        }

        const result = await response.json();

        if (!response.ok) {
            throw new Error(result.error || 'Failed to start live session');
        }

        currentLiveSessionId = result.session_id;
        
        // Store whether we have old phishlet for later comparison
        if (result.has_old_phishlet) {
            sessionStorage.setItem('has_old_phishlet', 'true');
        }

        // Show session panel
        document.querySelector('.live-form').style.display = 'none';
        liveSessionPanel.style.display = 'block';

        // Start polling for status
        startStatusPolling();

        addLogEntry('Session started: ' + result.message);
        if (result.has_old_phishlet) {
            addLogEntry('Old phishlet loaded for comparison');
        }

    } catch (error) {
        alert('Error: ' + error.message);
        startLiveBtn.disabled = false;
        startLiveBtn.innerHTML = 'Launch Browser & Start Capture';
    }
}

function startStatusPolling() {
    // Clear any existing interval
    if (liveStatusInterval) {
        clearInterval(liveStatusInterval);
    }

    // Poll every 2 seconds
    liveStatusInterval = setInterval(async () => {
        if (!currentLiveSessionId) {
            clearInterval(liveStatusInterval);
            return;
        }

        try {
            const response = await fetch(`/api/live/status/${currentLiveSessionId}`);
            const status = await response.json();

            updateSessionStatus(status);

        } catch (error) {
            console.error('Status poll error:', error);
        }
    }, 2000);
}

function updateSessionStatus(status) {
    // Update status badge
    const statusBadge = document.getElementById('sessionStatus');
    statusBadge.textContent = formatStatus(status.session_status, !!status.auth_observed);
    statusBadge.className = 'status-badge ' + status.session_status;

    // Update stats
    document.getElementById('requestsCount').textContent = status.requests_captured || 0;
    document.getElementById('hostsCount').textContent = status.unique_hosts || status.hosts_seen || 0;
    document.getElementById('formsCount').textContent = status.form_submissions || status.forms_detected || 0;

    // Add new log entries
    if (status.status_messages) {
        const sessionLog = document.getElementById('sessionLog');
        const existingEntries = sessionLog.querySelectorAll('.log-entry').length;

        status.status_messages.slice(existingEntries).forEach(msg => {
            addLogEntry(msg);
        });
    }

    // Check if session is complete or has error
    if (status.session_status === 'completed' || status.session_status === 'error') {
        clearInterval(liveStatusInterval);

        if (status.session_status === 'completed') {
            fetchAndDisplayLiveResults();
        } else if (status.error) {
            addLogEntry('Error: ' + status.error);
        }
    }
}

function formatStatus(status, authObserved=false) {
    const statusMap = {
        'starting': 'Starting...',
        'waiting_for_auth': authObserved ? 'Auth Activity Detected' : 'Waiting for Auth',
        'analyzing': 'Analyzing...',
        'completed': 'Completed',
        'error': 'Error'
    };
    return statusMap[status] || status;
}

function addLogEntry(message) {
    const sessionLog = document.getElementById('sessionLog');
    const entry = document.createElement('div');
    entry.className = 'log-entry';
    entry.textContent = message;
    sessionLog.appendChild(entry);
    sessionLog.scrollTop = sessionLog.scrollHeight;
}

async function stopLiveSession() {
    if (!currentLiveSessionId) return;

    try {
        stopLiveBtn.disabled = true;
        stopLiveBtn.innerHTML = '<span class="spinner"></span> Analyzing...';

        const response = await fetch(`/api/live/stop/${currentLiveSessionId}`, {
            method: 'POST'
        });

        const result = await response.json();

        if (!response.ok) {
            throw new Error(result.error || 'Failed to stop session');
        }

        addLogEntry('Analyzing captured traffic...');

        // If result is immediately available, display it
        if (result.result) {
            displayLiveResults(result.result);
        } else {
            // Wait for analysis to complete
            addLogEntry('Analysis in progress...');
        }

    } catch (error) {
        alert('Error: ' + error.message);
        stopLiveBtn.disabled = false;
        stopLiveBtn.innerHTML = 'Stop & Analyze Traffic';
    }
}

async function cancelLiveSession() {
    if (liveStatusInterval) {
        clearInterval(liveStatusInterval);
    }

    currentLiveSessionId = null;

    // Reset UI
    liveSessionPanel.style.display = 'none';
    document.querySelector('.live-form').style.display = 'block';
    startLiveBtn.disabled = false;
    startLiveBtn.innerHTML = 'Launch Browser & Start Capture';
    stopLiveBtn.disabled = false;
    stopLiveBtn.innerHTML = 'Stop & Analyze Traffic';

    // Clear session log
    document.getElementById('sessionLog').innerHTML = '<div class="log-entry">Initializing browser...</div>';
}

async function fetchAndDisplayLiveResults() {
    if (!currentLiveSessionId) return;

    try {
        const response = await fetch(`/api/live/result/${currentLiveSessionId}`);
        const data = await response.json();

        if (data.success && data.result) {
            displayLiveResults(data.result);
        }
    } catch (error) {
        console.error('Failed to fetch results:', error);
    }
}

function displayLiveResults(result) {
    // Hide session panel, show results
    liveSessionPanel.style.display = 'none';
    liveResultsSection.style.display = 'block';

    // Update stats
    const proxyHosts = result.detected_proxy_hosts || [];
    const authTokens = result.detected_auth_tokens || [];
    const credentials = result.detected_credentials || {};
    const warnings = result.warnings || [];
    const storageState = result.storage_state || {};

    document.getElementById('liveHostsCount').textContent = proxyHosts.length;
    document.getElementById('liveTokensCount').textContent = authTokens.length;

    let credsCount = 0;
    if (credentials.username) credsCount++;
    if (credentials.password) credsCount++;
    document.getElementById('liveCredsCount').textContent = credsCount;

    // Display proxy hosts
    const hostsContainer = document.getElementById('liveProxyHosts');
    hostsContainer.innerHTML = proxyHosts.map(host => `
        <div class="element-item ${host.is_landing ? 'landing' : ''}">
            <span class="element-name">${host._original_host || host.domain}</span>
            ${host.is_landing ? '<span class="element-badge">Landing</span>' : ''}
            <span class="element-count">${host._request_count || 0} requests</span>
        </div>
    `).join('') || '<div class="element-empty">No proxy hosts detected</div>';

    // Display auth tokens
    const tokensContainer = document.getElementById('liveAuthTokens');
    tokensContainer.innerHTML = authTokens.map(token => `
        <div class="element-item ${token._priority}">
            <span class="element-name">${token.keys ? token.keys.join(', ') : 'unknown'}</span>
            <span class="element-badge ${token._priority}">${token._priority}</span>
            <span class="element-domain">${token.domain}</span>
        </div>
    `).join('') || '<div class="element-empty">No auth tokens detected</div>';

    // Display credentials
    const credsContainer = document.getElementById('liveCredentials');
    let credsHtml = '';
    if (credentials.username) {
        credsHtml += `<div class="element-item"><span class="element-label">Username:</span> <code>${escapeHtml(credentials.username)}</code></div>`;
    }
    if (credentials.password) {
        credsHtml += `<div class="element-item"><span class="element-label">Password:</span> <code>${escapeHtml(credentials.password)}</code></div>`;
    }
    if (result.detected_login_url) {
        credsHtml += `<div class="element-item"><span class="element-label">Login URL:</span> <code>${escapeHtml(result.detected_login_url)}</code></div>`;
    }
    credsContainer.innerHTML = credsHtml || '<div class="element-empty">No credential fields detected</div>';

    // Display warnings
    if (warnings.length > 0) {
        document.getElementById('liveWarningsSection').style.display = 'block';
        const warningsContainer = document.getElementById('liveWarnings');
        warningsContainer.innerHTML = warnings.map(w => `
            <div class="element-item warning">${escapeHtml(w)}</div>
        `).join('');
    }

    // Display storage tokens (best-effort) if the UI has a container
    const storageContainer = document.getElementById('liveStorageTokens');
    if (storageContainer) {
        const tokenKeys = [];
        ['localStorage', 'sessionStorage'].forEach(containerName => {
            const container = storageState[containerName] || {};
            Object.keys(container).forEach(k => {
                const kl = String(k).toLowerCase();
                if (['token','jwt','bearer','access','refresh','id_token','saml'].some(x => kl.includes(x))) {
                    tokenKeys.push(containerName + ':' + k);
                }
            });
        });
        storageContainer.innerHTML = tokenKeys.length
            ? tokenKeys.slice(0, 20).map(k => `<div class="element-item"><code>${escapeHtml(k)}</code></div>`).join('')
            : '<div class="element-empty">No storage tokens detected</div>';
    }

    // Show comparison button if we have old phishlet
    if (sessionStorage.getItem('has_old_phishlet') === 'true') {
        const viewComparisonBtn = document.getElementById('viewComparisonBtn');
        if (viewComparisonBtn) {
            viewComparisonBtn.style.display = 'inline-block';
        }
    }

    // Enable generate button
    generatePhishletBtn.disabled = false;
}

async function generatePhishlet() {
    if (!currentLiveSessionId) {
        alert('No live session available');
        return;
    }

    try {
        generatePhishletBtn.disabled = true;
        generatePhishletBtn.innerHTML = '<span class="spinner"></span> Generating...';

        const phishletName = phishletNameInput.value.trim() || null;

        let response;

        // If user provided an authenticated HAR, use multipart upload to merge traffic server-side.
        if (authHarFileInput && authHarFileInput.files && authHarFileInput.files.length > 0) {
            const formData = new FormData();
            if (phishletName) formData.append('name', phishletName);
            formData.append('auth_har', authHarFileInput.files[0]);

            response = await fetch(`/api/live/generate-phishlet/${currentLiveSessionId}`, {
                method: 'POST',
                body: formData
            });
        } else {
            response = await fetch(`/api/live/generate-phishlet/${currentLiveSessionId}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name: phishletName })
            });
        }

        const result = await response.json();

        if (!response.ok) {
            throw new Error(result.error || 'Failed to generate phishlet');
        }

        // Show YAML preview
        const yamlPreviewSection = document.getElementById('yamlPreviewSection');
        const yamlPreview = document.getElementById('yamlPreview');
        yamlPreview.textContent = result.yaml_preview;
        yamlPreviewSection.style.display = 'block';
        
        // Show generation info
        if (result.generation_method || result.used_baseline) {
            const infoBox = document.getElementById('yamlGenerationInfo');
            let infoHTML = '';
            if (result.used_baseline) {
                infoHTML += '<p><strong>✓ Generated using old phishlet as baseline</strong></p>';
                if (result.changes_made && result.changes_made.length > 0) {
                    infoHTML += '<p>Changes made: ' + result.changes_made.length + '</p>';
                    infoHTML += '<ul>';
                    result.changes_made.slice(0, 5).forEach(change => {
                        infoHTML += '<li>' + change + '</li>';
                    });
                    if (result.changes_made.length > 5) {
                        infoHTML += '<li>... and ' + (result.changes_made.length - 5) + ' more</li>';
                    }
                    infoHTML += '</ul>';
                }
            } else {
                infoHTML += '<p>Generated fresh phishlet from live traffic</p>';
            }
            infoBox.innerHTML = infoHTML;
            infoBox.style.display = 'block';
        }

        // Enable download button
        downloadLiveBtn.disabled = false;

        // Show comparison button if we have old phishlet
        if (sessionStorage.getItem('has_old_phishlet') === 'true') {
            const viewComparisonBtn = document.getElementById('viewComparisonBtn');
            if (viewComparisonBtn) {
                viewComparisonBtn.style.display = 'inline-block';
            }
        }

        generatePhishletBtn.innerHTML = 'Regenerate Phishlet YAML';

    } catch (error) {
        alert('Error: ' + error.message);
    } finally {
        generatePhishletBtn.disabled = false;
    }
}

async function viewComparison() {
    if (!currentLiveSessionId) return;
    
    try {
        const response = await fetch(`/api/live/compare/${currentLiveSessionId}`);
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error || 'Failed to load comparison');
        }
        
        // Show comparison section
        const comparisonSection = document.getElementById('comparisonSection');
        const comparisonMissing = document.getElementById('comparisonMissing');
        const comparisonExtra = document.getElementById('comparisonExtra');
        const comparisonRecommendations = document.getElementById('comparisonRecommendations');
        
        // Display changes made
        let missingHTML = '';
        if (data.comparison.hosts_added && data.comparison.hosts_added.length > 0) {
            missingHTML += '<h5>Hosts Added:</h5><ul>';
            data.comparison.hosts_added.forEach(host => {
                missingHTML += `<li>${host}</li>`;
            });
            missingHTML += '</ul>';
        }
        if (data.comparison.cookies_added && Object.keys(data.comparison.cookies_added).length > 0) {
            missingHTML += '<h5>Cookies Added:</h5><ul>';
            Object.entries(data.comparison.cookies_added).forEach(([domain, cookies]) => {
                missingHTML += `<li>${domain}: ${cookies.join(', ')}</li>`;
            });
            missingHTML += '</ul>';
        }
        comparisonMissing.innerHTML = missingHTML || '<p>No new items detected</p>';
        
        // Display changes
        let changesHTML = '';
        if (data.comparison.changes_made && data.comparison.changes_made.length > 0) {
            changesHTML = '<ul>';
            data.comparison.changes_made.forEach(change => {
                changesHTML += `<li>${change}</li>`;
            });
            changesHTML += '</ul>';
        }
        comparisonExtra.innerHTML = changesHTML || '<p>No issues detected</p>';
        
        // Display recommendations
        let recsHTML = '';
        if (data.comparison.warnings && data.comparison.warnings.length > 0) {
            recsHTML = '<ul>';
            data.comparison.warnings.forEach(warning => {
                recsHTML += `<li>${warning}</li>`;
            });
            recsHTML += '</ul>';
        }
        comparisonRecommendations.innerHTML = recsHTML || '<p>No additional recommendations</p>';
        
        comparisonSection.style.display = 'block';
        
    } catch (error) {
        alert('Error loading comparison: ' + error.message);
    }
}

function downloadLivePhishlet() {
    if (currentLiveSessionId) {
        window.location.href = `/api/live/download/${currentLiveSessionId}`;
    }
}

// ============================================================================
// EVENT LISTENERS - LIVE MODE
// ============================================================================

if (startLiveBtn) {
    startLiveBtn.addEventListener('click', startLiveSession);
}

if (stopLiveBtn) {
    stopLiveBtn.addEventListener('click', stopLiveSession);
}

if (cancelLiveBtn) {
    cancelLiveBtn.addEventListener('click', cancelLiveSession);
}

if (generatePhishletBtn) {
    generatePhishletBtn.addEventListener('click', generatePhishlet);
}

if (downloadLiveBtn) {
    downloadLiveBtn.addEventListener('click', downloadLivePhishlet);
}

if (aiUpdateBtn) {
    aiUpdateBtn.addEventListener('click', submitAiUpdate);
}

const viewComparisonBtn = document.getElementById('viewComparisonBtn');
if (viewComparisonBtn) {
    viewComparisonBtn.addEventListener('click', viewComparison);
}

// File name display for old phishlet
const oldPhishletFileInput = document.getElementById('oldPhishletFile');
if (oldPhishletFileInput) {
    oldPhishletFileInput.addEventListener('change', (e) => {
        const fileName = e.target.files[0]?.name || '';
        const fileNameDisplay = document.getElementById('oldPhishletFileName');
        if (fileNameDisplay) {
            fileNameDisplay.textContent = fileName ? `Selected: ${fileName}` : '';
        }
    });
}

// File name display for authenticated HAR
if (authHarFileInput) {
    authHarFileInput.addEventListener('change', (e) => {
        const fileName = e.target.files[0]?.name || '';
        const fileNameDisplay = document.getElementById('authHarFileName');
        if (fileNameDisplay) {
            fileNameDisplay.textContent = fileName ? `Selected: ${fileName}` : '';
        }
    });
}

// File name display for AI update inputs
if (aiOldPhishletFile) {
    aiOldPhishletFile.addEventListener('change', () => updateAiFileName(aiOldPhishletFile, 'aiOldPhishletFileName'));
}
if (aiLiveYamlFile) {
    aiLiveYamlFile.addEventListener('change', () => updateAiFileName(aiLiveYamlFile, 'aiLiveYamlFileName'));
}
if (aiHarFile) {
    aiHarFile.addEventListener('change', () => updateAiFileName(aiHarFile, 'aiHarFileName'));
}

// ============================================================================
// INITIALIZATION
// ============================================================================

// Load config on page load
window.addEventListener('DOMContentLoaded', async () => {
    // Setup mode tabs
    setupModeTabs();
    updateAiTabState();
    if (aiPromptPreview) {
        aiPromptPreview.value = [
            'Use the HAR file and the live-session YAML to update the old phishlet YAML.',
            'Preserve any custom overrides from the old file unless the live YAML/HAR shows newer values.',
            'Output a complete updated phishlet and a short changelog.'
        ].join('\n');
    }

    try {
        const response = await fetch('/api/config');
        const config = await response.json();

        // Show indicators if API keys are set
        if (config.manus_api_key_set) {
            document.getElementById('manusApiKey').placeholder = 'API key configured (enter to override)';
        }

        // Check service status
        const statusResponse = await fetch('/api/status');
        const status = await statusResponse.json();

        liveAnalyzerAvailable = status.live_analyzer_available || false;

        if (status.modules_available) {
            console.log('PhishCreator modules loaded successfully');
        } else {
            console.warn('Some PhishCreator modules are not available');
        }

        if (liveAnalyzerAvailable) {
            console.log('Live traffic analyzer available');
        } else {
            console.warn('Live traffic analyzer not available');
        }
    } catch (error) {
        console.error('Failed to load config:', error);
    }
});

if (useAICheckbox) {
    useAICheckbox.addEventListener('change', () => {
        updateAiTabState();
        if (currentMode === 'ai' && !useAICheckbox.checked) {
            switchMode('upload');
            const tabButtons = document.querySelectorAll('.tab-btn');
            tabButtons.forEach(btn => btn.classList.remove('active'));
            const uploadTab = document.querySelector('[data-mode="upload"]');
            if (uploadTab) uploadTab.classList.add('active');
        }
    });
}
