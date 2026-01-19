/**
 * VulnAI - AI-Powered Vulnerability Analysis Platform
 * Frontend Application v2.0
 *
 * Features:
 * - Upload code files for AI scanning
 * - View discovered vulnerabilities
 * - Generate AI-powered reports
 */

// API Configuration
const API_BASE = '/api';

// Application State
const state = {
    currentPage: 'dashboard',
    vulnerabilities: [],
    stats: null,
    filters: {
        severity: 'all',
        file: '',
        search: ''
    },
    pagination: {
        page: 1,
        pageSize: 20,
        total: 0
    },
    sortBy: 'severity',
    sortOrder: 'desc',
    selectedReportType: 'both',
    currentScanJob: null,
    // Project management
    projects: [],
    selectedProject: null,
    projectFiles: [],
    selectedFiles: new Set()
};

// DOM Elements
const elements = {
    pages: document.querySelectorAll('.page'),
    navItems: document.querySelectorAll('.nav-item'),
    sidebar: document.querySelector('.sidebar'),
    menuToggle: document.querySelector('.menu-toggle'),
    pageTitle: document.getElementById('current-page-title'),
    globalSearch: document.getElementById('global-search'),
    toastContainer: document.getElementById('toast-container')
};

// ========================================
// Initialization
// ========================================

document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    initModals();
    initFilters();
    initUpload();
    initReportGenerator();
    initDataSources();
    initProjectManager();
    checkOllamaStatus();
    loadDashboard();

    // Periodically check Ollama status
    setInterval(checkOllamaStatus, 30000);
});

// ========================================
// Ollama Status Check
// ========================================

async function checkOllamaStatus() {
    const indicator = document.getElementById('ollama-indicator');
    const text = document.getElementById('ollama-text');

    try {
        const status = await fetchAPI('/status');

        if (status.ollama_available) {
            indicator.classList.add('online');
            indicator.classList.remove('offline');
            text.textContent = 'Ollama Ready';
        } else {
            indicator.classList.remove('online');
            indicator.classList.add('offline');
            text.textContent = 'Ollama Offline';
        }

        // Update counts
        document.getElementById('scan-count').textContent = status.scans_completed || 0;
        document.getElementById('vuln-count').textContent = status.vulnerabilities || 0;

    } catch (error) {
        indicator.classList.remove('online');
        indicator.classList.add('offline');
        text.textContent = 'API Error';
    }
}

// ========================================
// Data Sources (NVD & MITRE)
// ========================================

function initDataSources() {
    // NVD refresh button
    const nvdBtn = document.getElementById('refresh-nvd');
    if (nvdBtn) {
        nvdBtn.addEventListener('click', fetchNVDData);
    }

    // MITRE refresh button
    const mitreBtn = document.getElementById('refresh-mitre');
    if (mitreBtn) {
        mitreBtn.addEventListener('click', fetchMITREData);
    }
}

async function fetchNVDData() {
    const btn = document.getElementById('refresh-nvd');
    btn.classList.add('spinning');

    showToast('info', 'Fetching CVEs', 'Connecting to NVD API...');

    try {
        const response = await fetchAPI('/nvd/fetch', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                days: 7,
                severity: null  // Fetch CRITICAL and HIGH
            })
        });

        if (response.job_id) {
            // Poll for status
            pollNVDFetchStatus(response.job_id);
        }
    } catch (error) {
        showToast('error', 'NVD Error', error.message || 'Failed to fetch CVEs');
        btn.classList.remove('spinning');
    }
}

async function pollNVDFetchStatus(jobId) {
    const btn = document.getElementById('refresh-nvd');

    try {
        const status = await fetchAPI(`/nvd/fetch/${jobId}`);

        if (status.status === 'running') {
            showToast('info', 'Fetching CVEs', status.message);
            setTimeout(() => pollNVDFetchStatus(jobId), 3000);
        } else if (status.status === 'completed') {
            showToast('success', 'NVD Fetch Complete', `Fetched ${status.cves_fetched} CVEs`);
            btn.classList.remove('spinning');
            loadDashboard();
            checkOllamaStatus();
        } else {
            showToast('error', 'NVD Fetch Failed', status.error || 'Unknown error');
            btn.classList.remove('spinning');
        }
    } catch (error) {
        showToast('error', 'NVD Error', error.message);
        btn.classList.remove('spinning');
    }
}

async function fetchMITREData() {
    const btn = document.getElementById('refresh-mitre');
    btn.classList.add('spinning');

    showToast('info', 'Fetching MITRE Data', 'Connecting to MITRE ATT&CK...');

    try {
        const response = await fetchAPI('/mitre/fetch', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ force_refresh: true })
        });

        if (response.status === 'completed') {
            const stats = response.stats || {};
            showToast('success', 'MITRE Data Fetched',
                `${stats.tactics_count || 0} tactics, ${stats.techniques_count || 0} techniques`);

            // Reload MITRE page if on it
            if (state.currentPage === 'mitre') {
                loadMITREPage();
            }
        } else {
            showToast('error', 'MITRE Fetch Failed', response.message || 'Unknown error');
        }
    } catch (error) {
        showToast('error', 'MITRE Error', error.message || 'Failed to fetch MITRE data');
    } finally {
        btn.classList.remove('spinning');
    }
}

// ========================================
// Navigation
// ========================================

function initNavigation() {
    // Nav items click
    elements.navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const page = item.dataset.page;
            navigateTo(page);
        });
    });

    // View all links
    document.querySelectorAll('.view-all').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const page = link.dataset.page;
            navigateTo(page);
        });
    });

    // Mobile menu toggle
    elements.menuToggle.addEventListener('click', () => {
        elements.sidebar.classList.toggle('open');
    });

    // Global search
    elements.globalSearch.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            state.filters.search = e.target.value;
            navigateTo('vulnerabilities');
        }
    });

    // New scan button - navigate to scans page with projects
    document.getElementById('new-scan-btn').addEventListener('click', () => {
        navigateTo('scans');
    });
}

async function loadAvailableModels() {
    try {
        const modelsResponse = await fetchAPI('/models').catch(() => ({ models: [] }));
        const modelSelect = document.getElementById('scan-model');

        if (!modelSelect) return;

        const models = modelsResponse.models || [];
        const currentModel = modelsResponse.current || 'mistral';

        if (models.length > 0) {
            // Clear and repopulate with available models
            modelSelect.innerHTML = models.map(model => {
                const displayName = getModelDisplayName(model);
                const isDefault = model === currentModel || model.startsWith(currentModel);
                return `<option value="${model}" ${isDefault ? 'selected' : ''}>${displayName}</option>`;
            }).join('');
        }
    } catch (error) {
        console.error('Failed to load models:', error);
    }
}

function getModelDisplayName(model) {
    // Clean up model name for display
    const name = model.split(':')[0]; // Remove tag like :latest
    const displayNames = {
        'gpt-oss-20b': 'GPT-OSS-20B (Default)',
        'phi-4': 'Phi-4 (Fast)',
        'mistral-small': 'Mistral Small',
        'qwen-coder-32b': 'Qwen Coder 32B',
        'mistral': 'Mistral',
        'codellama': 'CodeLlama',
        'llama2': 'Llama 2',
        'llama3': 'Llama 3',
        'phi3': 'Phi-3',
        'deepseek-coder': 'DeepSeek Coder'
    };
    return displayNames[name] || model;
}

function navigateTo(page) {
    state.currentPage = page;

    // Update active nav item
    elements.navItems.forEach(item => {
        item.classList.toggle('active', item.dataset.page === page);
    });

    // Update page visibility
    elements.pages.forEach(p => {
        p.classList.toggle('active', p.id === `${page}-page`);
    });

    // Update title
    const titles = {
        'dashboard': 'Dashboard',
        'vulnerabilities': 'Vulnerabilities',
        'hosts': 'Affected Files',
        'scans': 'AI Scans',
        'reports': 'Security Reports',
        'mitre': 'MITRE ATT&CK Mapping'
    };
    elements.pageTitle.textContent = titles[page] || page;

    // Load page data
    switch (page) {
        case 'dashboard':
            loadDashboard();
            break;
        case 'vulnerabilities':
            loadVulnerabilities();
            break;
        case 'hosts':
            loadHosts();
            break;
        case 'scans':
            loadScans();
            break;
        case 'reports':
            loadReports();
            break;
        case 'mitre':
            loadMitre();
            break;
    }

    elements.sidebar.classList.remove('open');
}

// ========================================
// Dashboard
// ========================================

async function loadDashboard() {
    try {
        const stats = await fetchAPI('/dashboard/stats');
        state.stats = stats;
        renderDashboardStats(stats);
        renderSeverityBars(stats.severity_breakdown);
        await loadTopVulnerabilities();
        await loadRecentVulnerabilities();
    } catch (error) {
        console.error('Dashboard error:', error);
    }
}

function renderDashboardStats(stats) {
    // Risk score - ensure it's a number
    const riskScore = parseFloat(stats.risk_score) || 0;
    document.getElementById('risk-score').textContent = riskScore.toFixed(1);
    const circle = document.getElementById('risk-circle');
    circle.setAttribute('stroke-dasharray', `${Math.min(riskScore, 100)}, 100`);

    // Update circle color and risk level badge
    const riskLevel = stats.risk_level || (riskScore >= 80 ? 'CRITICAL' : riskScore >= 60 ? 'HIGH' : riskScore >= 40 ? 'MEDIUM' : riskScore >= 20 ? 'LOW' : 'MINIMAL');
    const riskLevelBadge = document.getElementById('risk-level-badge');
    riskLevelBadge.textContent = riskLevel;
    riskLevelBadge.className = 'risk-level-badge ' + riskLevel.toLowerCase();

    if (riskScore >= 80 || riskLevel === 'CRITICAL') {
        circle.style.stroke = 'var(--critical)';
    } else if (riskScore >= 60 || riskLevel === 'HIGH') {
        circle.style.stroke = 'var(--high)';
    } else if (riskScore >= 40 || riskLevel === 'MEDIUM') {
        circle.style.stroke = 'var(--medium)';
    } else {
        circle.style.stroke = 'var(--low)';
    }

    // Risk breakdown details - with fallback for old API responses
    const breakdown = stats.risk_breakdown || {};
    const hasBreakdown = Object.keys(breakdown).length > 0;

    if (hasBreakdown) {
        document.getElementById('cvss-contribution').textContent =
            parseFloat(breakdown.cvss_contribution || 0).toFixed(1) + ' pts';
        document.getElementById('business-contribution').textContent =
            parseFloat(breakdown.business_impact_contribution || 0).toFixed(1) + ' pts';
        document.getElementById('exploit-contribution').textContent =
            parseFloat(breakdown.exploitability_contribution || 0).toFixed(1) + ' pts';
        document.getElementById('asset-contribution').textContent =
            parseFloat(breakdown.asset_criticality_contribution || 0).toFixed(1) + ' pts';
        document.getElementById('cvss-max').textContent =
            parseFloat(breakdown.cvss_max || 0).toFixed(1) + '/10';
        document.getElementById('cvss-avg').textContent =
            parseFloat(breakdown.cvss_average || 0).toFixed(1) + '/10';
    } else {
        // Fallback: no breakdown available (restart server to enable)
        document.getElementById('cvss-contribution').textContent = 'N/A';
        document.getElementById('business-contribution').textContent = 'N/A';
        document.getElementById('exploit-contribution').textContent = 'N/A';
        document.getElementById('asset-contribution').textContent = 'N/A';
        document.getElementById('cvss-max').textContent = 'N/A';
        document.getElementById('cvss-avg').textContent = 'N/A';
    }

    // Severity counts
    const sevBreakdown = stats.severity_breakdown || {};
    document.getElementById('critical-count').textContent = sevBreakdown.critical || 0;
    document.getElementById('high-count').textContent = sevBreakdown.high || 0;
    document.getElementById('medium-count').textContent = sevBreakdown.medium || 0;
    document.getElementById('exploitable-count').textContent = stats.exploitable_count || 0;
    document.getElementById('hosts-count').textContent = stats.hosts_affected || 0;
}

function renderSeverityBars(breakdown) {
    const container = document.getElementById('severity-bars');
    const total = Object.values(breakdown).reduce((a, b) => a + b, 0) || 1;

    const severities = ['critical', 'high', 'medium', 'low'];

    container.innerHTML = severities.map(sev => {
        const count = breakdown[sev] || 0;
        const percentage = Math.round((count / total) * 100);
        return `
            <div class="severity-bar-item">
                <span class="severity-bar-label">${capitalize(sev)}</span>
                <div class="severity-bar-track">
                    <div class="severity-bar-fill ${sev}" style="width: ${percentage}%">
                        ${count > 0 ? count : ''}
                    </div>
                </div>
            </div>
        `;
    }).join('');
}

async function loadTopVulnerabilities() {
    const response = await fetchAPI('/vulnerabilities?sort_by=severity&sort_order=desc&page_size=5');
    const container = document.getElementById('top-vulns');

    if (response.items.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-shield-alt"></i>
                <p>No vulnerabilities found</p>
                <small>Upload code files and run an AI scan</small>
            </div>
        `;
        return;
    }

    container.innerHTML = response.items.map((vuln, index) => `
        <div class="top-vuln-item" onclick="showVulnDetail('${vuln.id}')">
            <div class="vuln-rank ${(vuln.severity || 'low').toLowerCase()}">${index + 1}</div>
            <div class="vuln-info">
                <div class="vuln-title">${vuln.title}</div>
                <div class="vuln-host">${vuln.affected_file || 'Unknown file'}</div>
            </div>
            <div class="vuln-cvss">${(vuln.cvss_score || 0).toFixed(1)}</div>
        </div>
    `).join('');
}

async function loadRecentVulnerabilities() {
    const response = await fetchAPI('/vulnerabilities?page_size=5');
    const tbody = document.getElementById('recent-vulns');

    if (response.items.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="6" class="text-center text-muted" style="padding: 3rem;">
                    <i class="fas fa-code" style="font-size: 2rem; margin-bottom: 1rem; display: block;"></i>
                    No vulnerabilities discovered yet.<br>
                    <small>Upload code files and run an AI scan to detect vulnerabilities.</small>
                </td>
            </tr>
        `;
        return;
    }

    tbody.innerHTML = response.items.map(vuln => {
        const sev = (vuln.severity || 'low').toLowerCase();
        return `
        <tr onclick="showVulnDetail('${vuln.id}')" style="cursor: pointer;">
            <td>
                <span class="severity-badge ${sev}">
                    <i class="fas fa-circle"></i>
                    ${capitalize(vuln.severity)}
                </span>
            </td>
            <td>
                <div>${vuln.title}</div>
                <small class="text-muted">${vuln.type || 'Unknown type'}</small>
            </td>
            <td class="font-mono">${vuln.affected_file || '-'}</td>
            <td>
                <span class="cvss-score ${sev}">${(vuln.cvss_score || 0).toFixed(1)}</span>
            </td>
            <td>
                <span class="exploit-badge ${vuln.exploit_available ? 'available' : 'not-available'}">
                    <i class="fas ${vuln.exploit_available ? 'fa-check' : 'fa-times'}"></i>
                    ${vuln.exploit_available ? 'Yes' : 'No'}
                </span>
            </td>
            <td>
                <span class="severity-badge ${vuln.patch_available ? 'low' : 'high'}">
                    ${vuln.patch_available ? 'Fix Available' : 'No Fix'}
                </span>
            </td>
        </tr>`;
    }).join('');
}

// ========================================
// Vulnerabilities Page
// ========================================

function initFilters() {
    // Severity filter chips
    document.getElementById('severity-filter').addEventListener('click', (e) => {
        if (e.target.classList.contains('chip')) {
            document.querySelectorAll('#severity-filter .chip').forEach(c => c.classList.remove('active'));
            e.target.classList.add('active');
            state.filters.severity = e.target.dataset.value;
            state.pagination.page = 1;
            loadVulnerabilities();
        }
    });

    // Exploit filter
    document.getElementById('exploit-filter').addEventListener('change', (e) => {
        state.filters.hasExploit = e.target.value === '' ? null : e.target.value === 'true';
        state.pagination.page = 1;
        loadVulnerabilities();
    });

    // Host/File filter
    document.getElementById('host-filter').addEventListener('change', (e) => {
        state.filters.file = e.target.value;
        state.pagination.page = 1;
        loadVulnerabilities();
    });

    // Table sorting
    document.querySelectorAll('.data-table th.sortable').forEach(th => {
        th.addEventListener('click', () => {
            const sortBy = th.dataset.sort;
            if (state.sortBy === sortBy) {
                state.sortOrder = state.sortOrder === 'desc' ? 'asc' : 'desc';
            } else {
                state.sortBy = sortBy;
                state.sortOrder = 'desc';
            }
            loadVulnerabilities();
        });
    });

    // Export button
    document.getElementById('export-vulns').addEventListener('click', exportVulnerabilities);
}

async function loadVulnerabilities() {
    try {
        const params = new URLSearchParams({
            page: state.pagination.page,
            page_size: state.pagination.pageSize,
            sort_by: state.sortBy,
            sort_order: state.sortOrder
        });

        if (state.filters.severity !== 'all') {
            params.append('severity', state.filters.severity);
        }
        if (state.filters.file) {
            params.append('file', state.filters.file);
        }
        if (state.filters.search) {
            params.append('search', state.filters.search);
        }

        const response = await fetchAPI(`/vulnerabilities?${params}`);
        state.vulnerabilities = response.items;
        state.pagination.total = response.total;

        renderVulnerabilitiesTable(response.items);
        renderPagination(response);
        updateFileFilter();
    } catch (error) {
        showToast('Error', 'Failed to load vulnerabilities', 'error');
        console.error('Vulnerabilities error:', error);
    }
}

function renderVulnerabilitiesTable(vulns) {
    const tbody = document.getElementById('vulns-table-body');

    if (vulns.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="8" class="text-center text-muted" style="padding: 3rem;">
                    <i class="fas fa-search" style="font-size: 2rem; margin-bottom: 1rem; display: block;"></i>
                    No vulnerabilities found.<br>
                    <small>Run an AI scan on your code to detect vulnerabilities.</small>
                </td>
            </tr>
        `;
        return;
    }

    const sevLower = (s) => (s || 'low').toLowerCase();
    tbody.innerHTML = vulns.map(vuln => `
        <tr>
            <td>
                <span class="severity-badge ${sevLower(vuln.severity)}">
                    <i class="fas fa-circle"></i>
                    ${capitalize(vuln.severity)}
                </span>
            </td>
            <td>
                <div style="max-width: 300px;">
                    <div style="font-weight: 500;">${vuln.title}</div>
                    <small class="text-muted">${truncate(vuln.description, 60)}</small>
                </div>
            </td>
            <td>
                <span class="font-mono" style="color: var(--accent-primary);">
                    ${vuln.type || '-'}
                </span>
            </td>
            <td>
                <span class="cvss-score ${sevLower(vuln.severity)}">${(vuln.cvss_score || 0).toFixed(1)}</span>
            </td>
            <td class="font-mono">${vuln.affected_file || '-'}</td>
            <td class="font-mono">${vuln.location || '-'}</td>
            <td>
                <span class="exploit-badge ${vuln.exploit_available ? 'available' : 'not-available'}">
                    <i class="fas ${vuln.exploit_available ? 'fa-crosshairs' : 'fa-times'}"></i>
                </span>
            </td>
            <td>
                <button class="action-btn" onclick="showVulnDetail('${vuln.id}')" title="View Details">
                    <i class="fas fa-eye"></i>
                </button>
            </td>
        </tr>
    `).join('');
}

function renderPagination(response) {
    const container = document.getElementById('vulns-pagination');
    const { page, total_pages } = response;

    if (total_pages <= 1) {
        container.innerHTML = '';
        return;
    }

    let buttons = [];

    buttons.push(`
        <button onclick="goToPage(${page - 1})" ${page === 1 ? 'disabled' : ''}>
            <i class="fas fa-chevron-left"></i>
        </button>
    `);

    const range = getPageRange(page, total_pages);
    range.forEach(p => {
        if (p === '...') {
            buttons.push('<span style="padding: 0 0.5rem;">...</span>');
        } else {
            buttons.push(`
                <button onclick="goToPage(${p})" class="${p === page ? 'active' : ''}">
                    ${p}
                </button>
            `);
        }
    });

    buttons.push(`
        <button onclick="goToPage(${page + 1})" ${page === total_pages ? 'disabled' : ''}>
            <i class="fas fa-chevron-right"></i>
        </button>
    `);

    container.innerHTML = buttons.join('');
}

function goToPage(page) {
    state.pagination.page = page;
    loadVulnerabilities();
}

async function updateFileFilter() {
    const select = document.getElementById('host-filter');
    const currentValue = select.value;

    try {
        const response = await fetchAPI('/hosts');
        const files = response.hosts;

        select.innerHTML = '<option value="">All Files</option>' +
            files.map(f => `<option value="${f.ip}">${f.ip}</option>`).join('');

        select.value = currentValue;
    } catch (error) {
        console.error('Failed to load files:', error);
    }
}

async function exportVulnerabilities() {
    try {
        const data = state.vulnerabilities;
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `vulnerabilities_${new Date().toISOString().split('T')[0]}.json`;
        a.click();
        URL.revokeObjectURL(url);
        showToast('Success', 'Vulnerabilities exported successfully', 'success');
    } catch (error) {
        showToast('Error', 'Failed to export vulnerabilities', 'error');
    }
}

// ========================================
// Vulnerability Detail Modal
// ========================================

async function showVulnDetail(id) {
    try {
        const vuln = await fetchAPI(`/vulnerabilities/${id}`);
        renderVulnDetail(vuln);
        openModal('vuln-modal');
    } catch (error) {
        showToast('Error', 'Failed to load vulnerability details', 'error');
    }
}

function renderVulnDetail(vuln) {
    document.getElementById('modal-title').textContent = 'Vulnerability Details';

    const enrichment = vuln.enrichment || {};
    const hasEnrichment = enrichment.cwes || enrichment.related_cves || enrichment.mitre_techniques;
    const sev = (vuln.severity || 'low').toLowerCase();

    const body = document.getElementById('modal-body');
    body.innerHTML = `
        <div class="vuln-detail-header">
            <div class="vuln-detail-title">
                <h3>${vuln.title}</h3>
                <span class="vuln-type-badge">${vuln.type || 'Unknown'}</span>
                ${hasEnrichment ? `<span class="enriched-badge" title="Enriched with CVE and MITRE data"><i class="fas fa-check-circle"></i> Enriched</span>` : ''}
            </div>
            <div class="vuln-detail-cvss">
                <div class="cvss-large" style="color: var(--${sev});">${(vuln.cvss_score || 0).toFixed(1)}</div>
                <span class="severity-badge ${sev}">
                    <i class="fas fa-circle"></i> ${capitalize(vuln.severity)}
                </span>
                ${enrichment.confidence ? `<div class="confidence-score">Confidence: ${Math.round(enrichment.confidence * 100)}%</div>` : ''}
            </div>
        </div>

        <div class="vuln-detail-section">
            <h4><i class="fas fa-info-circle"></i> Description</h4>
            <p>${vuln.description || 'No description available.'}</p>
        </div>

        <div class="vuln-detail-section">
            <h4><i class="fas fa-file-code"></i> Location</h4>
            <div class="detail-grid">
                <div class="detail-item">
                    <label>File</label>
                    <span class="font-mono">${vuln.affected_file || '-'}</span>
                </div>
                <div class="detail-item">
                    <label>Location</label>
                    <span>${vuln.location || '-'}</span>
                </div>
                <div class="detail-item">
                    <label>CWE</label>
                    <span>${vuln.cwe_id || (enrichment.cwes && enrichment.cwes.length > 0 ? enrichment.cwes.join(', ') : 'N/A')}</span>
                </div>
            </div>
        </div>

        ${enrichment.cwe_details && enrichment.cwe_details.length > 0 ? `
        <div class="vuln-detail-section">
            <h4><i class="fas fa-tag"></i> Associated CWEs (Semantic Match)</h4>
            <div class="cwe-details-list">
                ${enrichment.cwe_details.map(cwe => `
                    <div class="cwe-detail-item">
                        <div class="cwe-detail-header">
                            <a href="https://cwe.mitre.org/data/definitions/${cwe.id.replace('CWE-', '')}.html"
                               target="_blank" class="cwe-id-link">
                                ${cwe.id}
                            </a>
                            <span class="cwe-confidence ${cwe.confidence >= 0.8 ? 'high' : cwe.confidence >= 0.5 ? 'medium' : 'low'}">
                                ${Math.round(cwe.confidence * 100)}% match
                            </span>
                        </div>
                        <div class="cwe-name">${cwe.name || ''}</div>
                        ${cwe.match_reasons && cwe.match_reasons.length > 0 ? `
                            <div class="cwe-reasons">
                                ${cwe.match_reasons.map(r => `<span class="reason-tag">${r}</span>`).join('')}
                            </div>
                        ` : ''}
                    </div>
                `).join('')}
            </div>
        </div>
        ` : enrichment.cwes && enrichment.cwes.length > 0 ? `
        <div class="vuln-detail-section">
            <h4><i class="fas fa-tag"></i> Associated CWEs</h4>
            <div class="cwe-tags">
                ${enrichment.cwes.map(cwe => `
                    <a href="https://cwe.mitre.org/data/definitions/${cwe.replace('CWE-', '')}.html"
                       target="_blank" class="cwe-tag">
                        ${cwe}
                    </a>
                `).join('')}
            </div>
        </div>
        ` : ''}

        ${enrichment.related_cves && enrichment.related_cves.length > 0 ? `
        <div class="vuln-detail-section">
            <h4><i class="fas fa-database"></i> Related CVEs (Auto-Enriched)</h4>
            <div class="related-cves">
                ${enrichment.related_cves.map(cve => `
                    <div class="related-cve-item">
                        <div class="cve-header">
                            <a href="https://nvd.nist.gov/vuln/detail/${cve.id}" target="_blank" class="cve-id">${cve.id}</a>
                            <span class="cve-cvss severity-badge ${getSeverityClass(cve.cvss)}">${cve.cvss ? cve.cvss.toFixed(1) : 'N/A'}</span>
                        </div>
                        <div class="cve-title">${cve.title || 'No title'}</div>
                        ${cve.match_reason ? `<div class="cve-match-reason"><i class="fas fa-link"></i> ${cve.match_reason}</div>` : ''}
                    </div>
                `).join('')}
            </div>
        </div>
        ` : ''}

        ${vuln.vulnerable_code ? `
        <div class="vuln-detail-section">
            <h4><i class="fas fa-code"></i> Vulnerable Code</h4>
            <pre class="code-block">${escapeHtml(vuln.vulnerable_code)}</pre>
        </div>
        ` : ''}

        <div class="vuln-detail-section">
            <h4><i class="fas fa-wrench"></i> Remediation</h4>
            <p>${vuln.remediation || 'No remediation guidance available.'}</p>
        </div>

        ${vuln.fixed_code ? `
        <div class="vuln-detail-section">
            <h4><i class="fas fa-check-circle"></i> Fixed Code</h4>
            <pre class="code-block">${escapeHtml(vuln.fixed_code)}</pre>
        </div>
        ` : ''}

        ${(enrichment.mitre_techniques && enrichment.mitre_techniques.length > 0) || (enrichment.mitre_tactics && enrichment.mitre_tactics.length > 0) ? `
        <div class="vuln-detail-section">
            <h4><i class="fas fa-sitemap"></i> MITRE ATT&CK (Auto-Enriched)</h4>
            ${enrichment.mitre_tactics && enrichment.mitre_tactics.length > 0 ? `
            <div class="mitre-section">
                <label>Tactics</label>
                <div class="mitre-tags">
                    ${enrichment.mitre_tactics.map(t => `<span class="mitre-tag tactic">${t}</span>`).join('')}
                </div>
            </div>
            ` : ''}
            ${enrichment.mitre_techniques && enrichment.mitre_techniques.length > 0 ? `
            <div class="mitre-section">
                <label>Techniques</label>
                <div class="mitre-tags">
                    ${enrichment.mitre_techniques.map(t => `
                        <a href="${t.url || '#'}" target="_blank" class="mitre-tag technique">
                            ${t.id}: ${t.name || 'Unknown'}
                        </a>
                    `).join('')}
                </div>
            </div>
            ` : ''}
        </div>
        ` : (vuln.mitre_tactics && vuln.mitre_tactics.length > 0 ? `
        <div class="vuln-detail-section">
            <h4><i class="fas fa-sitemap"></i> MITRE ATT&CK</h4>
            <div class="mitre-tags">
                ${vuln.mitre_tactics.map(t => `<span class="mitre-tag">${t}</span>`).join('')}
            </div>
            ${vuln.mitre_techniques && vuln.mitre_techniques.length > 0 ? `
            <div class="mitre-tags mt-1">
                ${vuln.mitre_techniques.map(t => `<span class="mitre-tag" style="background: rgba(139, 92, 246, 0.15); color: #a78bfa;">${t}</span>`).join('')}
            </div>
            ` : ''}
        </div>
        ` : '')}
    `;
}

function getSeverityClass(cvss) {
    if (!cvss) return 'info';
    if (cvss >= 9.0) return 'critical';
    if (cvss >= 7.0) return 'high';
    if (cvss >= 4.0) return 'medium';
    return 'low';
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ========================================
// Hosts/Files Page
// ========================================

async function loadHosts() {
    try {
        const response = await fetchAPI('/hosts');
        renderHostsGrid(response.hosts);
    } catch (error) {
        showToast('Error', 'Failed to load files', 'error');
    }
}

function renderHostsGrid(hosts) {
    const container = document.getElementById('hosts-grid');

    if (hosts.length === 0) {
        container.innerHTML = `
            <div class="text-center text-muted" style="grid-column: 1 / -1; padding: 3rem;">
                <i class="fas fa-file-code" style="font-size: 3rem; margin-bottom: 1rem;"></i>
                <p>No files analyzed yet</p>
                <small>Upload code files and run an AI scan</small>
            </div>
        `;
        return;
    }

    container.innerHTML = hosts.map(host => `
        <div class="host-card" onclick="filterByFile('${host.ip}')">
            <div class="host-header">
                <div class="host-icon">
                    <i class="fas fa-file-code"></i>
                </div>
                <div class="host-info">
                    <h4>${host.ip}</h4>
                    <p>${host.vulnerabilities.length} vulnerabilities</p>
                </div>
            </div>
            <div class="host-stats">
                <div class="host-stat critical">
                    <span class="host-stat-value">${host.severity_counts.critical || 0}</span>
                    <span class="host-stat-label">Critical</span>
                </div>
                <div class="host-stat high">
                    <span class="host-stat-value">${host.severity_counts.high || 0}</span>
                    <span class="host-stat-label">High</span>
                </div>
                <div class="host-stat medium">
                    <span class="host-stat-value">${host.severity_counts.medium || 0}</span>
                    <span class="host-stat-label">Medium</span>
                </div>
            </div>
        </div>
    `).join('');
}

function filterByFile(filename) {
    state.filters.file = filename;
    document.getElementById('host-filter').value = filename;
    navigateTo('vulnerabilities');
}

// ========================================
// Scans Page & Upload
// ========================================

function initUpload() {
    // Legacy upload area removed - now using project-based uploads
    // This function is kept for compatibility but does nothing
}

function handleFileSelect(e) {
    const files = e.target.files;
    uploadFiles(files);
}

async function uploadFiles(files) {
    for (const file of files) {
        try {
            const formData = new FormData();
            formData.append('file', file);

            const response = await fetch(`${API_BASE}/upload`, {
                method: 'POST',
                body: formData
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.detail || 'Upload failed');
            }

            const result = await response.json();
            showToast('Uploaded', `${file.name} ready for scanning`, 'success');
            loadScans();
        } catch (error) {
            showToast('Error', `Failed to upload ${file.name}: ${error.message}`, 'error');
        }
    }
}

// ========================================
// Project Management
// ========================================

function initProjectManager() {
    // New project button
    const newProjectBtn = document.getElementById('new-project-btn');
    if (newProjectBtn) {
        newProjectBtn.addEventListener('click', () => {
            document.getElementById('create-project-modal').classList.add('active');
            document.getElementById('project-name-input').focus();
        });
    }

    // Modal close buttons
    const closeModalBtn = document.getElementById('close-project-modal');
    const cancelProjectBtn = document.getElementById('cancel-project-btn');
    if (closeModalBtn) {
        closeModalBtn.addEventListener('click', closeProjectModal);
    }
    if (cancelProjectBtn) {
        cancelProjectBtn.addEventListener('click', closeProjectModal);
    }

    // Create project button
    const confirmProjectBtn = document.getElementById('confirm-project-btn');
    if (confirmProjectBtn) {
        confirmProjectBtn.addEventListener('click', createProject);
    }

    // Upload to project
    const uploadToProjectBtn = document.getElementById('upload-to-project-btn');
    const projectFileInput = document.getElementById('project-file-input');
    if (uploadToProjectBtn && projectFileInput) {
        uploadToProjectBtn.addEventListener('click', () => projectFileInput.click());
        projectFileInput.addEventListener('change', handleProjectFileUpload);
    }

    // Select all files checkbox
    const selectAllCheckbox = document.getElementById('select-all-files');
    if (selectAllCheckbox) {
        selectAllCheckbox.addEventListener('change', toggleSelectAllFiles);
    }

    // Scan buttons
    const scanSelectedBtn = document.getElementById('scan-selected-btn');
    const scanAllBtn = document.getElementById('scan-all-btn');
    if (scanSelectedBtn) {
        scanSelectedBtn.addEventListener('click', () => startProjectScan(false));
    }
    if (scanAllBtn) {
        scanAllBtn.addEventListener('click', () => startProjectScan(true));
    }

    // Enter key in project name input
    const projectNameInput = document.getElementById('project-name-input');
    if (projectNameInput) {
        projectNameInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') createProject();
        });
    }
}

function closeProjectModal() {
    document.getElementById('create-project-modal').classList.remove('active');
    document.getElementById('project-name-input').value = '';
    document.getElementById('project-desc-input').value = '';
}

async function loadProjects() {
    try {
        const response = await fetchAPI('/projects');
        state.projects = response.projects || [];
        renderProjectList();
    } catch (error) {
        console.error('Failed to load projects:', error);
        state.projects = [];
        renderProjectList();
    }
}

function renderProjectList() {
    const container = document.getElementById('project-list');
    if (!container) return;

    if (state.projects.length === 0) {
        container.innerHTML = `
            <div class="no-projects">
                <i class="fas fa-folder-plus"></i>
                <p>No projects yet</p>
                <small>Create a project to organize your files</small>
            </div>
        `;
        return;
    }

    container.innerHTML = state.projects.map(project => `
        <div class="project-card ${state.selectedProject?.id === project.id ? 'selected' : ''}"
             data-project-id="${project.id}"
             onclick="selectProject('${project.id}')">
            <div class="project-card-header">
                <span class="project-card-name">${escapeHtml(project.name)}</span>
                <button class="project-card-delete" onclick="event.stopPropagation(); deleteProject('${project.id}')" title="Delete project">
                    <i class="fas fa-trash"></i>
                </button>
            </div>
            ${project.description ? `<div class="project-card-desc">${escapeHtml(project.description)}</div>` : ''}
            <div class="project-card-stats">
                <span><i class="fas fa-file"></i> ${project.file_count} files</span>
                <span><i class="fas fa-hdd"></i> ${formatBytes(project.total_size)}</span>
                ${project.vulnerability_count > 0 ? `<span><i class="fas fa-bug"></i> ${project.vulnerability_count} vulns</span>` : ''}
            </div>
        </div>
    `).join('');
}

async function createProject() {
    const nameInput = document.getElementById('project-name-input');
    const descInput = document.getElementById('project-desc-input');

    const name = nameInput.value.trim();
    if (!name) {
        showToast('Error', 'Project name is required', 'error');
        nameInput.focus();
        return;
    }

    try {
        const response = await fetchAPI('/projects', {
            method: 'POST',
            body: JSON.stringify({
                name: name,
                description: descInput.value.trim()
            })
        });

        showToast('Success', `Project "${name}" created`, 'success');
        closeProjectModal();
        await loadProjects();

        // Auto-select the new project
        selectProject(response.project.id);
    } catch (error) {
        showToast('Error', 'Failed to create project: ' + error.message, 'error');
    }
}

async function deleteProject(projectId) {
    if (!confirm('Delete this project and all its files?')) return;

    try {
        await fetchAPI(`/projects/${projectId}`, { method: 'DELETE' });
        showToast('Deleted', 'Project deleted', 'success');

        // Clear selection if this was selected
        if (state.selectedProject?.id === projectId) {
            state.selectedProject = null;
            state.projectFiles = [];
            state.selectedFiles.clear();
            document.getElementById('project-files-section').classList.add('hidden');
        }

        await loadProjects();
    } catch (error) {
        showToast('Error', 'Failed to delete project: ' + error.message, 'error');
    }
}

async function selectProject(projectId) {
    try {
        const response = await fetchAPI(`/projects/${projectId}`);
        state.selectedProject = response;
        state.projectFiles = response.files || [];
        state.selectedFiles.clear();

        // Update UI
        renderProjectList();
        renderProjectFiles();

        // Show project files section
        document.getElementById('project-files-section').classList.remove('hidden');
        document.getElementById('selected-project-name').textContent = response.name;
        document.getElementById('project-file-count').textContent = `${response.file_count} files`;

        // Update buttons
        updateScanButtons();
    } catch (error) {
        showToast('Error', 'Failed to load project: ' + error.message, 'error');
    }
}

function renderProjectFiles() {
    const container = document.getElementById('project-file-list');
    if (!container) return;

    if (state.projectFiles.length === 0) {
        container.innerHTML = `
            <div class="file-list-empty">
                <i class="fas fa-file-upload"></i>
                <p>No files in this project</p>
                <small>Upload files to start scanning</small>
            </div>
        `;
        return;
    }

    container.innerHTML = state.projectFiles.map(file => {
        const ext = file.extension?.replace('.', '') || '';
        const isSelected = state.selectedFiles.has(file.id);
        return `
            <div class="file-list-item ${isSelected ? 'selected' : ''}" data-file-id="${file.id}">
                <input type="checkbox" ${isSelected ? 'checked' : ''}
                       onchange="toggleFileSelection('${file.id}')">
                <i class="fas fa-file-code file-icon ${ext}"></i>
                <div class="file-name">
                    ${escapeHtml(file.name)}
                    ${file.path !== file.name ? `<div class="file-path">${escapeHtml(file.path)}</div>` : ''}
                </div>
                <span class="file-size">${formatBytes(file.size)}</span>
                <button class="file-delete" onclick="deleteProjectFile('${file.id}')" title="Delete file">
                    <i class="fas fa-times"></i>
                </button>
            </div>
        `;
    }).join('');

    updateSelectedFilesCount();
}

function toggleFileSelection(fileId) {
    if (state.selectedFiles.has(fileId)) {
        state.selectedFiles.delete(fileId);
    } else {
        state.selectedFiles.add(fileId);
    }

    // Update UI
    const item = document.querySelector(`[data-file-id="${fileId}"]`);
    if (item) {
        item.classList.toggle('selected', state.selectedFiles.has(fileId));
        item.querySelector('input[type="checkbox"]').checked = state.selectedFiles.has(fileId);
    }

    updateSelectedFilesCount();
    updateScanButtons();
}

function toggleSelectAllFiles() {
    const selectAll = document.getElementById('select-all-files');
    const shouldSelect = selectAll.checked;

    state.selectedFiles.clear();
    if (shouldSelect) {
        state.projectFiles.forEach(file => state.selectedFiles.add(file.id));
    }

    renderProjectFiles();
    updateScanButtons();
}

function updateSelectedFilesCount() {
    const countEl = document.getElementById('selected-files-count');
    if (countEl) {
        countEl.textContent = `${state.selectedFiles.size} selected`;
    }

    // Update select all checkbox state
    const selectAll = document.getElementById('select-all-files');
    if (selectAll && state.projectFiles.length > 0) {
        selectAll.checked = state.selectedFiles.size === state.projectFiles.length;
        selectAll.indeterminate = state.selectedFiles.size > 0 && state.selectedFiles.size < state.projectFiles.length;
    }
}

function updateScanButtons() {
    const scanSelectedBtn = document.getElementById('scan-selected-btn');
    if (scanSelectedBtn) {
        scanSelectedBtn.disabled = state.selectedFiles.size === 0;
    }
}

async function handleProjectFileUpload(event) {
    const files = event.target.files;
    if (!files.length || !state.selectedProject) return;

    const formData = new FormData();
    for (const file of files) {
        formData.append('files', file);
    }

    try {
        const response = await fetch(`${API_BASE}/projects/${state.selectedProject.id}/upload/multiple`, {
            method: 'POST',
            body: formData
        });

        if (!response.ok) throw new Error('Upload failed');

        const result = await response.json();
        showToast('Uploaded', `${result.count} files uploaded`, 'success');

        // Refresh project files
        await selectProject(state.selectedProject.id);
    } catch (error) {
        showToast('Error', 'Failed to upload files: ' + error.message, 'error');
    }

    // Reset file input
    event.target.value = '';
}

async function deleteProjectFile(fileId) {
    if (!state.selectedProject) return;

    try {
        await fetchAPI(`/projects/${state.selectedProject.id}/files/${fileId}`, { method: 'DELETE' });
        showToast('Deleted', 'File deleted', 'success');

        // Refresh project files
        await selectProject(state.selectedProject.id);
    } catch (error) {
        showToast('Error', 'Failed to delete file: ' + error.message, 'error');
    }
}

async function startProjectScan(scanAll = true) {
    if (!state.selectedProject) return;

    const progress = document.getElementById('analysis-progress');
    const progressFill = document.getElementById('progress-fill');
    const statusEl = document.getElementById('analysis-status');
    const messageEl = document.getElementById('analysis-message');

    try {
        const fileIds = scanAll ? [] : Array.from(state.selectedFiles);
        const model = document.getElementById('scan-model')?.value || 'mistral';

        const response = await fetchAPI('/scan', {
            method: 'POST',
            body: JSON.stringify({
                project_id: state.selectedProject.id,
                file_ids: fileIds,
                model: model
            })
        });

        progress.classList.remove('hidden');
        state.currentScanJob = response.job_id;

        // Poll for status
        const pollStatus = async () => {
            try {
                const status = await fetchAPI(`/scan/${response.job_id}`);

                progressFill.style.width = `${status.progress}%`;
                statusEl.textContent = `${status.progress}%`;
                messageEl.textContent = status.message;

                if (status.status === 'completed') {
                    showToast('Scan Complete', `Found ${status.vulnerabilities_found} vulnerabilities`, 'success');
                    loadDashboard();
                    loadScans();
                    // Refresh project to update vuln count
                    if (state.selectedProject) {
                        selectProject(state.selectedProject.id);
                    }
                    setTimeout(() => progress.classList.add('hidden'), 2000);
                    state.currentScanJob = null;
                } else if (status.status === 'failed') {
                    showToast('Scan Failed', status.error || 'Unknown error', 'error');
                    progress.classList.add('hidden');
                    state.currentScanJob = null;
                } else {
                    setTimeout(pollStatus, 1000);
                }
            } catch (error) {
                console.error('Poll error:', error);
                setTimeout(pollStatus, 2000);
            }
        };

        pollStatus();
    } catch (error) {
        showToast('Error', 'Failed to start scan: ' + error.message, 'error');
    }
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

async function loadScans() {
    try {
        // Load projects, scans, and models in parallel
        const [projectsResponse, scansResponse] = await Promise.all([
            fetchAPI('/projects'),
            fetchAPI('/scans')
        ]);

        state.projects = projectsResponse.projects || [];
        renderProjectList();
        renderScansTable(scansResponse.scans);

        // Load available AI models
        loadAvailableModels();
    } catch (error) {
        console.error('Failed to load scans:', error);
    }
}

function renderScansTable(scans) {
    const tbody = document.getElementById('scans-table-body');

    if (scans.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="5" class="text-center text-muted" style="padding: 2rem;">
                    <i class="fas fa-history" style="font-size: 2rem; margin-bottom: 1rem; display: block;"></i>
                    No scans performed yet<br>
                    <small>Create a project, upload files, and start a scan</small>
                </td>
            </tr>
        `;
        return;
    }

    // Show completed scans with source info
    const rows = scans.map(scan => {
        // Determine source display
        let sourceDisplay = 'Legacy uploads';
        let sourceIcon = 'fa-folder';
        if (scan.project_id) {
            const project = state.projects.find(p => p.id === scan.project_id);
            sourceDisplay = project ? project.name : scan.project_id;
            sourceIcon = 'fa-project-diagram';
        } else if (scan.source) {
            sourceDisplay = scan.source;
        }

        return `
            <tr>
                <td>
                    <i class="fas fa-check-circle" style="margin-right: 0.5rem; color: var(--success);"></i>
                    <span class="font-mono">${scan.id}</span>
                </td>
                <td>
                    <i class="fas ${sourceIcon}" style="margin-right: 0.5rem; color: var(--accent-primary);"></i>
                    ${escapeHtml(sourceDisplay)}
                </td>
                <td>${scan.files_scanned || 0} files</td>
                <td>
                    <span style="color: var(--${scan.vulnerabilities_found > 0 ? 'warning' : 'success'});">
                        ${scan.vulnerabilities_found || 0}
                    </span>
                </td>
                <td>${formatDate(scan.scanned_at)}</td>
            </tr>
        `;
    }).join('');

    tbody.innerHTML = rows;
}

async function startAIScan() {
    const progress = document.getElementById('analysis-progress');
    const progressFill = document.getElementById('progress-fill');
    const statusEl = document.getElementById('analysis-status');
    const messageEl = document.getElementById('analysis-message');

    try {
        const model = document.getElementById('scan-model').value;

        const response = await fetchAPI('/scan', {
            method: 'POST',
            body: JSON.stringify({
                file_ids: [],  // Scan all uploaded files
                model: model
            })
        });

        closeModal('scan-modal');
        progress.classList.remove('hidden');

        state.currentScanJob = response.job_id;

        // Poll for status
        const pollStatus = async () => {
            try {
                const status = await fetchAPI(`/scan/${response.job_id}`);

                progressFill.style.width = `${status.progress}%`;
                statusEl.textContent = `${status.progress}%`;
                messageEl.textContent = status.message;

                if (status.status === 'completed') {
                    showToast('Scan Complete', `Found ${status.vulnerabilities_found} vulnerabilities`, 'success');
                    loadDashboard();
                    checkOllamaStatus();
                    setTimeout(() => progress.classList.add('hidden'), 2000);
                    state.currentScanJob = null;
                } else if (status.status === 'failed') {
                    showToast('Scan Failed', status.error || 'Unknown error', 'error');
                    progress.classList.add('hidden');
                    state.currentScanJob = null;
                } else {
                    setTimeout(pollStatus, 1000);
                }
            } catch (error) {
                console.error('Poll error:', error);
                setTimeout(pollStatus, 2000);
            }
        };

        pollStatus();

    } catch (error) {
        showToast('Error', 'Failed to start AI scan', 'error');
    }
}

// ========================================
// Reports Page
// ========================================

function initReportGenerator() {
    // Report type selection
    document.querySelectorAll('.report-type-card').forEach(card => {
        card.addEventListener('click', () => {
            document.querySelectorAll('.report-type-card').forEach(c => c.classList.remove('selected'));
            card.classList.add('selected');
            state.selectedReportType = card.dataset.type;
        });
    });

    // Generate button
    document.getElementById('generate-report-btn').addEventListener('click', generateReport);
}

async function loadReports() {
    try {
        const response = await fetchAPI('/reports');
        renderReportsTable(response.reports);
    } catch (error) {
        console.error('Failed to load reports:', error);
    }
}

function renderReportsTable(reports) {
    const tbody = document.getElementById('reports-table-body');

    if (reports.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="5" class="text-center text-muted" style="padding: 2rem;">
                    <i class="fas fa-file-alt" style="font-size: 2rem; margin-bottom: 1rem; display: block;"></i>
                    No reports generated yet<br>
                    <small>Run a scan first, then generate reports</small>
                </td>
            </tr>
        `;
        return;
    }

    tbody.innerHTML = reports.map(report => `
        <tr>
            <td>
                <i class="fas fa-file-alt" style="margin-right: 0.5rem; color: var(--accent-primary);"></i>
                ${report.filename}
            </td>
            <td>
                <span class="severity-badge ${report.type === 'executive' ? 'info' : 'medium'}">
                    ${capitalize(report.type)}
                </span>
            </td>
            <td>${formatDate(report.generated_at)}</td>
            <td class="font-mono">${report.size ? formatBytes(report.size) : '-'}</td>
            <td>
                <a href="${API_BASE}/reports/${report.filename}" class="action-btn" title="Download" download>
                    <i class="fas fa-download"></i>
                </a>
            </td>
        </tr>
    `).join('');
}

async function generateReport() {
    const org = document.getElementById('org-name').value || 'Organization';

    try {
        showToast('Generating', 'AI is generating reports...', 'info');

        const response = await fetchAPI('/reports/generate', {
            method: 'POST',
            body: JSON.stringify({
                organization: org,
                report_type: state.selectedReportType
            })
        });

        showToast('Success', `Generated ${response.reports.length} report(s)`, 'success');
        loadReports();
    } catch (error) {
        if (error.message.includes('400')) {
            showToast('No Data', 'Run a scan first to find vulnerabilities', 'warning');
        } else {
            showToast('Error', 'Failed to generate reports', 'error');
        }
    }
}

// ========================================
// MITRE ATT&CK Page
// ========================================

// MITRE data cache
const mitreCache = {
    tactics: [],
    techniques: [],
    groups: [],
    software: [],
    mitigations: [],
    vulnMapping: {}
};

async function loadMitre() {
    await loadMITREPage();
}

async function loadMITREPage() {
    initMitreTabs();

    try {
        // Load tactics first (includes vulnerability mapping)
        const tacticsResponse = await fetchAPI('/mitre/tactics');
        mitreCache.vulnMapping = tacticsResponse.vulnerability_mapping || { tactics: {} };
        mitreCache.tactics = tacticsResponse.all_tactics || [];

        // Update tactics count
        document.getElementById('tactics-count').textContent = mitreCache.tactics.length;

        // Render tactics grid
        renderMitreGrid(mitreCache.vulnMapping.tactics, mitreCache.tactics);

        // Load other data in parallel
        loadMitreDataInBackground();

    } catch (error) {
        showToast('error', 'MITRE Error', 'Failed to load MITRE data');
    }
}

async function loadMitreDataInBackground() {
    // Load techniques, groups, software, mitigations in parallel
    const [techniquesRes, groupsRes, softwareRes, mitigationsRes] = await Promise.all([
        fetchAPI('/mitre/techniques').catch(() => ({ techniques: [] })),
        fetchAPI('/mitre/groups').catch(() => ({ groups: [] })),
        fetchAPI('/mitre/software').catch(() => ({ software: [] })),
        fetchAPI('/mitre/mitigations').catch(() => ({ mitigations: [] }))
    ]);

    mitreCache.techniques = techniquesRes.techniques || [];
    mitreCache.groups = groupsRes.groups || [];
    mitreCache.software = softwareRes.software || [];
    mitreCache.mitigations = mitigationsRes.mitigations || [];

    // Update counts
    document.getElementById('techniques-count').textContent = mitreCache.techniques.length;
    document.getElementById('groups-count').textContent = mitreCache.groups.length;
    document.getElementById('software-count').textContent = mitreCache.software.length;
    document.getElementById('mitigations-count').textContent = mitreCache.mitigations.length;
}

function initMitreTabs() {
    const tabs = document.querySelectorAll('.mitre-tab');
    const panels = document.querySelectorAll('.mitre-panel');

    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            const targetTab = tab.dataset.tab;

            // Update active tab
            tabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');

            // Update active panel
            panels.forEach(p => p.classList.remove('active'));
            document.getElementById(`${targetTab}-panel`).classList.add('active');

            // Load content for the tab
            switch (targetTab) {
                case 'tactics':
                    renderMitreGrid(mitreCache.vulnMapping.tactics, mitreCache.tactics);
                    break;
                case 'techniques':
                    renderTechniquesList(mitreCache.techniques);
                    break;
                case 'groups':
                    renderGroupsGrid(mitreCache.groups);
                    break;
                case 'software':
                    renderSoftwareGrid(mitreCache.software);
                    break;
                case 'mitigations':
                    renderMitigationsList(mitreCache.mitigations);
                    break;
            }
        });
    });

    // MITRE search
    const searchInput = document.getElementById('mitre-search');
    if (searchInput) {
        searchInput.addEventListener('input', debounce((e) => {
            searchMitreData(e.target.value);
        }, 300));
    }
}

function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

async function searchMitreData(query) {
    if (query.length < 2) {
        // Reset to show all data for current tab
        const activeTab = document.querySelector('.mitre-tab.active').dataset.tab;
        switch (activeTab) {
            case 'tactics':
                renderMitreGrid(mitreCache.vulnMapping.tactics, mitreCache.tactics);
                break;
            case 'techniques':
                renderTechniquesList(mitreCache.techniques);
                break;
            case 'groups':
                renderGroupsGrid(mitreCache.groups);
                break;
            case 'software':
                renderSoftwareGrid(mitreCache.software);
                break;
            case 'mitigations':
                renderMitigationsList(mitreCache.mitigations);
                break;
        }
        return;
    }

    try {
        const results = await fetchAPI(`/mitre/search?query=${encodeURIComponent(query)}`);

        // Update the active panel with search results
        const activeTab = document.querySelector('.mitre-tab.active').dataset.tab;

        switch (activeTab) {
            case 'tactics':
                renderMitreGrid({}, results.results.tactics || []);
                break;
            case 'techniques':
                renderTechniquesList(results.results.techniques || []);
                break;
            case 'groups':
                renderGroupsGrid(results.results.groups || []);
                break;
            case 'software':
                renderSoftwareGrid(results.results.software || []);
                break;
            case 'mitigations':
                renderMitigationsList(results.results.mitigations || []);
                break;
        }
    } catch (error) {
        console.error('MITRE search failed:', error);
    }
}

function renderMitreGrid(vulnTactics, allTactics) {
    const container = document.getElementById('mitre-grid');

    const tacticIcons = {
        'reconnaissance': 'fa-binoculars',
        'resource-development': 'fa-tools',
        'initial-access': 'fa-door-open',
        'execution': 'fa-play',
        'persistence': 'fa-anchor',
        'privilege-escalation': 'fa-arrow-up',
        'defense-evasion': 'fa-eye-slash',
        'credential-access': 'fa-key',
        'discovery': 'fa-search',
        'lateral-movement': 'fa-arrows-alt-h',
        'collection': 'fa-folder-open',
        'command-and-control': 'fa-satellite-dish',
        'exfiltration': 'fa-upload',
        'impact': 'fa-bolt'
    };

    // Check if we have MITRE data
    if (allTactics.length === 0 && Object.keys(vulnTactics).length === 0) {
        container.innerHTML = `
            <div class="text-center text-muted" style="grid-column: 1 / -1; padding: 3rem;">
                <i class="fas fa-sitemap" style="font-size: 3rem; margin-bottom: 1rem;"></i>
                <p>No MITRE ATT&CK data loaded</p>
                <small>Click the refresh button in the sidebar to fetch MITRE ATT&CK data</small>
            </div>
        `;
        return;
    }

    // Render all tactics, highlighting those with vulnerabilities
    let html = '';

    if (allTactics.length > 0) {
        // Show full MITRE ATT&CK matrix
        html = allTactics.map(tactic => {
            const tacticName = tactic.name;
            const shortName = tactic.short_name || tacticName.toLowerCase().replace(/ /g, '-');
            const vulnData = vulnTactics[tacticName] || { count: 0, vulnerabilities: [] };
            const hasVulns = vulnData.count > 0;

            return `
                <div class="mitre-card ${hasVulns ? 'has-vulns' : ''}">
                    <div class="mitre-tactic">
                        <div class="mitre-tactic-icon">
                            <i class="fas ${tacticIcons[shortName] || 'fa-shield-alt'}"></i>
                        </div>
                        <div>
                            <div class="mitre-tactic-name">${tacticName}</div>
                            <div class="mitre-tactic-id">${tactic.id}</div>
                            ${hasVulns ? `<div class="mitre-count">${vulnData.count} vulnerabilities</div>` : ''}
                        </div>
                    </div>
                    ${hasVulns ? `
                        <div class="mitre-vulns">
                            ${vulnData.vulnerabilities.slice(0, 5).map(v => `
                                <span class="mitre-vuln-badge clickable" onclick="event.stopPropagation(); showVulnDetail('${v}')" title="View vulnerability details">${v}</span>
                            `).join('')}
                            ${vulnData.vulnerabilities.length > 5 ? `
                                <span class="mitre-vuln-badge more">+${vulnData.vulnerabilities.length - 5}</span>
                            ` : ''}
                        </div>
                    ` : `
                        <div class="mitre-desc">
                            <small class="text-muted">${(tactic.description || '').substring(0, 100)}...</small>
                        </div>
                    `}
                </div>
            `;
        }).join('');
    } else {
        // Fallback: only show vulnerability mappings
        const entries = Object.entries(vulnTactics);
        html = entries.map(([tactic, data]) => `
            <div class="mitre-card has-vulns">
                <div class="mitre-tactic">
                    <div class="mitre-tactic-icon">
                        <i class="fas ${tacticIcons[tactic.toLowerCase().replace(/ /g, '-')] || 'fa-shield-alt'}"></i>
                    </div>
                    <div>
                        <div class="mitre-tactic-name">${tactic}</div>
                        <div class="mitre-count">${data.count} vulnerabilities</div>
                    </div>
                </div>
                <div class="mitre-vulns">
                    ${data.vulnerabilities.slice(0, 5).map(v => `
                        <span class="mitre-vuln-badge clickable" onclick="event.stopPropagation(); showVulnDetail('${v}')" title="View vulnerability details">${v}</span>
                    `).join('')}
                    ${data.vulnerabilities.length > 5 ? `
                        <span class="mitre-vuln-badge more">+${data.vulnerabilities.length - 5}</span>
                    ` : ''}
                </div>
            </div>
        `).join('');
    }

    container.innerHTML = html;
}

function renderTechniquesList(techniques) {
    const container = document.getElementById('techniques-list');

    if (!techniques || techniques.length === 0) {
        container.innerHTML = `
            <div class="mitre-empty">
                <i class="fas fa-cogs"></i>
                <p>No techniques loaded</p>
                <small>Click the MITRE refresh button to fetch data</small>
            </div>
        `;
        return;
    }

    // Only show first 100 techniques for performance
    const displayTechniques = techniques.slice(0, 100);

    container.innerHTML = displayTechniques.map(tech => `
        <div class="technique-item" onclick="window.open('${tech.url || '#'}', '_blank')">
            <div class="technique-header">
                <span class="technique-id">${tech.id}</span>
                ${tech.is_subtechnique ? '<span class="tactic-badge">Sub-technique</span>' : ''}
            </div>
            <div class="technique-name">${tech.name}</div>
            ${tech.tactics && tech.tactics.length > 0 ? `
                <div class="technique-tactics">
                    ${tech.tactics.map(t => `<span class="tactic-badge">${t}</span>`).join('')}
                </div>
            ` : ''}
            ${tech.platforms && tech.platforms.length > 0 ? `
                <div class="technique-platforms">
                    ${tech.platforms.slice(0, 5).map(p => `<span class="platform-badge">${p}</span>`).join('')}
                </div>
            ` : ''}
        </div>
    `).join('');

    if (techniques.length > 100) {
        container.innerHTML += `
            <div class="text-center text-muted" style="padding: 1rem;">
                <small>Showing 100 of ${techniques.length} techniques. Use search to find specific ones.</small>
            </div>
        `;
    }
}

function renderGroupsGrid(groups) {
    const container = document.getElementById('groups-grid');

    if (!groups || groups.length === 0) {
        container.innerHTML = `
            <div class="mitre-empty" style="grid-column: 1 / -1;">
                <i class="fas fa-users-cog"></i>
                <p>No threat groups loaded</p>
                <small>Click the MITRE refresh button to fetch data</small>
            </div>
        `;
        return;
    }

    container.innerHTML = groups.map(group => `
        <div class="group-card" onclick="window.open('${group.url || '#'}', '_blank')">
            <div class="group-header">
                <div class="group-icon">
                    <i class="fas fa-user-secret"></i>
                </div>
                <div>
                    <div class="group-name">${group.name}</div>
                    <div class="group-id">${group.id}</div>
                </div>
            </div>
            ${group.aliases && group.aliases.length > 1 ? `
                <div class="group-aliases">
                    ${group.aliases.slice(1, 6).map(a => `<span class="alias-badge">${a}</span>`).join('')}
                    ${group.aliases.length > 6 ? `<span class="alias-badge">+${group.aliases.length - 6}</span>` : ''}
                </div>
            ` : ''}
            ${group.description ? `
                <div class="group-desc">${group.description.substring(0, 150)}${group.description.length > 150 ? '...' : ''}</div>
            ` : ''}
        </div>
    `).join('');
}

function renderSoftwareGrid(software) {
    const container = document.getElementById('software-grid');

    if (!software || software.length === 0) {
        container.innerHTML = `
            <div class="mitre-empty" style="grid-column: 1 / -1;">
                <i class="fas fa-virus"></i>
                <p>No malware/tools loaded</p>
                <small>Click the MITRE refresh button to fetch data</small>
            </div>
        `;
        return;
    }

    container.innerHTML = software.map(sw => {
        const isMalware = sw.type === 'malware';
        return `
            <div class="software-card ${isMalware ? 'malware' : 'tool'}" onclick="window.open('${sw.url || '#'}', '_blank')">
                <div class="software-header">
                    <div class="software-icon">
                        <i class="fas ${isMalware ? 'fa-virus' : 'fa-wrench'}"></i>
                    </div>
                    <div>
                        <div class="software-name">${sw.name}</div>
                        <div class="software-id">${sw.id}</div>
                    </div>
                    <span class="software-type-badge ${isMalware ? 'malware' : 'tool'}">${sw.type}</span>
                </div>
                ${sw.platforms && sw.platforms.length > 0 ? `
                    <div class="technique-platforms">
                        ${sw.platforms.slice(0, 4).map(p => `<span class="platform-badge">${p}</span>`).join('')}
                    </div>
                ` : ''}
                ${sw.description ? `
                    <div class="group-desc">${sw.description.substring(0, 100)}${sw.description.length > 100 ? '...' : ''}</div>
                ` : ''}
            </div>
        `;
    }).join('');
}

function renderMitigationsList(mitigations) {
    const container = document.getElementById('mitigations-list');

    if (!mitigations || mitigations.length === 0) {
        container.innerHTML = `
            <div class="mitre-empty">
                <i class="fas fa-shield-alt"></i>
                <p>No mitigations loaded</p>
                <small>Click the MITRE refresh button to fetch data</small>
            </div>
        `;
        return;
    }

    container.innerHTML = mitigations.map(mit => `
        <div class="mitigation-item" onclick="window.open('${mit.url || '#'}', '_blank')">
            <div class="mitigation-header">
                <span class="mitigation-id">${mit.id}</span>
                <span class="mitigation-name">${mit.name}</span>
            </div>
            ${mit.description ? `
                <div class="mitigation-desc">${mit.description.substring(0, 200)}${mit.description.length > 200 ? '...' : ''}</div>
            ` : ''}
        </div>
    `).join('');
}

// ========================================
// Modal Management
// ========================================

function initModals() {
    // Close buttons
    document.querySelectorAll('.modal-close').forEach(btn => {
        btn.addEventListener('click', () => {
            const modal = btn.closest('.modal');
            modal.classList.remove('active');
        });
    });

    // Overlay click
    document.querySelectorAll('.modal-overlay').forEach(overlay => {
        overlay.addEventListener('click', () => {
            const modal = overlay.closest('.modal');
            modal.classList.remove('active');
        });
    });

    // Escape key
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            document.querySelectorAll('.modal.active').forEach(modal => {
                modal.classList.remove('active');
            });
        }
    });
}

function openModal(id) {
    document.getElementById(id).classList.add('active');
}

function closeModal(id) {
    document.getElementById(id).classList.remove('active');
}

// ========================================
// Toast Notifications
// ========================================

function showToast(title, message, type = 'info') {
    const icons = {
        success: 'fa-check-circle',
        error: 'fa-times-circle',
        warning: 'fa-exclamation-circle',
        info: 'fa-info-circle'
    };

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `
        <i class="fas ${icons[type]}"></i>
        <div class="toast-content">
            <div class="toast-title">${title}</div>
            <div class="toast-message">${message}</div>
        </div>
    `;

    elements.toastContainer.appendChild(toast);

    // Auto remove after 5 seconds
    setTimeout(() => {
        toast.style.animation = 'toastIn 0.3s ease reverse';
        setTimeout(() => toast.remove(), 300);
    }, 5000);
}

// ========================================
// API Helper
// ========================================

async function fetchAPI(endpoint, options = {}) {
    const url = `${API_BASE}${endpoint}`;

    const config = {
        headers: {
            'Content-Type': 'application/json',
            ...options.headers
        },
        ...options
    };

    const response = await fetch(url, config);

    if (!response.ok) {
        throw new Error(`API Error: ${response.status}`);
    }

    return response.json();
}

// ========================================
// Utility Functions
// ========================================

function capitalize(str) {
    return str ? str.charAt(0).toUpperCase() + str.slice(1) : '';
}

function truncate(str, length) {
    if (!str) return '';
    return str.length > length ? str.substring(0, length) + '...' : str;
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function formatDate(dateStr) {
    const date = new Date(dateStr);
    return date.toLocaleDateString('en-US', {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

function getPageRange(current, total) {
    const delta = 2;
    const range = [];
    const rangeWithDots = [];

    for (let i = 1; i <= total; i++) {
        if (i === 1 || i === total || (i >= current - delta && i <= current + delta)) {
            range.push(i);
        }
    }

    let prev;
    for (const i of range) {
        if (prev) {
            if (i - prev === 2) {
                rangeWithDots.push(prev + 1);
            } else if (i - prev !== 1) {
                rangeWithDots.push('...');
            }
        }
        rangeWithDots.push(i);
        prev = i;
    }

    return rangeWithDots;
}

// Make functions globally available
window.showVulnDetail = showVulnDetail;
window.goToPage = goToPage;
window.filterByFile = filterByFile;
