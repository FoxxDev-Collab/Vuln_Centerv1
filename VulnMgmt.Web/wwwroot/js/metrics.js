// ATO Metrics Dashboard JavaScript

// Chart.js color schemes matching Bootstrap
const ChartColors = {
    critical: '#dc3545',
    high: '#ffc107',
    medium: '#0dcaf0',
    low: '#0d6efd',
    info: '#6c757d',
    success: '#198754',
    danger: '#dc3545',
    warning: '#ffc107',
    primary: '#0d6efd',
    secondary: '#6c757d',
    // STIG status colors
    open: '#dc3545',
    notAFinding: '#198754',
    notApplicable: '#6c757d',
    notReviewed: '#adb5bd'
};

// Chart instances storage for cleanup
let chartInstances = {};

// Initialize all charts on page load
function initializeCharts(data) {
    // Destroy existing charts before recreating
    Object.values(chartInstances).forEach(chart => {
        if (chart) chart.destroy();
    });
    chartInstances = {};

    // Vulnerability Severity Doughnut Chart
    if (document.getElementById('vulnSeverityChart')) {
        chartInstances.vulnSeverity = createDoughnutChart('vulnSeverityChart', {
            labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
            data: data.vulnerabilityMetrics.severityData,
            colors: [ChartColors.critical, ChartColors.high, ChartColors.medium, ChartColors.low, ChartColors.info]
        });
    }

    // Vulnerability Status Bar Chart
    if (document.getElementById('vulnStatusChart')) {
        chartInstances.vulnStatus = createHorizontalBarChart('vulnStatusChart', {
            labels: ['Open', 'In Progress', 'Remediated', 'Accepted', 'False Positive'],
            data: data.vulnerabilityMetrics.statusData,
            colors: [ChartColors.danger, ChartColors.warning, ChartColors.success, ChartColors.primary, ChartColors.secondary]
        });
    }

    // STIG Status Doughnut Chart
    if (document.getElementById('stigStatusChart')) {
        chartInstances.stigStatus = createDoughnutChart('stigStatusChart', {
            labels: ['Open', 'Not a Finding', 'Not Applicable', 'Not Reviewed'],
            data: data.stigMetrics.statusData,
            colors: [ChartColors.open, ChartColors.notAFinding, ChartColors.notApplicable, ChartColors.notReviewed]
        });
    }

    // STIG CAT Distribution Bar Chart
    if (document.getElementById('stigCatChart')) {
        chartInstances.stigCat = createCatBarChart('stigCatChart', {
            catOpenData: data.stigMetrics.catOpenData,
            catTotalData: data.stigMetrics.catTotalData
        });
    }

    // Update compliance gauge
    if (data.stigMetrics.compliancePercentage !== undefined) {
        updateComplianceGauge(data.stigMetrics.compliancePercentage);
    }
}

// Create a doughnut chart
function createDoughnutChart(canvasId, config) {
    const ctx = document.getElementById(canvasId).getContext('2d');
    return new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: config.labels,
            datasets: [{
                data: config.data,
                backgroundColor: config.colors,
                borderWidth: 2,
                borderColor: '#ffffff'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        padding: 15,
                        usePointStyle: true,
                        font: {
                            size: 12
                        }
                    }
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const value = context.raw;
                            const percentage = total > 0 ? ((value / total) * 100).toFixed(1) : 0;
                            return `${context.label}: ${value.toLocaleString()} (${percentage}%)`;
                        }
                    }
                }
            },
            cutout: '60%'
        }
    });
}

// Create a horizontal bar chart
function createHorizontalBarChart(canvasId, config) {
    const ctx = document.getElementById(canvasId).getContext('2d');
    return new Chart(ctx, {
        type: 'bar',
        data: {
            labels: config.labels,
            datasets: [{
                data: config.data,
                backgroundColor: config.colors,
                borderWidth: 0,
                borderRadius: 4
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            return context.raw.toLocaleString() + ' vulnerabilities';
                        }
                    }
                }
            },
            scales: {
                x: {
                    beginAtZero: true,
                    grid: {
                        display: true,
                        color: 'rgba(0,0,0,0.05)'
                    },
                    ticks: {
                        callback: function(value) {
                            return value.toLocaleString();
                        }
                    }
                },
                y: {
                    grid: {
                        display: false
                    }
                }
            }
        }
    });
}

// Create CAT distribution grouped bar chart
function createCatBarChart(canvasId, config) {
    const ctx = document.getElementById(canvasId).getContext('2d');
    return new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['CAT I (High)', 'CAT II (Medium)', 'CAT III (Low)'],
            datasets: [
                {
                    label: 'Open Findings',
                    data: config.catOpenData,
                    backgroundColor: ChartColors.danger,
                    borderRadius: 4
                },
                {
                    label: 'Total Evaluated',
                    data: config.catTotalData,
                    backgroundColor: 'rgba(108, 117, 125, 0.3)',
                    borderRadius: 4
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        padding: 15,
                        usePointStyle: true
                    }
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            return `${context.dataset.label}: ${context.raw.toLocaleString()}`;
                        }
                    }
                }
            },
            scales: {
                x: {
                    grid: {
                        display: false
                    }
                },
                y: {
                    beginAtZero: true,
                    grid: {
                        color: 'rgba(0,0,0,0.05)'
                    },
                    ticks: {
                        callback: function(value) {
                            return value.toLocaleString();
                        }
                    }
                }
            }
        }
    });
}

// Update compliance gauge SVG
function updateComplianceGauge(percentage) {
    const gauge = document.querySelector('.compliance-gauge-progress');
    const text = document.querySelector('.compliance-gauge-percentage');

    if (gauge && text) {
        // Calculate stroke-dashoffset for the percentage
        const circumference = 2 * Math.PI * 70; // radius = 70
        const offset = circumference - (percentage / 100) * circumference;

        gauge.style.strokeDasharray = circumference;
        gauge.style.strokeDashoffset = offset;

        // Set color based on percentage
        let color = ChartColors.danger;
        if (percentage >= 90) color = ChartColors.success;
        else if (percentage >= 70) color = ChartColors.primary;
        else if (percentage >= 50) color = ChartColors.warning;

        gauge.style.stroke = color;
        text.textContent = percentage.toFixed(1) + '%';
        text.style.color = color;
    }
}

// Refresh dashboard data via AJAX
function refreshDashboard() {
    const refreshBtn = document.getElementById('refreshBtn');
    if (refreshBtn) {
        refreshBtn.classList.add('refreshing');
        refreshBtn.disabled = true;
    }

    fetch('/Metrics/RefreshDashboard')
        .then(response => response.json())
        .then(data => {
            // Update charts
            initializeCharts(data);

            // Update stat cards
            updateStatCards(data.overview);

            // Update site breakdown table
            updateSiteBreakdown(data.siteBreakdown);

            // Update timestamp
            const timestampEl = document.getElementById('lastUpdated');
            if (timestampEl) {
                timestampEl.textContent = 'Last updated: ' + data.generatedAt;
            }
        })
        .catch(error => {
            console.error('Error refreshing dashboard:', error);
            alert('Error refreshing dashboard. Please try again.');
        })
        .finally(() => {
            if (refreshBtn) {
                refreshBtn.classList.remove('refreshing');
                refreshBtn.disabled = false;
            }
        });
}

// Update stat cards with new data
function updateStatCards(overview) {
    const mappings = {
        'totalSites': overview.totalSites,
        'totalHosts': overview.totalHosts,
        'openVulns': overview.openVulnerabilities,
        'criticalVulns': overview.criticalVulnerabilities,
        'highVulns': overview.highVulnerabilities,
        'exploitableVulns': overview.exploitableVulnerabilities,
        'stigChecklists': overview.totalStigChecklists,
        'stigOpenFindings': overview.stigOpenFindings,
        'compliancePercent': overview.overallCompliancePercentage
    };

    Object.entries(mappings).forEach(([id, value]) => {
        const el = document.getElementById(id);
        if (el) {
            if (typeof value === 'number' && !Number.isInteger(value)) {
                el.textContent = value.toFixed(1) + '%';
            } else {
                el.textContent = value.toLocaleString();
            }
        }
    });
}

// Update site breakdown table
function updateSiteBreakdown(sites) {
    const tbody = document.getElementById('siteBreakdownBody');
    if (!tbody) return;

    tbody.innerHTML = '';
    sites.forEach(site => {
        const row = createSiteRow(site);
        tbody.appendChild(row);
    });
}

// Create a site row for the breakdown table
function createSiteRow(site) {
    const tr = document.createElement('tr');
    tr.className = 'site-row-clickable';
    tr.onclick = () => window.location.href = `/Metrics/Site/${site.siteId}`;

    const riskClass = getRiskClass(site.riskLevel);

    tr.innerHTML = `
        <td>
            <strong>${escapeHtml(site.siteName)}</strong>
            ${site.location ? `<br><small class="text-muted">${escapeHtml(site.location)}</small>` : ''}
        </td>
        <td class="text-center">${site.totalHosts}</td>
        <td class="text-center severity-cell">
            ${site.criticalCount > 0 ? `<span class="badge bg-danger">${site.criticalCount}</span>` : '<span class="text-muted">0</span>'}
        </td>
        <td class="text-center severity-cell">
            ${site.highCount > 0 ? `<span class="badge bg-warning text-dark">${site.highCount}</span>` : '<span class="text-muted">0</span>'}
        </td>
        <td class="text-center severity-cell">
            ${site.mediumCount > 0 ? `<span class="badge bg-info">${site.mediumCount}</span>` : '<span class="text-muted">0</span>'}
        </td>
        <td class="text-center">${site.openVulnerabilities}</td>
        <td class="text-center">
            <div class="benchmark-bar">
                <div class="benchmark-bar-fill ${getComplianceColorClass(site.stigCompliancePercentage)}"
                     style="width: ${site.stigCompliancePercentage}%">
                    ${site.stigCompliancePercentage.toFixed(1)}%
                </div>
            </div>
        </td>
        <td class="text-center">
            <span class="badge risk-badge ${riskClass}">${site.riskLevel}</span>
        </td>
    `;

    return tr;
}

// Get risk CSS class
function getRiskClass(riskLevel) {
    const classes = {
        'Critical': 'risk-critical',
        'High': 'risk-high',
        'Medium': 'risk-medium',
        'Low': 'risk-low',
        'Minimal': 'risk-minimal'
    };
    return classes[riskLevel] || 'risk-minimal';
}

// Get compliance color class based on percentage
function getComplianceColorClass(percentage) {
    if (percentage >= 90) return 'bg-success';
    if (percentage >= 70) return 'bg-primary';
    if (percentage >= 50) return 'bg-warning';
    return 'bg-danger';
}

// Escape HTML to prevent XSS
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Load host details for a site (AJAX)
function loadSiteHosts(siteId, containerId) {
    const container = document.getElementById(containerId);
    if (!container) return;

    container.innerHTML = '<div class="metrics-loading"><div class="spinner-border"></div><p>Loading hosts...</p></div>';

    fetch(`/Metrics/GetHostsForSite?siteId=${siteId}`)
        .then(response => response.json())
        .then(hosts => {
            container.innerHTML = createHostsTable(hosts);
        })
        .catch(error => {
            console.error('Error loading hosts:', error);
            container.innerHTML = '<div class="alert alert-danger">Error loading host data.</div>';
        });
}

// Create hosts table HTML
function createHostsTable(hosts) {
    if (!hosts || hosts.length === 0) {
        return '<div class="alert alert-info">No hosts found for this site.</div>';
    }

    let html = `
        <div class="table-responsive">
            <table class="table table-hover site-breakdown-table">
                <thead>
                    <tr>
                        <th>Host</th>
                        <th class="text-center">Critical</th>
                        <th class="text-center">High</th>
                        <th class="text-center">Medium</th>
                        <th class="text-center">Open Vulns</th>
                        <th class="text-center">STIG Compliance</th>
                        <th class="text-center">Risk</th>
                    </tr>
                </thead>
                <tbody>
    `;

    hosts.forEach(host => {
        const riskClass = getRiskClass(host.riskLevel);
        html += `
            <tr class="host-list-item ${host.criticalCount > 0 ? 'risk-critical-border' : host.highCount > 0 ? 'risk-high-border' : ''}">
                <td>
                    <a href="/Host/Details/${host.hostId}" class="text-decoration-none">
                        <strong>${escapeHtml(host.hostName)}</strong>
                    </a>
                    ${host.ipAddress ? `<br><small class="text-muted">${escapeHtml(host.ipAddress)}</small>` : ''}
                    ${host.operatingSystem ? `<br><small class="text-muted">${escapeHtml(host.operatingSystem)}</small>` : ''}
                </td>
                <td class="text-center severity-cell">
                    ${host.criticalCount > 0 ? `<span class="badge bg-danger">${host.criticalCount}</span>` : '<span class="text-muted">0</span>'}
                </td>
                <td class="text-center severity-cell">
                    ${host.highCount > 0 ? `<span class="badge bg-warning text-dark">${host.highCount}</span>` : '<span class="text-muted">0</span>'}
                </td>
                <td class="text-center severity-cell">
                    ${host.mediumCount > 0 ? `<span class="badge bg-info">${host.mediumCount}</span>` : '<span class="text-muted">0</span>'}
                </td>
                <td class="text-center">${host.openVulnerabilities}</td>
                <td class="text-center">
                    ${host.stigTotalFindings > 0 ? `
                        <div class="benchmark-bar">
                            <div class="benchmark-bar-fill ${getComplianceColorClass(host.stigCompliancePercentage)}"
                                 style="width: ${host.stigCompliancePercentage}%">
                                ${host.stigCompliancePercentage.toFixed(1)}%
                            </div>
                        </div>
                    ` : '<span class="text-muted">N/A</span>'}
                </td>
                <td class="text-center">
                    <span class="badge risk-badge ${riskClass}">${host.riskLevel}</span>
                </td>
            </tr>
        `;
    });

    html += '</tbody></table></div>';
    return html;
}

// Export functions for global access
window.MetricsDashboard = {
    initializeCharts,
    refreshDashboard,
    loadSiteHosts,
    updateComplianceGauge
};
