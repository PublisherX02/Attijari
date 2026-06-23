/* =========================================================================
   dashboard.js — Client-side logic for the Attijari SOC Dashboard
   Handles API calls, DOM updates, toast notifications, and interactivity
   ========================================================================= */

const API = {
    async get(url) {
        const res = await fetch(url);
        if (!res.ok) throw new Error(`API ${res.status}: ${await res.text()}`);
        return res.json();
    },
    async post(url, body = {}) {
        const res = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        if (!res.ok) throw new Error(`API ${res.status}: ${await res.text()}`);
        return res.json();
    },
    async del(url) {
        const res = await fetch(url, { method: 'DELETE' });
        if (!res.ok) throw new Error(`API ${res.status}: ${await res.text()}`);
        return res.json();
    },
};

/* --- Toast notifications --- */
function showToast(message, type = 'success') {
    let container = document.getElementById('toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        container.className = 'toast-container';
        document.body.appendChild(container);
    }

    const icons = { success: '✓', error: '✕', warning: '⚠' };
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `<span>${icons[type] || '●'}</span><span>${message}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(100%)';
        toast.style.transition = 'all 300ms ease-in';
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

/* --- Format helpers --- */
function formatDate(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    return d.toLocaleDateString('fr-FR', {
        day: '2-digit', month: 'short', year: 'numeric',
        hour: '2-digit', minute: '2-digit',
    });
}

function truncate(str, len = 50) {
    if (!str) return '—';
    return str.length > len ? str.substring(0, len) + '…' : str;
}

function statusBadge(status) {
    return `<span class="badge ${status}">${status}</span>`;
}

/* =========================================================================
   Inbox page
   ========================================================================= */

let currentPage = 1;
let currentStatus = null;
let currentSearch = '';

async function loadInbox(page = 1, status = null, search = '') {
    currentPage = page;
    currentStatus = status;
    currentSearch = search;

    const container = document.getElementById('email-table-body');
    const statsContainer = document.getElementById('stats-cards');
    if (!container) return;

    container.innerHTML = '<tr><td colspan="6" class="loading-overlay"><div class="spinner"></div> Loading…</td></tr>';

    try {
        // Load stats
        if (statsContainer) {
            const stats = await API.get('/api/stats');
            const s = stats.by_status || {};
            statsContainer.innerHTML = `
                <div class="stat-card total"><div class="stat-value">${stats.total_emails || 0}</div><div class="stat-label">Total Emails</div></div>
                <div class="stat-card accepted"><div class="stat-value">${s.accepted || 0}</div><div class="stat-label">Accepted</div></div>
                <div class="stat-card escalated"><div class="stat-value">${s.escalated || 0}</div><div class="stat-label">Escalated</div></div>
                <div class="stat-card quarantined"><div class="stat-value">${s.quarantined || 0}</div><div class="stat-label">Quarantined</div></div>
                <div class="stat-card released"><div class="stat-value">${s.released || 0}</div><div class="stat-label">Released</div></div>
            `;

            // Update nav badge
            const badge = document.getElementById('pending-badge');
            if (badge) badge.textContent = stats.pending_review || 0;
        }

        // Load emails
        let url = `/api/emails?page=${page}&per_page=25`;
        if (status) url += `&status=${status}`;
        if (search) url += `&search=${encodeURIComponent(search)}`;

        const data = await API.get(url);

        if (data.emails.length === 0) {
            container.innerHTML = '<tr><td colspan="6" class="empty-state"><div class="emoji">📭</div><p>No emails found</p></td></tr>';
            return;
        }

        container.innerHTML = data.emails.map(e => `
            <tr onclick="window.location='/email/${e.id}'">
                <td>${truncate(e.sender, 40)}</td>
                <td>${truncate(e.subject, 55)}</td>
                <td>${statusBadge(e.status)}</td>
                <td>${e.attachment_count > 0 ? '📎 ' + e.attachment_count : '—'}</td>
                <td>${formatDate(e.created_at)}</td>
                <td>
                    ${e.status === 'escalated' || e.status === 'recu' ? `
                        <div class="btn-group">
                            <button class="btn btn-success btn-sm" onclick="event.stopPropagation(); releaseEmail(${e.id})">Release</button>
                            <button class="btn btn-danger btn-sm" onclick="event.stopPropagation(); quarantineEmail(${e.id})">Quarantine</button>
                        </div>
                    ` : e.analyst_action ? `<span style="color:var(--text-muted)">${e.analyst_action}</span>` : ''}
                </td>
            </tr>
        `).join('');

        // Update pagination
        renderPagination(data.page, data.pages, data.total);

        // Update filter chip active state
        document.querySelectorAll('.chip').forEach(c => {
            c.classList.toggle('active', c.dataset.status === (status || ''));
        });

    } catch (err) {
        container.innerHTML = `<tr><td colspan="6" class="empty-state"><div class="emoji">❌</div><p>Error loading emails: ${err.message}</p></td></tr>`;
        showToast(err.message, 'error');
    }
}

function renderPagination(page, pages, total) {
    const el = document.getElementById('pagination');
    if (!el || pages <= 1) { if (el) el.innerHTML = ''; return; }

    let html = '';
    if (page > 1) html += `<button class="btn btn-outline btn-sm" onclick="loadInbox(${page - 1}, currentStatus, currentSearch)">← Prev</button>`;
    html += `<span class="current-page">Page ${page} of ${pages} (${total} total)</span>`;
    if (page < pages) html += `<button class="btn btn-outline btn-sm" onclick="loadInbox(${page + 1}, currentStatus, currentSearch)">Next →</button>`;
    el.innerHTML = html;
}

function filterByStatus(status) {
    loadInbox(1, status === currentStatus ? null : status, currentSearch);
}

function searchEmails() {
    const input = document.getElementById('search-input');
    if (input) loadInbox(1, currentStatus, input.value.trim());
}

/* =========================================================================
   Email actions
   ========================================================================= */

async function releaseEmail(id) {
    try {
        await API.post(`/api/emails/${id}/release`);
        showToast('Email released successfully', 'success');
        if (typeof loadInbox === 'function') loadInbox(currentPage, currentStatus, currentSearch);
        if (typeof loadEmailDetail === 'function') loadEmailDetail(id);
    } catch (err) {
        showToast(`Release failed: ${err.message}`, 'error');
    }
}

async function quarantineEmail(id) {
    try {
        await API.post(`/api/emails/${id}/quarantine`);
        showToast('Email quarantined + sender blocked', 'success');
        if (typeof loadInbox === 'function') loadInbox(currentPage, currentStatus, currentSearch);
        if (typeof loadEmailDetail === 'function') loadEmailDetail(id);
    } catch (err) {
        showToast(`Quarantine failed: ${err.message}`, 'error');
    }
}

async function overrideEmail(id) {
    const status = document.getElementById('override-status')?.value;
    const notes = document.getElementById('override-notes')?.value || '';
    if (!status) return showToast('Select a status', 'warning');

    try {
        await API.post(`/api/emails/${id}/override`, { status, notes });
        showToast(`Verdict overridden to ${status}`, 'success');
        closeModal();
        loadEmailDetail(id);
    } catch (err) {
        showToast(`Override failed: ${err.message}`, 'error');
    }
}

/* =========================================================================
   Email detail page
   ========================================================================= */

async function loadEmailDetail(emailId) {
    const container = document.getElementById('email-detail');
    if (!container) return;

    container.innerHTML = '<div class="loading-overlay"><div class="spinner"></div> Loading…</div>';

    try {
        const e = await API.get(`/api/emails/${emailId}`);

        // Build enrichment signals HTML
        let signalsHtml = '';
        const rules = e.rules_result;
        if (rules && rules.details) {
            signalsHtml = '<div class="signals-grid">';
            for (const d of rules.details) {
                const cls = d.flagged ? 'flagged' : 'clean';
                signalsHtml += `
                    <div class="signal-card ${cls}">
                        <div class="signal-name">${d.rule}</div>
                        <div>${d.reason}</div>
                    </div>
                `;
            }
            signalsHtml += '</div>';
        }

        // Build audit history
        let auditHtml = '';
        if (e.audit_history && e.audit_history.length > 0) {
            auditHtml = '<div class="detail-section" style="grid-column: 1 / -1"><h3>Audit History</h3>';
            for (const a of e.audit_history) {
                auditHtml += `
                    <div class="detail-row">
                        <span class="detail-label">${a.action} by ${a.actor}</span>
                        <span class="detail-value">${formatDate(a.created_at)}</span>
                    </div>
                `;
            }
            auditHtml += '</div>';
        }

        container.innerHTML = `
            <div class="page-header">
                <a href="/" class="btn btn-outline btn-sm" style="margin-bottom:12px">← Back to Inbox</a>
                <h2>${truncate(e.subject, 80)}</h2>
                <div class="page-subtitle">From: ${e.sender || 'Unknown'} · ${formatDate(e.created_at)}</div>
            </div>

            <div class="detail-grid">
                <div class="detail-section">
                    <h3>Email Metadata</h3>
                    <div class="detail-row"><span class="detail-label">Status</span><span class="detail-value">${statusBadge(e.status)}</span></div>
                    <div class="detail-row"><span class="detail-label">Sender</span><span class="detail-value">${e.sender || '—'}</span></div>
                    <div class="detail-row"><span class="detail-label">Domain</span><span class="detail-value">${e.sender_domain || '—'}</span></div>
                    <div class="detail-row"><span class="detail-label">Attachments</span><span class="detail-value">${e.attachment_count}</span></div>
                    <div class="detail-row"><span class="detail-label">SHA-256</span><span class="detail-value" style="font-family:monospace;font-size:0.75rem">${e.raw_sha256 || '—'}</span></div>
                    <div class="detail-row"><span class="detail-label">Message-ID</span><span class="detail-value" style="font-size:0.75rem">${truncate(e.message_id, 40)}</span></div>
                </div>

                <div class="detail-section">
                    <h3>Analyst Actions</h3>
                    <div class="detail-row"><span class="detail-label">Action taken</span><span class="detail-value">${e.analyst_action || 'None'}</span></div>
                    <div class="detail-row"><span class="detail-label">Notes</span><span class="detail-value">${e.analyst_notes || '—'}</span></div>
                    ${(() => {
                        const failSafeErrors = (e.parse_errors || []).filter(err => err.startsWith('fail-safe:'));
                        const normalErrors = (e.parse_errors || []).filter(err => !err.startsWith('fail-safe:'));
                        let html = '';
                        if (failSafeErrors.length > 0) {
                            html += `<div class="detail-row"><span class="detail-label" style="color:var(--color-escalated);font-weight:bold">⚠ Fail-Safe Triggered</span><span class="detail-value" style="color:var(--color-escalated);font-weight:bold">${failSafeErrors.map(err => err.replace('fail-safe: ', '')).join(', ')}</span></div>`;
                        }
                        if (normalErrors.length > 0) {
                            html += `<div class="detail-row"><span class="detail-label">Parse Errors</span><span class="detail-value" style="color:var(--color-escalated)">${normalErrors.join(', ')}</span></div>`;
                        }
                        return html;
                    })()}
                </div>
            </div>

            ${e.llm_reasoning ? `
                <div class="reasoning-card">
                    <h3>🤖 LLM Reasoning</h3>
                    <div class="reasoning-text">${e.llm_reasoning}</div>
                </div>
            ` : ''}

            ${signalsHtml ? `<h3 style="margin-bottom:12px;color:var(--text-muted);font-size:0.85rem;text-transform:uppercase;letter-spacing:0.06em">Security Signals</h3>${signalsHtml}` : ''}

            ${auditHtml}

            <div class="action-bar">
                <button class="btn btn-success" onclick="releaseEmail(${e.id})">✓ Release</button>
                <button class="btn btn-danger" onclick="quarantineEmail(${e.id})">🛡 Quarantine</button>
                <button class="btn btn-outline" onclick="openOverrideModal(${e.id})">Override Verdict</button>
                <div style="flex:1"></div>
                <span style="color:var(--text-muted);font-size:0.8rem">Email #${e.id}</span>
            </div>
        `;

    } catch (err) {
        container.innerHTML = `<div class="empty-state"><div class="emoji">❌</div><p>Error: ${err.message}</p></div>`;
    }
}

/* =========================================================================
   Blocklist / Whitelist management
   ========================================================================= */

async function loadBlocklist() {
    const container = document.getElementById('blocklist-body');
    if (!container) return;

    try {
        const data = await API.get('/api/blocklist?per_page=200');
        if (data.entries.length === 0) {
            container.innerHTML = '<tr><td colspan="5" class="empty-state"><p>No blocklist entries</p></td></tr>';
            return;
        }
        container.innerHTML = data.entries.map(e => `
            <tr>
                <td><span class="badge ${e.indicator_type === 'email' ? 'escalated' : 'recu'}">${e.indicator_type}</span></td>
                <td style="font-family:monospace">${e.value}</td>
                <td>${e.source}</td>
                <td>${formatDate(e.created_at)}</td>
                <td><button class="btn btn-outline btn-sm" onclick="removeBlocklistEntry(${e.id})">Remove</button></td>
            </tr>
        `).join('');
    } catch (err) {
        showToast(`Load failed: ${err.message}`, 'error');
    }
}

async function addBlocklistEntry() {
    const type = document.getElementById('bl-type')?.value;
    const value = document.getElementById('bl-value')?.value;
    if (!type || !value) return showToast('Fill all fields', 'warning');

    try {
        await API.post('/api/blocklist', { indicator_type: type, value });
        showToast(`Blocked ${type}: ${value}`, 'success');
        document.getElementById('bl-value').value = '';
        loadBlocklist();
    } catch (err) {
        showToast(err.message, 'error');
    }
}

async function removeBlocklistEntry(id) {
    try {
        await API.del(`/api/blocklist/${id}`);
        showToast('Entry removed', 'success');
        loadBlocklist();
    } catch (err) {
        showToast(err.message, 'error');
    }
}

async function loadWhitelist() {
    const container = document.getElementById('whitelist-body');
    if (!container) return;

    try {
        const data = await API.get('/api/whitelist?per_page=200');
        if (data.entries.length === 0) {
            container.innerHTML = '<tr><td colspan="5" class="empty-state"><p>No whitelist entries</p></td></tr>';
            return;
        }
        container.innerHTML = data.entries.map(e => `
            <tr>
                <td><span class="badge accepted">${e.indicator_type}</span></td>
                <td style="font-family:monospace">${e.value}</td>
                <td>${e.reason || '—'}</td>
                <td>${formatDate(e.created_at)}</td>
                <td><button class="btn btn-outline btn-sm" onclick="removeWhitelistEntry(${e.id})">Remove</button></td>
            </tr>
        `).join('');
    } catch (err) {
        showToast(`Load failed: ${err.message}`, 'error');
    }
}

async function addWhitelistEntry() {
    const type = document.getElementById('wl-type')?.value;
    const value = document.getElementById('wl-value')?.value;
    const reason = document.getElementById('wl-reason')?.value || '';
    if (!type || !value) return showToast('Fill required fields', 'warning');

    try {
        await API.post('/api/whitelist', { indicator_type: type, value, reason });
        showToast(`Whitelisted ${type}: ${value}`, 'success');
        document.getElementById('wl-value').value = '';
        document.getElementById('wl-reason').value = '';
        loadWhitelist();
    } catch (err) {
        showToast(err.message, 'error');
    }
}

async function removeWhitelistEntry(id) {
    try {
        await API.del(`/api/whitelist/${id}`);
        showToast('Entry removed', 'success');
        loadWhitelist();
    } catch (err) {
        showToast(err.message, 'error');
    }
}

/* =========================================================================
   Health page
   ========================================================================= */

async function loadHealth() {
    const container = document.getElementById('health-grid');
    if (!container) return;

    try {
        const h = await API.get('/api/health');
        container.innerHTML = Object.entries(h.components).map(([name, c]) => `
            <div class="health-card">
                <span class="status-dot ${c.status}"></span>
                <strong>${name.replace(/_/g, ' ').toUpperCase()}</strong>
                <div style="color:var(--text-muted);font-size:0.8rem;margin-top:6px">
                    Status: ${c.status}
                    ${c.age_hours ? ` · Age: ${c.age_hours}h` : ''}
                    ${c.error ? ` · Error: ${c.error}` : ''}
                </div>
            </div>
        `).join('');
    } catch (err) {
        container.innerHTML = `<div class="empty-state"><p>Health check failed: ${err.message}</p></div>`;
    }
}

/* =========================================================================
   Reports page
   ========================================================================= */

async function loadReports() {
    const container = document.getElementById('reports-body');
    if (!container) return;

    try {
        const data = await API.get('/api/reports?limit=50');
        if (data.reports.length === 0) {
            container.innerHTML = '<tr><td colspan="5" class="empty-state"><p>No reports generated yet</p></td></tr>';
            return;
        }
        container.innerHTML = data.reports.map(r => {
            const counts = r.data?.counts || {};
            return `
                <tr>
                    <td>${r.report_type}</td>
                    <td>${formatDate(r.period_start)} → ${formatDate(r.period_end)}</td>
                    <td>${counts.total || 0} emails</td>
                    <td>${(r.delivered_via || []).join(', ') || '—'}</td>
                    <td>${formatDate(r.created_at)}</td>
                </tr>
            `;
        }).join('');
    } catch (err) {
        showToast(err.message, 'error');
    }
}

async function generateReport() {
    try {
        showToast('Generating report…', 'warning');
        const report = await API.get('/api/stats');
        showToast('Report data refreshed', 'success');
        loadReports();
    } catch (err) {
        showToast(err.message, 'error');
    }
}

/* =========================================================================
   Modal
   ========================================================================= */

function openOverrideModal(emailId) {
    const overlay = document.getElementById('modal-overlay');
    if (!overlay) return;
    overlay.dataset.emailId = emailId;
    overlay.classList.add('open');
}

function closeModal() {
    const overlay = document.getElementById('modal-overlay');
    if (overlay) overlay.classList.remove('open');
}


/* =========================================================================
   WebSocket auto-refresh
   ========================================================================= */

function connectWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = protocol + '//' + window.location.host + '/ws';
    const ws = new WebSocket(wsUrl);

    ws.onmessage = (event) => {
        if (event.data === 'refresh') {
            console.log('Received refresh signal via WebSocket');
            if (typeof loadInbox === 'function' && document.getElementById('email-table-body')) {
                loadInbox(currentPage, currentStatus, currentSearch);
            }
        }
    };

    ws.onclose = () => {
        setTimeout(connectWebSocket, 5000);
    };
}

connectWebSocket();
