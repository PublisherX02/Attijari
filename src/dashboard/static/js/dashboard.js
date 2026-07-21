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

/* =========================================================================
   Delegated action dispatch (CSP-safe replacement for inline onclick/onchange)
   ========================================================================= */
const actionRegistry = {};
const changeRegistry = {};
const enterActionRegistry = {};

function registerAction(name, fn) { actionRegistry[name] = fn; }
function registerChangeAction(name, fn) { changeRegistry[name] = fn; }
function registerEnterAction(name, fn) { enterActionRegistry[name] = fn; }

document.addEventListener('click', (event) => {
    const el = event.target.closest('[data-action]');
    if (!el) return;
    const handler = actionRegistry[el.dataset.action];
    if (!handler) { console.error('Unknown data-action:', el.dataset.action); return; }
    handler(el, event);
});

document.addEventListener('change', (event) => {
    const el = event.target.closest('[data-change-action]');
    if (!el) return;
    const handler = changeRegistry[el.dataset.changeAction];
    if (!handler) { console.error('Unknown data-change-action:', el.dataset.changeAction); return; }
    handler(el, event);
});

document.addEventListener('keydown', (event) => {
    if (event.key !== 'Enter') return;
    const el = event.target.closest('[data-enter-action]');
    if (!el) return;
    const handler = enterActionRegistry[el.dataset.enterAction];
    if (!handler) return;
    handler(el, event);
});

registerAction('noop', () => {});
registerAction('backdrop-close', (el, event) => {
    if (event.target !== el) return;
    const closeFn = window[el.dataset.close];
    if (typeof closeFn === 'function') closeFn();
});

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
    toast.innerHTML = `<span>${icons[type] || '●'}</span><span>${esc(message)}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(100%)';
        toast.style.transition = 'all 300ms ease-in';
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

/* --- HTML escaping (XSS prevention) --- */
function esc(s) {
    if (s == null) return '';
    const d = document.createElement('div');
    d.textContent = String(s);
    return d.innerHTML;
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

/** Set of currently selected email IDs (integers). */
const selectedEmailIds = new Set();

function updateBulkBar() {
    const bar = document.getElementById('bulk-action-bar');
    if (!bar) return;
    const count = selectedEmailIds.size;
    if (count === 0) {
        bar.style.display = 'none';
        return;
    }
    bar.style.display = 'flex';
    const label = document.getElementById('bulk-count-label');
    if (label) label.textContent = `${count} email${count !== 1 ? 's' : ''} selected`;
    const releaseBtn = document.getElementById('bulk-release-btn');
    const quarantineBtn = document.getElementById('bulk-quarantine-btn');
    if (releaseBtn) releaseBtn.textContent = `Release Selected (${count})`;
    if (quarantineBtn) quarantineBtn.textContent = `Quarantine Selected (${count})`;
}

function toggleEmailSelection(id, checked) {
    if (checked) {
        selectedEmailIds.add(id);
    } else {
        selectedEmailIds.delete(id);
    }
    updateSelectAllCheckbox();
    updateBulkBar();
}

function toggleSelectAll(checked) {
    document.querySelectorAll('.row-checkbox').forEach(cb => {
        const id = parseInt(cb.dataset.id);
        cb.checked = checked;
        if (checked) selectedEmailIds.add(id); else selectedEmailIds.delete(id);
    });
    updateBulkBar();
}

function updateSelectAllCheckbox() {
    const allCbs = document.querySelectorAll('.row-checkbox');
    const headerCb = document.getElementById('select-all-checkbox');
    if (!headerCb || allCbs.length === 0) return;
    const checkedCount = Array.from(allCbs).filter(cb => cb.checked).length;
    headerCb.indeterminate = checkedCount > 0 && checkedCount < allCbs.length;
    headerCb.checked = checkedCount === allCbs.length;
}

async function executeBulkAction(action) {
    if (selectedEmailIds.size === 0) return;
    const ids = Array.from(selectedEmailIds);
    const reason = prompt(`Reason for bulk ${action} of ${ids.length} email(s):`);
    if (reason === null) return; // cancelled
    if (!reason.trim()) { showToast('Please provide a reason', 'warning'); return; }

    try {
        const result = await API.post(`/api/emails/bulk/${action}`, { email_ids: ids, reason: reason.trim() });
        const msg = `${action}: ${result.succeeded} succeeded, ${result.failed} failed`;
        showToast(msg, result.failed > 0 ? 'warning' : 'success');
        selectedEmailIds.clear();
        loadInbox(currentPage, currentStatus, currentSearch);
    } catch (err) {
        showToast(`Bulk ${action} failed: ${err.message}`, 'error');
    }
}

function clearSelection() {
    selectedEmailIds.clear();
    document.querySelectorAll('.row-checkbox').forEach(c => c.checked = false);
    updateBulkBar();
}

async function loadInbox(page = 1, status = null, search = '') {
    currentPage = page;
    currentStatus = status;
    currentSearch = search;

    const container = document.getElementById('email-table-body');
    const statsContainer = document.getElementById('stats-cards');
    if (!container) return;

    // Clear stale selections whenever the inbox reloads
    selectedEmailIds.clear();
    updateBulkBar();

    container.innerHTML = '<tr><td colspan="7" class="loading-overlay"><div class="spinner"></div> Loading…</td></tr>';

    try {
        // Load stats
        if (statsContainer) {
            const stats = await API.get('/api/stats');
            const s = stats.by_status || {};
            statsContainer.innerHTML = `
                <div class="stat-card total"><div class="stat-value">${stats.total_emails || 0}</div><div class="stat-label">Total Emails</div></div>
                <div class="stat-card pending"><div class="stat-value">${s.pending || 0}</div><div class="stat-label">Scanning</div></div>
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
            container.innerHTML = '<tr><td colspan="7" class="empty-state"><div class="emoji">📭</div><p>No emails found</p></td></tr>';
            return;
        }

        const canRelease = userCan('emails.release');
        const canQuarantine = userCan('emails.quarantine');
        const canRevert = userCan('emails.revert');
        const canBulk = userCan('emails.bulk');

        container.innerHTML = data.emails.map(e => `
            <tr data-action="open-email" data-id="${parseInt(e.id)}">
                ${canBulk ? `<td data-action="noop">
                    <input type="checkbox" class="row-checkbox" data-id="${parseInt(e.id)}"
                        data-change-action="toggle-email-selection">
                </td>` : '<td></td>'}
                <td>${esc(truncate(e.sender, 40))}</td>
                <td>${esc(truncate(e.subject, 55))}</td>
                <td>${statusBadge(e.status)}</td>
                <td>${e.attachment_count > 0 ? '📎 ' + parseInt(e.attachment_count) : '—'}</td>
                <td>${formatDate(e.email_date || e.created_at)}</td>
                <td>
                    ${e.status === 'pending' ? `<span class="badge pending">Scanning…</span>`
                    : e.status === 'escalated' || e.status === 'recu' ? `
                        <div class="btn-group">
                            ${canRelease ? `<button class="btn btn-success btn-sm" data-action="release-email" data-id="${parseInt(e.id)}">Release</button>` : ''}
                            ${canQuarantine ? `<button class="btn btn-danger btn-sm" data-action="quarantine-email" data-id="${parseInt(e.id)}">Quarantine</button>` : ''}
                        </div>
                    ` : e.analyst_action ? `
                        <div class="btn-group">
                            <span style="color:var(--text-muted)">${esc(e.analyst_action)}</span>
                            ${canRevert ? `<button class="btn btn-outline btn-sm" data-action="revert-action" data-id="${parseInt(e.id)}" title="Undo — return to escalated for re-review">Undo</button>` : ''}
                        </div>
                    ` : ''}
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
        container.innerHTML = `<tr><td colspan="7" class="empty-state"><div class="emoji">❌</div><p>Error loading emails: ${esc(err.message)}</p></td></tr>`;
        showToast(err.message, 'error');
    }
}

function renderPagination(page, pages, total) {
    const el = document.getElementById('pagination');
    if (!el || pages <= 1) { if (el) el.innerHTML = ''; return; }

    let html = '';
    if (page > 1) html += `<button class="btn btn-outline btn-sm" data-action="load-inbox-page" data-page="${page - 1}">← Prev</button>`;
    html += `<span class="current-page">Page ${page} of ${pages} (${total} total)</span>`;
    if (page < pages) html += `<button class="btn btn-outline btn-sm" data-action="load-inbox-page" data-page="${page + 1}">Next →</button>`;
    el.innerHTML = html;
}

function filterByStatus(status) {
    loadInbox(1, status === currentStatus ? null : status, currentSearch);
}

function searchEmails() {
    const input = document.getElementById('search-input');
    if (input) loadInbox(1, currentStatus, input.value.trim());
}

async function triggerScan() {
    const btn = document.getElementById('scan-btn');
    if (btn) {
        btn.disabled = true;
        btn.textContent = '⏳ Scanning…';
    }
    try {
        const res = await API.post('/api/scan');
        if (res.success) {
            showToast('Scan started — new emails will appear shortly', 'success');
        } else {
            showToast(res.message || 'Scan already in progress', 'warning');
        }
    } catch (err) {
        showToast(`Scan failed: ${err.message}`, 'error');
    }
    // Re-enable after a delay (scan runs in background)
    setTimeout(() => {
        if (btn) {
            btn.disabled = false;
            btn.textContent = '🔄 Scan Now';
        }
    }, 10000);
}

/* =========================================================================
   Email actions
   ========================================================================= */

async function releaseEmail(id) {
    openReasonModal('release', id);
}

async function quarantineEmail(id) {
    openReasonModal('quarantine', id);
}

function openReasonModal(action, emailId) {
    const overlay = document.getElementById('reason-modal-overlay');
    if (!overlay) return;
    overlay.dataset.action = action;
    overlay.dataset.emailId = emailId;

    const title = overlay.querySelector('.modal h3');
    const hint = overlay.querySelector('#reason-hint');
    if (action === 'release') {
        title.textContent = 'Release Email — Why is this safe?';
        hint.textContent = 'The sender will be whitelisted. If the domain is already blocklisted, only the specific sender address is whitelisted — the domain block remains in place for other senders.';
    } else {
        title.textContent = 'Quarantine Email — Why is this malicious?';
        hint.textContent = 'The sender will be blocklisted and the email moved to Gmail Spam.';
    }

    overlay.querySelector('#reason-text').value = '';
    overlay.classList.add('open');
}

async function confirmReasonAction() {
    const overlay = document.getElementById('reason-modal-overlay');
    if (!overlay) return;

    const action = overlay.dataset.action;
    const emailId = overlay.dataset.emailId;
    const reason = overlay.querySelector('#reason-text').value.trim();

    if (!reason) {
        showToast('Please provide a reason', 'warning');
        return;
    }

    overlay.classList.remove('open');

    try {
        if (action === 'release') {
            const result = await API.post(`/api/emails/${emailId}/release`, { reason });
            let msg = 'Email released';
            if (result.whitelisted_domain) {
                msg = `Released + whitelisted domain ${result.whitelisted_domain}`;
            } else if (result.whitelisted_email) {
                msg = `Released + whitelisted sender only (domain is blocklisted)`;
            }
            showToast(msg, 'success');
        } else {
            await API.post(`/api/emails/${emailId}/quarantine`, { reason });
            showToast('Quarantined + sender blocked + moved to Spam', 'success');
        }
        if (document.getElementById('email-table-body')) loadInbox(currentPage, currentStatus, currentSearch);
        if (document.getElementById('email-detail')) loadEmailDetail(emailId);
    } catch (err) {
        showToast(`${action} failed: ${err.message}`, 'error');
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

async function revertAction(id) {
    if (!confirm('Undo this action? The email will return to escalated status for re-review.')) return;

    try {
        const result = await API.post(`/api/emails/${id}/revert`);
        const msgs = [];
        if (result.unblocked_indicators && result.unblocked_indicators.length > 0) {
            msgs.push(`${result.unblocked_indicators.length} blocklist entry(s) removed`);
        }
        if (result.removed_whitelist_domain) {
            msgs.push(`whitelist removed for ${result.removed_whitelist_domain}`);
        }
        const detail = msgs.length > 0 ? ` (${msgs.join(', ')})` : '';
        showToast(`Reverted ${result.reverted_action} — email back to escalated${detail}`, 'success');
        if (document.getElementById('email-table-body')) loadInbox(currentPage, currentStatus, currentSearch);
        if (document.getElementById('email-detail')) loadEmailDetail(id);
    } catch (err) {
        showToast(`Revert failed: ${err.message}`, 'error');
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
                        <div class="signal-name">${esc(d.rule)}</div>
                        <div>${esc(d.reason)}</div>
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
                        <span class="detail-label">${esc(a.action)} by ${esc(a.actor)}</span>
                        <span class="detail-value">${formatDate(a.created_at)}</span>
                    </div>
                `;
            }
            auditHtml += '</div>';
        }

        // Domain conflict warning: shown when domain appears in BOTH blocklist and whitelist.
        // This means a previous quarantine blocked the domain, but a release whitelisted
        // a specific sender on that domain — the conflict is expected but must be visible.
        const domainConflictHtml = (e.domain_in_blocklist && e.domain_in_whitelist)
            ? `<div style="
                    background:rgba(234,179,8,0.12);
                    border:1px solid rgba(234,179,8,0.5);
                    border-radius:var(--radius);
                    padding:12px 16px;
                    margin-bottom:16px;
                    display:flex;
                    align-items:flex-start;
                    gap:10px;
                    font-size:0.85rem;
                    color:var(--color-escalated,#f59e0b)">
                <span style="font-size:1.1rem;line-height:1.4">&#9888;</span>
                <span>
                    <strong>Domain conflict detected:</strong>
                    <code style="margin:0 4px">${esc(e.sender_domain)}</code>
                    is in both the blocklist and the whitelist.
                    A previous quarantine blocked this domain, but a release whitelisted a specific sender on it.
                    The domain remains blocked for other senders. Review the
                    <a href="/blocklist" style="color:inherit;text-decoration:underline">blocklist</a> if this is unexpected.
                </span>
              </div>`
            : '';

        container.innerHTML = `
            <div class="page-header">
                <a href="/" class="btn btn-outline btn-sm" style="margin-bottom:12px">← Back to Inbox</a>
                <h2>${esc(truncate(e.subject, 80))}</h2>
                <div class="page-subtitle">From: ${esc(e.sender) || 'Unknown'} · ${formatDate(e.email_date || e.created_at)}</div>
            </div>

            ${domainConflictHtml}

            <div class="detail-grid">
                <div class="detail-section">
                    <h3>Email Metadata</h3>
                    <div class="detail-row"><span class="detail-label">Status</span><span class="detail-value">${statusBadge(e.status)}</span></div>
                    <div class="detail-row"><span class="detail-label">Sender</span><span class="detail-value">${esc(e.sender) || '—'}</span></div>
                    <div class="detail-row"><span class="detail-label">Domain</span><span class="detail-value">${esc(e.sender_domain) || '—'}${e.domain_in_blocklist ? ' <span class="badge quarantined" style="font-size:0.7rem">blocklisted</span>' : ''}${e.domain_in_whitelist ? ' <span class="badge accepted" style="font-size:0.7rem">whitelisted</span>' : ''}</span></div>
                    <div class="detail-row"><span class="detail-label">Date Sent</span><span class="detail-value">${formatDate(e.email_date) || '—'}</span></div>
                    <div class="detail-row"><span class="detail-label">Scanned At</span><span class="detail-value">${formatDate(e.created_at)}</span></div>
                    <div class="detail-row"><span class="detail-label">Attachments</span><span class="detail-value">${parseInt(e.attachment_count) || 0}</span></div>
                    <div class="detail-row"><span class="detail-label">SHA-256</span><span class="detail-value" style="font-family:monospace;font-size:0.75rem">${esc(e.raw_sha256) || '—'}</span></div>
                    <div class="detail-row"><span class="detail-label">Message-ID</span><span class="detail-value" style="font-size:0.75rem">${esc(truncate(e.message_id, 40))}</span></div>
                </div>

                <div class="detail-section">
                    <h3>Analyst Actions</h3>
                    <div class="detail-row"><span class="detail-label">Action taken</span><span class="detail-value">${e.analyst_action ? `<span class="badge ${e.analyst_action === 'release' ? 'released' : e.analyst_action === 'quarantine' ? 'quarantined' : 'recu'}">${esc(e.analyst_action)}</span>` : '<span style="color:var(--text-muted)">Pending review</span>'}</span></div>
                    <div class="detail-row"><span class="detail-label">Notes</span><span class="detail-value">${e.analyst_notes ? esc(e.analyst_notes) : '<span style="color:var(--text-muted)">No notes yet</span>'}</span></div>
                    ${e.parse_errors && e.parse_errors.length > 0 ? `
                        <div class="detail-row"><span class="detail-label">Parse Errors</span><span class="detail-value" style="color:var(--color-escalated)">${esc(e.parse_errors.join(', '))}</span></div>
                    ` : ''}
                </div>
            </div>

            ${e.llm_reasoning ? `
                <div class="reasoning-card">
                    <h3>🤖 LLM Reasoning</h3>
                    <div class="reasoning-text">${esc(e.llm_reasoning)}</div>
                </div>
            ` : ''}

            ${signalsHtml ? `<h3 style="margin-bottom:12px;color:var(--text-muted);font-size:0.85rem;text-transform:uppercase;letter-spacing:0.06em">Security Signals</h3>${signalsHtml}` : ''}

            <div id="detonation-panel"></div>

            ${auditHtml}

            <div class="action-bar">
                ${userCan('emails.release') ? `<button class="btn btn-success" data-action="release-email" data-id="${parseInt(e.id)}">✓ Release</button>` : ''}
                ${userCan('emails.quarantine') ? `<button class="btn btn-danger" data-action="quarantine-email" data-id="${parseInt(e.id)}">🛡 Quarantine</button>` : ''}
                ${userCan('emails.override') ? `<button class="btn btn-outline" data-action="open-override-modal" data-id="${parseInt(e.id)}">Override Verdict</button>` : ''}
                ${e.analyst_action && userCan('emails.revert') ? `<button class="btn btn-outline" data-action="revert-action" data-id="${parseInt(e.id)}" title="Undo ${esc(e.analyst_action)} — return to escalated for re-review">Undo ${esc(e.analyst_action)}</button>` : ''}
                <div style="flex:1"></div>
                <span style="color:var(--text-muted);font-size:0.8rem">Email #${parseInt(e.id)}</span>
            </div>
        `;

        renderDetonationPanel(e);

    } catch (err) {
        container.innerHTML = `<div class="empty-state"><div class="emoji">❌</div><p>Error: ${esc(err.message)}</p></div>`;
    }
}

/* =========================================================================
   Detonation sandbox panel (CAPE integration)
   ========================================================================= */

let _detonationPollTimer = null;
let _activeRfb = null;

function _detonationStatusBadge(status) {
    const map = { queued: 'recu', running: 'escalated', done: 'accepted', error: 'quarantined' };
    return `<span class="badge ${map[status] || 'recu'}">${esc(status)}</span>`;
}

function _attachmentPreviewHtml(emailId, row) {
    const name = (row.filename || '').toLowerCase();
    const inline = /\.(pdf|png|jpe?g|gif)$/.test(name);
    const rawUrl = `/api/emails/${parseInt(emailId)}/attachments/${parseInt(row.id)}/raw`;
    if (inline) {
        // Server re-verifies via magic bytes and forces the content type; a
        // lying extension just yields a download instead of a render.
        return `<iframe class="sandbox-preview-frame" src="${rawUrl}" title="Attachment preview"></iframe>`;
    }
    return `
        <div class="sandbox-preview-meta">
            <div class="detail-row"><span class="detail-label">File</span>
                <span class="detail-value">${esc(truncate(row.filename, 60))}</span></div>
            <div class="detail-row"><span class="detail-label">SHA-256</span>
                <span class="detail-value" style="font-family:monospace;font-size:0.72rem">${esc(row.sha256)}</span></div>
            <div class="detail-row"><span class="detail-label">Queued because</span>
                <span class="detail-value">${esc(row.reason) || '—'}</span></div>
            <a class="btn btn-outline btn-sm" href="${rawUrl}" download>Download original (handle with care)</a>
        </div>`;
}

function _detonationRowHtml(e, row, windowActive) {
    const det = (e.enrichment_result && e.enrichment_result.detonation) || {};
    const result = row.result || {};
    const taskId = result.cape_task_id || det.cape_task_id || null;
    const reportUrl = result.web_report_url || det.web_report_url ||
        (taskId ? `/api/detonation/report/${parseInt(taskId)}/` : null);

    let body = '';
    if (row.status === 'queued' || row.status === 'running') {
        const live = (row.status === 'running' && windowActive && taskId)
            ? `<div class="sandbox-live" id="sandbox-live-${parseInt(row.id)}" data-task-id="${parseInt(taskId)}"></div>`
            : `<div class="sandbox-empty">
                   <div class="spinner"></div>
                   <p>${row.status === 'queued'
                        ? 'Queued for detonation — runs in the next drained window.'
                        : 'Detonation running…'}</p>
               </div>`;
        body = `
            <div class="sandbox-columns">
                <div>${_attachmentPreviewHtml(e.id, row)}</div>
                <div>${live}</div>
            </div>`;
    } else if (row.status === 'done' && reportUrl) {
        const score = (result.malscore !== undefined) ? result.malscore : det.malscore;
        const sigs = result.suspicious_behaviors || det.suspicious_behaviors || [];
        body = `
            <div class="sandbox-verdict">
                <span class="detail-label">Malscore</span>
                <strong>${score !== undefined ? esc(String(score)) : '—'} / 10</strong>
                ${sigs.length ? `<span class="detail-label">· ${parseInt(sigs.length)} signature(s)</span>` : ''}
                <a class="btn btn-outline btn-sm" href="${reportUrl}" target="_blank" rel="noopener">Open full report ↗</a>
                ${userCan('emails.scan')
                    ? `<button class="btn btn-outline btn-sm"
                         data-action="see-in-vm" data-pending-id="${parseInt(row.id)}" data-email-id="${parseInt(e.id)}">🖥 See in VM</button>`
                    : ''}
            </div>
            <iframe class="sandbox-report-frame" src="${reportUrl}" title="CAPE report"></iframe>
            <details style="margin-top:8px"><summary class="detail-label" style="cursor:pointer">Attachment preview</summary>
                ${_attachmentPreviewHtml(e.id, row)}</details>`;
    } else { // error (or done without a report)
        const errMsg = result.error || 'detonation failed';
        body = `
            <div class="sandbox-error">
                <p>⚠ Detonation failed: <code>${esc(errMsg)}</code>.
                   The email was escalated to human review (fail-safe).</p>
                ${userCan('emails.scan')
                    ? `<button class="btn btn-outline btn-sm"
                         data-action="detonation-retry" data-pending-id="${parseInt(row.id)}" data-email-id="${parseInt(e.id)}">↻ Retry detonation</button>
                       <button class="btn btn-outline btn-sm"
                         data-action="see-in-vm" data-pending-id="${parseInt(row.id)}" data-email-id="${parseInt(e.id)}">🖥 See in VM</button>`
                    : ''}
            </div>`;
    }

    return `
        <div class="sandbox-row">
            <div class="sandbox-row-head">
                <span>💣 ${esc(truncate(row.filename, 50))}</span>
                ${_detonationStatusBadge(row.status)}
                ${row.attempts > 1 ? `<span class="detail-label">attempt ${parseInt(row.attempts)}</span>` : ''}
                ${taskId ? `<span class="detail-label">CAPE task #${parseInt(taskId)}</span>` : ''}
            </div>
            ${body}
        </div>`;
}

async function renderDetonationPanel(e) {
    const panel = document.getElementById('detonation-panel');
    if (!panel) return;
    const rows = e.detonation_queue || [];
    if (rows.length === 0) { panel.innerHTML = ''; return; }

    let windowActive = false;
    try {
        const st = await API.get('/api/detonation/status');
        windowActive = !!st.window_active;
    } catch (_) { /* status endpoint down — panel still renders, no live view */ }

    const firstTask = (rows[0].result && rows[0].result.cape_task_id) || 0;
    panel.innerHTML = `
        <div class="detail-section" style="grid-column: 1 / -1; margin-bottom:16px">
            <h3>🔬 Detonation Sandbox
                <button class="btn btn-outline btn-sm" style="float:right"
                        data-action="open-sandbox-viewer" data-task-id="${parseInt(firstTask)}">Open sandbox</button>
            </h3>
            ${rows.map(r => _detonationRowHtml(e, r, windowActive)).join('')}
        </div>`;

    // Live noVNC for any row currently running inside an active window
    for (const r of rows) {
        const el = document.getElementById(`sandbox-live-${r.id}`);
        if (el) mountNoVnc(el, parseInt(el.dataset.taskId) || 0);
    }

    // Poll while anything is pending so the panel advances queued→running→done
    const pending = rows.some(r => r.status === 'queued' || r.status === 'running');
    clearInterval(_detonationPollTimer);
    if (pending) {
        _detonationPollTimer = setInterval(() => refreshDetonationPanel(e.id), 10000);
    }
}

async function refreshDetonationPanel(emailId) {
    if (!document.getElementById('detonation-panel')) {
        clearInterval(_detonationPollTimer);
        return;
    }
    try {
        const e = await API.get(`/api/emails/${emailId}`);
        renderDetonationPanel(e);
    } catch (_) { /* transient — next tick retries */ }
}

async function mountNoVnc(container, taskId, onFail) {
    try {
        if (_activeRfb) { try { _activeRfb.disconnect(); } catch (_) {} _activeRfb = null; }
        const mod = await import('/static/novnc/core/rfb.js');
        const RFB = mod.default;
        const token = document.querySelector('meta[name="ws-token"]')?.content || '';
        const proto = location.protocol === 'https:' ? 'wss' : 'ws';
        const url = `${proto}://${location.host}/ws/vnc/${parseInt(taskId) || 0}?token=${encodeURIComponent(token)}`;
        const rfb = new RFB(container, url);
        rfb.viewOnly = true;          // analyst watches; never drives the guest
        rfb.scaleViewport = true;
        rfb.addEventListener('disconnect', (ev) => {
            if (!ev.detail.clean) {
                container.innerHTML = `<div class="sandbox-empty"><p>Sandbox view unavailable
                    (window closed or relay refused). The verdict is unaffected.</p></div>`;
                // Retry on the next status poll instead of staying stuck: the VM is
                // often still booting (websockify not listening yet) when the first
                // connection attempt lands, and the window can stay active for
                // minutes after that transient failure.
                if (onFail) onFail();
            }
        });
        _activeRfb = rfb;
    } catch (err) {
        container.innerHTML = `<div class="sandbox-empty"><p>Sandbox view unavailable: ${esc(err.message)}</p></div>`;
        if (onFail) onFail();
    }
}

let _viewerPollTimer = null;

async function openSandboxViewer(taskId) {
    document.getElementById('sandbox-viewer-overlay')?.remove();
    clearInterval(_viewerPollTimer);

    const overlay = document.createElement('div');
    overlay.id = 'sandbox-viewer-overlay';
    overlay.className = 'sandbox-overlay';
    overlay.innerHTML = `
        <div class="sandbox-overlay-box">
            <div class="sandbox-overlay-head"><span>Sandbox</span>
                <button class="btn btn-outline btn-sm" data-action="close-sandbox-viewer">✕ Close</button></div>
            <div id="sandbox-viewer-body"></div>
        </div>`;
    document.body.appendChild(overlay);

    // Three honest states driven by /api/detonation/status:
    //   window_active + a running task  -> live noVNC feed
    //   window_active, nothing running  -> "starting" (drain + VM wake gap, 10-20s+)
    //   no window                       -> "no active session" (never a doomed spinner)
    let mounted = false;
    const render = async () => {
        const body = document.getElementById('sandbox-viewer-body');
        if (!body) { clearInterval(_viewerPollTimer); return; }
        let st = { window_active: false, by_status: {} };
        try { st = await API.get('/api/detonation/status'); } catch (_) {}
        const running = (st.by_status && st.by_status.running) || 0;

        if (st.window_active && running > 0) {
            if (!mounted) {
                body.innerHTML = '<div class="sandbox-live" id="sandbox-viewer-screen"></div>';
                mountNoVnc(document.getElementById('sandbox-viewer-screen'), parseInt(taskId) || 0,
                    () => { mounted = false; });
                mounted = true;
            }
        } else if (st.window_active) {
            mounted = false;
            body.innerHTML = `<div class="sandbox-empty"><div class="spinner"></div>
                <p><strong>Starting sandbox…</strong></p>
                <p>Draining RAM and waking the VM — the live view appears when the
                   sample starts running.</p></div>`;
        } else {
            mounted = false;
            body.innerHTML = `<div class="sandbox-empty"><div class="emoji">😴</div>
                <p><strong>No active session right now.</strong></p>
                <p>The detonation VM only runs during a drained analysis window.
                   The live view activates automatically when your queued sample runs.</p></div>`;
        }
    };
    await render();
    _viewerPollTimer = setInterval(render, 5000);
}

function closeSandboxViewer() {
    clearInterval(_viewerPollTimer);
    _viewerPollTimer = null;
    if (_activeRfb) { try { _activeRfb.disconnect(); } catch (_) {} _activeRfb = null; }
    document.getElementById('sandbox-viewer-overlay')?.remove();
    refreshDetonationBanner();
}

async function detonationRetry(pendingId, emailId) {
    try {
        await API.post(`/api/detonation/${pendingId}/retry`);
        showToast('Re-queued for detonation — runs in the next drained window', 'success');
        refreshDetonationPanel(emailId);
    } catch (err) {
        showToast(`Retry failed: ${err.message}`, 'error');
    }
}

/* --- Manual VM control ------------------------------------------------- */

function confirmVmSuspension(onConfirm) {
    document.getElementById('vm-warning-overlay')?.remove();
    const ov = document.createElement('div');
    ov.id = 'vm-warning-overlay';
    ov.className = 'modal-overlay open';
    ov.innerHTML = `
        <div class="modal">
            <h3>⚠ Suspend email analysis?</h3>
            <p>Email analysis will be <strong>temporarily suspended</strong> while the
               sandbox VM is running. Unprocessed mail stays safely on the IMAP server
               and is analyzed when the window closes.</p>
            <div class="action-bar" style="margin-top:16px">
                <button class="btn btn-outline" id="vm-warning-cancel">Cancel</button>
                <button class="btn btn-danger" id="vm-warning-confirm">Suspend analysis &amp; open VM</button>
            </div>
        </div>`;
    document.body.appendChild(ov);
    ov.querySelector('#vm-warning-cancel').onclick = () => ov.remove();
    ov.querySelector('#vm-warning-confirm').onclick = () => { ov.remove(); onConfirm(); };
}

async function _startWindowAndView() {
    try {
        const r = await API.post('/api/detonation/run-window');
        if (r.status === 'empty') {
            showToast('Nothing in the detonation queue — the sandbox only opens with work to run', 'warning');
            return;
        }
        refreshDetonationBanner();
        openSandboxViewer(0);
    } catch (err) {
        if (String(err.message).startsWith('API 409')) {
            openSandboxViewer(0);   // a window is already live — just show it
        } else {
            showToast(`Could not start sandbox window: ${err.message}`, 'error');
        }
    }
}

function openVmWindow() {
    confirmVmSuspension(_startWindowAndView);
}

function seeInVm(pendingId, emailId) {
    confirmVmSuspension(async () => {
        try {
            await API.post(`/api/detonation/${parseInt(pendingId)}/retry`);
        } catch (err) {
            // 409 = already queued/running — fine, keep going. Anything else is fatal.
            if (!String(err.message).startsWith('API 409')) {
                showToast(`Could not queue the sample: ${err.message}`, 'error');
                return;
            }
        }
        if (emailId) refreshDetonationPanel(parseInt(emailId));
        await _startWindowAndView();
    });
}

async function refreshDetonationBanner() {
    const banner = document.getElementById('detonation-banner');
    if (!banner) return;
    try {
        const st = await API.get('/api/detonation/status');
        banner.style.display = st.window_active ? 'block' : 'none';
        notifyManualReady(st.manual_ready, banner);
    } catch (_) { /* not permitted or transient — leave as-is */ }
}

// Branch-B manual detonations that just became ready → alert on any page
// (desktop notification + sound + banner). Fires once per detonation id.
function notifyManualReady(ready, banner) {
    window.__mdReadySeen = window.__mdReadySeen || {};
    (ready || []).forEach(function (row) {
        if (window.__mdReadySeen[row.id]) return;
        window.__mdReadySeen[row.id] = true;
        const msg = 'Emails analyzed — "' + (row.filename || 'your file') + '" is ready to open.';
        // 1) in-page banner
        if (banner) { banner.style.display = 'block'; banner.textContent = '✅ ' + msg; }
        // 2) desktop notification
        if ('Notification' in window && Notification.permission === 'granted') {
            try { new Notification('Attijari SOC — sandbox ready', { body: msg }); } catch (_) {}
        }
        // 3) sound cue (WebAudio beep — no asset, no CSP change)
        try {
            const ctx = new (window.AudioContext || window.webkitAudioContext)();
            const o = ctx.createOscillator(), g = ctx.createGain();
            o.type = 'sine'; o.frequency.value = 880; o.connect(g); g.connect(ctx.destination);
            g.gain.setValueAtTime(0.15, ctx.currentTime);
            g.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + 0.6);
            o.start(); o.stop(ctx.currentTime + 0.6);
        } catch (_) { /* audio unavailable — banner + notification still fire */ }
    });
}
setInterval(refreshDetonationBanner, 30000);
document.addEventListener('DOMContentLoaded', refreshDetonationBanner);

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
                <td><span class="badge ${e.indicator_type === 'email' ? 'escalated' : 'recu'}">${esc(e.indicator_type)}</span></td>
                <td style="font-family:monospace">${esc(e.value)}</td>
                <td>${esc(e.source)}</td>
                <td>${formatDate(e.created_at)}</td>
                <td>${userCan('blocklist.manage') ? `<button class="btn btn-outline btn-sm" data-action="remove-blocklist-entry" data-id="${parseInt(e.id)}">Remove</button>` : ''}</td>
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
                <td><span class="badge accepted">${esc(e.indicator_type)}</span></td>
                <td style="font-family:monospace">${esc(e.value)}</td>
                <td>${esc(e.reason) || '—'}</td>
                <td>${formatDate(e.created_at)}</td>
                <td>${userCan('whitelist.manage') ? `<button class="btn btn-outline btn-sm" data-action="remove-whitelist-entry" data-id="${parseInt(e.id)}">Remove</button>` : ''}</td>
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
                <span class="status-dot ${esc(c.status)}"></span>
                <strong>${esc(name.replace(/_/g, ' ').toUpperCase())}</strong>
                <div style="color:var(--text-muted);font-size:0.8rem;margin-top:6px">
                    Status: ${esc(c.status)}
                    ${c.age_hours ? ` · Age: ${parseFloat(c.age_hours)}h` : ''}
                    ${c.error ? ` · Error: ${esc(c.error)}` : ''}
                </div>
            </div>
        `).join('');
    } catch (err) {
        container.innerHTML = `<div class="empty-state"><p>Health check failed: ${esc(err.message)}</p></div>`;
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
                    <td>${esc(r.report_type)}</td>
                    <td>${formatDate(r.period_start)} → ${formatDate(r.period_end)}</td>
                    <td>${parseInt(counts.total) || 0} emails</td>
                    <td>${esc((r.delivered_via || []).join(', ')) || '—'}</td>
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

function confirmOverrideFromModal() {
    overrideEmail(document.getElementById('modal-overlay').dataset.emailId);
}

function closeReasonModal() {
    document.getElementById('reason-modal-overlay').classList.remove('open');
}


/* =========================================================================
   Admin Audit Panel
   ========================================================================= */

let currentAuditTool = '';

async function loadAuditPanel(tool = '') {
    currentAuditTool = tool;
    await Promise.all([
        loadToolHealth(tool),
        loadAlertHistory(tool),
        loadFeedbackHistory(),
    ]);
}

async function loadToolHealth(tool) {
    const grid = document.getElementById('tool-health-grid');
    const filters = document.getElementById('tool-filters');
    if (!grid) return;

    try {
        const data = await API.get('/api/audit/errors' + (tool ? `?tool=${tool}` : ''));
        const summary = data.tool_summary || {};

        // Build filter chips
        if (filters && !tool) {
            const tools = Object.keys(summary);
            filters.innerHTML = `<button class="chip active" data-tool="" data-action="filter-audit-tool">All Tools</button>` +
                tools.map(t => `<button class="chip" data-tool="${esc(t)}" data-action="filter-audit-tool">${esc(t)}</button>`).join('');
        }

        // Update active chip
        if (filters) {
            filters.querySelectorAll('.chip').forEach(c => {
                c.classList.toggle('active', c.dataset.tool === (tool || ''));
            });
        }

        const statusColors = {
            healthy: 'ok', warning: 'stale', degraded: 'error', critical: 'error', unknown: 'unavailable'
        };

        grid.innerHTML = Object.entries(summary).map(([name, s]) => `
            <div class="health-card" data-action="filter-audit-tool" data-tool="${esc(name)}" style="cursor:pointer">
                <span class="status-dot ${statusColors[s.status] || 'unavailable'}"></span>
                <strong>${esc(name.toUpperCase())}</strong>
                <div style="margin-top:10px;display:grid;grid-template-columns:1fr 1fr;gap:4px 16px;font-size:0.8rem;color:var(--text-secondary)">
                    <div>Calls: <strong style="color:var(--text-primary)">${parseInt(s.total_calls) || 0}</strong></div>
                    <div>Errors: <strong style="color:${s.failure_count > 0 ? 'var(--danger)' : 'var(--text-primary)'}">${parseInt(s.failure_count) || 0}</strong></div>
                    <div>Error Rate: <strong style="color:${s.error_rate > 0.3 ? 'var(--danger)' : 'var(--text-primary)'}">${(parseFloat(s.error_rate) * 100).toFixed(1)}%</strong></div>
                    <div>Consec. Fails: <strong style="color:${s.consecutive_failures >= 3 ? 'var(--danger)' : 'var(--text-primary)'}">${parseInt(s.consecutive_failures) || 0}</strong></div>
                    <div>Avg Latency: <strong>${s.avg_latency_s != null ? parseFloat(s.avg_latency_s).toFixed(2) + 's' : '—'}</strong></div>
                    <div>P95 Latency: <strong>${s.p95_latency_s != null ? parseFloat(s.p95_latency_s).toFixed(2) + 's' : '—'}</strong></div>
                </div>
                ${s.last_error ? `<div style="margin-top:8px;padding:8px;background:rgba(239,68,68,0.1);border-radius:var(--radius-sm);font-size:0.75rem;color:var(--danger);word-break:break-all">Last error: ${esc(s.last_error)}</div>` : ''}
                ${s.recent_errors && s.recent_errors.length > 0 ? `<div style="margin-top:6px;font-size:0.7rem;color:var(--text-muted)">${parseInt(s.recent_errors.length)} recent error(s)</div>` : ''}
            </div>
        `).join('');

        if (Object.keys(summary).length === 0) {
            grid.innerHTML = '<div class="empty-state"><p>No tool data available yet</p></div>';
        }
    } catch (err) {
        grid.innerHTML = `<div class="empty-state"><p>Failed to load: ${esc(err.message)}</p></div>`;
    }
}

async function loadAlertHistory(tool) {
    const tbody = document.getElementById('alert-table-body');
    if (!tbody) return;

    try {
        const data = await API.get('/api/audit/errors' + (tool ? `?tool=${tool}&limit=100` : '?limit=100'));
        const alerts = data.alerts || [];

        if (alerts.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="empty-state"><p>No alerts recorded</p></td></tr>';
            return;
        }

        const severityColors = {
            critical: 'var(--danger)', warning: 'var(--color-escalated)', info: 'var(--color-released)'
        };

        tbody.innerHTML = alerts.map(a => `
            <tr>
                <td style="font-size:0.8rem;white-space:nowrap">${formatDate(a.ts)}</td>
                <td><span class="badge recu">${esc(a.tool) || '—'}</span></td>
                <td style="font-family:monospace;font-size:0.8rem">${esc(a.alert_type) || '—'}</td>
                <td><span style="color:${severityColors[a.severity] || 'var(--text-muted)'};font-weight:600;text-transform:uppercase;font-size:0.75rem">${esc(a.severity) || '—'}</span></td>
                <td style="font-size:0.82rem;max-width:400px;word-break:break-word">${esc(a.message) || '—'}</td>
            </tr>
        `).join('');
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="5" class="empty-state"><p>Failed: ${esc(err.message)}</p></td></tr>`;
    }
}

async function loadFeedbackHistory() {
    const tbody = document.getElementById('feedback-table-body');
    if (!tbody) return;

    try {
        const data = await API.get('/api/feedback?per_page=100');
        const entries = data.entries || [];

        if (entries.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="empty-state"><p>No feedback yet — release or quarantine emails to generate learning data</p></td></tr>';
            return;
        }

        tbody.innerHTML = entries.map(fb => `
            <tr data-action="open-email" data-id="${parseInt(fb.email_id)}" style="cursor:pointer">
                <td style="white-space:nowrap">${formatDate(fb.created_at)}</td>
                <td>#${parseInt(fb.email_id)}</td>
                <td><span class="badge ${fb.action === 'release' ? 'released' : 'quarantined'}">${esc(fb.action)}</span></td>
                <td><span class="badge ${fb.pipeline_verdict || 'recu'}">${esc(fb.pipeline_verdict) || '—'}</span></td>
                <td style="font-family:monospace;font-size:0.82rem">${esc(fb.domain) || '—'}</td>
                <td>${fb.indicator_type ? `<span class="badge ${fb.indicator_type === 'whitelist' ? 'accepted' : 'escalated'}">${esc(fb.indicator_type)}</span>` : '—'}</td>
                <td style="max-width:300px;font-size:0.82rem;word-break:break-word">${esc(truncate(fb.reasoning, 80))}</td>
            </tr>
        `).join('');
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="7" class="empty-state"><p>Failed: ${esc(err.message)}</p></td></tr>`;
    }
}

function filterAuditTool(tool) {
    loadAuditPanel(tool);
}


/* =========================================================================
   WebSocket auto-refresh
   ========================================================================= */

function connectWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    // Get WS token from meta tag (set server-side, separate from httponly cookie)
    const wsMeta = document.querySelector('meta[name="ws-token"]');
    const wsToken = wsMeta ? wsMeta.content : '';
    const wsUrl = protocol + '//' + window.location.host + '/ws?token=' + encodeURIComponent(wsToken);
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

/* =========================================================================
   Action registrations (data-action / data-change-action / data-enter-action)
   ========================================================================= */
registerAction('open-email', (el) => { window.location = `/email/${el.dataset.id}`; });
registerAction('release-email', (el) => releaseEmail(parseInt(el.dataset.id)));
registerAction('quarantine-email', (el) => quarantineEmail(parseInt(el.dataset.id)));
registerAction('revert-action', (el) => revertAction(parseInt(el.dataset.id)));
registerAction('open-override-modal', (el) => openOverrideModal(parseInt(el.dataset.id)));
registerAction('load-inbox-page', (el) => loadInbox(parseInt(el.dataset.page), currentStatus, currentSearch));
registerAction('filter-by-status', (el) => filterByStatus(el.dataset.status));
registerAction('search-emails', () => searchEmails());
registerAction('trigger-scan', () => triggerScan());
registerAction('open-vm-window', () => openVmWindow());
registerAction('clear-selection', () => clearSelection());
registerAction('bulk-release', () => executeBulkAction('release'));
registerAction('bulk-quarantine', () => executeBulkAction('quarantine'));
registerAction('close-modal', () => closeModal());
registerAction('confirm-override', () => confirmOverrideFromModal());
registerAction('close-reason-modal', () => closeReasonModal());
registerAction('confirm-reason-action', () => confirmReasonAction());
registerAction('see-in-vm', (el) => seeInVm(parseInt(el.dataset.pendingId), parseInt(el.dataset.emailId)));
registerAction('detonation-retry', (el) => detonationRetry(parseInt(el.dataset.pendingId), parseInt(el.dataset.emailId)));
registerAction('open-sandbox-viewer', (el) => openSandboxViewer(parseInt(el.dataset.taskId)));
registerAction('close-sandbox-viewer', () => closeSandboxViewer());
registerAction('remove-blocklist-entry', (el) => removeBlocklistEntry(parseInt(el.dataset.id)));
registerAction('add-blocklist-entry', () => addBlocklistEntry());
registerAction('remove-whitelist-entry', (el) => removeWhitelistEntry(parseInt(el.dataset.id)));
registerAction('add-whitelist-entry', () => addWhitelistEntry());
registerAction('load-health', () => loadHealth());
registerAction('generate-report', () => generateReport());
registerAction('filter-audit-tool', (el) => filterAuditTool(el.dataset.tool));
registerAction('load-audit-panel', () => loadAuditPanel());

registerChangeAction('toggle-email-selection', (el) => toggleEmailSelection(parseInt(el.dataset.id), el.checked));
registerChangeAction('toggle-select-all', (el) => toggleSelectAll(el.checked));

registerEnterAction('search-emails', () => searchEmails());
