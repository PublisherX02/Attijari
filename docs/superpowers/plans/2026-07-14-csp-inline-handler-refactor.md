# CSP Inline-Handler Refactor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate all inline `onclick`/`onchange`/`onkeydown` attributes from the dashboard so `script-src` in `src/api.py` can drop `'unsafe-inline'` and use the per-request nonce that's already generated but currently unused for scripts.

**Architecture:** One delegated `click` listener, one delegated `change` listener, and one delegated `keydown` (Enter-key) listener, all added once in `dashboard.js`. Elements carry `data-action` / `data-change-action` / `data-enter-action` attributes naming a handler registered via `registerAction()` / `registerChangeAction()` / `registerEnterAction()`; handlers read parameters off the element's `dataset` instead of receiving them as literal arguments baked into HTML strings.

**Tech Stack:** Vanilla JS (`dashboard.js`), Jinja2 templates, FastAPI (`src/api.py`) for the CSP header.

## Global Constraints

- Every inline `onclick=`, `onchange=`, `onkeydown=` attribute across `src/dashboard/static/js/dashboard.js` and the 9 templates (`base.html`, `inbox.html`, `admin.html`, `history.html`, `whitelist.html`, `blocklist.html`, `audit.html`, `reports.html`, `health.html`) must be removed — confirmed count as of 2026-07-14: 66 `onclick`, 6 `onchange`, 1 `onkeydown`.
- `manual_detonation.html` / `manual_detonation.js` already have zero inline handlers — do not touch them.
- Do not add `event.stopPropagation()` calls when converting — delegation's `closest('[data-action]')` picking the nearest match makes them unnecessary; drop them.
- `style=""` inline style attributes are out of scope. `style-src 'unsafe-inline'` stays as-is.
- Phase 3 (CSP flip) must not land until phases 1–2 are done and manually verified in a browser — this is the exact class of regression (Jul 10 incident, `src/api.py:105-111` comment) that a test suite alone did not catch.
- Existing test suite (`tests/`) must stay green throughout.

---

### Task 1: Delegation infrastructure in `dashboard.js`

**Files:**
- Modify: `src/dashboard/static/js/dashboard.js:1-26` (insert after the `API` object)

**Interfaces:**
- Produces: `registerAction(name, fn)`, `registerChangeAction(name, fn)`, `registerEnterAction(name, fn)` — global functions (via `function` declarations, so they attach to `window` and are callable from every other inline `<script>` on the page, since those scripts load after `dashboard.js`). Also produces the `noop` action.

- [ ] **Step 1: Insert the delegation infrastructure**

In `src/dashboard/static/js/dashboard.js`, immediately after the closing `};` of the `API` object (currently line 26) and before the `/* --- Toast notifications --- */` comment, insert:

```js
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
```

- [ ] **Step 2: Verify the file still parses**

Run: `node --check src/dashboard/static/js/dashboard.js`
Expected: no output, exit code 0.

- [ ] **Step 3: Commit**

```bash
git add src/dashboard/static/js/dashboard.js
git commit -m "feat: add delegated action-dispatch infrastructure to dashboard.js"
```

---

### Task 2: Convert `dashboard.js`'s own 22 dynamic handlers + add 2 new helper functions

**Files:**
- Modify: `src/dashboard/static/js/dashboard.js` (multiple locations, listed below)

**Interfaces:**
- Consumes: `registerAction`, `registerChangeAction`, `registerEnterAction`, `noop`, `backdrop-close` from Task 1.
- Produces: `clearSelection()`, `confirmOverrideFromModal()` functions; all `data-action`/`data-change-action` names used by Task 2's own registrations (listed in the registration block below) — later tasks (templates) reference these same names.

- [ ] **Step 1: Convert the inbox row renderer (`loadInbox`, currently ~line 204-230)**

Find:
```js
        container.innerHTML = data.emails.map(e => `
            <tr onclick="window.location='/email/${parseInt(e.id)}'">
                ${canBulk ? `<td onclick="event.stopPropagation()">
                    <input type="checkbox" class="row-checkbox" data-id="${parseInt(e.id)}"
                        onchange="toggleEmailSelection(${parseInt(e.id)}, this.checked)">
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
                            ${canRelease ? `<button class="btn btn-success btn-sm" onclick="event.stopPropagation(); releaseEmail(${parseInt(e.id)})">Release</button>` : ''}
                            ${canQuarantine ? `<button class="btn btn-danger btn-sm" onclick="event.stopPropagation(); quarantineEmail(${parseInt(e.id)})">Quarantine</button>` : ''}
                        </div>
                    ` : e.analyst_action ? `
                        <div class="btn-group">
                            <span style="color:var(--text-muted)">${esc(e.analyst_action)}</span>
                            ${canRevert ? `<button class="btn btn-outline btn-sm" onclick="event.stopPropagation(); revertAction(${parseInt(e.id)})" title="Undo — return to escalated for re-review">Undo</button>` : ''}
                        </div>
                    ` : ''}
                </td>
            </tr>
        `).join('');
```

Replace with:
```js
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
```

- [ ] **Step 2: Convert `renderPagination` (currently ~line 251-253)**

Find:
```js
    if (page > 1) html += `<button class="btn btn-outline btn-sm" onclick="loadInbox(${page - 1}, currentStatus, currentSearch)">← Prev</button>`;
    html += `<span class="current-page">Page ${page} of ${pages} (${total} total)</span>`;
    if (page < pages) html += `<button class="btn btn-outline btn-sm" onclick="loadInbox(${page + 1}, currentStatus, currentSearch)">Next →</button>`;
```

Replace with:
```js
    if (page > 1) html += `<button class="btn btn-outline btn-sm" data-action="load-inbox-page" data-page="${page - 1}">← Prev</button>`;
    html += `<span class="current-page">Page ${page} of ${pages} (${total} total)</span>`;
    if (page < pages) html += `<button class="btn btn-outline btn-sm" data-action="load-inbox-page" data-page="${page + 1}">Next →</button>`;
```

- [ ] **Step 3: Add `clearSelection()` next to `executeBulkAction`**

Find (the closing brace of `executeBulkAction`, currently ~line 151):
```js
    } catch (err) {
        showToast(`Bulk ${action} failed: ${err.message}`, 'error');
    }
}

async function loadInbox(page = 1, status = null, search = '') {
```

Replace with:
```js
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
```

- [ ] **Step 4: Add `confirmOverrideFromModal()` next to `openOverrideModal`/`closeModal`**

Find (currently ~line 1044-1054):
```js
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
```

Replace with:
```js
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
```

- [ ] **Step 5: Convert the detail-page action bar (currently ~line 512-516)**

Find:
```js
                ${userCan('emails.release') ? `<button class="btn btn-success" onclick="releaseEmail(${parseInt(e.id)})">✓ Release</button>` : ''}
                ${userCan('emails.quarantine') ? `<button class="btn btn-danger" onclick="quarantineEmail(${parseInt(e.id)})">🛡 Quarantine</button>` : ''}
                ${userCan('emails.override') ? `<button class="btn btn-outline" onclick="openOverrideModal(${parseInt(e.id)})">Override Verdict</button>` : ''}
                ${e.analyst_action && userCan('emails.revert') ? `<button class="btn btn-outline" onclick="revertAction(${parseInt(e.id)})" title="Undo ${esc(e.analyst_action)} — return to escalated for re-review">Undo ${esc(e.analyst_action)}</button>` : ''}
```

Replace with:
```js
                ${userCan('emails.release') ? `<button class="btn btn-success" data-action="release-email" data-id="${parseInt(e.id)}">✓ Release</button>` : ''}
                ${userCan('emails.quarantine') ? `<button class="btn btn-danger" data-action="quarantine-email" data-id="${parseInt(e.id)}">🛡 Quarantine</button>` : ''}
                ${userCan('emails.override') ? `<button class="btn btn-outline" data-action="open-override-modal" data-id="${parseInt(e.id)}">Override Verdict</button>` : ''}
                ${e.analyst_action && userCan('emails.revert') ? `<button class="btn btn-outline" data-action="revert-action" data-id="${parseInt(e.id)}" title="Undo ${esc(e.analyst_action)} — return to escalated for re-review">Undo ${esc(e.analyst_action)}</button>` : ''}
```

- [ ] **Step 6: Convert the detonation panel's 4 buttons**

Find (currently ~line 593-596):
```js
                ${userCan('emails.scan')
                    ? `<button class="btn btn-outline btn-sm"
                         onclick="seeInVm(${parseInt(row.id)}, ${parseInt(e.id)})">🖥 See in VM</button>`
                    : ''}
```

Replace with:
```js
                ${userCan('emails.scan')
                    ? `<button class="btn btn-outline btn-sm"
                         data-action="see-in-vm" data-pending-id="${parseInt(row.id)}" data-email-id="${parseInt(e.id)}">🖥 See in VM</button>`
                    : ''}
```

Find (currently ~line 607-612):
```js
                ${userCan('emails.scan')
                    ? `<button class="btn btn-outline btn-sm"
                         onclick="detonationRetry(${parseInt(row.id)}, ${parseInt(e.id)})">↻ Retry detonation</button>
                       <button class="btn btn-outline btn-sm"
                         onclick="seeInVm(${parseInt(row.id)}, ${parseInt(e.id)})">🖥 See in VM</button>`
                    : ''}
```

Replace with:
```js
                ${userCan('emails.scan')
                    ? `<button class="btn btn-outline btn-sm"
                         data-action="detonation-retry" data-pending-id="${parseInt(row.id)}" data-email-id="${parseInt(e.id)}">↻ Retry detonation</button>
                       <button class="btn btn-outline btn-sm"
                         data-action="see-in-vm" data-pending-id="${parseInt(row.id)}" data-email-id="${parseInt(e.id)}">🖥 See in VM</button>`
                    : ''}
```

Find (currently ~line 644-645):
```js
                <button class="btn btn-outline btn-sm" style="float:right"
                        onclick="openSandboxViewer(${parseInt(firstTask)})">Open sandbox</button>
```

Replace with:
```js
                <button class="btn btn-outline btn-sm" style="float:right"
                        data-action="open-sandbox-viewer" data-task-id="${parseInt(firstTask)}">Open sandbox</button>
```

Find (currently ~line 710):
```js
                <button class="btn btn-outline btn-sm" onclick="closeSandboxViewer()">✕ Close</button></div>
```

Replace with:
```js
                <button class="btn btn-outline btn-sm" data-action="close-sandbox-viewer">✕ Close</button></div>
```

- [ ] **Step 7: Convert blocklist/whitelist remove buttons**

Find (currently ~line 888):
```js
                <td>${userCan('blocklist.manage') ? `<button class="btn btn-outline btn-sm" onclick="removeBlocklistEntry(${parseInt(e.id)})">Remove</button>` : ''}</td>
```

Replace with:
```js
                <td>${userCan('blocklist.manage') ? `<button class="btn btn-outline btn-sm" data-action="remove-blocklist-entry" data-id="${parseInt(e.id)}">Remove</button>` : ''}</td>
```

Find (currently ~line 937):
```js
                <td>${userCan('whitelist.manage') ? `<button class="btn btn-outline btn-sm" onclick="removeWhitelistEntry(${parseInt(e.id)})">Remove</button>` : ''}</td>
```

Replace with:
```js
                <td>${userCan('whitelist.manage') ? `<button class="btn btn-outline btn-sm" data-action="remove-whitelist-entry" data-id="${parseInt(e.id)}">Remove</button>` : ''}</td>
```

- [ ] **Step 8: Convert audit filter chips/cards and the feedback-history row**

Find (currently ~line 1084-1085):
```js
            filters.innerHTML = `<button class="chip active" data-tool="" onclick="filterAuditTool('')">All Tools</button>` +
                tools.map(t => `<button class="chip" data-tool="${esc(t)}" onclick="filterAuditTool('${esc(t)}')">${esc(t)}</button>`).join('');
```

Replace with:
```js
            filters.innerHTML = `<button class="chip active" data-tool="" data-action="filter-audit-tool">All Tools</button>` +
                tools.map(t => `<button class="chip" data-tool="${esc(t)}" data-action="filter-audit-tool">${esc(t)}</button>`).join('');
```

Find (currently ~line 1100):
```js
            <div class="health-card" onclick="filterAuditTool('${esc(name)}')" style="cursor:pointer">
```

Replace with:
```js
            <div class="health-card" data-action="filter-audit-tool" data-tool="${esc(name)}" style="cursor:pointer">
```

Find (currently ~line 1169):
```js
            <tr onclick="window.location='/email/${parseInt(fb.email_id)}'" style="cursor:pointer">
```

Replace with:
```js
            <tr data-action="open-email" data-id="${parseInt(fb.email_id)}" style="cursor:pointer">
```

- [ ] **Step 9: Add the consolidated registration block at the end of the file**

At the very end of `src/dashboard/static/js/dashboard.js` (after the final `connectWebSocket();` call), append:

```js

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
registerAction('close-modal', () => closeModal());
registerAction('confirm-override', () => confirmOverrideFromModal());
registerAction('close-reason-modal', () => document.getElementById('reason-modal-overlay').classList.remove('open'));
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
```

- [ ] **Step 10: Verify the file still parses**

Run: `node --check src/dashboard/static/js/dashboard.js`
Expected: no output, exit code 0.

- [ ] **Step 11: Commit**

```bash
git add src/dashboard/static/js/dashboard.js
git commit -m "refactor: convert dashboard.js dynamic onclick/onchange to data-action delegation"
```

---

### Task 3: Convert `base.html` (6 onclick — 2 modal backdrops × 2 handlers each, plus 2 buttons)

**Files:**
- Modify: `src/dashboard/templates/base.html:112,130-131,137,146-147`

**Interfaces:**
- Consumes: `backdrop-close`, `close-modal`, `confirm-override`, `close-reason-modal`, `confirm-reason-action` action names from Task 2.

- [ ] **Step 1: Convert the override modal (currently lines 112-134)**

Find:
```html
    <div class="modal-overlay" id="modal-overlay" onclick="if(event.target===this)closeModal()">
```

Replace with:
```html
    <div class="modal-overlay" id="modal-overlay" data-action="backdrop-close" data-close="closeModal">
```

Find:
```html
                <button class="btn btn-outline" onclick="closeModal()">Cancel</button>
                <button class="btn btn-primary" onclick="overrideEmail(document.getElementById('modal-overlay').dataset.emailId)">Confirm Override</button>
```

Replace with:
```html
                <button class="btn btn-outline" data-action="close-modal">Cancel</button>
                <button class="btn btn-primary" data-action="confirm-override">Confirm Override</button>
```

- [ ] **Step 2: Convert the reason modal (currently lines 137-150)**

Find:
```html
    <div class="modal-overlay" id="reason-modal-overlay" onclick="if(event.target===this)this.classList.remove('open')">
```

Replace with:
```html
    <div class="modal-overlay" id="reason-modal-overlay" data-action="backdrop-close" data-close="closeReasonModal">
```

Find:
```html
                <button class="btn btn-outline" onclick="document.getElementById('reason-modal-overlay').classList.remove('open')">Cancel</button>
                <button class="btn btn-primary" onclick="confirmReasonAction()">Confirm</button>
```

Replace with:
```html
                <button class="btn btn-outline" data-action="close-reason-modal">Cancel</button>
                <button class="btn btn-primary" data-action="confirm-reason-action">Confirm</button>
```

- [ ] **Step 3: Add the missing `closeReasonModal()` function and register it**

The backdrop-close for the reason modal needs a real `closeReasonModal` function on `window` (Task 2 only registered `close-reason-modal` as a data-action, not a bare function). In `src/dashboard/static/js/dashboard.js`, find (added in Task 2 Step 4, next to `confirmOverrideFromModal`):

```js
function confirmOverrideFromModal() {
    overrideEmail(document.getElementById('modal-overlay').dataset.emailId);
}
```

Replace with:
```js
function confirmOverrideFromModal() {
    overrideEmail(document.getElementById('modal-overlay').dataset.emailId);
}

function closeReasonModal() {
    document.getElementById('reason-modal-overlay').classList.remove('open');
}
```

And in the registration block (end of file), find:
```js
registerAction('close-reason-modal', () => document.getElementById('reason-modal-overlay').classList.remove('open'));
```

Replace with:
```js
registerAction('close-reason-modal', () => closeReasonModal());
```

- [ ] **Step 4: Verify template renders**

Run: `python -c "from jinja2 import Environment, FileSystemLoader; e = Environment(loader=FileSystemLoader('src/dashboard/templates')); e.get_template('base.html')"`
Expected: no output, exit code 0 (syntax-valid Jinja2).

- [ ] **Step 5: Commit**

```bash
git add src/dashboard/templates/base.html src/dashboard/static/js/dashboard.js
git commit -m "refactor: convert base.html modals to data-action delegation"
```

---

### Task 4: Convert `inbox.html` (13 onclick, 1 onchange, 1 onkeydown)

**Files:**
- Modify: `src/dashboard/templates/inbox.html:12-13,30-31,35-41,49,52,54,63`

**Interfaces:**
- Consumes: `trigger-scan`, `open-vm-window`, `search-emails` (both click and enter), `filter-by-status`, `clear-selection`, `toggle-select-all` action names from Task 2.

- [ ] **Step 1: Convert the header buttons (currently lines 12-13)**

Find:
```html
        <button class="btn btn-primary" id="scan-btn" onclick="triggerScan()">🔄 Scan Now</button>
        <button class="btn btn-outline" id="open-vm-btn" onclick="openVmWindow()">🔬 Open sandbox VM</button>
```

Replace with:
```html
        <button class="btn btn-primary" id="scan-btn" data-action="trigger-scan">🔄 Scan Now</button>
        <button class="btn btn-outline" id="open-vm-btn" data-action="open-vm-window">🔬 Open sandbox VM</button>
```

- [ ] **Step 2: Convert the search bar (currently lines 30-31)**

Find:
```html
    <input type="text" class="form-input" id="search-input" placeholder="Search by sender, subject, or domain…" onkeydown="if(event.key==='Enter')searchEmails()">
    <button class="btn btn-primary" onclick="searchEmails()">Search</button>
```

Replace with:
```html
    <input type="text" class="form-input" id="search-input" placeholder="Search by sender, subject, or domain…" data-enter-action="search-emails">
    <button class="btn btn-primary" data-action="search-emails">Search</button>
```

- [ ] **Step 3: Convert the filter chips (currently lines 35-41)**

Find:
```html
    <button class="chip active" data-status="" onclick="filterByStatus('')">All</button>
    <button class="chip" data-status="pending" onclick="filterByStatus('pending')">⏳ Scanning</button>
    <button class="chip" data-status="escalated" onclick="filterByStatus('escalated')">⚠️ Escalated</button>
    <button class="chip" data-status="accepted" onclick="filterByStatus('accepted')">✅ Accepted</button>
    <button class="chip" data-status="quarantined" onclick="filterByStatus('quarantined')">🔴 Quarantined</button>
    <button class="chip" data-status="released" onclick="filterByStatus('released')">🔵 Released</button>
    <button class="chip" data-status="recu" onclick="filterByStatus('recu')">🟣 Received</button>
```

Replace with:
```html
    <button class="chip active" data-status="" data-action="filter-by-status">All</button>
    <button class="chip" data-status="pending" data-action="filter-by-status">⏳ Scanning</button>
    <button class="chip" data-status="escalated" data-action="filter-by-status">⚠️ Escalated</button>
    <button class="chip" data-status="accepted" data-action="filter-by-status">✅ Accepted</button>
    <button class="chip" data-status="quarantined" data-action="filter-by-status">🔴 Quarantined</button>
    <button class="chip" data-status="released" data-action="filter-by-status">🔵 Released</button>
    <button class="chip" data-status="recu" data-action="filter-by-status">🟣 Received</button>
```

- [ ] **Step 4: Convert the bulk action bar (currently lines 49,52,54)**

Find:
```html
    <button id="bulk-release-btn" class="btn btn-success btn-sm" onclick="executeBulkAction('release')">Release Selected</button>
    {% endif %}
    {% if role == 'admin' or permissions.get('emails.quarantine', False) %}
    <button id="bulk-quarantine-btn" class="btn btn-danger btn-sm" onclick="executeBulkAction('quarantine')">Quarantine Selected</button>
    {% endif %}
    <button class="btn btn-outline btn-sm" onclick="selectedEmailIds.clear();document.querySelectorAll('.row-checkbox').forEach(c=>c.checked=false);updateBulkBar()">Clear Selection</button>
```

Replace with:
```html
    <button id="bulk-release-btn" class="btn btn-success btn-sm" data-action="bulk-release">Release Selected</button>
    {% endif %}
    {% if role == 'admin' or permissions.get('emails.quarantine', False) %}
    <button id="bulk-quarantine-btn" class="btn btn-danger btn-sm" data-action="bulk-quarantine">Quarantine Selected</button>
    {% endif %}
    <button class="btn btn-outline btn-sm" data-action="clear-selection">Clear Selection</button>
```

- [ ] **Step 5: Register the two bulk action names**

`executeBulkAction('release')` / `executeBulkAction('quarantine')` need dedicated action names since delegation handlers take no literal argument beyond the element. In `src/dashboard/static/js/dashboard.js`, in the registration block added in Task 2 Step 9, find:

```js
registerAction('clear-selection', () => clearSelection());
```

Replace with:
```js
registerAction('clear-selection', () => clearSelection());
registerAction('bulk-release', () => executeBulkAction('release'));
registerAction('bulk-quarantine', () => executeBulkAction('quarantine'));
```

- [ ] **Step 6: Convert the select-all checkbox (currently line 63)**

Find:
```html
                <th style="width:36px">{% if role == 'admin' or permissions.get('emails.bulk', False) %}<input type="checkbox" id="select-all-checkbox" title="Select all" onchange="toggleSelectAll(this.checked)">{% endif %}</th>
```

Replace with:
```html
                <th style="width:36px">{% if role == 'admin' or permissions.get('emails.bulk', False) %}<input type="checkbox" id="select-all-checkbox" title="Select all" data-change-action="toggle-select-all">{% endif %}</th>
```

- [ ] **Step 7: Verify template renders**

Run: `python -c "from jinja2 import Environment, FileSystemLoader; e = Environment(loader=FileSystemLoader('src/dashboard/templates')); e.get_template('inbox.html')"`
Expected: no output, exit code 0.

- [ ] **Step 8: Verify dashboard.js still parses**

Run: `node --check src/dashboard/static/js/dashboard.js`
Expected: no output, exit code 0.

- [ ] **Step 9: Commit**

```bash
git add src/dashboard/templates/inbox.html src/dashboard/static/js/dashboard.js
git commit -m "refactor: convert inbox.html to data-action delegation"
```

---

### Task 5: Convert `admin.html` (16 onclick, 2 onchange — static markup + its own inline script's dynamic rows)

**Files:**
- Modify: `src/dashboard/templates/admin.html:7,31,44,55-56,62,68,86-87,93,107,112,121-122,170-173`

**Interfaces:**
- Consumes: `backdrop-close` from Task 1. Produces (page-local, registered from within `admin.html`'s own `<script nonce>` block, calling the global `registerAction` from Task 1): `open-create-modal`, `close-create-modal`, `create-user`, `close-edit-modal`, `save-user`, `close-totp-modal`, `close-reset-pw-modal`, `open-edit-modal`, `reset-password`, `reset-totp`, `deactivate-user`.

- [ ] **Step 1: Convert the page header button (currently line 7)**

Find:
```html
    <button class="btn btn-primary" onclick="openCreateModal()">+ Create User</button>
```

Replace with:
```html
    <button class="btn btn-primary" data-action="open-create-modal">+ Create User</button>
```

- [ ] **Step 2: Convert the Create User modal (currently lines 31,44,55-56)**

Find:
```html
<div class="modal-overlay" id="create-modal" onclick="if(event.target===this)closeCreateModal()">
```

Replace with:
```html
<div class="modal-overlay" id="create-modal" data-action="backdrop-close" data-close="closeCreateModal">
```

Find:
```html
            <select class="form-select" id="new-role" onchange="applyRoleDefaults()">
```

Replace with:
```html
            <select class="form-select" id="new-role" data-change-action="apply-role-defaults">
```

Find:
```html
            <button class="btn btn-outline" onclick="closeCreateModal()">Cancel</button>
            <button class="btn btn-primary" onclick="createUser()">Create User</button>
```

Replace with:
```html
            <button class="btn btn-outline" data-action="close-create-modal">Cancel</button>
            <button class="btn btn-primary" data-action="create-user">Create User</button>
```

- [ ] **Step 3: Convert the Edit User modal (currently lines 62,68,86-87)**

Find:
```html
<div class="modal-overlay" id="edit-modal" onclick="if(event.target===this)closeEditModal()">
```

Replace with:
```html
<div class="modal-overlay" id="edit-modal" data-action="backdrop-close" data-close="closeEditModal">
```

Find:
```html
            <select class="form-select" id="edit-role" onchange="applyEditRoleDefaults()">
```

Replace with:
```html
            <select class="form-select" id="edit-role" data-change-action="apply-edit-role-defaults">
```

Find:
```html
            <button class="btn btn-outline" onclick="closeEditModal()">Cancel</button>
            <button class="btn btn-primary" onclick="saveUser()">Save Changes</button>
```

Replace with:
```html
            <button class="btn btn-outline" data-action="close-edit-modal">Cancel</button>
            <button class="btn btn-primary" data-action="save-user">Save Changes</button>
```

- [ ] **Step 4: Convert the TOTP modal (currently lines 93,107)**

Find:
```html
<div class="modal-overlay" id="totp-modal" onclick="if(event.target===this)closeTotpModal()">
```

Replace with:
```html
<div class="modal-overlay" id="totp-modal" data-action="backdrop-close" data-close="closeTotpModal">
```

Find:
```html
        <button class="btn btn-primary" onclick="closeTotpModal()" style="margin-top:12px;">Done</button>
```

Replace with:
```html
        <button class="btn btn-primary" data-action="close-totp-modal" style="margin-top:12px;">Done</button>
```

- [ ] **Step 5: Convert the Reset Password modal (currently lines 112,121-122)**

Find:
```html
<div class="modal-overlay" id="reset-pw-modal" onclick="if(event.target===this)this.classList.remove('open')">
```

Replace with:
```html
<div class="modal-overlay" id="reset-pw-modal" data-action="backdrop-close" data-close="closeResetPwModal">
```

Find:
```html
            <button class="btn btn-outline" onclick="document.getElementById('reset-pw-modal').classList.remove('open')">Cancel</button>
            <button class="btn btn-primary" onclick="confirmResetPassword()">Reset Password</button>
```

Replace with:
```html
            <button class="btn btn-outline" data-action="close-reset-pw-modal">Cancel</button>
            <button class="btn btn-primary" data-action="confirm-reset-password">Reset Password</button>
```

- [ ] **Step 6: Convert the dynamically-rendered user-row buttons in the page's own `<script>` block (currently lines 170-173)**

Find:
```js
                    <button class="btn btn-outline btn-sm" onclick="openEditModal(${u.id})" title="Edit">Edit</button>
                    <button class="btn btn-outline btn-sm" onclick="resetPassword(${u.id}, '${esc(u.username)}')" title="Reset password">PW</button>
                    <button class="btn btn-outline btn-sm" onclick="resetTotp(${u.id}, '${esc(u.username)}')" title="Reset 2FA">2FA</button>
                    ${u.role !== 'admin' ? `<button class="btn btn-outline btn-sm" style="color:#e74c3c;" onclick="deactivateUser(${u.id}, '${esc(u.username)}')" title="Deactivate">X</button>` : ''}
```

Replace with:
```js
                    <button class="btn btn-outline btn-sm" data-action="open-edit-modal" data-id="${u.id}" title="Edit">Edit</button>
                    <button class="btn btn-outline btn-sm" data-action="reset-password" data-id="${u.id}" data-username="${esc(u.username)}" title="Reset password">PW</button>
                    <button class="btn btn-outline btn-sm" data-action="reset-totp" data-id="${u.id}" data-username="${esc(u.username)}" title="Reset 2FA">2FA</button>
                    ${u.role !== 'admin' ? `<button class="btn btn-outline btn-sm" style="color:#e74c3c;" data-action="deactivate-user" data-id="${u.id}" data-username="${esc(u.username)}" title="Deactivate">X</button>` : ''}
```

- [ ] **Step 7: Add `closeResetPwModal()` and register all admin.html action names**

Find (currently the `closeEditModal` function definition):
```js
function closeEditModal() { document.getElementById('edit-modal').classList.remove('open'); editUserData = null; }
```

Replace with:
```js
function closeEditModal() { document.getElementById('edit-modal').classList.remove('open'); editUserData = null; }
function closeResetPwModal() { document.getElementById('reset-pw-modal').classList.remove('open'); }
```

Find (the final lines of the file, currently):
```js
// Initial load
loadUsers();
```

Replace with:
```js
// ----- Action registrations -----
registerAction('open-create-modal', () => openCreateModal());
registerAction('close-create-modal', () => closeCreateModal());
registerAction('create-user', () => createUser());
registerChangeAction('apply-role-defaults', () => applyRoleDefaults());
registerAction('close-edit-modal', () => closeEditModal());
registerAction('save-user', () => saveUser());
registerChangeAction('apply-edit-role-defaults', () => applyEditRoleDefaults());
registerAction('close-totp-modal', () => closeTotpModal());
registerAction('close-reset-pw-modal', () => closeResetPwModal());
registerAction('confirm-reset-password', () => confirmResetPassword());
registerAction('open-edit-modal', (el) => openEditModal(parseInt(el.dataset.id)));
registerAction('reset-password', (el) => resetPassword(parseInt(el.dataset.id), el.dataset.username));
registerAction('reset-totp', (el) => resetTotp(parseInt(el.dataset.id), el.dataset.username));
registerAction('deactivate-user', (el) => deactivateUser(parseInt(el.dataset.id), el.dataset.username));

// Initial load
loadUsers();
```

- [ ] **Step 8: Verify template renders**

Run: `python -c "from jinja2 import Environment, FileSystemLoader; e = Environment(loader=FileSystemLoader('src/dashboard/templates')); e.get_template('admin.html')"`
Expected: no output, exit code 0.

- [ ] **Step 9: Commit**

```bash
git add src/dashboard/templates/admin.html
git commit -m "refactor: convert admin.html to data-action delegation"
```

---

### Task 6: Convert `history.html` (3 onclick, 2 onchange)

**Files:**
- Modify: `src/dashboard/templates/history.html:10,17,23,274,276`

**Interfaces:**
- Produces (page-local): `refresh-history`, `filter-history` (change), pagination handled inline since `loadHistory` is page-local.

- [ ] **Step 1: Convert the Refresh button and the two filter selects (currently lines 10,17,23)**

Find:
```html
    <button class="btn btn-outline" onclick="loadHistory()">Refresh</button>
```

Replace with:
```html
    <button class="btn btn-outline" data-action="refresh-history">Refresh</button>
```

Find:
```html
        <select class="form-select" id="filter-actor" onchange="loadHistory()" style="min-width:140px;padding:6px 10px;font-size:0.85rem">
```

Replace with:
```html
        <select class="form-select" id="filter-actor" data-change-action="filter-history" style="min-width:140px;padding:6px 10px;font-size:0.85rem">
```

Find:
```html
        <select class="form-select" id="filter-action" onchange="loadHistory()" style="min-width:160px;padding:6px 10px;font-size:0.85rem">
```

Replace with:
```html
        <select class="form-select" id="filter-action" data-change-action="filter-history" style="min-width:160px;padding:6px 10px;font-size:0.85rem">
```

- [ ] **Step 2: Convert the pagination buttons in the page's own `<script>` block (currently lines 274,276)**

Find:
```js
            if (currentPage > 1) html += `<button class="btn btn-outline btn-sm" onclick="loadHistory(${currentPage - 1})">Prev</button>`;
            html += `<span style="color:var(--text-muted);font-size:0.85rem;padding:6px">Page ${data.page} of ${data.pages}</span>`;
            if (currentPage < data.pages) html += `<button class="btn btn-outline btn-sm" onclick="loadHistory(${currentPage + 1})">Next</button>`;
```

Replace with:
```js
            if (currentPage > 1) html += `<button class="btn btn-outline btn-sm" data-action="load-history-page" data-page="${currentPage - 1}">Prev</button>`;
            html += `<span style="color:var(--text-muted);font-size:0.85rem;padding:6px">Page ${data.page} of ${data.pages}</span>`;
            if (currentPage < data.pages) html += `<button class="btn btn-outline btn-sm" data-action="load-history-page" data-page="${currentPage + 1}">Next</button>`;
```

- [ ] **Step 3: Register the action names**

Find (currently the last line of the file, before the closing `</script>`):
```js
document.addEventListener('DOMContentLoaded', () => loadHistory());
```

Replace with:
```js
registerAction('refresh-history', () => loadHistory());
registerChangeAction('filter-history', () => loadHistory());
registerAction('load-history-page', (el) => loadHistory(parseInt(el.dataset.page)));

document.addEventListener('DOMContentLoaded', () => loadHistory());
```

- [ ] **Step 4: Verify template renders**

Run: `python -c "from jinja2 import Environment, FileSystemLoader; e = Environment(loader=FileSystemLoader('src/dashboard/templates')); e.get_template('history.html')"`
Expected: no output, exit code 0.

- [ ] **Step 5: Commit**

```bash
git add src/dashboard/templates/history.html
git commit -m "refactor: convert history.html to data-action delegation"
```

---

### Task 7: Convert `audit.html` (2 onclick)

**Files:**
- Modify: `src/dashboard/templates/audit.html:10,15`

**Interfaces:**
- Consumes: `load-audit-panel`, `filter-audit-tool` (registered in Task 2).

- [ ] **Step 1: Convert the Refresh button and the "All Tools" chip**

Find:
```html
    <button class="btn btn-outline" onclick="loadAuditPanel()">Refresh</button>
```

Replace with:
```html
    <button class="btn btn-outline" data-action="load-audit-panel">Refresh</button>
```

Find:
```html
    <button class="chip active" data-tool="" onclick="filterAuditTool('')">All Tools</button>
```

Replace with:
```html
    <button class="chip active" data-tool="" data-action="filter-audit-tool">All Tools</button>
```

- [ ] **Step 2: Verify template renders**

Run: `python -c "from jinja2 import Environment, FileSystemLoader; e = Environment(loader=FileSystemLoader('src/dashboard/templates')); e.get_template('audit.html')"`
Expected: no output, exit code 0.

- [ ] **Step 3: Commit**

```bash
git add src/dashboard/templates/audit.html
git commit -m "refactor: convert audit.html to data-action delegation"
```

---

### Task 8: Convert `whitelist.html`, `blocklist.html`, `reports.html`, `health.html` (1 onclick each)

**Files:**
- Modify: `src/dashboard/templates/whitelist.html:33`
- Modify: `src/dashboard/templates/blocklist.html:30`
- Modify: `src/dashboard/templates/reports.html:11`
- Modify: `src/dashboard/templates/health.html:11`

**Interfaces:**
- Consumes: `add-whitelist-entry`, `add-blocklist-entry`, `generate-report`, `load-health` (all registered in Task 2).

- [ ] **Step 1: Convert `whitelist.html`**

Find:
```html
        <button class="btn btn-success" onclick="addWhitelistEntry()" style="height:42px;">✅ Whitelist</button>
```

Replace with:
```html
        <button class="btn btn-success" data-action="add-whitelist-entry" style="height:42px;">✅ Whitelist</button>
```

- [ ] **Step 2: Convert `blocklist.html`**

Find:
```html
        <button class="btn btn-danger" onclick="addBlocklistEntry()" style="height:42px;">🚫 Block</button>
```

Replace with:
```html
        <button class="btn btn-danger" data-action="add-blocklist-entry" style="height:42px;">🚫 Block</button>
```

- [ ] **Step 3: Convert `reports.html`**

Find:
```html
    <button class="btn btn-primary" onclick="generateReport()">📊 Generate Report Now</button>
```

Replace with:
```html
    <button class="btn btn-primary" data-action="generate-report">📊 Generate Report Now</button>
```

- [ ] **Step 4: Convert `health.html`**

Find:
```html
    <button class="btn btn-outline" onclick="loadHealth()">🔄 Refresh</button>
```

Replace with:
```html
    <button class="btn btn-outline" data-action="load-health">🔄 Refresh</button>
```

- [ ] **Step 5: Verify all four templates render**

Run:
```bash
python -c "
from jinja2 import Environment, FileSystemLoader
e = Environment(loader=FileSystemLoader('src/dashboard/templates'))
for t in ['whitelist.html', 'blocklist.html', 'reports.html', 'health.html']:
    e.get_template(t)
print('OK')
"
```
Expected: `OK`, exit code 0.

- [ ] **Step 6: Commit**

```bash
git add src/dashboard/templates/whitelist.html src/dashboard/templates/blocklist.html src/dashboard/templates/reports.html src/dashboard/templates/health.html
git commit -m "refactor: convert whitelist/blocklist/reports/health pages to data-action delegation"
```

---

### Task 9: Browser-verify every converted page before touching CSP

**Files:** none (manual verification checkpoint — no code changes)

This task is the gate the design doc calls out as non-negotiable: the Jul 10 incident happened because a CSP-adjacent change shipped without clicking through the UI. Do not proceed to Task 10 until every item below has been clicked in a real browser against the running dashboard (`CSP_WRAPPER` still has `'unsafe-inline'` at this point, so nothing should look broken yet — this pass is to catch mistakes in Tasks 2-8 before they're masked or unmasked by the CSP flip):

- [ ] Inbox: row click opens email detail; checkbox click does NOT navigate; Release/Quarantine/Undo buttons work and do NOT also navigate the row; pagination Prev/Next; status filter chips; search box (button AND pressing Enter); bulk select-all checkbox; bulk Release/Quarantine/Clear Selection buttons; Scan Now; Open sandbox VM.
- [ ] Email detail page: Release/Quarantine/Override Verdict/Undo buttons; override modal open, backdrop-click-to-close, Cancel, Confirm Override; reason modal open, backdrop-click-to-close, Cancel, Confirm.
- [ ] Detonation panel (on an email with a queued/running/done/error attachment): Open sandbox, See in VM, Retry detonation, sandbox viewer Close button.
- [ ] Admin: Create User button/modal (backdrop close, Cancel, Create, role-select onchange), Edit/PW/2FA/Deactivate buttons per row, Edit modal (backdrop close, Cancel, Save, role-select onchange), TOTP modal Done button, Reset Password modal (backdrop close, Cancel, Reset Password).
- [ ] History: Refresh, actor filter select, action filter select, pagination Prev/Next.
- [ ] Audit panel: Refresh, "All Tools" chip, per-tool chips (rendered dynamically), health-card click-to-filter.
- [ ] Blocklist: Block button, per-row Remove button.
- [ ] Whitelist: Whitelist button, per-row Remove button.
- [ ] Reports: Generate Report Now button.
- [ ] Health: Refresh button.

If anything doesn't respond, check the browser console for `Unknown data-action:` / `Unknown data-change-action:` errors (Task 1's dispatcher logs these) — that pinpoints a missing registration before you ever touch the CSP header.

---

### Task 10: Flip the CSP `script-src` header and add a regression test

**Files:**
- Modify: `src/api.py:103-121`
- Create: `tests/test_csp_no_inline_handlers.py`

**Interfaces:**
- Consumes: `request.state.csp_nonce` (already produced at `src/api.py:87-89`, unchanged).

- [ ] **Step 1: Write the regression test first**

Create `tests/test_csp_no_inline_handlers.py`:

```python
"""
Regression test for the Jul 10 incident: a CSP script-src change that silently
disabled every inline onclick/onchange handler in the dashboard for 3 days
because the app wasn't restarted. This test makes two independent guarantees
so the class of bug can't recur silently:
  1. No dashboard source file re-introduces an inline event-handler attribute.
  2. The CSP header's script-src directive is nonce-based, not unsafe-inline.
"""
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DASHBOARD_DIR = REPO_ROOT / "src" / "dashboard"

INLINE_HANDLER_RE = re.compile(r'\bon(?:click|change|keydown|keyup|keypress|submit|input)\s*=')


def _dashboard_source_files():
    files = list((DASHBOARD_DIR / "templates").glob("*.html"))
    files += list((DASHBOARD_DIR / "static" / "js").glob("*.js"))
    return files


def test_no_inline_event_handler_attributes_remain():
    offenders = []
    for path in _dashboard_source_files():
        text = path.read_text(encoding="utf-8")
        for match in INLINE_HANDLER_RE.finditer(text):
            line_no = text.count("\n", 0, match.start()) + 1
            offenders.append(f"{path.relative_to(REPO_ROOT)}:{line_no}")
    assert not offenders, f"Inline event-handler attributes found: {offenders}"


def test_csp_script_src_is_nonce_based_not_unsafe_inline():
    api_source = (REPO_ROOT / "src" / "api.py").read_text(encoding="utf-8")
    match = re.search(r'script-src[^;]*', api_source)
    assert match, "Could not find a script-src directive in src/api.py"
    directive = match.group(0)
    assert "'unsafe-inline'" not in directive, (
        "script-src still contains 'unsafe-inline' — nonce-based CSP was not applied "
        "(or was silently reverted, as happened on Jul 10)."
    )
    assert "nonce-" in directive, "script-src does not reference the per-request nonce"
```

- [ ] **Step 2: Run the new test and confirm it FAILS on the current (pre-flip) CSP header**

Run: `pytest tests/test_csp_no_inline_handlers.py -v`
Expected: `test_no_inline_event_handler_attributes_remain` PASSES (Tasks 2-8 already removed every inline handler); `test_csp_script_src_is_nonce_based_not_unsafe_inline` FAILS, because `src/api.py` still emits `'unsafe-inline'`.

- [ ] **Step 3: Flip the CSP header**

In `src/api.py`, find:
```python
    response.headers["Content-Security-Policy"] = (
        f"default-src 'self'; "
        # 'unsafe-inline' is required: the dashboard wires ~70 inline
        # onclick=""/onchange="" attributes (JS-generated rows + templates),
        # which a nonce can never authorize — the Jul 10 nonce-only policy
        # silently disabled every button in the UI. The nonce must NOT be
        # emitted alongside 'unsafe-inline' (browsers then ignore the latter).
        # Re-tightening requires first refactoring all inline handlers to
        # addEventListener/delegation.
        f"script-src 'self' 'unsafe-inline'; "
        # style-src keeps 'unsafe-inline': inline style="" attributes cannot use
        # a nonce, and inline styles are not the injection risk scripts are.
        f"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        f"connect-src 'self' ws: wss:; "
        # Same-origin iframes only: the proxied CAPE report and the /raw
        # attachment preview. Nothing cross-origin is ever framed.
        f"frame-src 'self'; "
        f"font-src 'self' https://fonts.gstatic.com"
    )
```

Replace with:
```python
    response.headers["Content-Security-Policy"] = (
        f"default-src 'self'; "
        # All inline onclick/onchange/onkeydown attributes were refactored to
        # data-action delegation (see docs/superpowers/plans/2026-07-14-csp-inline-handler-refactor.md).
        # script-src is nonce-only — do NOT add 'unsafe-inline' back alongside
        # the nonce (browsers ignore 'unsafe-inline' whenever a nonce is present,
        # which is exactly what caused the Jul 10 incident in the other direction).
        f"script-src 'self' 'nonce-{nonce}'; "
        # style-src keeps 'unsafe-inline': inline style="" attributes cannot use
        # a nonce, and inline styles are not the injection risk scripts are.
        f"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        f"connect-src 'self' ws: wss:; "
        # Same-origin iframes only: the proxied CAPE report and the /raw
        # attachment preview. Nothing cross-origin is ever framed.
        f"frame-src 'self'; "
        f"font-src 'self' https://fonts.gstatic.com"
    )
```

- [ ] **Step 4: Run the regression test and confirm it now PASSES**

Run: `pytest tests/test_csp_no_inline_handlers.py -v`
Expected: both tests PASS.

- [ ] **Step 5: Run the full test suite**

Run: `pytest -v`
Expected: all tests pass (same pass count as before this plan, plus the 2 new tests).

- [ ] **Step 6: Restart the dashboard server and browser-verify again, end to end**

The dashboard only picks up `src/api.py` changes on restart (per the CLAUDE.md build log: "the server only runs while the `start.bat` console window is open"). Restart it, then re-run the FULL checklist from Task 9 against the live server — this time with the real nonce-only CSP in effect. Open the browser console on each page and confirm zero CSP violation errors (`Refused to execute inline event handler...`) and zero `Unknown data-action:` errors.

- [ ] **Step 7: Commit**

```bash
git add src/api.py tests/test_csp_no_inline_handlers.py
git commit -m "fix: tighten CSP script-src to nonce-only now that inline handlers are gone"
```

---

## Note: pre-existing, out-of-scope issue found during this work

`admin.html` (script block, ~line 369-374) loads `qrcodejs` from `https://cdn.jsdelivr.net` via a dynamically-created `<script>` tag. This is **not** an inline script (so it's unaffected by the `script-src` nonce change), but `script-src 'self' ...` does not list `cdn.jsdelivr.net` as an allowed source — meaning this external script load may already be silently blocked by CSP today, independent of anything in this plan. Not in scope here; flag to the user as a possible follow-up (vendor the QR library locally, or add the CDN host to `script-src`, matching the project's general preference for local dependencies over CDNs seen with noVNC).
