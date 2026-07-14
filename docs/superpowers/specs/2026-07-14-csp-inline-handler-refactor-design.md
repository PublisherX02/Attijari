# CSP Inline-Handler Refactor — Design

## Problem

`script-src` in `src/api.py` currently includes `'unsafe-inline'` because the dashboard wires ~66 inline `onclick=""` attributes across `dashboard.js` and 9 templates. A per-request nonce is already generated (`request.state.csp_nonce`, `src/api.py:87-89`) and already applied to every inline `<script nonce="{{ csp_nonce }}">` block in the templates — but it cannot be used for `script-src` while `'unsafe-inline'` is present (browsers ignore `'unsafe-inline'` once a nonce appears, which is exactly the bug that caused the Jul 10 incident: the whole UI went dead for 3 days before anyone noticed).

Goal: eliminate every inline `onclick`, then flip `script-src` to `'self' 'nonce-{nonce}'`, with the change verified live in a browser before it ships — not just by test suite.

## Scope (confirmed by grep, 2026-07-14)

- `src/dashboard/static/js/dashboard.js` — 22 inline `onclick` occurrences, all in dynamically-rendered (`innerHTML`) markup: inbox rows, pagination, detonation panel, audit filter chips, admin user rows.
- 9 templates — 44 static inline `onclick` occurrences: `base.html` (6), `inbox.html` (13), `admin.html` (16), `history.html` (3), `whitelist.html` (1), `blocklist.html` (1), `audit.html` (2), `reports.html` (1), `health.html` (1).
- `manual_detonation.html` / `manual_detonation.js` already have zero inline handlers — no change needed.
- All inline `<script nonce="...">` blocks already carry the nonce correctly.

## Architecture

One delegated click listener added once in `dashboard.js`:

```js
document.addEventListener('click', (event) => {
  const el = event.target.closest('[data-action]');
  if (!el) return;
  const handler = actionRegistry[el.dataset.action];
  if (!handler) { console.error('Unknown data-action:', el.dataset.action); return; }
  handler(el, event);
});
```

`actionRegistry` maps action names (`release-email`, `filter-status`, `open-edit-modal`, …) to functions that read parameters off `el.dataset` instead of receiving them as literal arguments baked into HTML strings.

Because delegation dispatches to the single *closest* `[data-action]` ancestor, a click on a button inside a table row no longer also triggers the row's own action — the explicit `event.stopPropagation()` calls sprinkled through the current code become unnecessary and are dropped, not ported.

This also has a latency/footprint benefit over the alternative (binding `addEventListener` per rendered element): there is exactly one listener for the whole app, so repeated `innerHTML` re-renders of tables (inbox list, audit panel, admin user list, etc.) never need to rebind anything.

### Special cases

- **Modal backdrop clicks** (`onclick="if(event.target===this)closeModal()"`, 4 occurrences): `data-action="backdrop-close" data-close="closeModal"` on the overlay div; the registry entry checks `event.target === el` before invoking the named close function via a small lookup (`closeModal`, `closeEditModal`, etc.).
- **Compound inline scripts** (2 occurrences — inbox "Clear Selection" button; `base.html` override-confirm reading another element's `dataset.emailId`): each becomes a small named function in `dashboard.js` (`clearSelection()`, `confirmOverrideFromModal()`) referenced via a normal `data-action`.

### Markup convention

`onclick="releaseEmail(${parseInt(e.id)})"` becomes:
`data-action="release-email" data-id="${parseInt(e.id)}"`

`onclick="resetPassword(${u.id}, '${esc(u.username)}')"` becomes:
`data-action="reset-password" data-id="${u.id}" data-username="${esc(u.username)}"`

## CSP change

In `src/api.py`, once every inline handler is gone:

```
script-src 'self' 'nonce-{nonce}';
```

replacing the current `script-src 'self' 'unsafe-inline';`. `style-src` is unaffected (inline `style=""` attributes are out of scope — not the injection risk scripts are).

## Rollout — 3 phases, each independently testable

1. Build the delegation infra (`actionRegistry` + document listener) and convert `dashboard.js`'s 22 dynamic handlers.
2. Convert the 44 static template handlers to the same `data-action` convention.
3. Flip the CSP header and **browser-verify every button on every page**: inbox filters/pagination/bulk actions/release/quarantine/override/revert, admin create/edit/reset-password/reset-2FA/deactivate, audit filters, history pagination, health refresh, reports generate, blocklist/whitelist add/remove, all modal open/close/backdrop-click paths, sandbox viewer open/close.

Existing automated test suite must stay green throughout; browser verification in phase 3 is the primary gate (this is precisely the class of regression the test suite did not catch on Jul 10).

## Out of scope

- `style="" ` inline style attributes (kept under `'unsafe-inline'` for `style-src`, unrelated risk).
- `manual_detonation.html`/`.js` (already clean).
- Any change to CAPE VM connectivity — that's the next task after this one lands.
