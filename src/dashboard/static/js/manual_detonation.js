// Manual Detonation page — upload, two-outcome modal, history table.
// Event handlers wired via addEventListener (no inline onclick — CSP discipline).
(function () {
  const attachBtn = document.getElementById("md-attach-btn");
  if (!attachBtn) return; // not on this page

  const fileInput = document.getElementById("md-file-input");
  const modal = document.getElementById("md-modal-overlay");
  const modalFile = document.getElementById("md-modal-file");
  let pendingFile = null;

  function toast(msg, type) { if (window.showToast) showToast(msg, type || "success"); }
  function esc(s) { const d = document.createElement("div"); d.textContent = s == null ? "" : s; return d.innerHTML; }

  // Ask for desktop-notification permission up front (needs a user gesture)
  attachBtn.addEventListener("click", () => {
    if ("Notification" in window && Notification.permission === "default") {
      Notification.requestPermission();
    }
    fileInput.click();
  });

  fileInput.addEventListener("change", () => {
    if (!fileInput.files.length) return;
    pendingFile = fileInput.files[0];
    modalFile.textContent = `${pendingFile.name} (${Math.round(pendingFile.size / 1024)} KB)`;
    modal.classList.add("open");
  });

  function closeModal() { modal.classList.remove("open"); fileInput.value = ""; }
  document.getElementById("md-branch-cancel").addEventListener("click", closeModal);

  async function submit(branch) {
    if (!pendingFile) return;
    const fd = new FormData();
    fd.append("file", pendingFile);
    fd.append("branch", branch);
    modal.classList.remove("open");
    try {
      const r = await fetch("/api/detonation/manual", { method: "POST", body: fd });
      const data = await r.json();
      if (!data.success) {
        toast(data.error || "Upload failed", "error");
      } else if (branch === "queue") {
        toast("Queued with priority — you'll be alerted when it's ready.");
      } else if (data.window === "active") {
        toast("Added to the active sandbox window.");
        if (window.openSandboxViewer) openSandboxViewer(0);
      } else {
        toast("Sandbox starting…");
        if (window.openSandboxViewer) openSandboxViewer(0);
      }
    } catch (e) {
      toast("Upload error: " + e, "error");
    }
    fileInput.value = "";
    loadTable();
  }
  document.getElementById("md-branch-now").addEventListener("click", () => submit("now"));
  document.getElementById("md-branch-queue").addEventListener("click", () => submit("queue"));

  async function loadTable() {
    let data;
    try { data = await (await fetch("/api/detonation/manual")).json(); }
    catch (e) { return; }
    const tbody = document.getElementById("md-tbody");
    const rows = data.detonations || [];
    if (!rows.length) {
      tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--text-muted);">No manual detonations yet.</td></tr>';
      return;
    }
    tbody.innerHTML = rows.map((r) => {
      const verdict = r.escalate === true ? "🔴 malicious" : (r.status === "done" ? "🟢 clean" : "—");
      const mal = (r.malscore == null) ? "—" : r.malscore;
      let action = "";
      if (r.status === "ready") {
        action = `<button class="btn btn-sm btn-primary" data-confirm="${r.id}">Open now</button>`;
      } else if (r.cape_task_id) {
        action = `<a class="btn btn-sm btn-outline" href="/api/detonation/report/${r.cape_task_id}/" target="_blank">View report</a>`;
      }
      return `<tr>
        <td>${esc(r.filename)}</td>
        <td title="${esc(r.sha256)}">${esc((r.sha256 || "").slice(0, 12))}…</td>
        <td>${esc(String(mal))}</td>
        <td>${verdict}</td>
        <td>${esc(r.status)}</td>
        <td>${esc(r.created_by)}</td>
        <td>${esc(r.updated_at || r.created_at || "")}</td>
        <td>${action}</td>
      </tr>`;
    }).join("");
  }

  // Event delegation for row buttons (no inline handlers — CSP discipline)
  document.getElementById("md-tbody").addEventListener("click", async (ev) => {
    const c = ev.target.closest("[data-confirm]");
    if (!c) return;
    try {
      const r = await (await fetch(`/api/detonation/manual/${c.dataset.confirm}/confirm`, { method: "POST" })).json();
      if (!r.success) { toast(r.error || "Could not start", "error"); }
      else { toast("Sandbox starting…"); if (window.openSandboxViewer) openSandboxViewer(0); }
    } catch (e) { toast("Error: " + e, "error"); }
    loadTable();
  });

  loadTable();
  setInterval(loadTable, 8000);
})();
