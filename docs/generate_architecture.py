"""Generate minimal architecture diagram — 'Attention Is All You Need' style.
Complete pipeline with all components."""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

fig, ax = plt.subplots(figsize=(10, 18))
ax.set_xlim(0, 12)
ax.set_ylim(0, 22)
ax.axis("off")
fig.patch.set_facecolor("white")

# ── Helpers ──
def box(ax, cx, cy, w, h, label, color="#f0f0f0", ec="black", fontsize=9, lw=1.2):
    x, y = cx - w/2, cy - h/2
    b = FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.12",
                        facecolor=color, edgecolor=ec, linewidth=lw, zorder=2)
    ax.add_patch(b)
    ax.text(cx, cy, label, ha="center", va="center",
            fontsize=fontsize, fontweight="bold", color="#1a1a1a", zorder=3)

def smallbox(ax, cx, cy, w, h, label, color="#f5f5f5", ec="#aaa", fontsize=7, lw=0.8):
    x, y = cx - w/2, cy - h/2
    b = FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.08",
                        facecolor=color, edgecolor=ec, linewidth=lw, zorder=2)
    ax.add_patch(b)
    ax.text(cx, cy, label, ha="center", va="center",
            fontsize=fontsize, color="#444", zorder=3)

def arrow(ax, x1, y1, x2, y2, label=None, color="#333", lw=1.5):
    ax.annotate("", xy=(x2, y2), xytext=(x1, y1),
                arrowprops=dict(arrowstyle="-|>", color=color,
                                lw=lw, mutation_scale=14), zorder=4)
    if label:
        mx, my = (x1+x2)/2, (y1+y2)/2
        if x1 == x2:  # vertical
            ax.text(mx + 0.15, my, label, fontsize=7, color="#555",
                    fontstyle="italic", ha="left", va="center", zorder=5)
        else:  # horizontal
            ax.text(mx, my + 0.15, label, fontsize=7, color="#555",
                    fontstyle="italic", ha="center", va="bottom", zorder=5)

def dashed(ax, x1, y1, x2, y2, color="#aaa", lw=0.8):
    ax.plot([x1, x2], [y1, y2], color=color, lw=lw, ls="--", zorder=1)

# ── Colors ──
C_SRC   = "#d5e8d4"
C_DET   = "#dae8fc"
C_ISO   = "#e1d5e7"
C_API   = "#fff2cc"
C_LLM   = "#f8cecc"
C_GUARD = "#fce4d6"
C_HUMAN = "#d5e8d4"
C_DB    = "#cfe2f3"
C_SIDE  = "#f5f5f5"

cx = 5.5  # main flow center

# ═══════════════════════════════════════════════
# MAIN VERTICAL FLOW
# ═══════════════════════════════════════════════

# ── Email Input ──
box(ax, cx, 21.0, 3.0, 0.65, "Email Source\n(IMAP/SSL)", C_SRC)
smallbox(ax, 2.0, 21.0, 2.0, 0.5, "APScheduler\n(60s poll)", C_SIDE)
dashed(ax, 3.0, 21.0, 4.0, 21.0, "#888")

arrow(ax, cx, 20.67, cx, 20.1)

# ── Ingestion ──
box(ax, cx, 19.65, 3.0, 0.65, "Ingestion &\nParsing", C_DET)
smallbox(ax, 9.5, 19.65, 2.2, 0.5, "Idempotency\n(SHA-256 + Msg-ID)", C_SIDE)
dashed(ax, 8.4, 19.65, 7.0, 19.65, "#888")

# Auth check annotation
smallbox(ax, 2.0, 19.65, 2.0, 0.5, "SPF / DKIM\nDMARC check", C_SIDE)
dashed(ax, 3.0, 19.65, 4.0, 19.65, "#888")

arrow(ax, cx, 19.32, cx, 18.75)

# ── Rules Engine ──
box(ax, cx, 18.3, 3.0, 0.65, "Rules Engine", C_DET)

# Threat feeds feeding into rules
smallbox(ax, 2.0, 18.3, 2.0, 0.5, "OpenPhish\nURLhaus", C_API, ec="#b08c2c")
dashed(ax, 3.0, 18.3, 4.0, 18.3, "#b08c2c")

# Short-circuit to quarantine
smallbox(ax, 9.5, 18.3, 1.6, 0.45, "Quarantine", C_LLM, ec="#c0392b")
arrow(ax, 7.0, 18.3, 8.7, 18.3, label="match", color="#c0392b", lw=1.3)

arrow(ax, cx, 17.97, cx, 17.4, label="pass")

# ── Isolated Extraction ──
box(ax, cx, 16.95, 3.0, 0.65, "Isolated\nExtraction", C_ISO)

smallbox(ax, 2.0, 16.95, 2.0, 0.7, "Docker container\nno network\nread-only FS", C_ISO, ec="#7b68a4")
dashed(ax, 3.0, 16.95, 4.0, 16.95, "#7b68a4")

# Tools
smallbox(ax, 9.5, 17.25, 2.2, 0.35, "oletools  pdfid  YARA", C_SIDE)
smallbox(ax, 9.5, 16.8, 2.2, 0.35, "Tesseract  python-magic", C_SIDE)
dashed(ax, 8.4, 16.95, 7.0, 16.95, "#888")

arrow(ax, cx, 16.62, cx, 16.05)

# ── Signal Enrichment ──
box(ax, cx, 15.6, 3.0, 0.65, "Signal\nEnrichment", C_API)

# External APIs
smallbox(ax, 9.5, 15.9, 2.2, 0.35, "VirusTotal  AbuseIPDB", C_API, ec="#b08c2c")
smallbox(ax, 9.5, 15.45, 2.2, 0.35, "ThreatFox  OTX", C_API, ec="#b08c2c")
dashed(ax, 8.4, 15.6, 7.0, 15.6, "#b08c2c")
ax.text(7.7, 15.85, "metadata only", fontsize=5.5, color="#b08c2c",
        fontstyle="italic", ha="center")

# Local tools
smallbox(ax, 2.0, 15.6, 2.0, 0.5, "dnstwist\nRDAP / WHOIS", C_SIDE)
dashed(ax, 3.0, 15.6, 4.0, 15.6, "#888")

# API Cache
smallbox(ax, 2.0, 14.9, 2.0, 0.4, "API Cache\n(SQLite, 24h TTL)", C_DB, ec="#6fa8dc")
dashed(ax, 3.0, 14.9, 4.0, 15.3, "#6fa8dc")

arrow(ax, cx, 15.27, cx, 14.5)

# ── Llama Guard 3 ──
box(ax, cx, 14.05, 3.0, 0.65, "Llama Guard 3\n(1B)", C_GUARD, ec="#e67e22")

smallbox(ax, 2.0, 14.05, 2.2, 0.5, "Hugging Face\nmeta-llama/\nLlama-Guard-3-1B", C_SIDE, ec="#e67e22")
dashed(ax, 3.1, 14.05, 4.0, 14.05, "#e67e22")

# Flagged path
smallbox(ax, 9.5, 13.55, 1.4, 0.4, "Escalate", C_API, ec="#e67e22")
arrow(ax, 7.0, 13.8, 8.8, 13.55, label="flagged", color="#e67e22", lw=1.2)

arrow(ax, cx, 13.72, cx, 13.15, label="safe")

# ── Local LLM ──
box(ax, cx, 12.7, 3.0, 0.65, "Local LLM\n(Gemma 3 4B)", C_LLM)

smallbox(ax, 2.0, 12.7, 2.0, 0.5, "Ollama\n(local inference)", C_SIDE, ec="#c0392b")
dashed(ax, 3.0, 12.7, 4.0, 12.7, "#c0392b")

# Override constraint
smallbox(ax, 9.5, 12.7, 2.0, 0.45, "cannot override\nrules engine", C_LLM, ec="#c0392b")

# Analyst feedback to LLM
smallbox(ax, 9.5, 12.15, 2.0, 0.35, "+ analyst feedback\nper domain", C_SIDE, ec="#27ae60")
dashed(ax, 8.5, 12.4, 7.0, 12.5, "#27ae60")

arrow(ax, cx, 12.37, cx, 11.8)

# ── Verdict Schema ──
box(ax, cx, 11.35, 3.0, 0.65, "Verdict Schema\n(Pydantic)", "#e8e8e8")

# Confidence override
smallbox(ax, 9.5, 11.35, 2.2, 0.45, "conf < 0.6 \u2192\nforce escalation", "#e8e8e8", ec="#888")

arrow(ax, cx, 11.02, cx, 10.45)

# ── Human Review ──
box(ax, cx, 10.0, 3.0, 0.65, "Human Analyst\nReview", C_HUMAN)

smallbox(ax, 9.5, 10.0, 2.0, 0.45, "Dashboard\n(FastAPI + Jinja2)", C_SIDE)
dashed(ax, 8.5, 10.0, 7.0, 10.0, "#888")

# ── Output decisions ──
arrow(ax, 4.2, 9.67, 3.5, 9.1, color="#27ae60")
arrow(ax, cx, 9.67, cx, 9.1, color="#c0392b")
arrow(ax, 6.8, 9.67, 7.5, 9.1, color="#e67e22")

box(ax, 3.5, 8.85, 1.4, 0.4, "Accept", "#d5e8d4", ec="#27ae60", fontsize=8)
box(ax, cx, 8.85, 1.4, 0.4, "Reject", "#f8cecc", ec="#c0392b", fontsize=8)
box(ax, 7.5, 8.85, 1.4, 0.4, "Escalate", "#fff2cc", ec="#e67e22", fontsize=8)

# ═══════════════════════════════════════════════
# FEEDBACK LOOPS
# ═══════════════════════════════════════════════

# Cascading blocklist feedback (reject -> rules engine)
ax.annotate("", xy=(1.0, 18.3), xytext=(1.0, 8.85),
            arrowprops=dict(arrowstyle="-|>", color="#27ae60",
                            lw=1.2, mutation_scale=12,
                            connectionstyle="arc3,rad=0.25"),
            zorder=1)
ax.text(0.15, 13.5, "cascading\nblocklist\nupdate", ha="center", va="center",
        fontsize=6, color="#27ae60", fontstyle="italic")

# Reject -> Vault
smallbox(ax, cx, 8.2, 2.0, 0.4, "Vault (AES encrypt)", C_DB, ec="#6fa8dc")
arrow(ax, cx, 8.65, cx, 8.4, color="#c0392b", lw=1.0)

# Reject -> IMAP move to spam
smallbox(ax, 7.8, 8.2, 2.0, 0.35, "IMAP \u2192 Spam", C_SIDE, ec="#c0392b")

# ═══════════════════════════════════════════════
# SIDE INFRASTRUCTURE
# ═══════════════════════════════════════════════

# PostgreSQL (central)
box(ax, 2.0, 8.2, 2.2, 0.5, "PostgreSQL", C_DB, ec="#6fa8dc", fontsize=8)
ax.text(2.0, 7.75, "emails \u2022 blocklist \u2022 whitelist\naudit_log \u2022 feedback \u2022 users",
        ha="center", va="center", fontsize=5.5, color="#555")

# Connect DB to pipeline
dashed(ax, 3.1, 8.45, 4.0, 10.0, "#6fa8dc")

# ── Trust hierarchy bracket ──
bx = 11.2
ax.plot([bx, bx+0.15, bx+0.15, bx], [19.65, 19.65, 12.7, 12.7],
        color="#888", lw=1.0, zorder=1)
ax.plot([bx+0.15, bx+0.3], [16.2, 16.2], color="#888", lw=1.0, zorder=1)
ax.text(bx+0.35, 16.2, "Trust\nHierarchy", ha="left", va="center",
        fontsize=7, color="#888", fontweight="bold")
ax.text(bx+0.35, 15.5, "deterministic\noverrides\nprobabilistic", ha="left", va="center",
        fontsize=5.5, color="#999", fontstyle="italic")

# ── Monitoring side ──
smallbox(ax, 2.0, 7.2, 2.2, 0.4, "Prometheus Metrics", C_SIDE, ec="#888")
smallbox(ax, 2.0, 6.7, 2.2, 0.4, "Audit Log (ISO 27001)", C_SIDE, ec="#888")
smallbox(ax, 5.5, 7.2, 2.2, 0.4, "WebSocket (live)", C_SIDE, ec="#888")
smallbox(ax, 5.5, 6.7, 2.2, 0.4, "Health Monitor", C_SIDE, ec="#888")

# ── Figure label ──
ax.text(6.0, 6.0, "Figure 1: Trust No Email — Complete Pipeline Architecture",
        ha="center", va="center", fontsize=10, fontstyle="italic", color="#555")

plt.tight_layout()
out = "C:/Users/moham/Attijari/docs/architecture_diagram.png"
plt.savefig(out, dpi=300, bbox_inches="tight", facecolor="white")
plt.close()
print(f"Saved: {out}")
