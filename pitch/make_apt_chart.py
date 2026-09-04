"""Render the APT29 before/after hero image for LinkedIn from the audit JSON."""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib import font_manager  # noqa: F401

REPO = Path(__file__).resolve().parents[1]
RES = REPO / "evaluation" / "results"
v2 = json.loads((RES / "apt_audit_day1_v2.json").read_text())
d1 = json.loads((RES / "apt_audit_day1_v21.json").read_text())
v22 = json.loads((RES / "apt_audit_day1_v22.json").read_text())
d2 = json.loads((RES / "apt_audit_day2_v22.json").read_text())

BG = "#0a0e1a"; PANEL = "#11182b"; INK = "#e8edf7"; MUTED = "#8b97b0"
CYAN = "#38bdf8"; GREEN = "#22c55e"; RED = "#ef4444"; INDIGO = "#818cf8"; LINE = "#242e47"

plt.rcParams.update({
    "figure.facecolor": BG, "axes.facecolor": BG, "savefig.facecolor": BG,
    "text.color": INK, "axes.labelcolor": INK, "xtick.color": MUTED, "ytick.color": MUTED,
    "font.family": "DejaVu Sans", "axes.edgecolor": LINE,
})

fig = plt.figure(figsize=(12, 6.4), dpi=170)
fig.suptitle("Aegis vs REAL APT telemetry: MITRE ATT&CK Evals APT29 (196k + 587k events)",
             fontsize=15, fontweight="bold", color=INK, y=0.965)
fig.text(0.5, 0.905, "Telemetry the author did not write. Audit-driven arc: v2 -> v2.1 -> v2.2.",
         ha="center", fontsize=10.5, color=MUTED)

# --- left: grouped bars (v2 / v2.1 / v2.2) ---
ax = fig.add_axes([0.07, 0.14, 0.52, 0.7])
groups = ["Schema\ncoverage", "ATT&CK technique\nrecall"]
x = range(len(groups))
v2vals = [v2["schema_coverage_pct"], v2["apt29_recall_pct"]]
v21vals = [d1["schema_coverage_pct"], d1["apt29_recall_pct"]]
v22vals = [v22["schema_coverage_pct"], v22["apt29_recall_pct"]]
w = 0.26
b1 = ax.bar([i - w for i in x], v2vals, w, label="v2", color="#4a5675")
b2 = ax.bar(list(x), v21vals, w, label="v2.1", color=INDIGO)
b3 = ax.bar([i + w for i in x], v22vals, w, label="v2.2", color=CYAN)
for b in list(b1) + list(b2) + list(b3):
    ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 1.5, f"{b.get_height():.0f}%",
            ha="center", fontsize=10, color=INK, fontweight="bold")
ax.set_xticks(list(x)); ax.set_xticklabels(groups, fontsize=11, color=INK)
ax.set_ylim(0, 100); ax.set_ylabel("percent", fontsize=10)
ax.grid(axis="y", color=LINE, linewidth=0.6)
ax.set_axisbelow(True)
for s in ("top", "right"):
    ax.spines[s].set_visible(False)
leg = ax.legend(loc="upper left", frameon=False, fontsize=11)
for t in leg.get_texts():
    t.set_color(INK)

# --- right: the headline callouts ---
def card(x0, y0, w0, h0, title, big, sub, color):
    axc = fig.add_axes([x0, y0, w0, h0])
    axc.set_facecolor(PANEL)
    for s in axc.spines.values():
        s.set_color(LINE)
    axc.set_xticks([]); axc.set_yticks([])
    axc.text(0.06, 0.72, title, transform=axc.transAxes, fontsize=10.5, color=MUTED)
    axc.text(0.06, 0.34, big, transform=axc.transAxes, fontsize=20, color=color, fontweight="bold")
    axc.text(0.06, 0.12, sub, transform=axc.transAxes, fontsize=9.2, color=MUTED)

card(0.63, 0.55, 0.32, 0.3, "ATT&CK technique recall (Day 1)",
     f"{v2['apt29_recall_pct']:.0f}%  ->  {v22['apt29_recall_pct']:.0f}%",
     "Nearly doubled. LSASS + injection + NTDS now caught.", GREEN)
card(0.63, 0.20, 0.32, 0.3, "Day 2 (587k events) recall",
     f"{d2['apt29_recall_pct']:.0f}%",
     f"{len(d2['apt29_detected'])}/30 techniques on real telemetry.", CYAN)

fig.text(0.07, 0.045, "Honest: nobody tuned these logs to Aegis. Remaining misses are the v2.3 roadmap.  "
                      "github.com/raunitgrey7/aegis", fontsize=9, color=MUTED)
fig.text(0.955, 0.045, "(c) 2026 Raunit Thakur", fontsize=8.5, color="#55607a", ha="right")

out = REPO / "docs" / "screenshots" / "apt29_v22_hero.png"
out.parent.mkdir(parents=True, exist_ok=True)
fig.savefig(out, dpi=170)
print("written", out)
