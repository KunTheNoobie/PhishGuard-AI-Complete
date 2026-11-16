"""
PhishGuard-AI — chart style shared by every quantitative figure in the dissertation.
===================================================================================

The architecture and UML diagrams are maintained as draw.io sources in
``report/diagrams_drawio/``.  The charts produced by ``make_report_figures.py``
use the same palette as those diagrams (the classic diagrams.net blue, green,
amber, red and purple), one typeface (Arial) and are exported at 300 DPI.
"""

from __future__ import annotations

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

DPI = 300

# ── Palette: draw.io stroke colours for marks, draw.io fills for light areas ──
INK = "#1A1A1A"
MUTED = "#555555"
LINE = "#8C8C8C"
GRID = "#E6E6E6"

NAVY, NAVY_L = "#3B5B8C", "#DAE8FC"
BLUE, BLUE_L = "#6C8EBF", "#DAE8FC"
TEAL, TEAL_L = "#5B9A4B", "#D5E8D4"
GREEN, GREEN_L = "#82B366", "#D5E8D4"
AMBER, AMBER_L = "#D6B656", "#FFF2CC"
RED, RED_L = "#B85450", "#F8CECC"
PURPLE, PURPLE_L = "#9673A6", "#E1D5E7"
GREY, GREY_L = "#888888", "#F5F5F5"

TONES = {
    "navy": (NAVY, NAVY_L), "blue": (BLUE, BLUE_L), "teal": (TEAL, TEAL_L), "green": (GREEN, GREEN_L),
    "amber": (AMBER, AMBER_L), "red": (RED, RED_L), "purple": (PURPLE, PURPLE_L), "grey": (GREY, GREY_L),
}


def apply_style() -> None:
    plt.rcParams.update({
        "font.family": "Arial",
        "font.size": 7.5,
        "axes.titlesize": 8.5,
        "axes.titleweight": "bold",
        "axes.labelsize": 7.5,
        "axes.edgecolor": LINE,
        "axes.linewidth": 0.6,
        "axes.labelcolor": INK,
        "axes.titlecolor": INK,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "axes.grid": True,
        "grid.color": GRID,
        "grid.linewidth": 0.5,
        "xtick.color": MUTED,
        "ytick.color": MUTED,
        "xtick.labelsize": 6.8,
        "ytick.labelsize": 6.8,
        "legend.fontsize": 6.8,
        "legend.frameon": False,
        "text.color": INK,
        "savefig.dpi": DPI,
        "figure.dpi": 110,
        "mathtext.default": "regular",
    })


def save(fig, path) -> None:
    fig.savefig(path, dpi=DPI, bbox_inches="tight", pad_inches=0.04, facecolor="white")
    plt.close(fig)
