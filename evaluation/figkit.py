"""
PhishGuard-AI — Figure Toolkit (unified style for all dissertation figures).
=============================================================================

One palette, one type scale and a small set of drawing primitives (boxes,
containers, arrows, actors, use cases, ERD entities, UML classes, swimlanes)
used by ``make_report_figures.py``.  Diagram canvases are laid out in inches
so that a figure drawn 6.5 in wide maps 1:1 onto the report's text width and
its type stays at 6.5–8 pt when printed.  Everything is exported at 300 DPI.
"""

from __future__ import annotations

from dataclasses import dataclass

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Ellipse, FancyArrowPatch, FancyBboxPatch, Rectangle

DPI = 300
TEXT_WIDTH_IN = 6.5

# ── Palette ───────────────────────────────────────────────────────────────────
INK = "#1B2430"
MUTED = "#5B6675"
LINE = "#8A94A3"
GRID = "#E3E7ED"
PANEL = "#F6F8FA"
WHITE = "#FFFFFF"

NAVY, NAVY_L = "#1F3A5F", "#E4EAF2"
BLUE, BLUE_L = "#2F6DB5", "#E6EEF8"
TEAL, TEAL_L = "#0F7C7A", "#E2F1F0"
GREEN, GREEN_L = "#2E7D32", "#E7F2E8"
AMBER, AMBER_L = "#B7791F", "#FBF1E1"
RED, RED_L = "#B42318", "#FBE8E6"
PURPLE, PURPLE_L = "#5B4B8A", "#EEEAF6"
GREY, GREY_L = "#6B7280", "#F1F3F6"

SERIES = [NAVY, TEAL, AMBER, RED, PURPLE, BLUE, GREEN, GREY]

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


# ── Diagram canvas ────────────────────────────────────────────────────────────

@dataclass
class Node:
    x: float
    y: float
    w: float
    h: float

    @property
    def left(self):
        return (self.x, self.y + self.h / 2)

    @property
    def right(self):
        return (self.x + self.w, self.y + self.h / 2)

    @property
    def top(self):
        return (self.x + self.w / 2, self.y + self.h)

    @property
    def bottom(self):
        return (self.x + self.w / 2, self.y)

    @property
    def cx(self):
        return self.x + self.w / 2

    @property
    def cy(self):
        return self.y + self.h / 2

    def at(self, fx: float, fy: float):
        return (self.x + fx * self.w, self.y + fy * self.h)


class Canvas:
    """A diagram surface measured in inches with the origin at bottom-left."""

    def __init__(self, width: float, height: float):
        apply_style()
        self.W, self.H = width, height
        self.fig = plt.figure(figsize=(width, height))
        self.ax = self.fig.add_axes([0, 0, 1, 1])
        self.ax.set_xlim(0, width)
        self.ax.set_ylim(0, height)
        self.ax.axis("off")

    def save(self, path) -> None:
        self.fig.savefig(path, dpi=DPI, facecolor="white")
        plt.close(self.fig)

    # text -------------------------------------------------------------------
    def text(self, x, y, s, size=7, color=INK, weight="normal", ha="center", va="center", style="normal",
             mono=False, z=6, rotation=0, linespacing=1.25):
        self.ax.text(x, y, s, fontsize=size, color=color, fontweight=weight, ha=ha, va=va, fontstyle=style,
                     family="Consolas" if mono else "Arial", zorder=z, rotation=rotation, linespacing=linespacing)

    # boxes ------------------------------------------------------------------
    def box(self, x, y, w, h, title=None, lines=(), tone="navy", fill=None, edge=None, size=6.6, title_size=7.2,
            radius=0.05, lw=0.8, align="center", mono=False, dashed=False, title_color=None, z=3, header=False):
        edge_c, fill_c = TONES[tone]
        edge_c = edge or edge_c
        fill_c = fill if fill is not None else fill_c
        patch = FancyBboxPatch((x, y), w, h, boxstyle=f"round,pad=0,rounding_size={radius}", fc=fill_c, ec=edge_c,
                               lw=lw, ls=(0, (3, 2)) if dashed else "-", zorder=z)
        self.ax.add_patch(patch)
        lines = [ln for ln in lines]
        n = len(lines) + (1 if title else 0)
        line_h = size / 72 * 1.32
        if header and title:
            hh = title_size / 72 * 1.75
            self.ax.add_patch(FancyBboxPatch((x, y + h - hh), w, hh, boxstyle=f"round,pad=0,rounding_size={radius}",
                                             fc=edge_c, ec=edge_c, lw=lw, zorder=z + 0.1))
            self.ax.add_patch(Rectangle((x, y + h - hh), w, hh / 2, fc=edge_c, ec=edge_c, lw=0, zorder=z + 0.1))
            self.text(x + w / 2, y + h - hh / 2, title, size=title_size, color=WHITE, weight="bold", z=z + 1)
            top = y + h - hh - line_h * 0.75
            for i, ln in enumerate(lines):
                xx = x + w / 2 if align == "center" else x + 0.07
                self.text(xx, top - i * line_h, ln, size=size, ha=align if align != "center" else "center",
                          mono=mono, z=z + 1, color=INK)
            return Node(x, y, w, h)
        block = n * line_h
        cur = y + h / 2 + block / 2 - line_h / 2
        if title:
            xx = x + w / 2 if align == "center" else x + 0.07
            self.text(xx, cur, title, size=title_size, weight="bold", color=title_color or edge_c,
                      ha="center" if align == "center" else "left", z=z + 1)
            cur -= line_h * 1.05
        for ln in lines:
            xx = x + w / 2 if align == "center" else x + 0.07
            self.text(xx, cur, ln, size=size, color=INK, ha="center" if align == "center" else "left", mono=mono,
                      z=z + 1)
            cur -= line_h
        return Node(x, y, w, h)

    def group(self, x, y, w, h, label=None, tone="grey", dashed=True, fill=None, label_size=6.8, z=1, lw=0.8):
        edge_c, fill_c = TONES[tone]
        self.ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0,rounding_size=0.07",
                                         fc=fill if fill is not None else fill_c, ec=edge_c, lw=lw,
                                         ls=(0, (4, 2)) if dashed else "-", zorder=z, alpha=1))
        if label:
            self.text(x + 0.08, y + h - 0.1, label, size=label_size, weight="bold", color=edge_c, ha="left", va="top",
                      z=z + 0.5)
        return Node(x, y, w, h)

    def pill(self, x, y, s, tone="navy", size=6.2, solid=True, ha="center"):
        edge_c, fill_c = TONES[tone]
        w = max(0.25, len(s) * size / 72 * 0.56 + 0.12)
        h = size / 72 * 1.75
        x0 = x - w / 2 if ha == "center" else x
        self.ax.add_patch(FancyBboxPatch((x0, y - h / 2), w, h, boxstyle=f"round,pad=0,rounding_size={h / 2}",
                                         fc=edge_c if solid else fill_c, ec=edge_c, lw=0.6, zorder=7))
        self.text(x0 + w / 2, y, s, size=size, color=WHITE if solid else edge_c, weight="bold", z=8)
        return w

    # connectors -------------------------------------------------------------
    def arrow(self, p, q, color=INK, lw=0.8, style="-|>", ls="-", label=None, label_pos=0.5, label_dy=0.07,
              label_dx=0.0, size=6.2, rad=0.0, label_color=None, z=4, head=6, label_bg=True, ha="center"):
        arr = FancyArrowPatch(p, q, arrowstyle=f"{style},head_length={head / 10},head_width={head / 20}"
                              if style.endswith(">") else style,
                              connectionstyle=f"arc3,rad={rad}", color=color, lw=lw, ls=ls, zorder=z,
                              shrinkA=0, shrinkB=0, mutation_scale=10)
        self.ax.add_patch(arr)
        if label:
            mx = p[0] + (q[0] - p[0]) * label_pos + label_dx
            my = p[1] + (q[1] - p[1]) * label_pos + label_dy
            self.ax.text(mx, my, label, fontsize=size, color=label_color or MUTED, ha=ha, va="center", zorder=z + 2,
                         bbox=dict(boxstyle="round,pad=0.12", fc="white", ec="none", alpha=0.92) if label_bg else None)

    def path(self, points, color=INK, lw=0.8, ls="-", arrow_end=True, label=None, label_at=None, size=6.2, z=4,
             label_color=None):
        xs = [p[0] for p in points]
        ys = [p[1] for p in points]
        self.ax.plot(xs[:-1] + [xs[-1]], ys[:-1] + [ys[-1]], color=color, lw=lw, ls=ls, zorder=z,
                     solid_capstyle="butt")
        if arrow_end:
            self.arrow(points[-2], points[-1], color=color, lw=lw, ls=ls, z=z)
        if label and label_at:
            self.ax.text(label_at[0], label_at[1], label, fontsize=size, color=label_color or MUTED, ha="center",
                         va="center", zorder=z + 2, bbox=dict(boxstyle="round,pad=0.12", fc="white", ec="none"))

    # UML primitives ------------------------------------------------------------
    def actor(self, x, y, label, size=6.6, color=INK, scale=1.0):
        s = scale
        self.ax.add_patch(Ellipse((x, y + 0.36 * s), 0.12 * s, 0.12 * s, fc="white", ec=color, lw=0.8, zorder=5))
        self.ax.plot([x, x], [y + 0.30 * s, y + 0.14 * s], color=color, lw=0.8, zorder=5)
        self.ax.plot([x - 0.1 * s, x + 0.1 * s], [y + 0.25 * s, y + 0.25 * s], color=color, lw=0.8, zorder=5)
        self.ax.plot([x, x - 0.08 * s], [y + 0.14 * s, y], color=color, lw=0.8, zorder=5)
        self.ax.plot([x, x + 0.08 * s], [y + 0.14 * s, y], color=color, lw=0.8, zorder=5)
        self.text(x, y - 0.1, label, size=size, va="top")
        return Node(x - 0.1, y, 0.2, 0.42 * s)

    def usecase(self, x, y, w, h, label, tone="blue", size=6.4):
        edge_c, fill_c = TONES[tone]
        self.ax.add_patch(Ellipse((x, y), w, h, fc=fill_c, ec=edge_c, lw=0.8, zorder=4))
        self.text(x, y, label, size=size, z=5)
        return Node(x - w / 2, y - h / 2, w, h)

    def entity(self, x, y_top, w, name, rows, tone="navy", size=6.0, row_h=0.165, col_x=(0.06, 0.34, 1.32, 1.98)):
        """ERD table. rows: (key, column, type, constraint). Returns Node and row centre y-values."""
        edge_c, fill_c = TONES[tone]
        hh = 0.24
        h = hh + row_h * len(rows) + 0.06
        y = y_top - h
        self.ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0,rounding_size=0.04", fc="white",
                                         ec=edge_c, lw=0.9, zorder=3))
        self.ax.add_patch(FancyBboxPatch((x, y_top - hh), w, hh, boxstyle="round,pad=0,rounding_size=0.04",
                                         fc=edge_c, ec=edge_c, lw=0.9, zorder=3.1))
        self.ax.add_patch(Rectangle((x, y_top - hh), w, hh / 2, fc=edge_c, ec=edge_c, lw=0, zorder=3.1))
        self.text(x + w / 2, y_top - hh / 2, name, size=7.2, weight="bold", color=WHITE, mono=True, z=4)
        ys = []
        for i, (key, col, typ, cons) in enumerate(rows):
            cy = y_top - hh - row_h * (i + 0.5) - 0.02
            ys.append(cy)
            if i % 2 == 1:
                self.ax.add_patch(Rectangle((x + 0.01, cy - row_h / 2), w - 0.02, row_h, fc=fill_c, ec="none",
                                            zorder=3.2))
            key_color = AMBER if key == "PK" else (RED if key == "FK" else (TEAL if key in ("UQ", "IX") else MUTED))
            self.text(x + col_x[0], cy, key, size=size - 0.4, weight="bold", color=key_color, ha="left", z=4)
            self.text(x + col_x[1], cy, col, size=size, mono=True, ha="left", z=4)
            self.text(x + col_x[2], cy, typ, size=size, mono=True, color=BLUE, ha="left", z=4)
            self.text(x + col_x[3], cy, cons, size=size - 0.5, color=MUTED, ha="left", z=4)
        return Node(x, y, w, h), ys

    def uml_class(self, x, y_top, w, name, attrs=(), methods=(), stereotype=None, tone="navy", size=5.9):
        edge_c, fill_c = TONES[tone]
        lh = size / 72 * 1.38
        head = (0.2 if stereotype else 0.0) + 0.2
        h = head + lh * (len(attrs) + len(methods)) + 0.14 + (0.04 if attrs and methods else 0)
        y = y_top - h
        self.ax.add_patch(Rectangle((x, y), w, h, fc="white", ec=edge_c, lw=0.8, zorder=3))
        self.ax.add_patch(Rectangle((x, y_top - head), w, head, fc=fill_c, ec=edge_c, lw=0.8, zorder=3.1))
        if stereotype:
            self.text(x + w / 2, y_top - 0.11, f"«{stereotype}»", size=size - 0.4, color=MUTED, z=4, style="italic")
            self.text(x + w / 2, y_top - 0.3, name, size=size + 1, weight="bold", color=edge_c, z=4)
        else:
            self.text(x + w / 2, y_top - head / 2, name, size=size + 1, weight="bold", color=edge_c, z=4)
        cur = y_top - head - lh * 0.65
        for a in attrs:
            self.text(x + 0.05, cur, a, size=size, mono=True, ha="left", z=4)
            cur -= lh
        if attrs and methods:
            self.ax.plot([x, x + w], [cur + lh * 0.45, cur + lh * 0.45], color=edge_c, lw=0.6, zorder=4)
            cur -= 0.04
        for m in methods:
            self.text(x + 0.05, cur, m, size=size, mono=True, ha="left", z=4)
            cur -= lh
        return Node(x, y, w, h)

    def diamond(self, x, y, w, h, label, tone="amber", size=6.2):
        edge_c, fill_c = TONES[tone]
        self.ax.add_patch(plt.Polygon([(x, y + h / 2), (x + w / 2, y), (x, y - h / 2), (x - w / 2, y)], closed=True,
                                      fc=fill_c, ec=edge_c, lw=0.8, zorder=4))
        self.text(x, y, label, size=size, z=5)
        return Node(x - w / 2, y - h / 2, w, h)

    def dot(self, x, y, r=0.05, color=INK, ring=False):
        if ring:
            self.ax.add_patch(Ellipse((x, y), r * 2.8, r * 2.8, fc="white", ec=color, lw=0.8, zorder=5))
        self.ax.add_patch(Ellipse((x, y), r * 2, r * 2, fc=color, ec=color, lw=0, zorder=6))
        return Node(x - r, y - r, 2 * r, 2 * r)

    def bar(self, x, y, w, h, color, z=3):
        self.ax.add_patch(Rectangle((x, y), w, h, fc=color, ec="none", zorder=z))

    def hline(self, x0, x1, y, color=LINE, lw=0.6, ls="-", z=2):
        self.ax.plot([x0, x1], [y, y], color=color, lw=lw, ls=ls, zorder=z)

    def vline(self, x, y0, y1, color=LINE, lw=0.6, ls="-", z=2):
        self.ax.plot([x, x], [y0, y1], color=color, lw=lw, ls=ls, zorder=z)
