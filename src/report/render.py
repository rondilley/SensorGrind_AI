"""
report/render - rendering primitives extracted from comprehensive_report.py.

Contains:
  - Mermaid block builders (pie, xychart-beta bar/line, sequence, flowchart,
    sankey-beta, gantt)
  - Matplotlib-backed SVG fallbacks (bar/line) used when Mermaid would
    crowd labels
  - smart_bar / smart_line picker that switches between Mermaid + SVG
  - mermaid_histogram, percentile_table, svg_heatmap
  - HTML head/style + write_html
  - PDF rendering via WeasyPrint with Mermaid pre-render to SVG
  - safe_read_table / safe_columns DuckDB helpers

The split is motivated by the multi-AI methodology review: the original
comprehensive_report.py was 2300+ lines and impossible to unit-test in
pieces.  Keeping the "how to draw" code here lets the section-building
code in comprehensive_report.py stay focused on data + narrative.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sg import lib

OUT_PATH = lib.REPORTS / "COMPREHENSIVE.md"
HTML_PATH = lib.REPORTS / "COMPREHENSIVE.html"
PDF_PATH  = lib.REPORTS / "COMPREHENSIVE.pdf"
VISUALS_DIR = lib.REPORTS / "visuals"

MMDC = os.environ.get(
    "SG_MMDC",
    str(Path.home() / ".local" / "mmdc" / "node_modules" / ".bin" / "mmdc"),
)
PUPPETEER_CONFIG = os.environ.get(
    "SG_PUPPETEER_CONFIG",
    str(Path.home() / ".local" / "mmdc" / "puppeteer-config.json"),
)


# ----------------------------------------------------------------------
# Mermaid blocks
# ----------------------------------------------------------------------

def mm_text(s) -> str:
    """Sanitize free text for use inside a Mermaid label so it parses the
    same across every renderer we target: browser mermaid (HTML, v10),
    mmdc/Puppeteer (PDF pre-render, v11) and GitHub / VS Code preview.

    The browser renderer with securityLevel:'loose' is the most forgiving,
    which is why a chart can look fine in the HTML yet throw a syntax error
    in the PDF or in a Markdown preview.  The offenders:
      - `"` collides with the surrounding ["..."] quoting -> single quote
      - `&` is the flowchart node-conjunction operator and trips stricter
        parsers even inside quotes -> spell it out
      - `|` delimits edge labels (`-->|lbl|`) -> slash
      - newlines break single-line statements
    """
    s = str(s).replace('"', "'").replace('&', ' and ')
    # Commas delimit fields in sankey-beta CSV and trip stricter flowchart /
    # gantt parsers (GitHub / VS Code preview), so drop them entirely.
    s = s.replace(',', ' ')
    s = s.replace('|', '/').replace('\n', ' ').replace('\r', ' ')
    s = re.sub(r'\s+', ' ', s).strip()
    # Strip stray leading/trailing punctuation left behind when a caller
    # truncates an org name mid-token (e.g. "AT&T Enterprises, " -> trailing ',').
    return s.strip(" ,.;:-_/")


def mm_trunc(text, maxlen: int = 22) -> str:
    """Truncate label text to <=maxlen on a word boundary so node labels never
    cut mid-word (which reads as a broken label).  Falls back to a hard cut
    only when the first word alone already exceeds maxlen."""
    t = str(text).strip()
    if len(t) <= maxlen:
        return t
    cut = t[:maxlen].rsplit(" ", 1)[0]
    return cut if cut else t[:maxlen]


def mm_id(s) -> str:
    """Make a Mermaid-safe node/participant identifier (alphanumerics +
    underscore only).  Labels carry the human-readable text."""
    return re.sub(r'[^A-Za-z0-9_]', '_', str(s)) or "n"


def mm_csv_field(s) -> str:
    """Quote a sankey-beta CSV field.  sankey-beta is comma-delimited, so a
    label like `AT&T Enterprises, LLC` silently shifts every column unless
    the field is double-quoted (RFC-4180).  This was the bug that made the
    campaign-migration hand-off Sankey render in HTML but fail in the PDF."""
    return '"' + mm_text(s).replace('"', "'") + '"'


def mermaid_pie(title: str, data: list[tuple[str, float]]) -> str:
    lines = ["```mermaid", "pie showData", f'    title {mm_text(title)}']
    for label, value in data:
        lines.append(f'    "{mm_text(label)}" : {value}')
    lines.append("```")
    return "\n".join(lines)


def mermaid_xychart_bar(title: str, x_labels: list[str], y_values: list[float],
                        x_title: str = "", y_title: str = "") -> str:
    safe = [mm_text(x) for x in x_labels]
    x = ", ".join(f'"{s}"' for s in safe)
    y = ", ".join(f"{v:.0f}" for v in y_values)
    lines = ["```mermaid", "xychart-beta",
             f'    title "{mm_text(title)}"',
             f'    x-axis [{x}]',
             f'    y-axis "{y_title}"' if y_title else '    y-axis "count"',
             f"    bar [{y}]",
             "```"]
    return "\n".join(lines)


def mermaid_xychart_line(title: str, x_labels: list[str], y_values: list[float],
                         y_title: str = "value") -> str:
    safe = [mm_text(x) for x in x_labels]
    x = ", ".join(f'"{s}"' for s in safe)
    y = ", ".join(f"{v:.0f}" for v in y_values)
    lines = ["```mermaid", "xychart-beta",
             f'    title "{mm_text(title)}"',
             f'    x-axis [{x}]',
             f'    y-axis "{mm_text(y_title)}"',
             f"    line [{y}]",
             "```"]
    return "\n".join(lines)


def mermaid_sequence(actors: list[str],
                     messages: list[tuple[str, str, str]]) -> str:
    lines = ["```mermaid", "sequenceDiagram"]
    for a in actors:
        lines.append(f'    participant {mm_id(a)} as {mm_text(a)}')
    for src, dst, msg in messages:
        lines.append(f'    {mm_id(src)}->>{mm_id(dst)}: {mm_text(msg)}')
    lines.append("```")
    return "\n".join(lines)


def mermaid_flowchart(direction: str, nodes: list[tuple[str, str]],
                      edges: list[tuple[str, str, str]]) -> str:
    lines = ["```mermaid", f"flowchart {direction}"]
    for nid, lbl in nodes:
        lines.append(f'    {mm_id(nid)}["{mm_text(lbl)}"]')
    for src, dst, lbl in edges:
        if lbl:
            lines.append(f'    {mm_id(src)} -->|{mm_text(lbl)}| {mm_id(dst)}')
        else:
            lines.append(f'    {mm_id(src)} --> {mm_id(dst)}')
    lines.append("```")
    return "\n".join(lines)


def _sankey_acyclic(rows: list[tuple[str, str, float]]
                    ) -> list[tuple[str, str, float]]:
    """sankey-beta rejects directed cycles ('Error: circular link') and
    self-loops, so keep edges greedily by descending weight, skipping any
    that would close a cycle.  The heaviest flows survive; this is what makes
    the campaign-migration hand-off Sankey (which legitimately has A->B and
    B->A pairs) renderable instead of erroring out."""
    adj: dict[str, set] = {}

    def reaches(a: str, b: str) -> bool:
        seen, stack = set(), [a]
        while stack:
            cur = stack.pop()
            if cur == b:
                return True
            if cur in seen:
                continue
            seen.add(cur)
            stack.extend(adj.get(cur, ()))
        return False

    kept = []
    for s, t, v in sorted(rows, key=lambda r: r[2], reverse=True):
        if s == t:                      # self-loop
            continue
        if reaches(t, s):               # adding s->t would close a cycle
            continue
        adj.setdefault(s, set()).add(t)
        kept.append((s, t, v))
    return kept


def mermaid_sankey(rows: list[tuple[str, str, float]]) -> str:
    lines = ["```mermaid", "sankey-beta", ""]
    for s, t, v in _sankey_acyclic(rows):
        lines.append(f"{mm_csv_field(s)},{mm_csv_field(t)},{int(v)}")
    lines.append("```")
    return "\n".join(lines)


def mermaid_gantt(title: str,
                  items: list[tuple[str, str, str, str]]) -> str:
    # Mermaid's default Gantt tick spacing is 3-7 days regardless of the
    # full date range, so multi-year charts render with bare "M-D" labels
    # that look meaningless without a year.  Pick a tick interval based
    # on the actual span and pin the axis format to match.
    starts = [s for _, _, s, _ in items if s]
    ends   = [e for _, _, _, e in items if e]
    span_days = 0
    if starts and ends:
        try:
            import datetime as _dt
            s_min = min(_dt.date.fromisoformat(s) for s in starts)
            e_max = max(_dt.date.fromisoformat(e) for e in ends)
            span_days = (e_max - s_min).days
        except (ValueError, TypeError):
            span_days = 0
    if span_days >= 365:
        tick_interval = "1month"
        axis_format   = "%Y-%m"
    elif span_days >= 60:
        tick_interval = "1week"
        axis_format   = "%Y-%m-%d"
    else:
        tick_interval = "1day"
        axis_format   = "%Y-%m-%d"

    lines = ["```mermaid", "gantt",
             "    dateFormat YYYY-MM-DD",
             f"    title {mm_text(title)}",
             f"    axisFormat {axis_format}",
             f"    tickInterval {tick_interval}",
             "    weekday monday"]
    cur_section = None
    for section, task, start, end in items:
        clean_section = mm_text(section).replace(":", "-").replace(",", " ")
        if clean_section != cur_section:
            lines.append(f"    section {clean_section}")
            cur_section = clean_section
        # Gantt task metadata after the ':' is comma-delimited, so the task
        # name must not contain ':' or ',' or it shifts the start/end fields.
        clean_task = mm_text(task).replace(":", "-").replace(",", " ")
        lines.append(f"    {clean_task} :{start}, {end}")
    lines.append("```")
    return "\n".join(lines)


# ----------------------------------------------------------------------
# Matplotlib fallbacks
# ----------------------------------------------------------------------

def svg_bar_chart(title: str, x_labels: list[str], y_values: list[float],
                  out_path: Path, x_title: str = "",
                  y_title: str = "count") -> str:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    n = len(x_labels)
    max_lbl = max((len(str(x)) for x in x_labels), default=0)
    rotation = 0 if max_lbl <= 3 and n <= 8 else (45 if max_lbl <= 8 else 60)

    fig_w = max(7.5, min(16, 0.6 * n + 2))
    fig_h = 4.5 if rotation <= 45 else 5.5
    fig, ax = plt.subplots(figsize=(fig_w, fig_h))
    bars = ax.bar(range(n), y_values, color="#3b6ea5",
                  edgecolor="#08306b", linewidth=0.6)
    ax.set_xticks(range(n))
    ax.set_xticklabels([str(x) for x in x_labels],
                       rotation=rotation,
                       ha=("right" if rotation else "center"))
    if x_title:
        ax.set_xlabel(x_title)
    ax.set_ylabel(y_title)
    ax.set_title(title)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.yaxis.grid(True, linestyle="--", color="#e5e7eb", linewidth=0.7)
    ax.set_axisbelow(True)
    if any(v > 1000 for v in y_values):
        ax.yaxis.set_major_formatter(
            matplotlib.ticker.FuncFormatter(lambda v, _: f"{int(v):,}"))
    if n <= 20:
        for rect, val in zip(bars, y_values):
            if val <= 0:
                continue
            ax.text(rect.get_x() + rect.get_width() / 2,
                    rect.get_height(),
                    f"{int(val):,}" if val >= 1 else f"{val:.2f}",
                    ha="center", va="bottom", fontsize=8, color="#374151")
    plt.tight_layout()
    fig.savefig(out_path, format="svg", bbox_inches="tight")
    plt.close(fig)
    rel = out_path.relative_to(OUT_PATH.parent)
    return f"![{title}]({rel})"


def svg_line_chart(title: str, x_labels: list[str], y_values: list[float],
                   out_path: Path, y_title: str = "value") -> str:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    n = len(x_labels)
    max_lbl = max((len(str(x)) for x in x_labels), default=0)
    rotation = 0 if max_lbl <= 3 and n <= 8 else (45 if max_lbl <= 8 else 60)

    fig_w = max(8, min(16, 0.55 * n + 2))
    fig_h = 4.2
    fig, ax = plt.subplots(figsize=(fig_w, fig_h))
    ax.plot(range(n), y_values, marker="o", color="#08306b",
            markerfacecolor="#3b6ea5", linewidth=1.5)
    ax.set_xticks(range(n))
    ax.set_xticklabels([str(x) for x in x_labels],
                       rotation=rotation,
                       ha=("right" if rotation else "center"))
    ax.set_ylabel(y_title)
    ax.set_title(title)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.yaxis.grid(True, linestyle="--", color="#e5e7eb", linewidth=0.7)
    ax.set_axisbelow(True)
    if any(v > 1000 for v in y_values):
        ax.yaxis.set_major_formatter(
            matplotlib.ticker.FuncFormatter(lambda v, _: f"{int(v):,}"))
    plt.tight_layout()
    fig.savefig(out_path, format="svg", bbox_inches="tight")
    plt.close(fig)
    rel = out_path.relative_to(OUT_PATH.parent)
    return f"![{title}]({rel})"


def svg_gantt_chart(title: str,
                    items: list[tuple[str, str, str, str]],
                    out_path: Path) -> str:
    """Render a Gantt chart as an SVG via matplotlib.

    items: list of (section, label, start_iso, end_iso).  Section is
    ignored for now; labels are placed top-to-bottom in input order
    (so callers can pre-sort to put the most important bars at the top).
    """
    import datetime as _dt
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.dates import (DateFormatter, MonthLocator, WeekdayLocator,
                                  AutoDateLocator)
    import matplotlib.dates as mdates

    rows: list[tuple[str, _dt.date, _dt.date]] = []
    for _section, label, start, end in items:
        try:
            s = _dt.date.fromisoformat(start[:10])
            e = _dt.date.fromisoformat(end[:10])
        except (ValueError, TypeError):
            continue
        if e <= s:
            e = s + _dt.timedelta(days=1)
        rows.append((label, s, e))
    if not rows:
        return ""

    n = len(rows)
    span_days = (max(r[2] for r in rows) - min(r[1] for r in rows)).days
    fig_w = max(10.0, min(18.0, 0.18 * span_days / 7 + 8))
    fig_h = max(3.0, 0.30 * n + 1.5)
    fig, ax = plt.subplots(figsize=(fig_w, fig_h))

    # Bars top->bottom in input order (#1 at the top after invert_yaxis).
    bar_color = "#3b6ea5"
    bars: list = []
    for i, (_label, s, e) in enumerate(rows):
        b = ax.barh(i, (e - s).days, left=mdates.date2num(s), height=0.55,
                    color=bar_color, edgecolor="#08306b", linewidth=0.5,
                    align="center")
        bars.append(b[0])
    # Hide the y-axis tick labels - labels are placed onto the bars
    # themselves (or just outside, with a connector) below.
    ax.set_yticks(range(n))
    ax.set_yticklabels([""] * n)
    ax.tick_params(axis="y", length=0)
    ax.invert_yaxis()
    # Need final x-limits before we measure pixel widths.
    ax.relim()
    ax.autoscale(enable=True, axis="x", tight=False)

    # Time axis: monthly ticks for multi-year spans, weekly otherwise.
    if span_days >= 365:
        locator   = MonthLocator(interval=1)
        formatter = DateFormatter("%b-%Y")
    elif span_days >= 60:
        locator   = WeekdayLocator(byweekday=0)   # Mondays
        formatter = DateFormatter("%d/%m/%Y")
    else:
        locator   = AutoDateLocator()
        formatter = DateFormatter("%d/%m/%Y")
    ax.xaxis.set_major_locator(locator)
    ax.xaxis.set_major_formatter(formatter)
    plt.setp(ax.xaxis.get_majorticklabels(), rotation=45, ha="right",
             fontsize=9)

    # Gridlines: subtle gray dashes at every month, no heavy axis lines.
    ax.xaxis.grid(True, which="major", color="#9ca3af", linestyle="--",
                  linewidth=0.6, alpha=0.7)
    ax.set_axisbelow(True)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    ax.spines["left"].set_color("#9ca3af")
    ax.spines["bottom"].set_color("#9ca3af")
    ax.tick_params(axis="x", length=3, color="#9ca3af")
    ax.tick_params(axis="y", length=0)

    ax.set_title(title, loc="left", fontsize=11)
    ax.set_xlabel("date")

    # Place labels: inside the bar (white text, centered) if the label
    # fits with margin; otherwise just outside the right edge with a
    # thin connector and black text.  We measure widths in display
    # (pixel) coordinates so the decision matches what the SVG viewer
    # will actually render.
    plt.tight_layout()
    fig.canvas.draw()                  # populate the renderer
    renderer = fig.canvas.get_renderer()
    label_fontsize = 9
    inside_pad_px = 6                  # pixels of padding inside the bar
    outside_pad_px = 4                 # gap between bar end and label
    connector_color = "#6b7280"
    for i, ((label, s, e), bar) in enumerate(zip(rows, bars)):
        # Bar geometry in display pixels.
        x_left_data  = mdates.date2num(s)
        x_right_data = mdates.date2num(e)
        x_left_px, y_px  = ax.transData.transform((x_left_data,  i))
        x_right_px, _    = ax.transData.transform((x_right_data, i))
        bar_width_px = x_right_px - x_left_px

        # Estimate text width by actually rendering it offscreen.
        probe = ax.text(0, 0, label, fontsize=label_fontsize)
        bbox  = probe.get_window_extent(renderer=renderer)
        text_w_px = bbox.width
        text_h_px = bbox.height
        probe.remove()

        if bar_width_px >= text_w_px + 2 * inside_pad_px:
            # Inside the bar, centered.
            mid_data = x_left_data + (x_right_data - x_left_data) / 2
            ax.text(mid_data, i, label,
                    ha="center", va="center",
                    color="white", fontsize=label_fontsize, zorder=3)
        else:
            # Outside the bar to the right; small line connector from
            # the bar's right edge to the start of the text so the eye
            # can map the label back to its bar.
            label_x_px = x_right_px + outside_pad_px
            label_x_data = ax.transData.inverted().transform(
                (label_x_px, y_px))[0]
            ax.text(label_x_data, i, " " + label,
                    ha="left", va="center",
                    color="#111827", fontsize=label_fontsize, zorder=3)
            # Connector: a short horizontal line from the bar end to the
            # label's anchor.  Drawn in data coords on the same axes.
            ax.plot([x_right_data, label_x_data], [i, i],
                    color=connector_color, linewidth=0.6, zorder=2,
                    clip_on=False)

    fig.savefig(out_path, format="svg", bbox_inches="tight")
    plt.close(fig)
    rel = out_path.relative_to(OUT_PATH.parent)
    return f"![{title}]({rel})"


_BAR_CHART_COUNTER = [0]


def smart_bar(title: str, x_labels: list[str], y_values: list[float],
              x_title: str = "", y_title: str = "count") -> str:
    max_lbl = max((len(str(x)) for x in x_labels), default=0)
    n = len(x_labels)
    needs_svg = max_lbl > 4 or n > 12
    if not needs_svg:
        return mermaid_xychart_bar(title, x_labels, y_values, y_title=y_title)
    VISUALS_DIR.mkdir(parents=True, exist_ok=True)
    _BAR_CHART_COUNTER[0] += 1
    slug = re.sub(r"[^A-Za-z0-9_-]+", "_",
                  title.lower())[:48] or f"bar_{_BAR_CHART_COUNTER[0]:03d}"
    out_path = VISUALS_DIR / f"{slug}.svg"
    return svg_bar_chart(title, x_labels, y_values, out_path,
                         x_title=x_title, y_title=y_title)


def smart_line(title: str, x_labels: list[str], y_values: list[float],
               y_title: str = "value") -> str:
    max_lbl = max((len(str(x)) for x in x_labels), default=0)
    n = len(x_labels)
    needs_svg = max_lbl > 4 or n > 12
    if not needs_svg:
        return mermaid_xychart_line(title, x_labels, y_values, y_title=y_title)
    VISUALS_DIR.mkdir(parents=True, exist_ok=True)
    _BAR_CHART_COUNTER[0] += 1
    slug = re.sub(r"[^A-Za-z0-9_-]+", "_",
                  title.lower())[:48] or f"line_{_BAR_CHART_COUNTER[0]:03d}"
    out_path = VISUALS_DIR / f"{slug}.svg"
    return svg_line_chart(title, x_labels, y_values, out_path,
                          y_title=y_title)


def mermaid_histogram(title: str, values: list[float], n_bins: int = 10,
                      y_title: str = "count") -> str:
    if not values:
        return "_(no data)_"
    lo, hi = min(values), max(values)
    if hi == lo:
        hi = lo + 1.0
    bins = [0] * n_bins
    width = (hi - lo) / n_bins
    for v in values:
        i = min(n_bins - 1, int((v - lo) / width))
        bins[i] += 1
    labels = [f"{lo + i*width:.1f}-{lo + (i+1)*width:.1f}"
              for i in range(n_bins)]
    return smart_bar(title, labels, bins, y_title=y_title)


def percentile_table(values: list[float], unit: str = "") -> str:
    import numpy as np
    if not values:
        return "_(no data)_"
    arr = np.array(values)
    pct = [10, 25, 50, 75, 90, 95, 99]
    rows = ["| pct | value |", "| --- | --- |"]
    rows.append(f"| count | {len(arr):,} |")
    rows.append(f"| mean | {arr.mean():.2f} {unit} |")
    rows.append(f"| std | {arr.std():.2f} {unit} |")
    rows.append(f"| min | {arr.min():.2f} {unit} |")
    rows.append(f"| max | {arr.max():.2f} {unit} |")
    for p in pct:
        rows.append(f"| p{p} | {np.percentile(arr, p):.2f} {unit} |")
    return "\n".join(rows)


def svg_heatmap(matrix: list[list[float]], row_labels: list[str],
                col_labels: list[str], out_path: Path,
                title: str = "") -> str:
    flat = [v for row in matrix for v in row]
    if not flat:
        return "_(no data)_"
    mx = max(flat) or 1.0
    rows = len(matrix)
    cols = len(matrix[0]) if matrix else 0

    cell_w, cell_h = 56, 22
    margin_l, margin_t, margin_r, margin_b = 70, 50, 24, 80
    width = margin_l + cols * cell_w + margin_r
    height = margin_t + rows * cell_h + margin_b

    def color(v: float) -> str:
        r0, g0, b0 = 247, 251, 255
        r1, g1, b1 = 8, 48, 107
        t = (v / mx) if mx > 0 else 0.0
        t = t ** 0.6
        r = int(r0 + (r1 - r0) * t)
        g = int(g0 + (g1 - g0) * t)
        b = int(b0 + (b1 - b0) * t)
        return f"#{r:02x}{g:02x}{b:02x}"

    parts: list[str] = []
    parts.append(f'<svg xmlns="http://www.w3.org/2000/svg" '
                 f'width="{width}" height="{height}" '
                 f'viewBox="0 0 {width} {height}" '
                 f'font-family="system-ui, sans-serif">')
    parts.append('<style>text{font-size:11px}'
                 '.title{font-size:14px;font-weight:600}'
                 '.legendlabel{font-size:10px;fill:#555}</style>')
    parts.append('<rect width="100%" height="100%" fill="#ffffff"/>')

    if title:
        parts.append(f'<text class="title" x="{width/2:.0f}" y="22" '
                     f'text-anchor="middle">{title}</text>')

    for i, label in enumerate(col_labels):
        cx = margin_l + i * cell_w + cell_w / 2
        parts.append(f'<text x="{cx:.0f}" y="{margin_t - 6}" '
                     f'text-anchor="middle">{label}</text>')

    for i, row in enumerate(matrix):
        cy = margin_t + i * cell_h + cell_h / 2 + 4
        parts.append(f'<text x="{margin_l - 8}" y="{cy:.0f}" '
                     f'text-anchor="end">{row_labels[i]}</text>')
        for j, v in enumerate(row):
            x = margin_l + j * cell_w
            y = margin_t + i * cell_h
            c = color(v)
            parts.append(
                f'<rect x="{x:.0f}" y="{y:.0f}" '
                f'width="{cell_w}" height="{cell_h}" '
                f'fill="{c}" stroke="#e5e7eb" stroke-width="0.5">'
                f'<title>{row_labels[i]} {col_labels[j]}: '
                f'{int(v):,}</title></rect>'
            )

    legend_y = margin_t + rows * cell_h + 24
    legend_w = cols * cell_w
    gid = "heat_grad"
    parts.append(f'<defs><linearGradient id="{gid}" x1="0%" x2="100%">')
    for i in range(11):
        t = i / 10
        v = t * mx
        parts.append(f'<stop offset="{int(t*100)}%" '
                     f'stop-color="{color(v)}"/>')
    parts.append('</linearGradient></defs>')
    parts.append(f'<rect x="{margin_l}" y="{legend_y}" '
                 f'width="{legend_w}" height="14" '
                 f'fill="url(#{gid})" stroke="#9ca3af" stroke-width="0.5"/>')
    parts.append(f'<text class="legendlabel" x="{margin_l}" '
                 f'y="{legend_y + 28}" text-anchor="start">0</text>')
    parts.append(f'<text class="legendlabel" '
                 f'x="{margin_l + legend_w}" y="{legend_y + 28}" '
                 f'text-anchor="end">{int(mx):,}</text>')
    parts.append(f'<text class="legendlabel" '
                 f'x="{margin_l + legend_w/2}" y="{legend_y + 28}" '
                 f'text-anchor="middle">{int(mx/2):,}</text>')
    parts.append('</svg>')

    out_path.write_text("\n".join(parts))
    rel = out_path.relative_to(OUT_PATH.parent)
    return f"![{title or 'heatmap'}]({rel})"


# ----------------------------------------------------------------------
# HTML / PDF rendering
# ----------------------------------------------------------------------

_MERMAID_BLOCK = re.compile(r"```mermaid\n(.*?)\n```", re.DOTALL)


# Mermaid renders flowchart labels as HTML inside <foreignObject> by default
# (htmlLabels:true).  WeasyPrint (our PDF engine) cannot render foreignObject,
# so flowchart text silently disappears in the PDF while shapes/edges remain.
# Force native SVG <text> labels for the PDF pre-render path only -- the HTML
# report uses live mermaid.js where foreignObject is fine.
_MMDC_CONFIG = (
    '{"flowchart":{"htmlLabels":false,"useMaxWidth":false},'
    '"htmlLabels":false}'
)


def render_mermaid_to_svg(mmd_src: str, out_path: Path) -> bool:
    if not Path(MMDC).exists():
        return False
    with tempfile.NamedTemporaryFile("w", suffix=".mmd", delete=False) as f:
        f.write(mmd_src)
        tmp = f.name
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as cf:
        cf.write(_MMDC_CONFIG)
        cfg = cf.name
    try:
        cmd = [MMDC, "-i", tmp, "-o", str(out_path), "-b", "white",
               "-c", cfg]
        if Path(PUPPETEER_CONFIG).exists():
            cmd.extend(["-p", PUPPETEER_CONFIG])
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return r.returncode == 0 and out_path.exists()
    except Exception as e:
        print(f"[report] mmdc failed: {e}", file=sys.stderr)
        return False
    finally:
        for p in (tmp, cfg):
            try:
                os.unlink(p)
            except Exception:
                pass


def md_to_html_body(md_text: str) -> str:
    from markdown_it import MarkdownIt
    md = MarkdownIt("commonmark", {"html": True, "linkify": False,
                                   "typographer": False})
    md.enable("table").enable("strikethrough")
    return md.render(md_text)


HTML_STYLE = """
:root { color-scheme: light; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
       "Helvetica Neue", Arial, sans-serif; max-width: 1200px; margin: 24px auto;
       padding: 0 24px 80px; color: #1f2328; line-height: 1.55; }
h1 { border-bottom: 1px solid #d0d7de; padding-bottom: 8px; margin-top: 32px; }
h2 { border-bottom: 1px solid #eaeef2; padding-bottom: 6px; margin-top: 28px; }
h3 { margin-top: 22px; }
table { border-collapse: collapse; margin: 12px 0; font-size: 13px;
        width: 100%; table-layout: auto; }
th, td { border: 1px solid #d0d7de; padding: 6px 10px; text-align: left;
         vertical-align: top; word-wrap: break-word; overflow-wrap: anywhere;
         hyphens: auto; }
th { background: #f6f8fa; font-weight: 600; }
tr:nth-child(even) td { background: #fafbfc; }
code { background: #f6f8fa; padding: 2px 5px; border-radius: 4px;
       font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
       font-size: 12.5px; word-wrap: break-word; overflow-wrap: anywhere; }
pre { background: #f6f8fa; padding: 12px; border-radius: 6px; overflow-x: auto;
      font-size: 12.5px; }
pre code { background: transparent; padding: 0; }
img { max-width: 100%; height: auto; }
blockquote { border-left: 4px solid #d0d7de; padding-left: 14px; color: #57606a;
             margin: 12px 0; }
.mermaid { background: #fff; padding: 6px; border-radius: 6px; }
hr { border: 0; border-top: 1px solid #d0d7de; margin: 28px 0; }
@media print {
  body { max-width: none; margin: 0; padding: 10mm; font-size: 9.5pt; }
  h1, h2, h3 { page-break-after: avoid; }
  table { font-size: 7.5pt; width: 100%; table-layout: fixed; }
  th, td { padding: 3px 5px; word-wrap: break-word; overflow-wrap: anywhere;
           hyphens: auto; -webkit-hyphens: auto; }
  pre, code { font-size: 7.5pt; word-wrap: break-word; overflow-wrap: anywhere;
              white-space: pre-wrap; }
  pre { padding: 6px; }
  img, .mermaid { page-break-inside: avoid; max-width: 100%; }
}
"""

HTML_HEAD = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>SensorGrind_AI Comprehensive Report</title>
<style>{style}</style>
</head>
<body>
{body}
<script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
<script>
mermaid.initialize({{startOnLoad:false, theme:'neutral', securityLevel:'loose'}});
document.querySelectorAll('pre > code.language-mermaid, pre code.language-mermaid').forEach(function(el){{
  var pre = el.parentElement;
  var div = document.createElement('div');
  div.className = 'mermaid';
  div.textContent = el.textContent;
  pre.replaceWith(div);
}});
mermaid.run();
</script>
</body>
</html>
"""


def write_html(md_text: str, html_path: Path) -> None:
    body = md_to_html_body(md_text)
    html_path.write_text(HTML_HEAD.format(style=HTML_STYLE, body=body))


def prerender_mermaid_for_pdf(md_text: str, svg_dir: Path) -> str:
    svg_dir.mkdir(parents=True, exist_ok=True)
    counter = [0]

    def _sub(m: re.Match) -> str:
        counter[0] += 1
        idx = counter[0]
        src = m.group(1)
        out = svg_dir / f"mmd_{idx:04d}.svg"
        ok = render_mermaid_to_svg(src, out)
        if not ok:
            return m.group(0)
        return (f"![mermaid {idx}]"
                f"({out.relative_to(lib.REPORTS).as_posix()})")

    return _MERMAID_BLOCK.sub(_sub, md_text)


def write_pdf(md_text: str, pdf_path: Path) -> None:
    from weasyprint import HTML, CSS
    pdf_md = prerender_mermaid_for_pdf(md_text, VISUALS_DIR / "mermaid")
    body = md_to_html_body(pdf_md)
    html_doc = HTML_HEAD.format(style=HTML_STYLE, body=body)
    HTML(string=html_doc, base_url=str(lib.REPORTS)).write_pdf(
        str(pdf_path),
        stylesheets=[CSS(string="@page { size: A4; margin: 14mm; }")],
    )


# ----------------------------------------------------------------------
# DuckDB helpers used by section composers
# ----------------------------------------------------------------------

def safe_read_table(con, path: Path, where: str = "") -> list[tuple]:
    if not path.exists() or path.stat().st_size == 0:
        return []
    sql = f"SELECT * FROM read_parquet('{path}')"
    if where:
        sql += f" WHERE {where}"
    return con.execute(sql).fetchall()


def safe_columns(con, path: Path) -> list[str]:
    if not path.exists() or path.stat().st_size == 0:
        return []
    rows = con.execute(
        f"DESCRIBE SELECT * FROM read_parquet('{path}')"
    ).fetchall()
    return [r[0] for r in rows]
