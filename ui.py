
"""UI helpers and dark visual system for Drift Detector."""

import html
import json
import math
from datetime import datetime

from core import DOT, TYPE_LABEL, label, plain, RISK_RULES, STANDARD_BASELINE
from security_baseline import BASELINE_COUNTS, STANDARD_SECURITY_BASELINE

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def esc(s) -> str:
    return html.escape("" if s is None else str(s), quote=True).replace("$", "&#36;")


def rich(text: str) -> str:
    """Escape text and render backtick-wrapped content as code."""
    out, parts = [], esc(text).split("`")
    for i, part in enumerate(parts):
        out.append(f"<code>{part}</code>" if i % 2 else part)
    return "".join(out)


def time_ago(dt: datetime) -> str:
    seconds = (datetime.now() - dt).total_seconds()

    if seconds < 60:
        return "just now"

    minutes = seconds / 60
    if minutes < 60:
        return f"{round(minutes)} min ago"

    hours = minutes / 60
    if hours < 24:
        return f"{round(hours)} h ago"

    return f"{round(hours / 24)} d ago"


def fmt_date(dt) -> str:
    if isinstance(dt, str):
        dt = datetime.fromisoformat(dt)
    return dt.strftime("%b %d, %I:%M %p")


def kind_label(kind: str) -> str:
    return {
        "json": "JSON",
        "ssh": "SSH config",
        "standard": "Standard",
    }.get(kind, kind)


def risk_badge(r: str) -> str:
    return (
        f'<span class="badge {esc(r)}">'
        f'<i></i>{"Clean" if r == "None" else esc(r)}</span>'
    )


def type_badge(t: str) -> str:
    return f'<span class="badge t-{esc(t)}">{esc(TYPE_LABEL[t])}</span>'


def status_badge(s: str) -> str:
    return f'<span class="badge s-{esc(s)}">{esc(s)}</span>'


def chip(value, cls: str = "", present: bool = True) -> str:
    if not present:
        return '<span class="chip none">not set</span>'

    return (
        f'<span class="chip {esc(cls)}">'
        f'{esc(plain(value))}</span>'
    )


def finding_chips(f):
    """Return expected and actual value chips for a finding."""
    return (
        chip(f["expected"], "", f["type"] != "added"),
        chip(f["actual"], "t-" + f["type"], f["type"] != "removed"),
    )


def pill(text: str, cls: str = "") -> str:
    return f'<span class="pill {esc(cls)}">{esc(text)}</span>'


# ---------------------------------------------------------------------------
# Reusable HTML blocks
# ---------------------------------------------------------------------------

_ICON = (
    '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" '
    'stroke="currentColor" stroke-width="1.7" '
    'stroke-linecap="round" stroke-linejoin="round">{}</svg>'
)


def hero() -> str:
    return (
        '<div class="hero">'
        '<div class="hero-eyebrow">CONFIGURATION INTELLIGENCE</div>'
        '<h1>See what changed.<br>'
        '<span class="grad">Know what matters.</span></h1>'
        '<p class="hero-sub">'
        'Compare configurations against trusted baselines, '
        'identify security drift, and understand what needs attention.'
        '</p></div>'
    )


def step_head(n: str, title: str, tag: str, tag_cls: str, desc: str) -> str:
    return (
        f'<div class="step">'
        f'<div class="step-top">'
        f'<span class="step-n">{esc(n)}</span>'
        f'<span class="tag-pill {esc(tag_cls)}">{esc(tag)}</span>'
        f'</div>'
        f'<h3>{esc(title)}</h3>'
        f'<p>{esc(desc)}</p>'
        '<div class="fmt"><span>JSON</span><span>sshd_config</span></div>'
        '</div>'
    )


def ready_line(msg_html: str, ok: bool) -> str:
    return (
        f'<div class="ready {"ok" if ok else ""}">'
        f'<i></i><span>{msg_html}</span></div>'
    )


def features() -> str:
    items = [
        (
            _ICON.format('<path d="M4 6h16M4 12h16M4 18h10"/>'),
            "Rules decide",
            "Every change is evaluated using defined rules. Nothing is guessed.",
        ),
        (
            _ICON.format(
                '<path d="M12 3l1.8 5.2L19 10l-5.2 1.8L12 17'
                'l-1.8-5.2L5 10l5.2-1.8z"/>'
            ),
            "AI explains",
            "Understand verified findings with plain-language explanations.",
        ),
        (
            _ICON.format(
                '<circle cx="12" cy="12" r="9"/>'
                '<path d="M8.5 12.5l2.5 2.5 4.5-5"/>'
            ),
            "You approve",
            "Every proposed fix requires your decision. No server is modified.",
        ),
    ]

    return (
        '<div class="features">'
        + "".join(
            f'<div class="feat"><div class="feat-ic">{icon}</div>'
            f'<h4>{title}</h4><p>{description}</p></div>'
            for icon, title, description in items
        )
        + "</div>"
    )



def baseline_table() -> str:
    """Display the complete built-in 106-rule security baseline."""

    platform_names = {
        "ubuntu_22_04": "Ubuntu 22.04",
        "ssh": "SSH Server",
        "nginx": "NGINX",
    }

    parts = [
        '<div class="baseline-overview">',
        '<div class="baseline-summary">',
        '<div><strong>106</strong><span>Total rules</span></div>',
        f'<div><strong>{BASELINE_COUNTS["automatic"]}</strong><span>Automatic</span></div>',
        f'<div><strong>{BASELINE_COUNTS["manual"]}</strong><span>Manual review</span></div>',
        '</div>',
        '<p class="hint">Built-in security baseline · Version '
        f'{esc("1.0")}</p>',
        '</div>',
    ]

    for platform_key, rules in STANDARD_SECURITY_BASELINE.items():
        platform_name = platform_names.get(
            platform_key,
            platform_key.replace("_", " ").title(),
        )

        automatic_count = sum(1 for rule in rules if rule["automatic"])
        manual_count = len(rules) - automatic_count

        parts.append(
            '<div class="baseline-platform">'
            f'<div class="baseline-platform-heading">'
            f'<h3>{esc(platform_name)}</h3>'
            f'<span class="muted">{len(rules)} rules</span>'
            '</div>'
            f'<p class="hint">{automatic_count} automatic · '
            f'{manual_count} manual review</p>'
            '<div class="table-wrap"><table>'
            '<thead><tr>'
            '<th>Rule ID</th>'
            '<th>Security rule</th>'
            '<th>Setting</th>'
            '<th>Expected</th>'
            '<th>Severity</th>'
            '<th>Evaluation</th>'
            '</tr></thead><tbody>'
        )

        for rule in rules:
            evaluation = (
                '<span class="baseline-auto">Automatic</span>'
                if rule["automatic"]
                else '<span class="baseline-manual">Manual review</span>'
            )

            expected = rule["expected"]
            if isinstance(expected, (dict, list)):
                expected = json.dumps(expected)

            parts.append(
                '<tr>'
                f'<td><span class="mono">{esc(rule["id"])}</span></td>'
                f'<td><b>{esc(rule["title"])}</b>'
                f'<div class="muted">{esc(rule["category"])}</div></td>'
                f'<td><span class="key">{esc(rule["setting"])}</span></td>'
                f'<td>{chip(expected)}</td>'
                f'<td>{risk_badge(rule["severity"])}</td>'
                f'<td>{evaluation}</td>'
                '</tr>'
            )

        parts.append('</tbody></table></div></div>')

    return ''.join(parts)



def empty_state(title: str, msg: str) -> str:
    return (
        '<div class="empty-state">'
        '<div class="big">'
        '<svg width="30" height="30" viewBox="0 0 24 24" '
        'fill="none" stroke="currentColor" stroke-width="1.6" '
        'stroke-linecap="round" stroke-linejoin="round">'
        '<path d="M5 4h10l4 4v12H5z"/>'
        '<path d="M15 4v4h4"/><path d="M9 13h6M9 17h4"/>'
        '</svg></div>'
        f'<h3>{esc(title)}</h3><p>{esc(msg)}</p></div>'
    )


def empty_clean(msg: str) -> str:
    return (
        '<div class="empty-state ok">'
        '<div class="big">'
        '<svg width="30" height="30" viewBox="0 0 24 24" '
        'fill="none" stroke="currentColor" stroke-width="1.8" '
        'stroke-linecap="round" stroke-linejoin="round">'
        '<circle cx="12" cy="12" r="9"/>'
        '<path d="M8.5 12.5l2.5 2.5 4.5-5"/>'
        '</svg></div>'
        '<h3>No drift detected</h3>'
        f'<p>{esc(msg)}</p></div>'
    )


def empty(title: str, msg: str = "") -> str:
    return (
        f'<div class="empty-state">'
        f'<h3>{esc(title)}</h3><p>{esc(msg)}</p></div>'
    )


def result_head(name: str, kind: str, base_label: str, when: str) -> str:
    return (
        '<div class="res-head">'
        '<div class="eyebrow">COMPARISON RESULT</div>'
        f'<h1>{esc(name)}</h1>'
        f'<div class="res-meta">{pill(kind_label(kind))}'
        f'<span class="vs">compared with</span>'
        f'{pill(base_label, "accent")}'
        f'<span class="vs">· {esc(when)}</span>'
        '</div></div>'
    )


def verdict(findings: list, checked: int) -> str:
    count = len(findings)
    high = sum(1 for f in findings if f["risk"] == "High")

    if not count:
        title = "All clear."
        sub = f"All {checked} checked settings match the baseline."
    elif high:
        title = f"{high} critical change{'' if high == 1 else 's'} need attention."
        sub = (
            f"{count} difference{'' if count == 1 else 's'} "
            f"found across {checked} checked settings."
        )
    else:
        title = f"{count} change{'' if count == 1 else 's'} found."
        sub = f"None are high risk. {checked} settings were checked."

    counts = {
        risk: sum(1 for f in findings if f["risk"] == risk)
        for risk in ("High", "Medium", "Low")
    }

    stats = "".join(
        f'<div class="stat"><div class="stat-n">{counts[risk]}</div>'
        f'<div class="stat-l">'
        f'<i style="background:{DOT[risk]}"></i>{risk}</div></div>'
        for risk in counts
    )

    return (
        f'<div class="verdict"><h2>{esc(title)}</h2>'
        f'<p>{esc(sub)}</p><div class="stats">{stats}</div></div>'
    )


# ---------------------------------------------------------------------------
# SVG charts
# ---------------------------------------------------------------------------

def ring(score: int) -> str:
    circumference = 2 * math.pi * 56
    color = (
        DOT["Low"] if score >= 80
        else DOT["Medium"] if score >= 50
        else DOT["High"]
    )

    return (
        f'<svg class="ring" viewBox="0 0 140 140" role="img" '
        f'aria-label="Posture score {score} out of 100">'
        '<circle cx="70" cy="70" r="56" fill="none" '
        'stroke="#34343A" stroke-width="10"/>'
        f'<circle cx="70" cy="70" r="56" fill="none" '
        f'stroke="{color}" stroke-width="10" stroke-linecap="round" '
        f'stroke-dasharray="{circumference * score / 100:.2f} '
        f'{circumference:.2f}" transform="rotate(-90 70 70)"/>'
        f'<text x="70" y="77" text-anchor="middle" '
        f'class="r-num">{score}</text>'
        '<text x="70" y="96" text-anchor="middle" '
        'class="r-lbl">out of 100</text></svg>'
    )


def trend(points: list[dict]) -> str:
    if not points:
        return ""

    width, height, padding = 460, 150, 28
    maximum = max([1] + [p["drifts"] for p in points])
    count = len(points)

    def x_pos(i):
        fraction = 0.5 if count == 1 else i / (count - 1)
        return padding + (width - 2 * padding) * fraction

    def y_pos(value):
        return height - padding - (
            (height - 2 * padding) * value / maximum
        )

    line = " ".join(
        f"{x_pos(i):.1f},{y_pos(p['drifts']):.1f}"
        for i, p in enumerate(points)
    )

    dots = "".join(
        f'<circle cx="{x_pos(i):.1f}" '
        f'cy="{y_pos(p["drifts"]):.1f}" r="4" fill="#2997FF"/>'
        f'<text x="{x_pos(i):.1f}" '
        f'y="{y_pos(p["drifts"]) - 10:.1f}" '
        f'text-anchor="middle" font-size="11" '
        f'fill="#F5F5F7" font-weight="600">{p["drifts"]}</text>'
        for i, p in enumerate(points)
    )

    labels = "".join(
        f'<text x="{x_pos(i):.1f}" y="{height - 6}" '
        f'text-anchor="middle" font-size="10" fill="#A1A1AA">'
        f'{esc(p["time"].strftime("%H:%M"))}</text>'
        for i, p in enumerate(points)
    )

    return (
        f'<svg viewBox="0 0 {width} {height}" width="100%" '
        'role="img" aria-label="Drift count across comparisons">'
        f'<line x1="{padding}" y1="{height - padding}" '
        f'x2="{width - padding}" y2="{height - padding}" '
        'stroke="#34343A"/>'
        f'<polyline points="{line}" fill="none" '
        'stroke="#2997FF" stroke-width="2.5" '
        'stroke-linejoin="round"/>'
        f'{dots}{labels}</svg>'
    )


def raw_json(obj: dict, drifts: list[dict]) -> str:
    by = {d["setting"]: d["type"] for d in drifts}
    keys = list(obj)
    lines = ""

    for i, key in enumerate(keys):
        value = json.dumps(obj[key]).replace(",", ", ")
        txt = f'  "{key}": {value}'
        if i < len(keys) - 1:
            txt += ","

        cls = f" d-{by[key]}" if key in by else ""
        lines += f'<span class="ln{cls}">{esc(txt)}</span>'

    return (
        '<div class="code">'
        '<span class="ln">{</span>'
        f'{lines}'
        '<span class="ln">}</span>'
        '</div>'
    )


# ---------------------------------------------------------------------------
# Brand and footer
# ---------------------------------------------------------------------------

BRAND = (
    '<div class="brand">'
    '<span class="logo">'
    '<svg width="17" height="17" viewBox="0 0 24 24" fill="none" '
    'stroke="currentColor" stroke-width="2" '
    'stroke-linecap="round" stroke-linejoin="round">'
    '<path d="M12 3l8 3v6c0 4.5-3.2 8.2-8 9-4.8-.8-8-4.5-8-9V6z"/>'
    '<path d="M9 12l2 2 4-4"/></svg></span>'
    '<span class="brand-name">Drift<span class="brand-dot">.</span></span>'
    '</div>'
)

FOOTER = (
    '<div class="foot">'
    'Detection and risk are rule-based. AI only explains verified findings. '
    'A person approves every fix.'
    '</div>'
)


# ---------------------------------------------------------------------------
# Dark theme CSS
# ---------------------------------------------------------------------------

CSS = r"""
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

:root {
    color-scheme: dark;

    --bg: #090909;
    --surface: #111113;
    --alt: #161618;
    --raised: #1C1C1F;
    --hover: #242428;

    --ink: #F5F5F7;
    --ink-2: #D1D1D6;
    --muted: #929299;

    --line: #343438;
    --line-2: #29292D;

    --accent: #2997FF;
    --accent-h: #47A7FF;
    --accent-50: rgba(41,151,255,.12);
    --accent-ink: #66B5FF;

    --high: #FF6961;
    --high-bg: rgba(255,69,58,.12);
    --high-line: rgba(255,69,58,.28);

    --medium: #FFB454;
    --medium-bg: rgba(255,159,10,.12);
    --medium-line: rgba(255,159,10,.26);

    --low: #30D158;
    --low-bg: rgba(48,209,88,.11);
    --low-line: rgba(48,209,88,.24);

    --t-modified: #66B5FF;
    --t-modified-bg: rgba(41,151,255,.13);
    --t-added: #30D158;
    --t-added-bg: rgba(48,209,88,.11);
    --t-removed: #BF8AFF;
    --t-removed-bg: rgba(191,138,255,.12);

    --radius: 18px;
    --radius-sm: 12px;
    --shadow: 0 8px 32px rgba(0,0,0,.22);

    --mono: ui-monospace, 'SF Mono', SFMono-Regular, Menlo, Consolas, monospace;
    --sans: -apple-system, BlinkMacSystemFont, 'SF Pro Display',
            'SF Pro Text', 'Inter', 'Helvetica Neue', Arial, sans-serif;
}

html, body, [class*="st-"], .stApp {
    font-family: var(--sans);
    -webkit-font-smoothing: antialiased;
}

.stApp {
    background: var(--bg);
    color: var(--ink);
}

[data-testid="stMainBlockContainer"] {
    max-width: 1440px;
    padding: 1.8rem 3rem 4rem;
}

h1, h2, h3, h4, p {
    margin: 0;
    padding: 0;
    color: inherit;
}

code, .mono {
    font-family: var(--mono);
}

.muted {
    color: var(--muted);
}

[data-testid="stHeader"] {
    background: transparent;
}

[data-testid="stToolbar"],
[data-testid="stDecoration"],
.stDeployButton,
#MainMenu,
footer {
    display: none !important;
}

[data-testid="stIconMaterial"],
span[class*="material"] {
    font-family: 'Material Symbols Rounded',
                 'Material Symbols Outlined' !important;
}

/* ---------- sidebar foundation ---------- */

section[data-testid="stSidebar"] {
    background: #101012;
    border-right: 1px solid var(--line-2);
}

section[data-testid="stSidebar"] > div {
    background: #101012;
}

section[data-testid="stSidebar"] [data-testid="stVerticalBlock"] {
    gap: .7rem;
}

section[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p {
    color: var(--ink-2);
}

section[data-testid="stSidebar"] .stButton > button {
    width: 100%;
    justify-content: flex-start;
    text-align: left;
    border: 1px solid transparent;
    border-radius: 11px;
    background: transparent;
    color: var(--ink-2);
    padding: .65rem .85rem;
    transition: background .18s ease, border-color .18s ease;
}

section[data-testid="stSidebar"] .stButton > button:hover {
    background: var(--hover);
    border-color: var(--line);
    color: var(--ink);
}

section[data-testid="stSidebar"] [data-testid="stSidebarCollapseButton"] {
    color: var(--muted);
}

/* ---------- brand ---------- */

.brand {
    display: flex;
    align-items: center;
    gap: 11px;
    padding: 7px 0;
}

.logo {
    width: 34px;
    height: 34px;
    border-radius: 11px;
    background: var(--accent);
    color: #fff;
    display: grid;
    place-items: center;
    box-shadow: 0 3px 14px rgba(41,151,255,.2);
}

.brand-name {
    color: var(--ink);
    font-size: 1.22rem;
    font-weight: 700;
    letter-spacing: -.045em;
}

.brand-dot {
    color: var(--accent);
}

/* ---------- existing top navigation ---------- */

.st-key-topnav {
    position: sticky;
    top: 0;
    z-index: 100;
    background: rgba(9,9,9,.88);
    backdrop-filter: saturate(160%) blur(22px);
    -webkit-backdrop-filter: saturate(160%) blur(22px);
    border-bottom: 1px solid var(--line-2);
    padding: 12px 28px;
    margin: 0 -28px 0;
}

.st-key-topnav .stButton > button {
    border: 1px solid transparent;
    background: transparent;
    color: var(--muted);
    font-size: .86rem;
    font-weight: 500;
    border-radius: 10px;
    padding: .45rem .75rem;
    min-height: 0;
    transition: all .18s ease;
}

.st-key-topnav .stButton > button:hover {
    background: var(--hover);
    color: var(--ink);
}

.st-key-topnav .stButton > button p {
    font-size: .86rem;
}

.nav-right {
    text-align: right;
    color: var(--muted);
    font-size: .8rem;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}

/* ---------- hero ---------- */

.hero {
    text-align: center;
    padding: 76px 0 48px;
}

.hero-eyebrow {
    color: var(--accent);
    font-size: .76rem;
    font-weight: 700;
    letter-spacing: .16em;
    margin-bottom: 20px;
}

.stApp .hero h1 {
    color: var(--ink);
    font-size: clamp(2.6rem, 6vw, 4.5rem);
    line-height: 1.04;
    letter-spacing: -.065em;
    font-weight: 700;
}

.hero .grad {
    color: var(--accent);
}

.stApp .hero-sub {
    color: var(--muted);
    font-size: 1.12rem;
    line-height: 1.7;
    max-width: 650px;
    margin: 22px auto 0;
    font-weight: 400;
}

/* ---------- upload cards ---------- */

[class*="st-key-card_"] {
    background: var(--surface);
    border: 1px solid var(--line-2);
    border-radius: 20px;
    padding: 26px 26px 22px !important;
    gap: .8rem;
    transition: border-color .2s ease, background .2s ease;
}

[class*="st-key-card_"]:hover {
    border-color: #45454B;
    background: #141416;
}

.step-top {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 12px;
}

.step-n {
    width: 27px;
    height: 27px;
    border-radius: 9px;
    background: var(--accent-50);
    color: var(--accent);
    font-size: .8rem;
    font-weight: 700;
    display: grid;
    place-items: center;
}

.tag-pill {
    font-size: .7rem;
    font-weight: 600;
    padding: 4px 10px;
    border-radius: 999px;
}

.tag-pill.req {
    background: var(--accent-50);
    color: var(--accent-ink);
}

.tag-pill.opt {
    background: var(--raised);
    color: var(--muted);
    border: 1px solid var(--line);
}

.stApp .step h3 {
    font-size: 1.35rem;
    letter-spacing: -.035em;
    font-weight: 650;
    color: var(--ink);
}

.stApp .step p {
    color: var(--muted);
    margin-top: 7px;
    line-height: 1.6;
    font-size: .91rem;
}

.fmt {
    display: flex;
    gap: 7px;
    margin-top: 13px;
}

.fmt span {
    font-family: var(--mono);
    font-size: .7rem;
    background: var(--raised);
    border: 1px solid var(--line-2);
    color: var(--ink-2);
    padding: 4px 10px;
    border-radius: 7px;
}

[data-testid="stFileUploaderDropzone"] {
    background: #0D0D0F;
    border: 1.5px dashed #45454B;
    border-radius: 14px;
    padding: 20px;
    transition: border-color .2s ease, background .2s ease;
}

[data-testid="stFileUploaderDropzone"]:hover {
    border-color: var(--accent);
    background: rgba(41,151,255,.04);
}

[data-testid="stFileUploaderDropzone"] button {
    background: var(--raised);
    color: var(--ink);
    border: 1px solid var(--line);
}

[data-testid="stFileUploaderFile"] {
    background: var(--raised);
    border-radius: 10px;
    border: 1px solid var(--line);
}

.ready {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 10px;
    margin: 26px auto 16px;
    color: var(--muted);
    font-size: .94rem;
    text-align: center;
}

.ready i {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: #55555B;
    display: inline-block;
    flex: none;
}

.ready.ok i {
    background: var(--low);
    box-shadow: 0 0 0 4px var(--low-bg);
}

.ready b {
    color: var(--ink);
    font-weight: 600;
}

/* ---------- feature section ---------- */

.features {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 18px;
    margin: 62px 0 8px;
}

.feat {
    text-align: center;
    padding: 24px 18px;
    background: var(--surface);
    border: 1px solid var(--line-2);
    border-radius: 18px;
    transition: transform .2s ease, border-color .2s ease;
}

.feat:hover {
    transform: translateY(-3px);
    border-color: #45454B;
}

.feat-ic {
    width: 45px;
    height: 45px;
    border-radius: 13px;
    background: var(--accent-50);
    display: grid;
    place-items: center;
    margin: 0 auto 14px;
    color: var(--accent);
}

.stApp .feat h4 {
    color: var(--ink);
    font-size: 1rem;
    font-weight: 650;
}

.stApp .feat p {
    color: var(--muted);
    font-size: .86rem;
    line-height: 1.6;
    margin-top: 7px;
}

[data-testid="stExpander"] {
    border: 1px solid var(--line-2) !important;
    background: var(--surface);
    border-radius: 14px;
}

[data-testid="stExpander"] summary {
    color: var(--ink);
    font-weight: 600;
}

/* ---------- result header and verdict ---------- */

.res-head {
    padding: 38px 0 26px;
}

.eyebrow {
    color: var(--accent);
    font-size: .75rem;
    font-weight: 700;
    letter-spacing: .12em;
    margin-bottom: 10px;
}

.stApp .res-head h1 {
    font-family: var(--mono);
    color: var(--ink);
    font-size: clamp(1.5rem, 4vw, 2.25rem);
    letter-spacing: -.04em;
    font-weight: 650;
    word-break: break-all;
}

.res-meta {
    display: flex;
    align-items: center;
    gap: 9px;
    flex-wrap: wrap;
    margin-top: 14px;
    color: var(--muted);
}

.vs {
    font-size: .85rem;
    color: var(--muted);
}

.pill {
    display: inline-block;
    padding: 5px 11px;
    border-radius: 8px;
    font-size: .76rem;
    font-weight: 600;
    background: var(--raised);
    color: var(--ink-2);
    border: 1px solid var(--line-2);
}

.pill.accent {
    background: var(--accent-50);
    color: var(--accent-ink);
    border-color: rgba(41,151,255,.2);
}

.verdict {
    padding: 8px 0;
}

.stApp .verdict h2 {
    color: var(--ink);
    font-size: clamp(1.6rem, 4vw, 2.15rem);
    letter-spacing: -.05em;
    font-weight: 700;
    line-height: 1.15;
}

.stApp .verdict p {
    color: var(--muted);
    font-size: .98rem;
    margin-top: 10px;
    line-height: 1.6;
}

.stats {
    display: flex;
    gap: 30px;
    margin-top: 25px;
    flex-wrap: wrap;
}

.stat-n {
    color: var(--ink);
    font-size: 2.35rem;
    font-weight: 700;
    letter-spacing: -.06em;
    line-height: 1;
}

.stat-l {
    display: flex;
    align-items: center;
    gap: 8px;
    color: var(--muted);
    font-size: .85rem;
    margin-top: 8px;
}

.stat-l i {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    display: inline-block;
}

.card-title {
    color: var(--ink);
    font-size: 1rem;
    font-weight: 650;
    margin-bottom: 12px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 10px;
}

.card-title small {
    color: var(--muted);
    font-weight: 500;
    font-size: .78rem;
}

.center {
    display: flex;
    flex-direction: column;
    align-items: center;
    text-align: center;
}

.ring {
    width: 150px;
    height: 150px;
}

.ring text.r-num {
    font-size: 38px;
    font-weight: 700;
    fill: var(--ink);
    letter-spacing: -.04em;
}

.ring text.r-lbl {
    font-size: 11px;
    fill: var(--muted);
}

.stApp .formula {
    color: var(--muted);
    font-size: .76rem;
    margin-top: 8px;
}

.note {
    background: var(--surface);
    border: 1px solid var(--line-2);
    border-radius: 15px;
    padding: 16px 20px;
    color: var(--ink-2);
    font-size: .9rem;
    line-height: 1.6;
}

.note b {
    color: var(--ink);
}

.note code {
    background: var(--raised);
    padding: 2px 6px;
    border-radius: 5px;
    font-size: .82em;
}

/* ---------- badges and chips ---------- */

.badge {
    display: inline-flex;
    align-items: center;
    gap: 7px;
    padding: 4px 10px;
    border-radius: 7px;
    font-size: .73rem;
    font-weight: 650;
    border: 1px solid transparent;
    white-space: nowrap;
}

.badge i {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    display: inline-block;
}

.badge.High {
    background: var(--high-bg);
    color: var(--high);
    border-color: var(--high-line);
}

.badge.High i {
    background: var(--high);
}

.badge.Medium {
    background: var(--medium-bg);
    color: var(--medium);
    border-color: var(--medium-line);
}

.badge.Medium i {
    background: var(--medium);
}

.badge.Low,
.badge.None {
    background: var(--low-bg);
    color: var(--low);
    border-color: var(--low-line);
}

.badge.Low i,
.badge.None i {
    background: var(--low);
}

.badge.t-modified {
    background: var(--t-modified-bg);
    color: var(--t-modified);
}

.badge.t-added {
    background: var(--t-added-bg);
    color: var(--t-added);
}

.badge.t-removed {
    background: var(--t-removed-bg);
    color: var(--t-removed);
}

.badge.t-same {
    background: var(--raised);
    color: var(--muted);
}

.badge.s-Pending {
    background: var(--raised);
    color: var(--ink-2);
}

.badge.s-Approved {
    background: var(--low-bg);
    color: var(--low);
}

.badge.s-Rejected {
    background: var(--high-bg);
    color: var(--high);
}

.chip {
    font-family: var(--mono);
    font-size: .78rem;
    padding: 4px 9px;
    border-radius: 7px;
    background: var(--raised);
    color: var(--ink-2);
    border: 1px solid var(--line-2);
    display: inline-block;
}

.chip.none {
    background: transparent;
    border: 1px dashed var(--line);
    color: var(--muted);
    font-style: italic;
}

.chip.t-modified {
    background: var(--t-modified-bg);
    color: var(--t-modified);
}

.chip.t-added {
    background: var(--t-added-bg);
    color: var(--t-added);
}

.chip.t-removed {
    background: var(--t-removed-bg);
    color: var(--t-removed);
}

.tag {
    font-size: .66rem;
    font-weight: 700;
    letter-spacing: .06em;
    text-transform: uppercase;
    padding: 3px 7px;
    border-radius: 5px;
    margin-left: 8px;
    vertical-align: 2px;
}

.tag-rule {
    background: var(--raised);
    color: var(--ink-2);
}

.tag-ai {
    background: var(--accent-50);
    color: var(--accent-ink);
}

.key {
    display: block;
    font-family: var(--mono);
    font-size: .7rem;
    color: var(--muted);
    margin-top: 4px;
}

.stApp .cell-title {
    font-weight: 600;
    color: var(--ink);
}

.stApp .cell-sub {
    color: var(--muted);
    font-size: .8rem;
}

.empty-state {
    text-align: center;
    padding: 65px 20px;
    color: var(--muted);
    background: var(--surface);
    border: 1px solid var(--line-2);
    border-radius: 20px;
}

.stApp .empty-state h3 {
    color: var(--ink);
    font-size: 1.35rem;
    letter-spacing: -.035em;
    margin-bottom: 8px;
}

.empty-state p {
    color: var(--muted);
    line-height: 1.6;
}

.empty-state .big {
    width: 60px;
    height: 60px;
    border-radius: 17px;
    background: var(--raised);
    color: var(--muted);
    display: grid;
    place-items: center;
    margin: 0 auto 18px;
}

.empty-state.ok .big {
    background: var(--low-bg);
    color: var(--low);
}

.stApp .foot {
    text-align: center;
    color: var(--muted);
    font-size: .76rem;
    padding: 42px 0 0;
}

.mini-row {
    display: flex;
    gap: 12px;
    flex-wrap: wrap;
    margin: 6px 0 16px;
}

.mini {
    background: var(--surface);
    border: 1px solid var(--line-2);
    border-radius: 13px;
    padding: 12px 18px;
    display: flex;
    align-items: center;
    gap: 10px;
}

.mini b {
    color: var(--ink);
    font-size: 1.25rem;
    letter-spacing: -.03em;
}

/* ---------- tables built from Streamlit columns ---------- */

[class*="st-key-tbl_"] {
    background: var(--surface);
    border: 1px solid var(--line-2);
    border-radius: var(--radius);
    overflow: hidden;
    gap: 0 !important;
    margin-top: 6px;
}

[class*="st-key-thead_"] {
    background: var(--raised);
    padding: 13px 20px;
}

.th {
    font-size: .69rem;
    text-transform: uppercase;
    letter-spacing: .09em;
    color: var(--muted);
    font-weight: 700;
    white-space: nowrap;
}

[class*="st-key-trow_"] {
    border-top: 1px solid var(--line-2);
    padding: 13px 20px;
    transition: background .15s ease;
}

[class*="st-key-trow_"]:hover {
    background: rgba(255,255,255,.025);
}

[class*="st-key-trow_"] [data-testid="stVerticalBlock"] {
    gap: .15rem;
}

.table-wrap {
    overflow-x: auto;
    border: 1px solid var(--line-2);
    border-radius: var(--radius);
    background: var(--surface);
}

.table-wrap table {
    width: 100%;
    border-collapse: collapse;
}

.table-wrap th {
    text-align: left;
    font-size: .69rem;
    text-transform: uppercase;
    letter-spacing: .08em;
    color: var(--muted);
    font-weight: 700;
    padding: 13px 18px;
    background: var(--raised);
}

.table-wrap td {
    color: var(--ink-2);
    padding: 13px 18px;
    border-top: 1px solid var(--line-2);
}

.table-wrap tr {
    transition: background .15s ease;
}

.table-wrap tbody tr:hover {
    background: rgba(255,255,255,.025);
}

.table-wrap .num {
    text-align: right;
}

/* ---------- code view ---------- */

.code {
    background: #0D0D0F;
    color: #D1D1D6;
    border: 1px solid var(--line-2);
    border-radius: var(--radius);
    padding: 16px 0;
    font-family: var(--mono);
    font-size: .8rem;
    overflow-x: auto;
}

.code .ln {
    display: block;
    padding: 2px 18px;
    white-space: pre;
    border-left: 3px solid transparent;
}

.code .ln.d-modified {
    background: rgba(41,151,255,.13);
    border-left-color: #2997FF;
    color: #F5F5F7;
}

.code .ln.d-added {
    background: rgba(48,209,88,.12);
    border-left-color: #30D158;
    color: #F5F5F7;
}

.code .ln.d-removed {
    background: rgba(191,138,255,.13);
    border-left-color: #BF8AFF;
    color: #F5F5F7;
}

.code-title {
    color: var(--ink);
    font-weight: 600;
    margin-bottom: 8px;
}

.stApp .hint {
    color: var(--muted);
    font-size: .8rem;
    margin-top: 8px;
}

button[data-baseweb="tab"] {
    font-weight: 600;
}

/* ---------- buttons ---------- */

.stButton > button,
.stDownloadButton > button {
    border-radius: 10px;
    font-weight: 600;
    transition:
        background .18s ease,
        color .18s ease,
        border-color .18s ease,
        transform .18s ease;
}

.stButton > button[data-testid="stBaseButton-primary"] {
    background: var(--accent);
    border: 1px solid var(--accent);
    color: #fff;
    padding: .58rem 1.5rem;
}

.stButton > button[data-testid="stBaseButton-primary"]:hover {
    background: var(--accent-h);
    border-color: var(--accent-h);
    transform: translateY(-1px);
}

.stButton > button[data-testid="stBaseButton-primary"]:disabled {
    background: #333338;
    border-color: #333338;
    color: #77777E;
}

.stButton > button[data-testid="stBaseButton-secondary"],
.stDownloadButton > button {
    background: var(--raised);
    border: 1px solid var(--line);
    color: var(--ink);
}

.stButton > button[data-testid="stBaseButton-secondary"]:hover,
.stDownloadButton > button:hover {
    border-color: var(--accent);
    color: var(--accent-ink);
    background: var(--hover);
}

.stButton > button[data-testid="stBaseButton-tertiary"] {
    color: var(--accent-ink);
}

.stButton > button[data-testid="stBaseButton-tertiary"]:hover {
    background: var(--accent-50);
}

div[data-testid="stDialog"] .stButton > button {
    width: 100%;
}

[class*="st-key-rev_"] button {
    padding: .25rem .9rem;
    min-height: 0;
    font-size: .82rem;
    width: 100%;
}

/* ---------- inputs and select boxes ---------- */

.stApp input,
.stApp textarea,
.stApp [data-baseweb="select"] > div {
    background: var(--surface);
    color: var(--ink);
    border-color: var(--line);
    border-radius: 9px;
}

.stApp input:focus,
.stApp textarea:focus {
    border-color: var(--accent);
    box-shadow: 0 0 0 1px var(--accent);
}

.stApp [data-baseweb="popover"],
.stApp [data-baseweb="menu"] {
    background: var(--raised);
    border: 1px solid var(--line);
}

.stApp [role="option"] {
    color: var(--ink-2);
}

.stApp [role="option"]:hover {
    background: var(--hover);
}

.stApp [data-testid="stMetric"] {
    background: var(--surface);
    border: 1px solid var(--line-2);
    border-radius: 14px;
    padding: 15px 17px;
}

.stApp [data-testid="stMetricLabel"] {
    color: var(--muted);
}

.stApp [data-testid="stMetricValue"] {
    color: var(--ink);
}

.stApp [data-testid="stAlert"] {
    border-radius: 12px;
}

/* ---------- tabs and dividers ---------- */

.stApp [data-baseweb="tab-list"] {
    gap: 8px;
    border-bottom: 1px solid var(--line-2);
}

.stApp button[data-baseweb="tab"] {
    color: var(--muted);
    background: transparent;
}

.stApp button[data-baseweb="tab"][aria-selected="true"] {
    color: var(--accent-ink);
}

.stApp [data-testid="stDivider"] {
    border-color: var(--line-2);
}

/* ---------- review drawer ---------- */

div[data-testid="stDialog"] > div {
    position: fixed !important;
    inset: 0 !important;
    width: 100vw !important;
    max-width: none !important;
    height: 100vh !important;
    margin: 0 !important;
    padding: 0 !important;
    background: rgba(0,0,0,.68) !important;
    border-radius: 0 !important;
    align-items: stretch !important;
    justify-content: flex-end !important;
    backdrop-filter: blur(5px);
}

div[data-testid="stDialog"] section[role="dialog"] {
    width: min(560px, 100vw) !important;
    max-width: 560px !important;
    height: 100vh !important;
    max-height: 100vh !important;
    margin: 0 0 0 auto !important;
    border-radius: 0 !important;
    background: #111113 !important;
    border-left: 1px solid var(--line);
    box-shadow: -20px 0 50px rgba(0,0,0,.35);
    overflow-y: auto;
}

.drawer-head {
    padding: 0 0 14px;
    border-bottom: 1px solid var(--line-2);
    margin-bottom: 16px;
}

.stApp .drawer-head .eyebrow {
    font-family: var(--mono);
    font-size: .72rem;
    color: var(--muted);
    font-weight: 500;
}

.stApp .drawer-head h2 {
    color: var(--ink);
    font-size: 1.5rem;
    letter-spacing: -.035em;
    margin: 2px 0;
    padding: 0;
}

.drawer-head code {
    font-size: .78rem;
    color: var(--muted);
}

.badges {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
    margin-bottom: 18px;
}

.sec {
    font-size: .7rem;
    text-transform: uppercase;
    letter-spacing: .1em;
    color: var(--muted);
    font-weight: 700;
    margin: 18px 0 10px;
}

.evidence {
    display: grid;
    grid-template-columns: 1fr auto 1fr;
    gap: 12px;
    align-items: center;
}

.evidence .box {
    border: 1px solid var(--line-2);
    border-radius: var(--radius-sm);
    padding: 12px 14px;
    background: var(--surface);
    min-width: 0;
    overflow-wrap: anywhere;
}

.evidence .box .lbl {
    font-size: .7rem;
    color: var(--muted);
    font-weight: 600;
    margin-bottom: 6px;
}

.arr {
    color: var(--muted);
    font-size: 1.2rem;
}

.exp-block {
    margin-bottom: 14px;
}

.stApp .exp-block h4 {
    font-size: .85rem;
    font-weight: 650;
    margin-bottom: 5px;
    color: var(--ink);
}

.stApp .exp-block p {
    color: var(--ink-2);
    line-height: 1.65;
}

.exp-block code,
.fixbox code {
    background: var(--raised);
    color: var(--accent-ink);
    padding: 2px 6px;
    border-radius: 5px;
    font-size: .84em;
}

.fixbox {
    background: var(--surface);
    border: 1px solid var(--line-2);
    border-left: 3px solid var(--accent);
    border-radius: var(--radius-sm);
    padding: 12px 14px;
    color: var(--ink-2);
    line-height: 1.6;
}

.decided {
    background: var(--surface);
    border: 1px solid var(--line-2);
    border-radius: var(--radius-sm);
    padding: 12px 14px;
}

/* ---------- print ---------- */

/* ---------- print ---------- */

.print-report {
    display: none;
}

@media print {
    @page {
        size: auto;
        margin: 14mm;
    }

    html,
    body,
    .stApp,
    [data-testid="stAppViewContainer"],
    [data-testid="stMain"],
    [data-testid="stMainBlockContainer"] {
        background: #ffffff !important;
        color: #000000 !important;
    }

    .st-key-topnav,
    section[data-testid="stSidebar"],
    header[data-testid="stHeader"] {
        display: none !important;
    }

    [data-testid="stMainBlockContainer"] >
    [data-testid="stVerticalBlock"] > *:not(:has(.print-report)) {
        display: none !important;
    }

    .print-report {
        display: block !important;
        width: 100%;
        padding: 0;
        margin: 0;
        background: #ffffff !important;
        color: #000000 !important;
        font-family: Arial, sans-serif;
    }

    .print-report * {
        color: #000000 !important;
        background-color: #ffffff !important;
        box-shadow: none !important;
        text-shadow: none !important;
    }

    .print-report h1 {
        font-size: 20pt;
        margin-bottom: 4pt;
    }

    .print-report h2 {
        font-size: 13pt;
        margin: 16pt 0 6pt;
        font-family: Arial, sans-serif;
    }

    .print-report p {
        font-size: 10pt;
        line-height: 1.5;
    }

    .print-report table {
        width: 100%;
        border-collapse: collapse;
        font-size: 9.5pt;
        background: #ffffff !important;
    }

    .print-report th {
        background: #eeeeee !important;
        font-weight: 700;
    }

    .print-report th,
    .print-report td {
        border: 1px solid #cccccc !important;
        padding: 5pt 7pt;
        text-align: left;
    }

    .print-report tr {
        page-break-inside: avoid;
    }

    *,
    *::before,
    *::after {
        -webkit-print-color-adjust: exact !important;
        print-color-adjust: exact !important;
    }
}

/* ---------- responsive ---------- */

@media (max-width: 900px) {
    [data-testid="stMainBlockContainer"] {
        padding: 1.3rem 1.2rem 3rem;
    }

    .evidence {
        grid-template-columns: 1fr;
    }

    .evidence .arr {
        transform: rotate(90deg);
        justify-self: center;
    }

    .features {
        grid-template-columns: 1fr;
    }

    .hero {
        padding: 48px 0 34px;
    }
}

@media (max-width: 600px) {
    .stats {
        gap: 20px;
    }

    .stApp .hero h1 {
        font-size: 2.5rem;
    }

    .stApp .hero-sub {
        font-size: 1rem;
    }

    [class*="st-key-card_"] {
        padding: 19px !important;
    }

    .res-meta {
        align-items: flex-start;
    }
}

/* ---------- motion accessibility ---------- */

@media (prefers-reduced-motion: reduce) {
    *,
    *::before,
    *::after {
        scroll-behavior: auto !important;
        animation-duration: .01ms !important;
        transition-duration: .01ms !important;
    }
}

/* ---------- sidebar details ---------- */

.sidebar-label {
    color: #86868B;
    font-size: .68rem;
    font-weight: 700;
    letter-spacing: .12em;
    margin: 1.1rem 0 .35rem;
    padding-left: .65rem;
}

.sidebar-session {
    background: #18181B;
    border: 1px solid #29292E;
    border-radius: 12px;
    padding: 13px;
    margin: .25rem 0 .8rem;
}

.session-name {
    color: #F5F5F7;
    font-size: .83rem;
    font-weight: 600;
    overflow-wrap: anywhere;
    line-height: 1.45;
}

.session-time {
    color: #86868B;
    font-size: .72rem;
    margin-top: 5px;
}

.sidebar-footer {
    color: #66666B;
    font-size: .62rem;
    font-weight: 600;
    letter-spacing: .07em;
    line-height: 1.6;
    margin-top: 1.5rem;
    padding: 10px 5px;
    border-top: 1px solid #29292E;
}

"""
