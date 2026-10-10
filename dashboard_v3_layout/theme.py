"""화면 꾸밈: 보안 솔루션 브랜드 톤 (시안 → 블루 → 딥네이비 + 육각형 네트워크).

- 색·글꼴의 기본값은 .streamlit/config.toml의 [theme], [theme.sidebar]에서 정한다.
- 여기서는 설정으로 안 되는 것만 CSS로 더한다: 머리 배너, 카드, 사이드바 무늬, 표·탭 장식.
- 나중에 색을 바꿀 때는 아래 TOKENS만 고치면 된다 (차트 색은 components.py).
- 데이터·차트 내용에는 영향이 없다.
"""
import html
import math
from pathlib import Path
from urllib.parse import quote

import streamlit as st

TOKENS = {
    "cyan": "#2fe0f7",
    "sky": "#1aa3ff",
    "blue": "#0b5be0",
    "navy": "#062a7a",       # 본문 제목·수치 글자색 (밝은 배경 위라 그대로 둔다)
    "abyss": "#0a2560",      # 어두운 면의 가장 깊은 색. 한 톤 밝힘 (이전 #041640)
    "side_top": "#0f3f93",   # 사이드바 그라데이션 위 (이전 #072a73)
    "side_mid": "#0b2f78",   # 사이드바 그라데이션 중간 (이전 #061c52)
    "side_text": "#f1f7ff",  # 사이드바 본문 글자 (이전 #e6f1ff)
    "side_sub": "#d6e6fb",   # 사이드바 보조 글자 (이전 rgba(220,236,255,0.72))
    "ink": "#0b1b33",
    "body": "#2b3b56",       # 본문 보조 설명 (차트 글자 등)
    "muted": "#4a5b76",      # 보조 글자. 대비를 높임 (이전 #5a6b85)
    "faint": "#66768f",      # 가장 약한 글자: 차트 눈금 등 (이전 #7a8aa3)
    "line": "#d6e1f0",
    "card": "#ffffff",
    "page": "#f3f7fc",
}
T = TOKENS

# 상태 배지 색: 이름 → (글자, 연한 배경, 얇은 테두리). 채도는 낮거나 중간으로 맞췄다.
# 배지·표 셀·사이드바 범례가 모두 이 값을 쓴다 (components.py는 색을 따로 적지 않는다).
TONES = {
    "observed": ("#1d6689", "#e2f0f7", "#b3d5e6"),   # 관측: 차분한 청록
    "inferred": ("#8a5a14", "#fbf0d9", "#ead0a0"),   # 추정: 부드러운 황토 (주의)
    "mixed":    ("#45568f", "#e9edf9", "#c5cfec"),   # 관측+추정: 회청
    "unknown":  ("#55627a", "#eef1f5", "#d2d9e4"),   # 모름: 중립 회색
    "danger":   ("#a9343c", "#fbe9e9", "#efc3c5"),   # 의심 확인 · 경보 · high
    "hold":     ("#6b4d9c", "#f0ebfa", "#d7caef"),   # 보류
    "benign":   ("#44724c", "#e8f2e9", "#c6dcc8"),   # 오탐 후보 (확정 정상이 아니라 채도를 낮춤)
    "caution":  ("#9a5a2b", "#fbeee2", "#ecd0b5"),   # 점수 있음(비경보) · medium
    "neutral":  ("#3d4d68", "#f4f7fb", "#d6e1f0"),   # 일반 칩
}


# ---------------------------------------------------------------- 육각형 네트워크 그림 (SVG)
def _hex_points(cx, cy, r):
    return " ".join(f"{cx + r * math.cos(math.radians(60 * i - 30)):.1f},{cy + r * math.sin(math.radians(60 * i - 30)):.1f}"
                    for i in range(6))


def _hex_network_svg(width=560, height=200) -> str:
    """이미지 오른쪽의 빛나는 육각형 묶음을 단순화한 그림. 위치는 고정값이라 매번 같다."""
    r = 34
    w, h = math.sqrt(3) * r, 1.5 * r
    cells = [(0, 0, 1), (1, 0, 2), (2, 0, 0), (0, 1, 0), (1, 1, 1), (2, 1, 2), (1, 2, 0), (2, 2, 1), (3, 1, 0),
             (3, 2, 0), (0, 2, 0)]  # (열, 행, 강조 정도)
    ox, oy = width - 4 * w - 10, 30
    parts, nodes = [], []
    for col, row, level in cells:
        cx = ox + col * w + (w / 2 if row % 2 else 0)
        cy = oy + row * h
        fill = {0: "rgba(255,255,255,0.03)", 1: "url(#hexFill)", 2: "rgba(120,200,255,0.10)"}[level]
        stroke = {0: "rgba(140,210,255,0.35)", 1: "rgba(160,240,255,0.95)", 2: "rgba(140,220,255,0.7)"}[level]
        sw = {0: 1, 1: 2.2, 2: 1.5}[level]
        filt = ' filter="url(#glow)"' if level == 1 else ""
        parts.append(f'<polygon points="{_hex_points(cx, cy, r - 2)}" fill="{fill}" stroke="{stroke}" '
                     f'stroke-width="{sw}"{filt}/>')
        if level:
            for i in (0, 2, 4):
                a = math.radians(60 * i - 30)
                nodes.append((cx + (r - 2) * math.cos(a), cy + (r - 2) * math.sin(a)))
        if level == 2:  # 점 무늬
            for dx in range(-12, 13, 6):
                for dy in range(-12, 13, 6):
                    parts.append(f'<circle cx="{cx + dx:.1f}" cy="{cy + dy:.1f}" r="0.9" fill="rgba(200,240,255,0.55)"/>')
    # 바깥으로 뻗는 연결선과 노드
    links = [((ox - 70, oy + 20), (ox + 10, oy + 40)), ((ox - 40, oy + 120), (ox + 20, oy + 95)),
             ((ox + 60, oy - 25), (ox + 40, oy + 10)), ((ox + 4.6 * w, oy - 10), (ox + 4 * w, oy + 30)),
             ((ox + 4.6 * w, oy + 150), (ox + 3.8 * w, oy + 110))]
    for (x1, y1), (x2, y2) in links:
        parts.append(f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" stroke="rgba(150,225,255,0.55)" stroke-width="1.2"/>')
        nodes += [(x1, y1)]
    for x, y in nodes:
        parts.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3.2" fill="#bff6ff" filter="url(#glow)"/>')
    return f"""<svg class="hex-net" viewBox="0 0 {width} {height}" preserveAspectRatio="xMaxYMid slice"
 xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
<defs>
  <filter id="glow" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="2.4" result="b"/>
    <feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
  <linearGradient id="hexFill" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="rgba(90,190,255,0.35)"/>
    <stop offset="1" stop-color="rgba(20,80,220,0.15)"/></linearGradient>
</defs>
<path d="M0 150 C 120 110, 220 190, 360 150 S 520 120, 600 160" stroke="rgba(255,255,255,0.28)" stroke-width="1.2" fill="none"/>
<path d="M0 175 C 140 140, 240 205, 380 175 S 520 150, 600 185" stroke="rgba(255,255,255,0.18)" stroke-width="1" fill="none"/>
{''.join(parts)}
</svg>"""


def _hero_art() -> str:
    svg = _hex_network_svg().replace('class="hex-net" ', "")
    return "data:image/svg+xml;utf8," + quote(" ".join(svg.split()), safe="")


def _sidebar_pattern() -> str:
    """사이드바 배경의 옅은 육각형 무늬 (data URI)."""
    r = 22
    pts = _hex_points(r * 0.87, r, r - 1)
    pts2 = _hex_points(r * 0.87 * 2, r * 2.5, r - 1)
    svg = (f"<svg xmlns='http://www.w3.org/2000/svg' width='{r * 0.87 * 2:.0f}' height='{r * 3:.0f}'>"
           f"<polygon points='{pts}' fill='none' stroke='rgba(120,200,255,0.07)'/>"
           f"<polygon points='{pts2}' fill='none' stroke='rgba(120,200,255,0.07)'/></svg>")
    return "data:image/svg+xml;utf8," + svg.replace("#", "%23").replace("<", "%3C").replace(">", "%3E")


# ---------------------------------------------------------------- CSS
def _pill_css() -> str:
    """배지 공통 모양 + TONES에서 만든 색 변형."""
    rules = [
        ".sec-pill { display: inline-flex; align-items: center; gap: 5px; border: 1px solid var(--sec-line);"
        " border-radius: 999px; padding: 2px 10px; margin: 0 6px 4px 0; font-size: 0.88rem; font-weight: 500;"
        " line-height: 1.5; white-space: nowrap; box-shadow: 0 1px 2px rgba(6,42,122,0.08); }",
        ".sec-pill .ic { font-size: 0.82em; line-height: 1; }",
        ".sec-legend { display: flex; align-items: center; gap: 2px; margin: 0 0 5px; font-size: 0.86rem; }",
        ".sec-legend .sec-pill { margin-bottom: 0; flex: none; }",
    ]
    for name, (fg, bg, border) in TONES.items():
        rules.append(f".sec-pill--{name} {{ color: {fg}; background: {bg}; border-color: {border}; }}")
    return "\n".join(rules)


CSS = f"""
<style>
:root {{
  --sec-cyan: {T['cyan']}; --sec-sky: {T['sky']}; --sec-blue: {T['blue']}; --sec-navy: {T['navy']};
  --sec-abyss: {T['abyss']}; --sec-ink: {T['ink']}; --sec-muted: {T['muted']}; --sec-line: {T['line']};
  --sec-card: {T['card']}; --sec-page: {T['page']}; --sec-body: {T['body']};
  --sec-side-text: {T['side_text']}; --sec-side-sub: {T['side_sub']};
  --sec-grad: linear-gradient(105deg, var(--sec-cyan) 0%, var(--sec-sky) 30%, var(--sec-blue) 58%, var(--sec-navy) 82%, var(--sec-abyss) 100%);
  --sec-shadow: 0 1px 2px rgba(6,42,122,0.06), 0 6px 18px rgba(6,42,122,0.06);
}}

/* 본문 배경: 아주 옅은 블루 + 위쪽에 은은한 빛 */
[data-testid="stAppViewContainer"] {{
  background:
    radial-gradient(1200px 380px at 85% -120px, rgba(26,163,255,0.10), transparent 70%),
    var(--sec-page);
}}
[data-testid="stHeader"] {{ background: transparent; }}
[data-testid="stMainBlockContainer"] {{ padding-top: 2.2rem; max-width: 1480px; }}

/* 사이드바: 딥네이비 그라데이션 + 육각형 무늬 */
[data-testid="stSidebar"] {{
  background: url("{_sidebar_pattern()}"), linear-gradient(180deg, {T['side_top']} 0%, {T['side_mid']} 45%, var(--sec-abyss) 100%);
  border-right: 1px solid rgba(53,214,245,0.22);
}}
[data-testid="stSidebar"]::before {{
  content: ""; position: absolute; inset: 0 0 auto 0; height: 3px; background: var(--sec-grad); z-index: 2;
}}
/* 사이드바 글자: 배경을 밝힌 만큼 글자도 조금 더 또렷하게 */
[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p,
[data-testid="stSidebar"] [data-testid="stWidgetLabel"] p {{ color: var(--sec-side-text); }}
[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] strong {{ color: #fff; font-weight: 600; }}
[data-testid="stSidebarNav"] a {{ border-radius: 8px; }}
[data-testid="stSidebarNav"] a span {{ color: var(--sec-side-sub); }}
[data-testid="stSidebarNav"] a[aria-current="page"] {{
  background: linear-gradient(90deg, rgba(47,224,247,0.26), rgba(26,163,255,0.10));
  box-shadow: inset 3px 0 0 var(--sec-cyan);
}}
[data-testid="stSidebarNav"] a[aria-current="page"] span {{ color: #fff; font-weight: 600; }}
[data-testid="stSidebarNav"] a:hover {{ background: rgba(47,224,247,0.12); }}
[data-testid="stSidebarNav"] a:hover span {{ color: #fff; }}
[data-testid="stSidebar"] [data-testid="stCaptionContainer"] p {{ color: var(--sec-side-sub); }}
[data-testid="stSidebar"] .sec-legend {{ color: var(--sec-side-text); }}
[data-testid="stSidebar"] .sec-brand {{
  display: flex; align-items: center; gap: 10px; margin: 2px 0 10px; color: #fff; font-weight: 800;
  letter-spacing: 0.02em; font-size: 1.02rem;
}}
[data-testid="stSidebar"] .sec-brand .mark {{
  width: 26px; height: 30px; background: var(--sec-grad);
  clip-path: polygon(50% 0, 100% 25%, 100% 75%, 50% 100%, 0 75%, 0 25%);
  box-shadow: 0 0 14px rgba(47,224,247,0.6);
}}
[data-testid="stSidebar"] .sec-brand small {{ display: block; font-weight: 500; font-size: 0.72rem;
  color: var(--sec-side-sub); letter-spacing: 0.08em; }}

/* 로고: 기본 크기(32px)보다 크게 */
[data-testid="stSidebarHeader"] {{ padding-top: 1.2rem; padding-bottom: 0.4rem; }}
[data-testid="stSidebarHeader"] img[data-testid="stSidebarLogo"],
[data-testid="stSidebarHeader"] [data-testid="stSidebarLogo"] img {{ height: 52px; max-width: 230px; width: auto; }}
[data-testid="stHeaderLogo"] {{ height: 40px; }}

/* 머리 배너 */
.sec-hero {{
  position: relative; overflow: hidden; border-radius: 16px; padding: 28px 32px 26px; margin: 0 0 14px;
  background: var(--sec-grad); color: #fff; min-height: 150px;
  box-shadow: 0 10px 30px rgba(11,91,224,0.22);
}}
.sec-hero::after {{
  content: ""; position: absolute; right: 0; top: 0; height: 100%; width: 64%; pointer-events: none;
  background: url("{_hero_art()}") right center / auto 100% no-repeat;
}}
.sec-hero .copy {{ position: relative; z-index: 1; max-width: 74%; }}
.sec-hero .eyebrow {{ font-size: 0.78rem; font-weight: 700; letter-spacing: 0.14em; text-transform: uppercase;
  color: rgba(255,255,255,0.85); }}
.sec-hero h1 {{ color: #fff !important; font-size: 2.1rem; font-weight: 800; margin: 6px 0 6px; padding: 0;
  text-wrap: balance; text-shadow: 0 2px 14px rgba(4,22,64,0.25); }}
.sec-hero p {{ color: rgba(255,255,255,0.92); margin: 0; font-size: 0.98rem; line-height: 1.55;
  word-break: keep-all; text-wrap: pretty; }}
.sec-hero .chips {{ display: flex; flex-wrap: wrap; gap: 6px; margin-top: 12px; }}
.sec-hero .chip {{ font-size: 0.78rem; padding: 3px 10px; border-radius: 999px; color: #fff;
  background: rgba(255,255,255,0.14); border: 1px solid rgba(255,255,255,0.28); backdrop-filter: blur(4px); }}
@media (max-width: 900px) {{ .sec-hero .copy {{ max-width: 100%; }} .sec-hero::after {{ opacity: 0.35; width: 100%; }} }}

/* 소제목: 육각형 표지 */
[data-testid="stMainBlockContainer"] h4 {{ color: var(--sec-navy); font-weight: 800; display: flex; align-items: center; gap: 8px; }}
[data-testid="stMainBlockContainer"] h4::before {{
  content: ""; width: 12px; height: 14px; flex: none; background: var(--sec-grad);
  clip-path: polygon(50% 0, 100% 25%, 100% 75%, 50% 100%, 0 75%, 0 25%);
}}
[data-testid="stMainBlockContainer"] h3 {{ color: var(--sec-navy); }}

/* 숫자 카드 */
[data-testid="stMain"] [data-testid="stMetric"] {{
  position: relative; background: var(--sec-card); border: 1px solid var(--sec-line); border-radius: 14px;
  padding: 14px 16px 12px; box-shadow: var(--sec-shadow); overflow: hidden;
}}
[data-testid="stMain"] [data-testid="stMetric"]::before {{
  content: ""; position: absolute; left: 0; right: 0; top: 0; height: 3px; background: var(--sec-grad);
}}
[data-testid="stMain"] [data-testid="stMetricLabel"] p {{ color: var(--sec-body); font-weight: 600; font-size: 0.85rem; }}
[data-testid="stMain"] [data-testid="stMetricValue"] {{ color: var(--sec-navy); }}

/* 차트·표·펼침 상자를 카드로 */
[data-testid="stMain"] [data-testid="stPlotlyChart"],
[data-testid="stMain"] [data-testid="stDataFrame"],
[data-testid="stMain"] [data-testid="stTable"],
[data-testid="stMain"] [data-testid="stExpander"] details,
[data-testid="stMain"] [data-testid="stGraphVizChart"] {{
  background: var(--sec-card); border: 1px solid var(--sec-line); border-radius: 12px; box-shadow: var(--sec-shadow);
}}
[data-testid="stMain"] [data-testid="stPlotlyChart"] {{ padding: 6px 4px 2px; }}
[data-testid="stMain"] [data-testid="stTable"] {{ overflow: hidden; }}
[data-testid="stMain"] [data-testid="stTable"] th {{ background: #eaf1fb; color: var(--sec-navy); font-weight: 700; }}
[data-testid="stMain"] [data-testid="stVerticalBlockBorderWrapper"]:has(> div > [data-testid="stVerticalBlock"]) {{
  background: var(--sec-card);
}}

/* 탭 */
[data-testid="stMain"] [data-baseweb="tab-list"] {{ gap: 4px; border-bottom: 1px solid var(--sec-line); }}
[data-testid="stMain"] [data-baseweb="tab"] {{ padding: 8px 14px; border-radius: 8px 8px 0 0; }}
[data-testid="stMain"] [data-baseweb="tab"][aria-selected="true"] {{ background: linear-gradient(180deg, rgba(26,163,255,0.10), transparent); }}
[data-testid="stMain"] [data-baseweb="tab"][aria-selected="true"] p {{ color: var(--sec-blue); font-weight: 700; }}
[data-testid="stMain"] [data-baseweb="tab-highlight"] {{ background: var(--sec-grad); height: 3px; }}

/* 버튼 */
[data-testid="stMain"] button[kind="primary"] {{
  background: linear-gradient(90deg, var(--sec-sky), var(--sec-blue)); border: 0; color: #fff;
  box-shadow: 0 4px 14px rgba(11,91,224,0.28);
}}
[data-testid="stMain"] button[kind="primary"]:hover {{ box-shadow: 0 6px 20px rgba(26,163,255,0.45); filter: brightness(1.05); }}
[data-testid="stMain"] button[kind="primary"]:disabled {{ background: #c9d6ea; box-shadow: none; color: #fff; }}
[data-testid="stSidebar"] button[kind="secondary"] {{
  background: rgba(255,255,255,0.06); border: 1px solid rgba(53,214,245,0.35); color: #e6f1ff;
}}
[data-testid="stSidebar"] button[kind="secondary"]:hover {{ border-color: var(--sec-cyan); color: #fff; }}

/* 안내 상자: 테두리만 정돈 */
[data-testid="stMain"] [data-testid="stAlertContainer"] {{ border-radius: 12px; }}
[data-testid="stMain"] [data-testid="stCaptionContainer"],
[data-testid="stMain"] [data-testid="stCaptionContainer"] p {{ color: var(--sec-muted); opacity: 1; }}
[data-testid="stSidebar"] [data-testid="stCaptionContainer"] {{ color: var(--sec-side-sub); opacity: 1; }}
/* 사이드바 입력 상자: 배경보다 한 톤 밝게 해서 묻히지 않게 */
[data-testid="stSidebar"] [data-testid="stDateInputField"] {{ background-color: rgba(255,255,255,0.10);
  border: 1px solid rgba(53,214,245,0.28); color: #fff; }}
[data-testid="stMain"] [data-testid="stWidgetLabel"] p {{ color: var(--sec-body); font-weight: 500; }}
/* 한글이 낱말 중간에서 잘리지 않게 (예: "아닙니/다") */
[data-testid="stMarkdownContainer"] p, [data-testid="stCaptionContainer"] p, .sec-legend {{ word-break: keep-all; }}
hr {{ border-color: var(--sec-line) !important; }}

/* 상태 배지 (근거·판정·상태·심각도) */
{_pill_css()}
</style>
"""


def apply():
    st.html(CSS)


def pill(label: str, tone: str = "neutral", icon: str = "", tip: str = "") -> str:
    """배지 HTML. 색은 TONES, 모양은 CSS의 .sec-pill에서 온다."""
    tone = tone if tone in TONES else "neutral"
    title = f' title="{html.escape(tip)}"' if tip else ""
    ic = f'<span class="ic">{html.escape(icon)}</span>' if icon else ""
    return f'<span{title} class="sec-pill sec-pill--{tone}">{ic}{html.escape(label)}</span>'


def cell_style(tone: str) -> str:
    """표 셀에 같은 색을 입힐 때 쓰는 CSS 문자열."""
    fg, bg, _ = TONES.get(tone, TONES["neutral"])
    return f"color: {fg}; background-color: {bg}; font-weight: 600"


ASSETS = Path(__file__).resolve().parent / "assets"


def logo():
    """사이드바 맨 위 로고. 사이드바를 접으면 육각형 마크만 보인다."""
    st.logo(str(ASSETS / "sesac_security_logo_light.png"), size="large",
            icon_image=str(ASSETS / "sesac_security_mark.png"))


def sidebar_brand():
    st.html('<div class="sec-brand"><div class="mark"></div><div>SECURE LOG ANALYTICS'
            '<small>4종 로그 상관분석 · UEBA</small></div></div>')


def hero(title: str, subtitle: str = "", eyebrow: str = "Security Log Analytics", chips: list[str] | None = None):
    chip_html = "".join(f'<span class="chip">{html.escape(c)}</span>' for c in (chips or []))
    st.html(f"""<div class="sec-hero">
<div class="copy"><div class="eyebrow">{html.escape(eyebrow)}</div><h1>{html.escape(title)}</h1>
{f'<p>{html.escape(subtitle)}</p>' if subtitle else ''}{f'<div class="chips">{chip_html}</div>' if chip_html else ''}</div></div>""")
