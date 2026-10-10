"""화면 공통 요소: 색, 판정·근거 배지, 차트 기본 모양.

색은 dataviz 기준 팔레트(references/palette.md)의 검증된 값을 그대로 쓴다 (기존 dashboard/와 같은 값).
- 크기: 파랑 진하기 / 강조: 파랑 + 회색 / 구분 2종: 구분 색 1·2번(파랑·주황)
- 상태(판정·심각도): 상태 색, 항상 기호 + 글자와 함께
- 근거(관측·추정): 색이 아니라 채움/빈 기호·빗금으로 구분
"""
import html

import plotly.graph_objects as go
import streamlit as st

import theme as T

# 글자·면 색은 theme.py의 TOKENS에서 가져온다 (여기서 따로 적지 않는다)
INK = {"primary": T.TOKENS["ink"], "secondary": T.TOKENS["body"], "muted": T.TOKENS["faint"]}
SURFACE, GRID, AXIS = T.TOKENS["card"], "#e6edf6", "#c5d2e3"  # 카드(흰색) 위에 그린다
ACCENT = "#2a78d6"
DEEMPH = "#c5cfdd"
SERIES = ["#2a78d6", "#eb6834", "#1baf7a"]
SEQ = {150: "#b7d3f6", 300: "#6da7ec", 450: "#2a78d6", 600: "#184f95"}
STATUS = {"critical": "#d03b3b", "serious": "#ec835a", "warning": "#fab219", "good": "#0ca30c"}

VERDICT = {"의심 확인": (STATUS["critical"], "▲"), "보류": (STATUS["warning"], "◆"), "오탐 후보": (INK["muted"], "○")}
SEVERITY = {"high": (STATUS["critical"], "▲"), "medium": (STATUS["serious"], "◆"), "low": (STATUS["warning"], "▽")}
STATE = {"경보": (STATUS["critical"], "▲"), "점수 있음 (비경보)": (INK["muted"], "○"),
         "현재 규칙의 점수 없음": (INK["muted"], "·")}
BASIS_ICON = {"관측": "●", "추정": "◐", "관측+추정": "◑", "모름": "○", "판정": "■", "접음": "…"}
# 배지·표 셀 색 이름 (실제 색은 theme.TONES)
VERDICT_TONE = {"의심 확인": "danger", "보류": "hold", "오탐 후보": "benign"}
STATE_TONE = {"경보": "danger", "점수 있음 (비경보)": "caution", "현재 규칙의 점수 없음": "unknown"}
SEVERITY_TONE = {"high": "danger", "medium": "caution", "low": "inferred"}
BASIS_TONE = {"관측": "observed", "추정": "inferred", "관측+추정": "mixed", "모름": "unknown"}
ICONS = set("●◐◑○■…▲◆▽·")
LOG_LABEL = {"sshd": "sshd (서버 접속)", "nginx": "nginx (웹 요청)", "teiren_audit": "감사로그 (웹 행위)",
             "sysmon": "Sysmon (서버 내부)"}
LANES = ["sshd", "nginx", "teiren_audit", "sysmon"]
BUCKET_LABEL = {"session": "사용자 업무", "background": "시스템 배경", "external": "외부 시도"}
TYPE_LABEL = {"server+web": "서버+웹", "server_only": "서버 전용", "web_only": "웹 전용"}
TACTIC_KO = {"Reconnaissance": "정찰", "Initial Access": "초기 접근", "Execution": "실행", "Persistence": "지속",
             "Privilege Escalation": "권한 상승", "Defense Evasion": "방어 회피", "Credential Access": "자격 증명 접근",
             "Discovery": "탐색", "Lateral Movement": "측면 이동", "Collection": "수집",
             "Command and Control": "명령·제어", "Exfiltration": "유출", "Impact": "영향"}


def basis_kind(text: str) -> str:
    """파이프라인 근거 문자열을 배지 종류로 묶는다. 예: '관측(세션 소속)' → '관측'."""
    for k in ("접음", "판정", "모름"):
        if text.startswith(k):
            return k
    if text.startswith("관측") and "추정" in text:
        return "관측+추정"
    if text.startswith("관측"):
        return "관측"
    if text.startswith("추정"):
        return "추정"
    return text


def basis_text(text: str) -> str:
    return f"{BASIS_ICON.get(basis_kind(text), '')} {text}".strip()


def verdict_text(v: str) -> str:
    return f"{VERDICT[v][1]} {v}" if v in VERDICT else (v or "—")


def state_text(v: str) -> str:
    return f"{STATE[v][1]} {v}" if v in STATE else v


def severity_text(v: str) -> str:
    return f"{SEVERITY[v][1]} {v}" if v in SEVERITY else (v or "—")


def tone_of(text: str) -> str:
    """표·배지에 쓰인 글자(기호가 앞에 붙어 있어도 됨)에서 색 이름을 찾는다. 없으면 빈 문자열."""
    label = str(text).strip()
    if label[:1] in ICONS:
        label = label[1:].strip()
    for table in (VERDICT_TONE, STATE_TONE, SEVERITY_TONE):
        if label in table:
            return table[label]
    return BASIS_TONE.get(basis_kind(label), "")


def verdict_badge(prefix: str, v: str, tip: str = "") -> str:
    return T.pill(f"{prefix}: {v or '없음'}", VERDICT_TONE.get(v, "unknown"), VERDICT.get(v, ("", "·"))[1], tip)


def basis_badge(prefix: str, kind: str, tip: str = "") -> str:
    return T.pill(f"{prefix}: {kind}", BASIS_TONE.get(kind, "unknown"), BASIS_ICON.get(kind, "·"), tip)


def state_badge(v: str) -> str:
    return T.pill(v, STATE_TONE.get(v, "unknown"), STATE.get(v, ("", "·"))[1])


def severity_badge(level: str, label: str = "") -> str:
    return T.pill(label or level, SEVERITY_TONE.get(level, "unknown"), SEVERITY.get(level, ("", "·"))[1])


def chip(label: str) -> str:
    return T.pill(label)


def tag(label: str) -> str:
    """글 안에 넣는 작은 배지. 라벨만 주면 기호와 색을 알아서 고른다. 예: tag("관측"), tag("의심 확인")."""
    icon = (BASIS_ICON.get(label) or VERDICT.get(label, ("", ""))[1] or STATE.get(label, ("", ""))[1]
            or SEVERITY.get(label, ("", ""))[1])
    return T.pill(label, tone_of(label) or "neutral", icon)


def legend(label: str, icon: str, tone: str, desc: str = "") -> str:
    """사이드바 범례 한 줄: 배지 + 짧은 설명."""
    return f'<div class="sec-legend">{T.pill(label, tone, icon)}<span>{html.escape(desc)}</span></div>'


def html_row(*parts: str):
    st.markdown("".join(parts), unsafe_allow_html=True)


def tone_cells(df, columns):
    """표에서 상태·판정·근거 열의 셀에 배지와 같은 색을 입힌다. 값과 열은 바꾸지 않는다."""
    cols = [c for c in columns if c in df.columns]
    if not cols or df.empty:
        return df
    floats = list(df.select_dtypes("float").columns)  # Styler가 소수 6자리로 바꾸지 않게 원래 모양을 지킨다
    return (df.style.format("{:g}", subset=floats, na_rep="")
            .map(lambda v: T.cell_style(tone_of(v)) if tone_of(v) else "", subset=cols))


def style(fig: go.Figure, height: int = 320, legend: bool = True) -> go.Figure:
    fig.update_layout(
        height=height, margin=dict(l=10, r=24, t=30, b=10), paper_bgcolor=SURFACE, plot_bgcolor=SURFACE,
        font=dict(family="Pretendard, 'Malgun Gothic', system-ui, sans-serif", size=13,
                  color=INK["secondary"]),
        showlegend=legend, legend=dict(orientation="h", yanchor="bottom", y=1.02, x=0, font=dict(color=INK["secondary"])),
        hoverlabel=dict(bgcolor="white", bordercolor=T.TOKENS["sky"], font=dict(color=INK["primary"])), bargap=0.35,
    )
    fig.update_xaxes(gridcolor=GRID, linecolor=AXIS, zeroline=False, tickfont=dict(color=INK["muted"]),
                     automargin=True, title_standoff=8)
    fig.update_yaxes(gridcolor=GRID, linecolor=AXIS, zeroline=False, tickfont=dict(color=INK["secondary"]),
                     automargin=True, ticksuffix="  ")
    return fig


def show(fig: go.Figure, key: str | None = None):
    st.plotly_chart(fig, width="stretch", theme=None, key=key,
                    config={"displayModeBar": "hover", "modeBarButtonsToRemove": ["lasso2d", "select2d"],
                            "displaylogo": False})


def kpi(col, label: str, value: str, unit: str, help_text: str):
    col.metric(f"{label} ({unit})", value, help=help_text)
