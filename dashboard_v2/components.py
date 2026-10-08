"""화면 공통 요소: 색, 판정·근거 배지, 차트 기본 모양.

색은 dataviz 기준 팔레트(references/palette.md)의 검증된 값을 그대로 쓴다 (기존 dashboard/와 같은 값).
- 크기: 파랑 진하기 / 강조: 파랑 + 회색 / 구분 2종: 구분 색 1·2번(파랑·주황)
- 상태(판정·심각도): 상태 색, 항상 기호 + 글자와 함께
- 근거(관측·추정): 색이 아니라 채움/빈 기호·빗금으로 구분
"""
import html

import plotly.graph_objects as go
import streamlit as st

INK = {"primary": "#0b1b33", "secondary": "#3d4f6b", "muted": "#7a8aa3"}
SURFACE, GRID, AXIS = "#ffffff", "#e6edf6", "#c5d2e3"  # 카드(흰색) 위에 그린다
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


def _pill(icon: str, icon_color: str, label: str, tip: str = "") -> str:
    title = f' title="{html.escape(tip)}"' if tip else ""
    return (f'<span{title} style="display:inline-block;border:1px solid rgba(11,11,11,0.15);border-radius:999px;'
            f'padding:2px 10px;margin:0 6px 4px 0;font-size:0.9rem;color:{INK["primary"]};background:{SURFACE};box-shadow:0 1px 2px rgba(6,42,122,0.06)">'
            f'<span style="color:{icon_color}">{icon}</span> {html.escape(label)}</span>')


def verdict_badge(prefix: str, v: str, tip: str = "") -> str:
    color, icon = VERDICT.get(v, (INK["muted"], "·"))
    return _pill(icon, color, f"{prefix}: {v or '없음'}", tip)


def basis_badge(prefix: str, kind: str, tip: str = "") -> str:
    return _pill(BASIS_ICON.get(kind, "·"), INK["secondary"], f"{prefix}: {kind}", tip)


def state_badge(v: str) -> str:
    color, icon = STATE.get(v, (INK["muted"], "·"))
    return _pill(icon, color, v)


def chip(label: str) -> str:
    return _pill("", INK["muted"], label)


def html_row(*parts: str):
    st.markdown("".join(parts), unsafe_allow_html=True)


def page_note(extra: str = ""):
    st.caption("저장된 분석 결과 탐색 · 성능평가 전 · 시각은 KST · 근거: ● 관측 / ◐ 추정 / ○ 모름"
               + (f" · {extra}" if extra else ""))


def scope_note(kind: str):
    """기간 필터의 적용 기준을 화면마다 밝힌다."""
    import loaders as L
    a, b = L.date_range()
    label = "전체 기간" if L.is_full_range() else f"{a:%m-%d} ~ {b:%m-%d}"
    st.caption(f"기간: **{label}** · {kind}")


def style(fig: go.Figure, height: int = 320, legend: bool = True) -> go.Figure:
    fig.update_layout(
        height=height, margin=dict(l=10, r=24, t=30, b=10), paper_bgcolor=SURFACE, plot_bgcolor=SURFACE,
        font=dict(family="Pretendard, 'Malgun Gothic', system-ui, sans-serif", size=13,
                  color=INK["secondary"]),
        showlegend=legend, legend=dict(orientation="h", yanchor="bottom", y=1.02, x=0, font=dict(color=INK["secondary"])),
        hoverlabel=dict(bgcolor="white", bordercolor="#1aa3ff", font=dict(color=INK["primary"])), bargap=0.35,
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
