"""① 전체 현황: 무엇을 분석했고 무엇부터 확인할까."""
import plotly.graph_objects as go
import streamlit as st

import components as C
import loaders as L
import theme as T

T.hero("전체 현황", "서로 다른 보안 로그 4종(sshd·nginx·감사로그·Sysmon)을 연결해, 업무 세션 단위로 의심 활동과 조사 근거를 보여줍니다.",
       chips=["sshd", "nginx", "감사로그", "Sysmon", "RBA 위험점수", "성능평가 전"])

ss = L.sessions_full()
ref = L.reference_labels()
tl = L.load("timeline_sessions", ["event_time_utc", "log_source", "bucket"])
tl_kst = L.to_kst(tl["event_time_utc"])
tl_f = tl[L.in_range(tl_kst)]
ss_f = ss[L.in_range(ss["start_kst"])]
dets = L.load("detections")
dets_f = dets[L.in_range(L.to_kst(dets["event_time_utc"]))]
cfg = L.load("config_findings")
n_cfg = int((cfg["rule"] == "R16").sum())
r16_count = int(cfg.loc[cfg["rule"] == "R16", "count"].astype(int).sum()) if n_cfg else 0

k = st.columns(5)
C.kpi(k[0], "로그 이벤트", f"{len(tl_f):,}", "행", "4개 로그의 전체 행 수 (0단계 통합 타임라인)")
C.kpi(k[1], "업무 세션", f"{len(ss_f):,}", "개", "사용자 로그인부터 종료까지 묶은 단위 (3단계). 시스템 배경 활동은 세션에 들어가지 않습니다")
C.kpi(k[2], "탐지 신호", f"{len(dets_f):,}", "건", "룰·행동 탐지 신호 (5단계). 신호는 경보가 아닙니다")
C.kpi(k[3], "경보", f"{int(ss_f['is_alert'].sum()):,}", "세션", "세션 점수 100 이상 또는 ATT&CK 전술 3개 이상 (6단계)")
C.kpi(k[4], "설정 위험", f"{n_cfg:,}", "건", f"행동이 아니라 계정 설정 문제. MFA 없는 최상위 콘솔 계정 로그인 {r16_count}회 (전체 기간)")
st.caption("로그 행·세션·신호·경보는 단위가 서로 달라 차례로 줄어드는 깔때기가 아닙니다. 아래 '분석 흐름'에서 관계를 봅니다.")

# ---------------------------------------------------------------- 경보 요약
st.markdown("#### 우선 확인할 경보")
ctx = L.load("alert_context").set_index("work_session_id")
alerts = ss_f[ss_f["is_alert"]].sort_values("rank")
if alerts.empty:
    st.info("선택한 기간에 시작한 경보 세션이 없습니다. 사이드바에서 기간을 넓혀 보세요.")
else:
    def summary(sid):
        if sid not in ctx.index:
            return "조사 맥락 없음"
        names = [x.split(":", 1)[-1] for x in ctx.loc[sid, "top_signals"].split(" | ") if x]
        return " · ".join(names[:3])

    table = alerts.assign(
        우선순위=range(1, len(alerts) + 1),
        시작=alerts["start_kst"].dt.strftime("%m-%d %H:%M"),
        주요탐지=alerts["work_session_id"].map(summary),
        활동판정=alerts["activity_verdict"].map(C.verdict_text),
        귀속=alerts["attribution"].map(lambda a: f"{C.BASIS_ICON.get(a, '')} {a}".strip()),
    )[["우선순위", "work_session_id", "person_candidate", "시작", "risk_score", "tactic_count", "주요탐지", "활동판정", "귀속"]]
    table = table.rename(columns={"work_session_id": "세션", "person_candidate": "사람 후보", "risk_score": "점수",
                                  "tactic_count": "전술 수", "주요탐지": "주요 탐지 (점수 기여 순)", "활동판정": "활동 판정",
                                  "귀속": "귀속 판정"})
    if ref:
        table.insert(2, "참고 라벨", table["세션"].map(ref).fillna(""))
    ev = st.dataframe(C.tone_cells(table, ["활동 판정", "귀속 판정"]), hide_index=True, width="stretch",
                      on_select="rerun", selection_mode="single-row", key="ov_alerts", column_config={"점수": st.column_config.NumberColumn(format="%.0f")})
    picked = table.iloc[ev.selection.rows[0]]["세션"] if ev and ev.selection.rows else None
    if st.button(f"{picked} 경보 상세 보기" if picked else "표에서 경보를 고르면 상세로 이동합니다",
                 type="primary", disabled=picked is None, key="ov_go"):
        st.session_state["selected_session"] = picked
        st.switch_page("views/alert_detail.py")
    st.caption("‘주요 탐지’는 탐지 이름이며 유출 성공·감염 확정을 뜻하지 않습니다. "
               f"귀속 판정: {C.tag('관측')} 세션에 직접 기록된 high 룰 신호 있음 · {C.tag('추정')} 시간·서버로만 연결.",
               unsafe_allow_html=True)

# ---------------------------------------------------------------- 세션 분포 + 서버별 점수
left, right = st.columns([1.35, 1])
with left:
    st.markdown("#### 날짜별 업무 세션")
    fig = go.Figure()
    for is_alert, name, color, size in [(False, "그 외 세션", C.DEEMPH, 8), (True, "경보 세션", C.ACCENT, 13)]:
        d = ss_f[ss_f["is_alert"] == is_alert]
        labels = d["work_session_id"].map(lambda s: f" · 참고: {ref[s]}" if s in ref else "")
        fig.add_scatter(x=d["start_kst"], y=d["person_candidate"], mode="markers", name=name,
                        marker=dict(color=color, size=size, line=dict(width=2, color=C.SURFACE)),
                        customdata=list(zip(d["work_session_id"], d["risk_score"], d["session_type"], labels)),
                        hovertemplate="%{customdata[0]} · %{y}<br>%{x|%m-%d %H:%M} KST · %{customdata[2]}"
                                      "<br>%{customdata[1]:g}점%{customdata[3]}<extra></extra>")
    fig.update_xaxes(title="세션 시작 (KST)", tickformat="%m-%d")
    fig.update_yaxes(categoryorder="category descending")
    C.show(C.style(fig, height=340), key="ov_scatter")
    st.caption("점 하나 = 업무 세션 하나. 사람 이름은 같은 접속 IP로 묶은 ‘사람 후보’(추정)입니다.")

with right:
    st.markdown("#### 서버별 위험점수")
    er = L.num(L.load("entity_risk"), "total_score")
    hosts = er[er["entity_type"] == "host"].sort_values("total_score")
    fig = go.Figure(go.Bar(
        y=hosts["entity"], x=hosts["total_score"], orientation="h", marker=dict(color=C.SEQ[450], cornerradius=4),
        text=[f"{v:g}" for v in hosts["total_score"]], textposition="outside", cliponaxis=False,
        textfont=dict(color=C.INK["secondary"]), customdata=hosts[["signal_types"]].values,
        hovertemplate="%{y}: %{x:g}점<br>신호 종류 %{customdata[0]}<extra></extra>"))
    fig.update_xaxes(title="그 서버에서 일어난 신호 점수 합 (전체 기간)")
    fig.update_yaxes(showgrid=False)
    C.show(C.style(fig, height=340, legend=False), key="ov_hosts")
    st.caption("서버에서 발생한 위험 신호를 탐지 종류별로 한 번씩(최고 점수) 더한 전체 기간 점수입니다. "
               "세션, 사용자 연결과 추정 신뢰도(0.8)는 반영하지 않으며, 기간 필터와 무관합니다.")

# ---------------------------------------------------------------- 접어 보기
with st.expander("로그·분류 구성과 분석 흐름"):
    a, b = st.columns(2)
    with a:
        st.markdown("**로그별 행 수**")
        by_log = tl_f["log_source"].value_counts().reindex(C.LANES).fillna(0).astype(int)
        fig = go.Figure(go.Bar(y=[C.LOG_LABEL[x] for x in by_log.index], x=by_log.values, orientation="h",
                               marker=dict(color=C.SEQ[450], cornerradius=4), text=[f"{v:,}" for v in by_log.values],
                               textposition="outside", cliponaxis=False, textfont=dict(color=C.INK["secondary"]),
                               hovertemplate="%{y}: %{x:,}행<extra></extra>"))
        fig.update_yaxes(showgrid=False, autorange="reversed")
        fig.update_xaxes(title="행")
        C.show(C.style(fig, height=230, legend=False), key="ov_logs")
    with b:
        st.markdown("**2단계 분류 (서로 겹치지 않음)**")
        by_b = tl_f["bucket"].value_counts().reindex(list(C.BUCKET_LABEL)).fillna(0).astype(int)
        fig = go.Figure(go.Bar(y=[C.BUCKET_LABEL[x] for x in by_b.index], x=by_b.values, orientation="h",
                               marker=dict(color=C.SEQ[450], cornerradius=4), text=[f"{v:,}" for v in by_b.values],
                               textposition="outside", cliponaxis=False, textfont=dict(color=C.INK["secondary"]),
                               hovertemplate="%{y}: %{x:,}행<extra></extra>"))
        fig.update_yaxes(showgrid=False, autorange="reversed")
        fig.update_xaxes(title="행")
        C.show(C.style(fig, height=230, legend=False), key="ov_buckets")
    st.markdown("**분석 흐름** · 사용자 이벤트만 세션으로 묶이고, 시스템 배경 활동은 따로 탐지한 뒤 세션에 추정으로 연결됩니다.")
    n = {k: int(v) for k, v in tl["bucket"].value_counts().items()}
    # 탐지 신호가 어디로 갔는지: 저장된 결과 파일의 행 수만 센다 (점수·경보는 다시 계산하지 않음)
    rev = L.load("risk_events")
    alert_ids = set(ss.loc[ss["is_alert"], "work_session_id"])
    n_scored, n_r16 = len(rev), int((dets["detection_type"] == "R16").sum())
    n_scored_sessions = int((ss["risk_score"] > 0).sum())
    n_alert_signals = int(rev["work_session_id"].isin(alert_ids).sum())
    st.graphviz_chart(f"""
digraph {{
  rankdir=LR; node [shape=box, style="rounded", fontname="Malgun Gothic", fontsize=11, color="#c3c2b7"];
  edge [color="#898781", fontname="Malgun Gothic", fontsize=10];
  logs [label="로그 4종\\n{len(tl):,}행"];
  u [label="사용자 업무\\n{n.get('session', 0):,}행"]; bg [label="시스템 배경\\n{n.get('background', 0):,}행"];
  ex [label="외부 시도\\n{n.get('external', 0):,}행"];
  ses [label="업무 세션\\n{len(ss):,}개"]; det [label="탐지 신호\\n{len(dets):,}건"];
  scored [label="세션 점수 반영\\n{n_scored:,}건"]; scored_s [label="점수 있는 세션\\n{n_scored_sessions:,}개"];
  alert [label="경보 세션 {len(alert_ids)}개\\n(신호 {n_alert_signals:,}건)"];
  r16 [label="R16\\n{n_r16:,}건"]; cfg [label="설정 위험 {n_cfg}건\\n(MFA 미적용 최상위 계정)"];
  prof [label="외부 시도 요약\\n(점수 없음)"];
  logs -> u; logs -> bg; logs -> ex; u -> ses -> det; bg -> det [label="탐지 후 세션에 추정 연결"];
  det -> scored -> scored_s -> alert; det -> r16 [label="분리"]; r16 -> cfg; ex -> prof;
}}""")
    st.caption("전체 기간 기준 구조도입니다.")
