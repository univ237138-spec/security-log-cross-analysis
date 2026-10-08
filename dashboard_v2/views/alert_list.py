"""② 경보 목록: 무엇을 먼저 조사할까."""
import plotly.graph_objects as go
import streamlit as st

import components as C
import loaders as L
import theme as T

T.hero("경보 목록", "위험점수와 ATT&CK 전술 수로 정한 경보를 우선순위대로 봅니다. 점수가 있지만 경보가 아닌 세션도 함께 확인합니다.")
C.page_note()

ss = L.sessions_full()
ref = L.reference_labels()
ss_f = ss[L.in_range(ss["start_kst"])]
C.scope_note("세션 시작 시각 기준")

mode = st.radio("보기", ["경보", "점수 있는 세션", "전체 세션"], horizontal=True, key="al_mode")
base = {"경보": ss_f[ss_f["is_alert"]], "점수 있는 세션": ss_f[ss_f["risk_score"] > 0], "전체 세션": ss_f}[mode]

f1, f2 = st.columns(2)
people = sorted(ss["person_candidate"].unique())
pick_people = f1.multiselect("사람 후보", people, placeholder="전체", key="al_people")
types = sorted(ss["session_type"].unique())
pick_types = f2.multiselect("세션 유형", types, placeholder="전체", format_func=lambda t: C.TYPE_LABEL.get(t, t),
                            key="al_types")
view = base
if pick_people:
    view = view[view["person_candidate"].isin(pick_people)]
if pick_types:
    view = view[view["session_type"].isin(pick_types)]

table = view.assign(
    시작=view["start_kst"].dt.strftime("%m-%d %H:%M"),
    유형=view["session_type"].map(lambda t: C.TYPE_LABEL.get(t, t)),
    상태=view["state"].map(C.state_text),
    활동판정=view["activity_verdict"].map(lambda v: C.verdict_text(v) if v else "미조사"),
    귀속=view["attribution"].map(lambda a: f"{C.BASIS_ICON.get(a, '')} {a}".strip() if a else "—"),
)[["rank", "work_session_id", "시작", "person_candidate", "client_ip", "유형", "risk_score", "tactic_count", "상태",
   "활동판정", "귀속", "alert_reason"]]
table = table.rename(columns={"rank": "순위", "work_session_id": "세션", "person_candidate": "사람 후보",
                              "client_ip": "접속 IP", "risk_score": "점수", "tactic_count": "전술 수",
                              "활동판정": "활동 판정", "귀속": "귀속 판정", "alert_reason": "경보 사유"})
if ref:
    table.insert(2, "참고 라벨", table["세션"].map(ref).fillna(""))

st.caption(f"{len(table)}개 세션 · 점수 내림차순 · 행을 고른 뒤 버튼으로 이동합니다.")
ev = st.dataframe(
    table, hide_index=True, width="stretch", on_select="rerun", selection_mode="single-row", key="al_table",
    column_config={"점수": st.column_config.ProgressColumn("점수", min_value=0, max_value=float(ss["risk_score"].max()),
                                                          format="%.0f"),
                   "순위": st.column_config.NumberColumn(width="small"),
                   "전술 수": st.column_config.NumberColumn(width="small")})
if ev and ev.selection.rows:
    st.session_state["selected_session"] = table.iloc[ev.selection.rows[0]]["세션"]
target = st.session_state.get("selected_session")
target_row = ss[ss["work_session_id"] == target]
if target and not target_row.empty:
    r = target_row.iloc[0]
    if r["risk_score"] > 0:
        if st.button(f"{target} 경보 상세 보기", type="primary"):
            st.switch_page("views/alert_detail.py")
    else:
        st.info(f"{target}는 현재 규칙에서 점수가 없어 경보 상세가 없습니다. 세션·기준선 탐색에서 봅니다.")
        if st.button(f"{target} 세션 탐색에서 보기", type="primary"):
            st.switch_page("views/session_explorer.py")
    if target not in set(table["세션"]):
        st.caption(f"선택한 {target}는 현재 필터에 보이지 않습니다. 선택은 유지됩니다.")

# ---------------------------------------------------------------- 점수 막대
st.markdown("#### 점수가 있는 세션")
scored = ss_f[ss_f["risk_score"] > 0].sort_values("risk_score")
if scored.empty:
    st.info("선택한 기간에 점수가 있는 세션이 없습니다.")
else:
    fig = go.Figure()
    for is_alert, name, color in [(True, "경보", C.ACCENT), (False, "경보 아님", C.DEEMPH)]:
        d = scored[scored["is_alert"] == is_alert]
        if d.empty:
            continue
        fig.add_bar(y=d["work_session_id"] + " " + d["person_candidate"], x=d["risk_score"], orientation="h",
                    name=name, marker=dict(color=color, cornerradius=4),
                    text=[f"{v:g}" for v in d["risk_score"]], textposition="outside", cliponaxis=False,
                    textfont=dict(color=C.INK["secondary"]), customdata=d[["tactic_count", "alert_reason"]].values,
                    hovertemplate="%{y}<br>%{x:g}점 · 전술 %{customdata[0]}개<br>%{customdata[1]}<extra></extra>")
    fig.add_vline(x=100, line=dict(color=C.INK["muted"], width=1, dash="dot"), annotation_text="점수 기준 100",
                  annotation_position="bottom right", annotation_font_color=C.INK["muted"])
    fig.update_yaxes(categoryorder="array", showgrid=False,
                     categoryarray=list(scored["work_session_id"] + " " + scored["person_candidate"]))
    fig.update_xaxes(title="위험점수")
    C.show(C.style(fig, height=36 * len(scored) + 100), key="al_bar")
    st.caption("경보 기준은 **점수 100 이상 또는 ATT&CK 전술 3개 이상**입니다. 막대의 점수 기준만으로는 경보가 다 설명되지 않습니다 "
               "(전술 기준은 룰 탐지에서만 셉니다). 점수 0인 세션은 생략했습니다.")

# ---------------------------------------------------------------- 비경보 점수 세션
st.markdown("#### 경보가 아닌 점수 세션")
fp = ss_f[(~ss_f["is_alert"]) & (ss_f["risk_score"] > 0)]
if fp.empty:
    st.info("선택한 기간에 해당 세션이 없습니다.")
else:
    st.dataframe(fp.assign(점수=fp["risk_score"].map(lambda v: f"{v:g}"),
                           신호=fp["signal_types"].map(lambda n: f"행동 신호 {int(n)}개"),
                           판정=fp["activity_verdict"].map(C.verdict_text),
                           근거=fp["reason"].str.replace(" | ", " / "))[
        ["work_session_id", "person_candidate", "점수", "신호", "판정", "근거"]].rename(
        columns={"work_session_id": "세션", "person_candidate": "사람 후보"}), hide_index=True, width="stretch")
    st.caption("단일 행동 신호(각 20점)만 있는 세션입니다. 조사 단계의 판정은 ‘오탐 후보’이며 확정 정상이 아닙니다. "
               "사고 카드는 만들지 않았습니다(미조사).")
