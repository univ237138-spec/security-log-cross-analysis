"""④ 세션·기준선 탐색: 평소 활동과 어떤 점이 다른가.

- 146개 세션 모두 접근할 수 있다 (점수 0 세션 포함).
- 기준선은 4단계에 저장된 값을 쓴다. 화면 기간을 바꿔도 기준선을 다시 학습하지 않는다.
- 상태를 구분한다: 비교 불가(기준선 없음) / 미조사(사고 카드 없음) / 현재 규칙의 점수 없음.
"""
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

import components as C
import loaders as L
import theme as T

T.hero("세션·기준선 탐색", "업무 세션 146개와 시스템 배경 활동을 저장된 과거 기준선과 비교합니다. 점수 0 세션도 여기서 볼 수 있습니다.")

ss = L.sessions_full()
ref = L.reference_labels()
sb_all = L.load("session_baseline").set_index("work_session_id")
ss = ss.assign(baseline_level=ss["work_session_id"].map(sb_all["baseline_level"]),
               baseline_n=ss["work_session_id"].map(sb_all["baseline_n"]))

tab_s, tab_bg = st.tabs(["업무 세션 (146개)", "시스템 배경 활동"])

with tab_s:
    ss_f = ss[L.in_range(ss["start_kst"])]
    f1, f2, f3, f4 = st.columns(4)
    p = f1.multiselect("사람 후보", sorted(ss["person_candidate"].unique()), placeholder="전체", key="se_people")
    t = f2.multiselect("세션 유형", sorted(ss["session_type"].unique()), placeholder="전체", key="se_types",
                       format_func=lambda x: C.TYPE_LABEL.get(x, x))
    s = f3.multiselect("상태", list(C.STATE), placeholder="전체", key="se_state")
    b = f4.multiselect("기준선 수준", ["person", "peer", "global", "none"], placeholder="전체", key="se_level")
    view = ss_f
    for col, vals in (("person_candidate", p), ("session_type", t), ("state", s), ("baseline_level", b)):
        if vals:
            view = view[view[col].isin(vals)]

    k = st.columns(4)
    k[0].metric("세션 (개)", f"{len(view):,}")
    for i, typ in enumerate(["server+web", "server_only", "web_only"], 1):
        k[i].metric(f"{C.TYPE_LABEL[typ]} (개)", f"{(view['session_type'] == typ).sum():,}")

    fig = go.Figure()
    for state, color, size in [("현재 규칙의 점수 없음", C.DEEMPH, 8), ("점수 있음 (비경보)", C.SERIES[1], 11),
                               ("경보", C.SERIES[0], 13)]:
        d = view[view["state"] == state]
        if d.empty:
            continue
        fig.add_scatter(x=d["start_kst"], y=d["person_candidate"], mode="markers", name=state,
                        marker=dict(color=color, size=size, line=dict(width=2, color=C.SURFACE)),
                        customdata=list(zip(d["work_session_id"], d["session_type"], d["baseline_level"],
                                            d["risk_score"])),
                        hovertemplate="%{customdata[0]} · %{y}<br>%{x|%m-%d %H:%M} KST · %{customdata[1]}"
                                      "<br>기준선 %{customdata[2]} · %{customdata[3]:g}점<extra></extra>")
    fig.update_xaxes(title="세션 시작 (KST)", tickformat="%m-%d")
    fig.update_yaxes(categoryorder="category descending")
    C.show(C.style(fig, height=320), key="se_scatter")

    table = view.assign(
        시작=view["start_kst"].dt.strftime("%m-%d %H:%M"), 유형=view["session_type"].map(lambda x: C.TYPE_LABEL.get(x, x)),
        상태=view["state"].map(C.state_text),
        조사=view.apply(lambda r: "사고 카드 있음" if r["is_alert"] else ("판정까지 (미조사)" if r["risk_score"] > 0 else "미조사"),
                       axis=1),
    )[["work_session_id", "시작", "person_candidate", "client_ip", "유형", "duration_min", "event_count",
       "baseline_level", "baseline_n", "risk_score", "상태", "조사"]].rename(columns={
        "work_session_id": "세션", "person_candidate": "사람 후보", "client_ip": "접속 IP", "duration_min": "길이(분)",
        "event_count": "이벤트", "baseline_level": "기준선", "baseline_n": "과거 세션", "risk_score": "점수"})
    if ref:
        table.insert(1, "참고 라벨", table["세션"].map(ref).fillna(""))
    table = table.sort_values("세션")
    ev = st.dataframe(C.tone_cells(table, ["상태"]), hide_index=True, width="stretch", height=300, on_select="rerun",
                      selection_mode="single-row", key="se_table")
    if ev and ev.selection.rows:
        st.session_state["selected_session"] = table.iloc[ev.selection.rows[0]]["세션"]
    sid = st.session_state.get("selected_session")
    if sid not in set(ss["work_session_id"]):
        st.info("표에서 세션을 고르면 평소와의 비교와 세션 이벤트를 보여줍니다.")


def render_session(sid):
    r = ss.set_index("work_session_id").loc[sid]
    sb = sb_all.loc[sid]
    st.divider()
    st.subheader(f"{sid} · {r['person_candidate']}" + (f"  (참고: {ref[sid]})" if sid in ref else ""))
    if sid not in set(table["세션"]):
        st.caption("이 세션은 현재 필터에 보이지 않지만 선택을 유지했습니다.")
    st.markdown(f"**{r['start_kst']:%m-%d %H:%M} ~ {r['end_kst']:%H:%M} KST** ({r['duration_min']}분) · "
                f"`{C.TYPE_LABEL.get(r['session_type'], r['session_type'])}` · 접속 IP `{r['client_ip']}` · "
                f"이벤트 {r['event_count']}개 · 점수 {r['risk_score']:g}")
    status = ("조사: 사고 카드 있음" if r["is_alert"] else
              "조사: 점수·기준선·판정까지, 사고 카드 미조사" if r["risk_score"] > 0 else "조사: 미조사")
    C.html_row(C.state_badge(r["state"]), C.chip(status),
               C.chip(f"기준선 {sb['baseline_level']} · 과거 {sb['baseline_n']}개"))
    if r["risk_score"] > 0:
        if st.button(f"{sid} 경보 상세 보기 (점수 근거)", type="primary"):
            st.switch_page("views/alert_detail.py")
    else:
        st.caption("점수 0은 ‘현재 규칙에서 신호가 없었다’는 뜻이며 정상이 확인됐다는 뜻이 아닙니다.")

    a, c = st.columns([1, 1.2])
    with a:
        st.markdown("#### 평소와 비교")
        level = sb["baseline_level"]
        if level == "none":
            st.info("비교 불가: 이 세션 전에 끝난 세션이 5개 미만이라 기준선이 없습니다.")
        else:
            rows = [
                ("시작 시각(KST)", f"{sb['start_hour_kst']}시", f"{sb['hist_hour_min']}~{sb['hist_hour_max']}시",
                 f"{sb['hour_distance']}시간 벗어남" if sb["hour_outside"] == "true" else "범위 안"),
                ("주말 세션 비율", "주말" if sb["weekday_kst"] in ("토", "일") else "평일",
                 f"{float(sb['hist_weekend_ratio']):.0%}", ""),
                ("접속 IP", r["client_ip"], "", "처음 보는 IP" if sb["ip_new"] == "true" else "평소와 같음"),
                ("세션 유형", C.TYPE_LABEL.get(r["session_type"], r["session_type"]),
                 f"같은 유형 비율 {float(sb['hist_session_type_ratio']):.0%}", ""),
                ("로그인 전 실패", f"{r['failed_before_login']}회", f"실패 있던 과거 세션 {sb['hist_failed_sessions']}개", ""),
                ("처음 가는 서버", sb["hosts_new"] or "없음", "", ""),
                ("본인 과거에 없던 명령", f"{sb['cmds_new_count']}개", "", ""),
                ("누구도 쓴 적 없는 명령", f"{len(sb['cmds_new_global'].split('|'))}개" if sb["cmds_new_global"] else "없음", "", ""),
                ("처음 하는 민감 행위", sb["sensitive_new"].replace("|", ", ") or "없음", "", ""),
                ("세션 길이", f"{r['duration_min']}분", f"과거 이하 비율 {sb['duration_min_pct']}%",
                 "과거 최대 초과" if sb["duration_min_above_max"] == "true" else ""),
                ("프로세스 수", r["process_count"], f"과거 이하 비율 {sb['process_count_pct']}%",
                 "과거 최대 초과" if sb["process_count_above_max"] == "true" else ""),
                ("GET 외 웹 요청", r["non_get_count"], f"과거 이하 비율 {sb['non_get_count_pct']}%",
                 "과거 최대 초과" if sb["non_get_count_above_max"] == "true" else ""),
            ]
            st.table(pd.DataFrame([{"항목": x, "이번": y, "과거 기준선": z, "차이": w} for x, y, z, w in rows]).set_index("항목"))
            if level == "global":
                st.caption("global = 다른 사람들의 과거와 비교한 값입니다. 처음 접속이라 ‘처음 봄’이 당연하므로 행동 탐지에서 제외했습니다.")
            elif level == "peer":
                st.caption("peer = 같은 주 작업 서버를 쓰는 동료(추정 그룹)의 과거와 비교했습니다. 개인 기준선보다 근거가 약합니다.")
            else:
                st.caption("person = 본인이 이 세션 전에 끝낸 세션들과 비교했습니다.")
    with c:
        st.markdown("#### 이 세션에 직접 속한 이벤트")
        tl = L.load("timeline_sessions", L.TIMELINE_RAW)
        d = tl[tl["work_session_id"] == sid].copy()
        d["시각(KST)"] = L.to_kst(d["event_time_utc"]).dt.strftime("%m-%d %H:%M:%S")
        d["내용"] = (d["CommandLine"].where(d["CommandLine"] != "", d["request"])
                    .where(lambda x: x != "", d["TargetFilename"])
                    .where(lambda x: x != "", d["dst"] + ":" + d["dpt"]).str.strip(":"))
        lg = st.multiselect("로그", C.LANES, default=C.LANES, format_func=lambda x: C.LOG_LABEL[x], key="se_logs")
        d = d[d["log_source"].isin(lg)].sort_values("event_time_utc")
        st.dataframe(d.assign(로그=d["log_source"].map(C.LOG_LABEL))[
            ["시각(KST)", "로그", "event_action", "내용", "account", "host", "work_session_link", "source_row"]].rename(
            columns={"event_action": "행위", "account": "계정", "host": "서버", "work_session_link": "세션에 붙은 방법",
                     "source_row": "원본 행"}), hide_index=True, width="stretch", height=330)
        linked = L.load("detections")
        linked = linked[linked["linked_sessions"].str.contains(rf"\b{sid}\(", regex=True)]
        if not linked.empty:
            st.markdown(f"**추정으로 연결된 시스템 계정 활동 신호 {len(linked)}건** (세션 소속 아님) {C.tag('추정')}", unsafe_allow_html=True)
            st.dataframe(linked.assign(시각=linked["event_time_utc"].map(lambda u: L.kst_text(u, "%m-%d %H:%M:%S")))[
                ["시각", "detection_type", "name", "host", "account", "linked_sessions", "evidence"]].rename(
                columns={"detection_type": "탐지", "name": "이름", "host": "서버", "account": "계정",
                         "linked_sessions": "연결", "evidence": "근거"}), hide_index=True, width="stretch")
        st.caption("사용자 업무 세션에는 사람 계정의 이벤트만 들어갑니다. root·www-data 같은 시스템 계정 활동은 "
                   "‘시스템 배경’으로 따로 탐지한 뒤, 같은 서버·시간을 근거로 세션에 추정 연결합니다.")

with tab_s:
    if sid in set(ss["work_session_id"]):
        render_session(sid)

with tab_bg:
    pats = L.num(L.load("background_patterns"), "count")
    bb = L.load("background_baseline")
    dets = L.load("detections")
    hits = dets[dets["log_source"] == "sysmon"][["source_row", "detection_type"]]
    rel = bb.merge(hits, on="source_row", how="inner").groupby("pattern_id")["detection_type"].agg(
        lambda x: ", ".join(sorted(set(x))))
    pats = pats.assign(관련신호=pats["pattern_id"].map(rel).fillna(""),
                       처음=pats["first_seen"].map(L.kst_text), 마지막=pats["last_seen"].map(L.kst_text))
    st.caption("4단계 패턴 = 서버 + 계정 + 실행 파일 + (명령 / 목적지 구역·포트 / 파일 경로). 숫자는 N으로 바꿔 같은 모양을 묶었습니다. "
               "패턴 목록은 **전체 기간** 요약입니다.")
    k = st.columns(3)
    k[0].metric("패턴 (종)", f"{len(pats)}")
    k[1].metric("1회만 나온 패턴 (종)", f"{(pats['count'] == 1).sum()}")
    k[2].metric("신호가 걸린 패턴 (종)", f"{(pats['관련신호'] != '').sum()}")

    srt = pats.sort_values("count")
    fig = go.Figure(go.Bar(
        y=srt["pattern_id"] + " " + srt["host"] + " " + srt["account"], x=srt["count"], orientation="h",
        marker=dict(color=[C.SERIES[0] if v else C.DEEMPH for v in srt["관련신호"]], cornerradius=4),
        customdata=srt[["detail", "관련신호"]].values,
        hovertemplate="%{y}<br>%{customdata[0]}<br>%{x}회 · 신호 %{customdata[1]}<extra></extra>"))
    fig.update_xaxes(title="발생 횟수 (로그 눈금)", type="log", dtick=1)
    fig.update_yaxes(showgrid=False, categoryorder="array",
                     categoryarray=list(srt["pattern_id"] + " " + srt["host"] + " " + srt["account"]))
    C.show(C.style(fig, height=22 * len(srt) + 90, legend=False), key="se_patterns")
    st.caption("파랑 = 탐지 신호가 걸린 패턴, 회색 = 그 외. 정상 반복 패턴은 수십~수백 회, 신호가 걸린 패턴은 대부분 1회입니다.")

    show_cols = ["pattern_id", "host", "account", "kind", "detail", "count", "처음", "마지막", "관련신호"]
    pev = st.dataframe(pats[show_cols].rename(columns={"pattern_id": "패턴", "host": "서버", "account": "계정",
                                                      "kind": "종류", "detail": "내용", "count": "횟수",
                                                      "관련신호": "관련 신호"}),
                       hide_index=True, width="stretch", height=300, on_select="rerun", selection_mode="single-row",
                       key="se_pat_table")
    if pev and pev.selection.rows:
        pid = pats.iloc[pev.selection.rows[0]]["pattern_id"]
        e = bb[bb["pattern_id"] == pid].copy()
        e["t"] = L.to_kst(e["event_time_utc"])
        e_f = e[L.in_range(e["t"])]
        st.dataframe(e_f.assign(시각=e_f["t"].dt.strftime("%m-%d %H:%M:%S"))[
            ["시각", "event_action", "CommandLine", "dst", "dpt", "TargetFilename", "pattern_seen_before",
             "pattern_seen_other_hosts_before", "host_history_hours", "source_row"]].rename(columns={
                "event_action": "행위", "pattern_seen_before": "이 서버에서 이전 관측", "dst": "목적지", "dpt": "포트",
                "TargetFilename": "파일", "pattern_seen_other_hosts_before": "다른 서버 이전 관측",
                "host_history_hours": "서버 기록 축적(시간)", "source_row": "원본 행"}), hide_index=True, width="stretch")
    else:
        st.caption("패턴을 고르면 해당 이벤트와 ‘그 시점 이전 관측 횟수’·‘서버 기록 축적 시간’을 보여줍니다.")
