"""③ 경보 상세: 왜 위험하며 실제로 무엇이 관측됐나.

계획 4절 ③의 세부 원칙 1~8을 따른다. 특히
- 점수는 '기본 점수 × 자산 중요도 × 연결 신뢰도', 같은 세션·같은 탐지 종류는 최대 1개만 합산
- 세션 귀속 배지를 모든 이벤트에 전파하지 않는다 (이벤트별 근거를 따로 표시)
- ATT&CK 전술은 탐지 해석이며 사건 시간순 기록과 따로 보여준다
"""
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

import components as C
import loaders as L
import theme as T

Q_TITLE = {"Q1": "무엇이 경보를 만들었나", "Q2": "누구인가, 평소와 같은가", "Q3": "어디서 왔나",
           "Q4": "어떻게 들어왔나", "Q5": "무엇을 했나", "Q6": "무엇을 남겼나", "Q7": "퍼졌나",
           "Q8": "확인 못 한 것", "Q9": "판정"}
GAP_NEEDS = [  # docs/14_조사/02_조사결과_정리.md 4절: 공백 → 답하려면 필요한 로그 → 후속 확인
    ("넘어간 ssh", "담당 서버(app·node·web)의 sshd 로그", "점프 서버 이후 실제 접속 서버 확인"),
    ("시스템 계정 활동", "Linux auditd의 auid(로그인 사용자 ID), sudo 로그", "root·www-data 활동의 실제 사용자 확인"),
    ("부모 프로세스", "Sysmon 수집 범위 확대, auditd", "프로세스 시작 경로·권한 획득 경로 확인"),
    ("애플리케이션", "애플리케이션 로그, nginx·앱 공유 요청 ID", "웹 요청과 서버 명령 실행의 직접 연결 확인"),
    ("외부 연결", "방화벽·프록시 로그(전송 바이트), DNS, NetFlow", "전송 성공 여부·양 확인"),
]

ss = L.sessions_full()
ref = L.reference_labels()
cand = ss[ss["risk_score"] > 0].sort_values("rank")
options = cand["work_session_id"].tolist()
info = ss.set_index("work_session_id")

T.hero("경보 상세", "왜 위험한지(점수 근거·평소 차이)와 실제로 무엇이 관측됐는지(사건 타임라인·원문)를 근거 수준과 함께 봅니다.")
C.page_note("기간 필터와 상관없이 전체 조사 근거를 보여줍니다")

wanted = st.session_state.get("selected_session")
if wanted and wanted not in options and wanted in info.index:
    st.warning(f"{wanted}는 현재 규칙에서 점수가 없어 경보 상세가 없습니다. 다른 세션으로 바꾸지 않았습니다.",
               icon=":material/info:")
    if st.button(f"{wanted} 세션·기준선 탐색에서 보기"):
        st.switch_page("views/session_explorer.py")
    index = None
else:
    index = options.index(wanted) if wanted in options else 0


def label(sid):
    r = info.loc[sid]
    tag = "경보" if r["is_alert"] else "경보 아님"
    extra = f" · 참고: {ref[sid]}" if sid in ref else ""
    return f"{sid} · {r['person_candidate']} · {r['risk_score']:g}점 · {tag}{extra}"


sid = st.selectbox("세션 (점수가 있는 세션, 점수 순)", options, index=index, format_func=label,
                   placeholder="세션을 고르세요")
if sid is None:
    st.stop()
st.session_state["selected_session"] = sid

row = info.loc[sid]
sb = L.load("session_baseline").set_index("work_session_id").loc[sid]
ctx_all = L.load("alert_context").set_index("work_session_id")
has_ctx = sid in ctx_all.index
ev = L.num(L.load("risk_events"), "signal_score", "base_score", "criticality_factor", "confidence_factor")
ev = ev[ev["work_session_id"] == sid]
n_linked_types = ev[ev["link"] == "linked"]["detection_type"].nunique()

# ---------------------------------------------------------------- 머리말
st.subheader(f"{sid} · {row['person_candidate']}" + (f"  (참고: {ref[sid]})" if sid in ref else ""))
st.markdown(f"**{row['start_kst']:%m-%d %H:%M} ~ {row['end_kst']:%H:%M} KST** ({row['duration_min']}분) · "
            f"세션 유형 `{C.TYPE_LABEL.get(row['session_type'], row['session_type'])}` · 접속 IP `{row['client_ip']}` "
            f"({row['client_zone']}) · 위험점수 **{row['risk_score']:g}점** · ATT&CK 전술 **{int(row['tactic_count'])}개**")
badges = [C.state_badge(row["state"])]
if row["is_alert"]:
    badges.append(C.chip(f"경보 사유: {row['alert_reason']}"))
if row["activity_verdict"]:
    badges.append(C.verdict_badge("활동 판정", row["activity_verdict"],
                                  "high 룰 신호의 원본 이벤트가 로그에 관측됨" if row["activity_verdict"] == "의심 확인"
                                  else row["reason"]))
if row["attribution"]:
    badges.append(C.basis_badge("세션 귀속", row["attribution"],
                                "세션에 직접 속한 high 룰 신호가 있음" if row["attribution"] == "관측"
                                else "high 룰 신호가 모두 시간·서버로 추정 연결됨"))
C.html_row(*badges)

if row["attribution"] == "추정":
    st.warning("**시스템 계정 활동 자체는 로그에 관측됐지만, 이 세션(사람 후보)의 활동이라는 연결은 추정입니다.** "
               "같은 서버·가까운 시간이라는 근거뿐이므로 사람을 단정하지 마세요.", icon=":material/link:")
elif n_linked_types:
    st.info(f"세션 귀속 판정은 ‘관측’이지만, 점수에 들어간 탐지 중 **{n_linked_types}종은 시스템 계정 활동을 추정으로 연결한 것**입니다. "
            "세션 배지를 모든 이벤트에 적용하지 마세요. 이벤트별 근거는 타임라인에 따로 표시합니다.", icon=":material/link:")
if has_ctx:
    names = [x.split(":", 1)[-1] for x in ctx_all.loc[sid, "top_signals"].split(" | ") if x]
    st.markdown(f"**요약:** 점수 기여가 큰 탐지는 {', '.join(names[:3])}입니다. "
                f"데이터 공백 {ctx_all.loc[sid, 'data_gaps']}개가 남아 있어 결과(전송 성공 등)는 확인되지 않았습니다.")
else:
    st.markdown("**요약:** 점수는 있지만 경보가 아닌 세션입니다. 점수·기준선·판정까지만 조사했고 사고 카드는 없습니다(미조사).")

# ---------------------------------------------------------------- 점수 근거 + 평소 비교
left, right = st.columns([1.15, 1])
with left:
    st.markdown("#### 점수 근거")
    top = ev.loc[ev.groupby("detection_type")["signal_score"].idxmax()].sort_values("signal_score")
    if abs(top["signal_score"].sum() - row["risk_score"]) > 0.05:
        st.error("탐지 종류별 최대 점수의 합이 세션 점수와 다릅니다. 결과 파일 묶음이 섞였는지 확인하세요.")
    fig = go.Figure()
    order = [f"{t} {n}" for t, n in zip(top["detection_type"], top["name"])]
    for method, mname, color in [("rule", "룰", C.SERIES[0]), ("behavior", "행동", C.SERIES[1])]:
        for link, lname, pattern in [("direct", "직접", ""), ("linked", "추정 연결", "/")]:
            d = top[(top["method"] == method) & (top["link"] == link)]
            if d.empty:
                continue
            fig.add_bar(
                y=[f"{t} {n}" for t, n in zip(d["detection_type"], d["name"])], x=d["signal_score"], orientation="h",
                name=f"{mname} · {lname}",
                marker=dict(color=color, cornerradius=4,
                            pattern=dict(shape=pattern, fgcolor="white", size=6, fillmode="overlay")),
                text=[f"{v:g}" for v in d["signal_score"]], textposition="outside",
                textfont=dict(color=C.INK["secondary"]), cliponaxis=False,
                customdata=d[["base_score", "criticality_factor", "confidence_factor"]].values,
                hovertemplate="%{y}<br>기본 %{customdata[0]:g} × 중요도 %{customdata[1]:g} × 연결 신뢰도 %{customdata[2]:g}"
                              " = <b>%{x:g}점</b><extra></extra>")
    fig.update_yaxes(categoryorder="array", categoryarray=order, showgrid=False)
    fig.update_xaxes(title="신호 점수")
    C.show(C.style(fig, height=max(240, 34 * len(top) + 90)), key="ad_score")
    st.caption(f"합계 {top['signal_score'].sum():g}점 = 탐지 종류별 최대 점수 {len(top)}개의 합 (원시 신호 {len(ev)}행을 그대로 더하지 않음). "
               "빗금 = 추정 연결. 연결 신뢰도 0.8은 검증된 확률 80%가 아니라 미리 정한 할인 계수입니다.")
    with st.expander("표로 보기"):
        st.dataframe(top.sort_values("signal_score", ascending=False)[
            ["detection_type", "name", "method", "severity", "link", "base_score", "criticality_factor",
             "confidence_factor", "signal_score", "tactics"]].rename(columns={
                "detection_type": "탐지", "name": "이름", "method": "방식", "severity": "심각도", "link": "연결",
                "base_score": "기본", "criticality_factor": "중요도", "confidence_factor": "신뢰도",
                "signal_score": "점수", "tactics": "전술"}), hide_index=True, width="stretch")

with right:
    st.markdown("#### 평소와 비교")
    level, n = sb["baseline_level"], sb["baseline_n"]
    if level == "none":
        st.info("비교 불가: 이 세션 전에 끝난 세션이 5개 미만입니다 (기준선 없음).")
    else:
        rows = [
            ("시작 시각(KST)", f"{sb['start_hour_kst']}시", f"{sb['hist_hour_min']}~{sb['hist_hour_max']}시",
             f"{sb['hour_distance']}시간 벗어남" if sb["hour_outside"] == "true" else "범위 안"),
            ("접속 IP", row["client_ip"], "", "처음 보는 IP" if sb["ip_new"] == "true" else "평소와 같음"),
            ("세션 유형", C.TYPE_LABEL.get(row["session_type"], row["session_type"]),
             f"같은 유형 비율 {float(sb['hist_session_type_ratio']):.0%}",
             "처음 쓰는 경로" if float(sb["hist_session_type_ratio"]) == 0 else ""),
            ("로그인 전 실패", f"{row['failed_before_login']}회", f"실패 있던 과거 세션 {sb['hist_failed_sessions']}개",
             "처음 발생" if int(row["failed_before_login"]) and sb["hist_failed_sessions"] == "0" else ""),
            ("새 웹 로그인 종류", sb["login_types_new"] or "없음", "", ""),
            ("처음 하는 민감 행위", sb["sensitive_new"].replace("|", ", ") or "없음", "", ""),
            ("누구도 쓴 적 없는 명령", f"{len(sb['cmds_new_global'].split('|'))}개" if sb["cmds_new_global"] else "없음", "", ""),
            ("프로세스 수", row["process_count"], f"과거 이하 비율 {sb['process_count_pct']}%",
             "과거 최대 초과" if sb["process_count_above_max"] == "true" else ""),
            ("GET 외 웹 요청", row["non_get_count"], f"과거 이하 비율 {sb['non_get_count_pct']}%",
             "과거 최대 초과" if sb["non_get_count_above_max"] == "true" else ""),
        ]
        st.table(pd.DataFrame([{"항목": a, "이번": b, "과거 기준선": c, "차이": d} for a, b, c, d in rows]).set_index("항목"))
        note = "" if level in ("person", "peer") else " · 다른 사람과의 비교라 행동 탐지에서는 제외"
        st.caption(f"기준선 **{level}** · 과거 세션 **{n}개** (이 세션 시작 전에 끝난 세션만){note} · 근거 ● 관측")
    if has_ctx:
        c = ctx_all.loc[sid]
        st.markdown("#### 경보 맥락")
        crow = [
            ("직전 세션", f"{c['hours_since_prev_session']}시간 전" if c["hours_since_prev_session"] else "없음", "관측"),
            ("웹 로그인", c["web_login"].replace("|", ", ") or "없음", "관측"),
            ("연결된 시스템 활동", c["linked_system_activity"] or "없음",
             "추정(세션 귀속)" if c["linked_system_activity"] else "관측"),
            ("생성 파일", c["files_created"].replace("|", ", ") or "없음",
             "관측(이벤트) / 추정(세션 귀속)" if c["linked_system_activity"] else "관측"),
            ("외부 목적지", c["external_destinations"].replace("|", ", ") or "없음",
             "관측(이벤트) / 추정(세션 귀속)" if c["linked_system_activity"] else "관측"),
            ("계정·설정 변경", c["config_changes"].replace("|", ", ") or "없음", "관측"),
            ("같은 서버·같은 시간 다른 세션", c["concurrent_sessions_same_host"].replace("|", ", ") or "없음", "관측"),
        ]
        st.table(pd.DataFrame([{"항목": a, "값": b, "근거": C.basis_text(k)} for a, b, k in crow]).set_index("항목"))

tactics = ctx_all.loc[sid, "tactic_chain"].split(" → ") if has_ctx else [t for t in row["tactics"].split("|") if t]
if tactics:
    C.html_row("<span style='margin-right:6px'>탐지 해석 (ATT&amp;CK 전술)</span>",
               "".join(C.chip(C.TACTIC_KO.get(t, t)) for t in tactics))
    st.caption("룰 탐지에 붙은 전술의 목록입니다. 실제 사건 순서나 인과관계의 증명이 아닙니다. 시간순 사실은 아래 타임라인을 봅니다.")

# ---------------------------------------------------------------- 탭
tab_tl, tab_det, tab_card, tab_gap, tab_why = st.tabs(
    ["사건 타임라인", "탐지·원문", "조사 카드 (Q1~Q9)", "확인 못 한 것", "판정 기준"])

tl_all = L.load("incident_timeline")
tl_all = tl_all[tl_all["incident"] == sid]

with tab_tl:
    if tl_all.empty:
        st.info("사고 타임라인은 경보 세션만 만들었습니다(7단계 조사 대상). 이 세션은 미조사입니다. "
                "세션에 직접 속한 이벤트는 세션·기준선 탐색에서 볼 수 있습니다.")
        if st.button("세션 탐색에서 직접 이벤트 보기", key="ad_to_explorer"):
            st.switch_page("views/session_explorer.py")
    else:
        folded = tl_all[tl_all["event_time_utc"] == ""]
        tl = tl_all[tl_all["event_time_utc"] != ""].copy()
        tl["t"] = L.to_kst(tl["event_time_utc"])
        tl["kind"] = tl["basis"].map(C.basis_kind)
        tl["det"] = tl["detection_ids"] != ""

        f1, f2, f3 = st.columns([1.4, 1.3, 1])
        logs = f1.multiselect("로그", C.LANES, default=C.LANES, format_func=lambda x: C.LOG_LABEL[x], key="ad_logs")
        kinds = sorted(tl["kind"].unique())
        pick = f2.multiselect("근거", kinds, default=kinds, key="ad_kinds",
                              format_func=lambda k: f"{C.BASIS_ICON.get(k, '')} {k}")
        only_det = f3.toggle("탐지 걸린 이벤트만", value=False, key="ad_only_det")
        view = tl[tl["log_source"].isin(logs) & tl["kind"].isin(pick) & (tl["det"] | (not only_det))]
        st.caption(f"아래 그래프와 표에 같은 필터가 적용됩니다 ({len(view)} / {len(tl)}개 이벤트).")

        fig = go.Figure()
        for det in (True, False):
            for est in (False, True):
                d = view[(view["det"] == det) & ((view["kind"] == "추정") == est)]
                if d.empty:
                    continue
                fig.add_scatter(
                    x=d["t"], y=d["log_source"].map(C.LOG_LABEL), mode="markers",
                    name=f"{'탐지 걸림' if det else '그 외'} · {'세션 귀속 추정' if est else '세션 소속 관측'}",
                    marker=dict(color=C.ACCENT if det else C.DEEMPH, size=12 if det else 9,
                                symbol="circle-open" if est else "circle",
                                line=dict(width=2, color=C.ACCENT if det else C.DEEMPH) if est
                                else dict(width=2, color=C.SURFACE)),
                    customdata=d[["summary", "basis", "detection_ids", "event_time_utc"]].values,
                    hovertemplate="%{x|%m-%d %H:%M:%S} KST (UTC %{customdata[3]})<br>%{customdata[0]}"
                                  "<br>근거: %{customdata[1]}<br>탐지: %{customdata[2]}<extra></extra>")
        fig.update_yaxes(categoryorder="array", categoryarray=[C.LOG_LABEL[x] for x in reversed(C.LANES)])
        fig.update_xaxes(title="시각 (KST) · 끌어서 확대, 두 번 눌러 원래대로", tickformat="%H:%M:%S")
        C.show(C.style(fig, height=320), key="ad_tl")
        st.caption("점은 실제 시각에 그대로 놓았습니다(겹치는 점을 옮기지 않음). 채운 점 = 이 세션에 직접 기록, "
                   "빈 점 = 시스템 계정 활동을 시간·서버로 연결(이벤트 자체는 관측된 기록). 강조색 = 탐지 신호가 걸린 이벤트.")
        st.dataframe(view.sort_values(["event_time_utc", "source_row"]).assign(
            로그=view["log_source"].map(C.LOG_LABEL), 근거=view["basis"].map(C.basis_text))
                     [["time_kst", "event_time_utc", "로그", "근거", "summary", "detection_ids", "host", "account",
                       "source_row"]]
                     .rename(columns={"time_kst": "시각(KST)", "event_time_utc": "UTC", "summary": "내용",
                                      "detection_ids": "탐지", "host": "서버", "account": "계정", "source_row": "원본 행"}),
                     hide_index=True, width="stretch", height=380)
        if not folded.empty:
            st.caption(f"반복 정상 패턴 {len(folded)}종은 접었습니다(시각 없이 요약만): "
                       + " / ".join(folded["summary"]) + " · 원본은 세션·기준선 탐색의 ‘시스템 배경 활동’에서 봅니다.")

with tab_det:
    dets = L.load("detections")
    rules = L.load("detection_rules").set_index("id")
    mine = dets[dets["detection_id"].isin(ev["detection_id"])].copy()
    mine = mine.merge(ev[["detection_id", "link", "signal_score"]].drop_duplicates("detection_id"), on="detection_id")
    mine = L.num(mine, "signal_score").sort_values(["signal_score", "event_time_utc"], ascending=[False, True])
    st.caption(f"이 세션에 반영된 원시 신호 {len(mine)}건입니다. 같은 종류는 점수에 한 번만 들어갑니다.")
    pick_det = st.selectbox("신호", mine["detection_id"].tolist(), key="ad_det",
                            format_func=lambda d: (lambda r: f"{d} · {r['detection_type']} {r['name']} · "
                                                             f"{'추정 연결' if r['link'] == 'linked' else '직접'} · "
                                                             f"{L.kst_text(r['event_time_utc'], '%m-%d %H:%M:%S')}")(
                                mine.set_index("detection_id").loc[d]))
    if pick_det:
        d = mine.set_index("detection_id").loc[pick_det]
        rule = rules.loc[d["detection_type"]] if d["detection_type"] in rules.index else None
        a, b = st.columns([1, 1.2])
        with a:
            st.markdown(f"**{d['detection_type']} {d['name']}**")
            st.dataframe([
                {"항목": "방식", "값": "룰" if d["method"] == "rule" else "행동"},
                {"항목": "심각도", "값": C.severity_text(d["severity"]) if d["method"] == "rule" else "— (행동 20점)"},
                {"항목": "조건", "값": rule["condition"] if rule is not None else ""},
                {"항목": "ATT&CK", "값": d["attck"] or "— (행동 탐지는 전술에 넣지 않음)"},
                {"항목": "근거(evidence)", "값": d["evidence"]},
                {"항목": "세션 연결", "값": "직접 소속" if d["link"] == "direct"
                    else f"추정 연결: {d['linked_sessions'] or ''} {d['link_basis']}".strip()},
            ], hide_index=True, width="stretch")
        with b:
            st.markdown("**원문**")
            if not d["source_row"]:
                st.info("세션 수준 신호입니다. 4단계 비교값에서 계산해 단일 원문 행이 없습니다. 대표 원문을 임의로 연결하지 않습니다.")
            else:
                raw = L.raw_event(d["log_source"], d["source_row"])
                if raw.empty:
                    st.warning(f"원문을 하나로 특정하지 못했습니다 ({d['log_source']} 행 {d['source_row']}).")
                else:
                    r = raw.iloc[0]
                    fields = {k: r[k] for k in ["event_time_utc", "log_source", "source_row", "host", "account",
                                                "client_ip", "event_action", "CommandLine", "ParentImage",
                                                "TargetFilename", "dst", "dpt", "request", "http_status_code"] if r[k]}
                    st.dataframe([{"필드": k, "값": v} for k, v in fields.items()], hide_index=True, width="stretch")
                    st.code(r["rawEvent"], language="text", wrap_lines=True)
                    st.caption("키: log_source + source_row (통합 타임라인 기준)")

with tab_card:
    pv = L.load("pivots")
    pv = pv[pv["work_session_id"] == sid]
    if pv.empty:
        st.info("조사 카드(Q1~Q9)는 경보 세션만 만들었습니다. 이 세션은 미조사입니다.")
    else:
        for q in Q_TITLE:
            st.markdown(f"**{q}. {Q_TITLE[q]}**")
            if q == "Q5":
                st.caption("‘사건 타임라인’ 탭을 봅니다.")
                continue
            d = pv[pv["question"] == q]
            st.dataframe([{"항목": i, "값": v.replace("|", " / "), "근거": C.basis_text(b)}
                          for i, v, b in zip(d["item"], d["value"], d["basis"])], hide_index=True, width="stretch")

with tab_gap:
    pv = L.load("pivots")
    gaps = pv[(pv["work_session_id"] == sid) & (pv["question"] == "Q8")]["value"].tolist()
    if not gaps:
        st.info("이 세션은 조사 카드가 없어 데이터 공백도 정리되지 않았습니다(미조사)." if pv[pv["work_session_id"] == sid].empty
                else "기록된 데이터 공백이 없습니다.")
    else:
        rows = []
        for g in gaps:
            need = next(((n, f) for k, n, f in GAP_NEEDS if k in g), ("", ""))
            rows.append({"확인 못 한 것": g, "필요한 로그": need[0], "후속 확인": need[1]})
        st.dataframe(rows, hide_index=True, width="stretch")
        st.caption("데이터 공백은 분석 실패가 아니라 수집 개선 과제입니다. (출처: docs/14_조사/02_조사결과_정리.md 4절)")

with tab_why:
    st.markdown(f"**이 세션의 판정 근거:** {row['reason'] or '판정 없음 (미조사)'}")
    st.markdown(
        "- **활동 판정**: high 룰 신호의 원본 이벤트가 로그에 관측되면 `의심 확인`, 룰 없이 행동 탐지만 있고 정상 업무로 "
        "설명되면 `오탐 후보`, 그 외 `보류`\n"
        "- **귀속 판정**: high 룰 신호 중 세션에 직접 속한 것이 있으면 `관측`, 모두 시간·서버 추정 연결이면 `추정`\n"
        "- **경보**: 세션 점수 100 이상 **또는** ATT&CK 전술 3개 이상. 이 화면은 판정을 바꾸지 않습니다.\n"
        "- 기준은 실행 전에 고정했습니다 (docs/13_위험점수/00, docs/14_조사/00 7-4). ‘의심 확인’은 유출 성공·공격자 확정이 아닙니다.")
