"""⑥ 판정·점수 기준: 점수·경보를 정한 기준과 그 안에 들어간 분석자 판단.

2026-10-07: 사용자 요청으로 '판정·점수 기준'만 남기고, 도메인 판단 항목(A 그룹)을 더했다.
이전 전체 버전(0~7단계, 가중치 민감도, 데이터 공백·개선, 통계 검정 탭)은
dashboard_v2/archive/method_limits_full_20261007.py에 보관했다.

표의 값은 결과 파일에서 읽는다. '근거 유형'과 '기업 확인'은 각 단계 문서(docs/08_보강, 12_탐지, 14_조사)의
결정 기록을 옮긴 설명값이다.
"""
import pandas as pd
import streamlit as st

import components as C
import loaders as L
import theme as T

T.hero("판정·점수 기준", "점수와 경보를 정한 기준, 그리고 그 기준 안에 들어간 분석자 판단(도메인 판단)을 정리합니다. "
                        "기업이 공식 값을 주면 바뀔 수 있는 항목은 따로 표시했습니다.")

st.markdown("**근거 유형** · `도메인` 보안 상식·실무 관행으로 정함 · `분포` 데이터 분포를 보고 정함 · "
            "`임의` 근거 없이 정한 숫자 · **기업 확인** ✓ = 공식 자료로 바꿔야 확정되는 값")

ev = L.num(L.load("risk_events"), "base_score", "criticality_factor", "confidence_factor", "signal_score")
dets = L.load("detections")
sr = L.load("session_risk")
alerts = set(sr.loc[sr["alert"] == "true", "work_session_id"])

tab_score, tab_host, tab_rule, tab_sens, tab_link, tab_verdict = st.tabs(
    ["점수·경보 공식", "서버 중요도", "룰 심각도·임계값", "행위 민감도", "추정 연결 규칙", "판정 규칙"])

# ---------------------------------------------------------------- 점수·경보 공식
with tab_score:
    base_rule = ev[ev["method"] == "rule"].groupby("severity")["base_score"].first()
    base_beh = ev[ev["method"] == "behavior"]["base_score"].unique()
    a, b = st.columns(2)
    with a:
        st.markdown("#### 신호 점수 = 기본 점수 × 자산 중요도 × 연결 신뢰도")
        st.table(pd.DataFrame([
            {"요소": "기본 점수 (룰)", "값": " / ".join(f"{k} {v:g}" for k, v in base_rule.items())
                                         + ("" if "low" in base_rule.index else " (low: 이번 결과에 점수가 반영된 신호 없음)"),
             "근거 유형": "임의 (순서를 숫자로 옮김)"},
            {"요소": "기본 점수 (행동)", "값": ", ".join(f"{v:g}" for v in base_beh), "근거 유형": "임의"},
            {"요소": "자산 중요도", "값": ", ".join(f"×{v:g}" for v in sorted(ev["criticality_factor"].unique())),
             "근거 유형": "임의 (등급은 ‘서버 중요도’ 탭)"},
            {"요소": "연결 신뢰도", "값": "직접 ×1.0, 추정 연결 ×0.8", "근거 유형": "임의 (확률이 아닌 할인 계수)"},
            {"요소": "합산", "값": "같은 세션·같은 탐지 종류는 최대 점수 1개만", "근거 유형": "도메인 (RBA 관행)"},
            {"요소": "경보", "값": "세션 점수 ≥ 100 또는 ATT&CK 전술 ≥ 3 (룰 탐지만 셈)", "근거 유형": "도메인 (RBA 관행)"},
        ]).set_index("요소"))
        st.caption("값은 결과 파일에서 읽었습니다. 가중치는 실무 RBA 방식을 참고한 임의값이며 실행 전에 고정했습니다.")
    with b:
        st.markdown("#### 근거와 판정 배지의 뜻")
        C.html_row(*(C.legend(k, C.BASIS_ICON[k], C.BASIS_TONE[k], desc) for k, desc in [
            ("관측", "로그 한 행에 직접 기록된 사실"), ("추정", "시간·서버·IP로 이어 붙인 연결"),
            ("모름", "로그로 알 수 없음 (예: 전송 성공 여부)")]))
        C.html_row(*(C.legend(v, icon, C.VERDICT_TONE[v]) for v, (_, icon) in C.VERDICT.items()))
        st.markdown("- **활동 판정**과 **귀속 판정**의 규칙은 ‘판정 규칙’ 탭에 있습니다.\n"
                    "- **독립 성능평가는 하지 않았습니다.** 시나리오를 탐색으로 먼저 찾은 뒤 룰을 만들어 결과는 탐색적입니다.")

# ---------------------------------------------------------------- 서버 중요도
with tab_host:
    hosts = L.load("host_inventory")
    factor = ev.groupby("host")["criticality_factor"].first()
    by_level = ev.groupby(ev["host"].map(dict(zip(hosts["host"], hosts["criticality"]))))["criticality_factor"].first()
    er = L.num(L.load("entity_risk"), "total_score")
    host_score = er[er["entity_type"] == "host"].set_index("entity")["total_score"]
    rows = []
    for _, h in hosts.iterrows():
        sess = sorted(set(ev.loc[(ev["host"] == h["host"]) & ev["work_session_id"].isin(alerts), "work_session_id"]))
        f = factor.get(h["host"], by_level.get(h["criticality"]))
        rows.append({"서버": h["host"], "역할": h["role"], "중요도": h["criticality"],
                     "점수 계수": f"×{f:g}" if pd.notna(f) else "—",
                     "판단 근거": h["role_evidence"], "근거 유형": f"도메인 ({h['criticality_basis']})",
                     "기업 확인": "✓" if h["criticality_basis"] != "공식" else "",
                     "이 서버 신호가 들어간 경보": ", ".join(sess) or "없음",
                     "서버 신호 점수 합": f"{host_score.get(h['host'], 0):g}"})
    st.table(pd.DataFrame(rows).set_index("서버"))
    low = hosts.loc[hosts["criticality"] != "high", "host"].tolist()
    hit = sorted(set(ev.loc[ev["host"].isin(low) & ev["work_session_id"].isin(alerts), "work_session_id"]))
    st.info(f"중요도가 high가 아닌 서버({', '.join(low)})에서 나온 신호는 ×1.5를 받지 못합니다. "
            f"이 서버 신호가 점수에 들어간 경보: {', '.join(hit) or '없음'}. "
            "서버 중요도 판단 하나가 경보 순위를 바꿀 수 있으므로, 기업의 실제 자산 중요도를 받으면 가장 먼저 바꿀 항목입니다.",
            icon=":material/dns:")

# ---------------------------------------------------------------- 룰 심각도·임계값
with tab_rule:
    rules = L.load("detection_rules")
    rules = rules[rules["method"] == "rule"]
    count = dets["detection_type"].value_counts()
    base_by_sev = ev[ev["method"] == "rule"].groupby("severity")["base_score"].first()
    THRESHOLD = {"R04": "포트 80·443 외", "R05": "5분 · 3대", "R09": "1시간 · 5회", "R10": "10분", "R15": "5분 · 5회"}
    rows = []
    for _, r in rules.iterrows():
        rows.append({"룰": r["id"], "이름": r["name"], "심각도": C.severity_text(r["severity"]),
                     "기본 점수": f"{base_by_sev[r['severity']]:g}" if r["severity"] in base_by_sev else "— (반영 신호 없음)",
                     "조건": r["condition"], "숫자 기준": THRESHOLD.get(r["id"], "—"),
                     "근거 유형": "도메인 + 임의(숫자)" if r["id"] in THRESHOLD and r["id"] != "R04" else "도메인",
                     "탐지 건수": int(count.get(r["id"], 0))})
    st.table(C.tone_cells(pd.DataFrame(rows).set_index("룰"), ["심각도"]))
    st.caption("심각도는 기법의 일반적인 위험도로 정했고(실행 전 고정), 기본 점수가 이 등급을 따라갑니다. "
               "숫자 기준(시간 창·횟수)은 공식 표준이 없어 분석자가 정했습니다. R16은 설정 위험이라 점수에서 뺐습니다.")
    zero = [r["룰"] for r in rows if r["탐지 건수"] == 0]
    if zero:
        st.warning(f"탐지 0건인 룰: {', '.join(zero)}. R09는 외부 IP 3개가 하루 몇 회씩 천천히 시도해 ‘1시간 5회’에 한 번도 "
                   "걸리지 않았습니다. 숫자 기준이 결과를 좌우한 사례입니다.", icon=":material/warning:")
    st.caption("Sigma 공개 룰과의 대응: docs/12_탐지/02_Sigma_대조표.md (거의 같음 1, 변형 4, 개념만 5, 자체 제작 6)")

# ---------------------------------------------------------------- 행위 민감도
with tab_sens:
    cat = L.load("action_catalog")
    cat = cat[cat["sensitivity"].isin(["high", "medium"])].copy()
    cat["sort"] = cat["sensitivity"].map({"high": 0, "medium": 1})
    cat = cat.sort_values(["sort", "log_source", "event_action"])
    st.table(C.tone_cells(cat.assign(
        민감도=cat["sensitivity"].map(C.severity_text),
        쓰이는곳=cat["sensitivity"].map({"high": "B05 처음 하는 민감 행위", "medium": "표시용 (탐지에 직접 쓰지 않음)"}),
        근거유형=cat["sensitivity_basis"].map(lambda b: f"도메인 ({b})"),
        기업확인=cat["log_source"].map(lambda s: "✓" if s == "teiren_audit" else ""),
    )[["log_source", "event_action", "category", "민감도", "event_count", "쓰이는곳", "근거유형", "기업확인"]].rename(columns={
        "log_source": "로그", "event_action": "행위", "category": "분류", "event_count": "건수",
        "쓰이는곳": "쓰이는 곳", "근거유형": "근거 유형", "기업확인": "기업 확인"}).set_index("행위"), ["민감도"]))
    st.caption("low 행위는 생략했습니다. 감사로그(테이렌) 행위는 공개 문서가 없어 이름·요청 경로로 의미와 민감도를 추정했습니다. "
               "Sysmon 이벤트는 종류만으로는 모두 low라, 명령의 위험성은 민감도가 아니라 룰(R01~R08)이 판단합니다. "
               "시간대에 따른 민감도는 없습니다(시간은 개인 기준선 B01로 따로 봄).")

# ---------------------------------------------------------------- 추정 연결 규칙
with tab_link:
    st.table(pd.DataFrame([
        {"규칙": "서버 세션 연결", "조건": "같은 서버에서, 그 서버에 접속해 있던 사용자 세션의 ssh 시간 안 (세션의 작업 서버 또는 사람의 주 작업 서버)",
         "근거 유형": "도메인", "기업 확인": "✓ (auditd auid로 확정 가능)"},
        {"규칙": "웹 서버 연결", "조건": "웹 서버의 시스템 계정 이벤트 앞뒤 5분 안에 웹 요청을 보낸 세션",
         "근거 유형": "도메인 + 임의(5분)", "기업 확인": "✓ (앱 로그·공유 요청 ID로 확정 가능)"},
        {"규칙": "후보가 여럿일 때", "조건": "모두 남기고 시간 차이를 기록", "근거 유형": "도메인", "기업 확인": ""},
        {"규칙": "점수 반영", "조건": "추정 연결 신호는 ×0.8", "근거 유형": "임의", "기업 확인": ""},
    ]).set_index("규칙"))
    linked = dets[dets["linked_sessions"] != ""].copy()
    linked["세션"] = linked["linked_sessions"].str.extract(r"(S\d+)")
    summ = linked.groupby(["세션", "host"]).agg(신호=("detection_id", "size"),
                                                 탐지=("detection_type", lambda x: ", ".join(sorted(set(x))))).reset_index()
    tri = L.load("triage").set_index("work_session_id")
    summ["세션 귀속 판정"] = summ["세션"].map(tri["attribution"]).fillna("")
    st.markdown(f"#### 실제로 추정 연결된 신호 {len(linked)}건 / 전체 {len(dets)}건")
    st.table(summ.rename(columns={"host": "서버"}).set_index("세션"))
    st.caption("root·www-data 같은 시스템 계정 활동은 이벤트 자체는 관측이지만, 어느 사람의 활동인지는 이 규칙으로만 이어 붙였습니다. "
               "추정 연결 신호만으로 high 룰이 채워진 세션은 귀속 판정이 ‘추정’이 됩니다.")

# ---------------------------------------------------------------- 판정 규칙
with tab_verdict:
    tri = L.load("triage")
    a, b = st.columns(2)
    with a:
        st.markdown("#### 활동 판정 (의심스러운 활동인가)")
        st.dataframe(C.tone_cells(pd.DataFrame([
            {"판정": C.verdict_text("의심 확인"), "규칙": "high 룰 신호의 원본 이벤트가 로그에 관측됨", "근거 유형": "도메인"},
            {"판정": C.verdict_text("오탐 후보"), "규칙": "룰 신호 없이 행동 탐지만 있고 정상 업무로 설명됨", "근거 유형": "도메인"},
            {"판정": C.verdict_text("보류"), "규칙": "그 외", "근거 유형": "도메인"},
        ]), ["판정"]), hide_index=True, width="stretch")
        vc = tri["activity_verdict"].value_counts()
        st.caption("현재 결과: " + " / ".join(f"{k} {v}건" for k, v in vc.items()) +
                   ". ‘의심 확인’은 유출 성공·공격자 확정을 뜻하지 않습니다.")
    with b:
        st.markdown("#### 귀속 판정 (누구의 활동인가)")
        st.dataframe(C.tone_cells(pd.DataFrame([
            {"판정": f"{C.BASIS_ICON['관측']} 관측", "규칙": "high 룰 신호 중 세션에 직접 속한 것이 있음", "근거 유형": "도메인"},
            {"판정": f"{C.BASIS_ICON['추정']} 추정", "규칙": "high 룰 신호가 모두 시간·서버 추정 연결", "근거 유형": "도메인"},
        ]), ["판정"]), hide_index=True, width="stretch")
        ac = tri.loc[tri["attribution"] != "", "attribution"].value_counts()
        st.caption("현재 결과(경보 세션): " + " / ".join(f"{k} {v}건" for k, v in ac.items()) +
                   ". 활동 판정과 귀속 판정은 따로 읽습니다.")
    st.caption("판정 기준은 7단계 실행 전에 고정했습니다 (docs/14_조사/00_7단계_계획.md 7-4). 이 화면은 판정을 바꾸지 않습니다.")
