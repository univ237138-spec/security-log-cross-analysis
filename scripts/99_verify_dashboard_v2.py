"""대시보드 v2 검증: 페이지가 오류 없이 열리고, 화면 숫자·선택·가림 표시가 결과 파일과 맞는지 확인한다.

실행: python scripts/99_verify_dashboard_v2.py
계획: docs/15_대시보드/02_현재산출물_기반_대시보드_구성계획.md 8절 '핵심 검증 항목'
"""
import sys
from datetime import date

from streamlit.testing.v1 import AppTest

from common import RISK, ROOT, read_rows

APP = str(ROOT / "dashboard_v2" / "app.py")
PAGES = ["views/overview.py", "views/alert_list.py", "views/alert_detail.py", "views/session_explorer.py",
         "views/config_external.py", "views/method_limits.py"]

risk = read_rows(RISK / "session_risk.csv")
alerts = [r["work_session_id"] for r in sorted(risk, key=lambda r: int(r["rank"])) if r["alert"] == "true"]
scores = {r["work_session_id"]: float(r["risk_score"]) for r in risk}
zero = sorted(s for s, v in scores.items() if v == 0)[0]
timeline_n = len(read_rows(ROOT / "data" / "07_sessions" / "timeline_sessions.csv"))
det_n = len(read_rows(ROOT / "data" / "09_detections" / "detections.csv"))
r16_n = sum(r["rule"] == "R16" for r in read_rows(RISK / "config_findings.csv"))


def texts(at):
    out = [e.value for kind in ("markdown", "caption", "title", "subheader", "info", "warning", "error")
           for e in getattr(at, kind)]
    out += [f"{m.label} {m.value}" for m in at.metric]
    out += [df.value.to_string() for df in at.dataframe]
    return "\n".join(map(str, out))


def run(page=None, **state):
    at = AppTest.from_file(APP, default_timeout=180)
    for k, v in state.items():
        at.session_state[k] = v
    at.run()
    if page:
        at.switch_page(page).run()
    assert not at.exception, (page, [e.value for e in at.exception])
    return at


ok = lambda msg: print(f"OK  {msg}")

# 1. 모든 페이지 (기본·가림 표시)
for mask in (False, True):
    for p in PAGES:
        at = run(p, mask=mask)
        t = texts(at)
        assert not at.error, (p, [e.value for e in at.error])
        assert "시나리오 A" not in t, p  # 참고 라벨 기본 숨김
        if mask:
            for leak in ("@lab.internal", "10.20.10.", "10.10.1.", "bastion-01", "c0ffee12"):
                assert leak not in t, (p, leak)
    ok(f"6개 페이지 오류 없음 (가림 표시 {'켬' if mask else '끔'})")

# 2. 전체 기간 숫자 카드 = 결과 파일
at = run("views/overview.py")
m = {x.label: x.value for x in at.metric}
expect = {"로그 이벤트 (행)": f"{timeline_n:,}", "업무 세션 (개)": f"{len(risk):,}", "탐지 신호 (건)": f"{det_n:,}",
          "경보 (세션)": f"{len(alerts)}", "설정 위험 (건)": f"{r16_n}"}
assert m == expect, (m, expect)
ok(f"전체 현황 숫자 카드 {m}")

# 3. 경보 목록 기본 보기 = 결과 파일 경보 (점수 순)
at = run("views/alert_list.py")
assert list(at.dataframe[0].value["세션"]) == alerts, list(at.dataframe[0].value["세션"])
ok(f"경보 목록 = {alerts}")

# 4. 경보 상세: 점수 있는 세션 모두 열리고, 탐지 종류별 최대 점수 합 = 세션 점수 (불일치 시 화면 오류가 뜸)
for sid in [s for s, v in scores.items() if v > 0]:
    at = run("views/alert_detail.py", selected_session=sid)
    assert at.selectbox[0].value == sid and not at.error, sid
    t = texts(at)
    assert f"합계 {scores[sid]:g}점" in t, sid
ok(f"경보 상세 점수 합계 일치 ({sum(v > 0 for v in scores.values())}개 세션)")

# 5. 귀속 표시: 추정 세션 경고, 관측 세션이라도 추정 연결 탐지가 있으면 안내
tri = {r["work_session_id"]: r["attribution"] for r in read_rows(ROOT / "data" / "11_investigation" / "triage.csv")}
for sid in alerts:
    t = texts(run("views/alert_detail.py", selected_session=sid))
    if tri[sid] == "추정":
        assert "연결은 추정입니다" in t, sid
ok("추정 귀속 세션에 경고 표시")

# 6. 점수 0 세션: 경보 상세가 다른 세션으로 바꾸지 않음, 세션 탐색에서는 열림
at = run("views/alert_detail.py", selected_session=zero)
assert at.selectbox[0].value is None and any(zero in w.value for w in at.warning), zero
at = run("views/session_explorer.py", selected_session=zero)
assert "현재 규칙의 점수 없음" in texts(at), zero
ok(f"점수 0 세션 {zero}: 경보 상세는 대체하지 않고 세션 탐색에서 열림")

# 7. 기간 필터: 마지막 날만 고르면 경보·세션 수가 줄고 설정 위험은 전체 기간 값 유지
at = run("views/overview.py", date_range=(date(2026, 10, 16), date(2026, 10, 16)))
m = {x.label: x.value for x in at.metric}
assert int(m["업무 세션 (개)"]) < len(risk) and m["설정 위험 (건)"] == f"{r16_n}", m
ok(f"기간 필터 10-16: {m}")

# 8. 참고 라벨을 켜면 경보 목록에 4개 표시
at = run("views/alert_list.py", show_ref=True)
assert (at.dataframe[0].value["참고 라벨"] != "").sum() == 4
ok("참고 라벨 스위치를 켜면 4개 세션에 표시")
print("검증 통과")
sys.exit(0)
