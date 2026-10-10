"""분석 결과 CSV를 읽는다. 읽기 전용이다. 탐지·기준선·점수·판정은 다시 계산하지 않는다.

계획: docs/15_대시보드/02_현재산출물_기반_대시보드_구성계획.md 5·6절
- 캐시 키에 파일 경로·수정 시각·크기를 넣어, 결과 파일이 바뀌면 자동으로 다시 읽는다.
- 파일이 없거나 필요한 컬럼이 없으면 '0건'으로 바꾸지 않고 화면을 멈춘다.
- 공유용 가림 표시를 켜면 이메일·내부 IP·호스트·tenancy를 같은 별칭으로 바꾼다 (모든 화면·원문 공통).
"""
import re
from datetime import date, datetime, timedelta
from pathlib import Path

import pandas as pd
import streamlit as st

# 이 복사본은 김희서/ 아래에 있으므로, data/ 폴더가 있는 프로젝트 최상위를 위로 올라가며 찾는다
ROOT = next(p for p in Path(__file__).resolve().parents if (p / "data" / "README.md").exists())
DATA = ROOT / "data"
KST = timedelta(hours=9)

FILES = {
    "timeline_sessions": DATA / "07_sessions" / "timeline_sessions.csv",
    "sessions": DATA / "07_sessions" / "sessions.csv",
    "session_baseline": DATA / "08_baseline" / "session_baseline.csv",
    "background_patterns": DATA / "08_baseline" / "background_patterns.csv",
    "background_baseline": DATA / "08_baseline" / "background_baseline.csv",
    "external_profile": DATA / "08_baseline" / "external_profile.csv",
    "detections": DATA / "09_detections" / "detections.csv",
    "detection_rules": DATA / "09_detections" / "detection_rules.csv",
    "session_risk": DATA / "10_risk" / "session_risk.csv",
    "risk_events": DATA / "10_risk" / "risk_events.csv",
    "entity_risk": DATA / "10_risk" / "entity_risk.csv",
    "config_findings": DATA / "10_risk" / "config_findings.csv",
    "sensitivity": DATA / "10_risk" / "sensitivity.csv",
    "triage": DATA / "11_investigation" / "triage.csv",
    "alert_context": DATA / "11_investigation" / "alert_context.csv",
    "pivots": DATA / "11_investigation" / "pivots.csv",
    "incident_timeline": DATA / "11_investigation" / "incident_timeline.csv",
    "stats_summary": DATA / "12_stats" / "summary.csv",
    "stats_test1": DATA / "12_stats" / "test1_path.csv",
    "stats_test1_person": DATA / "12_stats" / "test1_per_person.csv",
    "stats_test2_describe": DATA / "12_stats" / "test2_describe.csv",
    "stats_test2": DATA / "12_stats" / "test2_hour.csv",
    "stats_test2_posthoc": DATA / "12_stats" / "test2_posthoc.csv",
    "host_inventory": DATA / "05_enriched" / "host_inventory.csv",
    "ip_inventory": DATA / "05_enriched" / "ip_inventory.csv",
    "action_catalog": DATA / "05_enriched" / "action_catalog.csv",
}

# 화면에서 쓰는 컬럼. 큰 파일(타임라인)은 필요한 컬럼만 읽는다.
TIMELINE_LIGHT = ["event_time_utc", "log_source", "source_row", "bucket", "client_ip", "host", "account",
                  "person_candidate", "event_action", "work_session_id", "work_session_link"]
TIMELINE_RAW = TIMELINE_LIGHT + ["msg", "request", "http_method", "http_status_code", "CommandLine", "Image",
                                 "ParentImage", "TargetFilename", "dst", "dpt", "dst_zone", "rawEvent",
                                 "bucket_reason", "fill_basis"]
REQUIRED = {
    "session_risk": ["work_session_id", "risk_score", "tactic_count", "alert", "alert_reason", "rank", "start_utc"],
    "risk_events": ["detection_id", "detection_type", "work_session_id", "link", "signal_score", "base_score",
                    "criticality_factor", "confidence_factor"],
    "detections": ["detection_id", "method", "detection_type", "event_time_utc", "log_source", "source_row",
                   "work_session_id", "linked_sessions", "link_basis", "evidence"],
    "incident_timeline": ["incident", "event_time_utc", "log_source", "source_row", "basis", "summary", "detection_ids"],
    "sessions": ["work_session_id", "start_utc", "end_utc", "session_type", "person_candidate", "client_ip"],
}
# 표에서 가리지 않는 식별 컬럼 (조인 키)
NO_MASK = {"work_session_id", "detection_id", "detection_type", "source_row", "incident", "pattern_id", "id",
           "rank", "question"}

# 분석자 참고 라벨: docs/07_분석기획 3절(2026-10-01 작성)의 계정·시각으로 세션을 찾는다. 탐지 결과가 아니다.
REFERENCE = [("A", "dev02", "2026-10-14 18:12:18"), ("B", "analyst01", "2026-10-15 05:07:03"),
             ("C", "ops02", "2026-10-15 17:41:09"), ("D", "intern01", "2026-10-16 06:19:43")]


# ---------------------------------------------------------------- 파일 읽기
def _signature(path: Path):
    s = path.stat()
    return str(path), s.st_mtime_ns, s.st_size


def _check_exists(name: str):
    if not FILES[name].exists():
        st.error(f"결과 파일이 없습니다: `{FILES[name].relative_to(ROOT)}`  \n"
                 "해당 단계 스크립트를 먼저 실행하세요. 화면은 빈 값(0건)으로 대신하지 않습니다.",
                 icon=":material/error:")
        st.stop()


@st.cache_data(show_spinner="결과 파일을 읽는 중…")
def _read(path: str, mtime: int, size: int, usecols: tuple | None, masked: bool) -> pd.DataFrame:
    df = pd.read_csv(path, encoding="utf-8-sig", usecols=list(usecols) if usecols else None,
                     keep_default_na=False, dtype=str, low_memory=False)
    if masked:
        rules = _mask_rules()
        for c in df.columns:
            if c not in NO_MASK:
                df[c] = df[c].map(lambda v: _apply_mask(v, rules) if v else v)
    return df


def load(name: str, cols: list[str] | None = None) -> pd.DataFrame:
    _check_exists(name)
    df = _read(*_signature(FILES[name]), tuple(cols) if cols else None, masked())
    missing = [c for c in REQUIRED.get(name, []) if c not in df.columns and (cols is None or c in cols)]
    if missing:
        st.error(f"`{FILES[name].name}`에 필요한 컬럼이 없습니다: {', '.join(missing)}", icon=":material/error:")
        st.stop()
    return df


def file_status() -> pd.DataFrame:
    rows = []
    for name, p in FILES.items():
        rows.append({"파일": str(p.relative_to(ROOT)).replace("\\", "/"),
                     "상태": "있음" if p.exists() else "없음",
                     "수정 시각(로컬)": datetime.fromtimestamp(p.stat().st_mtime).strftime("%Y-%m-%d %H:%M") if p.exists() else ""})
    return pd.DataFrame(rows)


# ---------------------------------------------------------------- 공유용 가림 표시
def masked() -> bool:
    return bool(st.session_state.get("mask", False))


@st.cache_data(show_spinner=False)
def _mask_rules_cached(sig_ip: tuple, sig_host: tuple) -> list:
    ips = pd.read_csv(sig_ip[0], dtype=str, keep_default_na=False, encoding="utf-8-sig")
    hosts = pd.read_csv(sig_host[0], dtype=str, keep_default_na=False, encoding="utf-8-sig")
    rules = []
    # 호스트 이름 → 서버-A, 서버-B … (이름순, 매번 같은 별칭)
    # 한글도 \w라서 \b를 쓰면 'bastion-01에서'가 안 걸린다 → 영숫자 기준으로 경계를 직접 정한다
    for i, h in enumerate(sorted(hosts["host"])):
        rules.append((re.compile(rf"(?<![A-Za-z0-9_-]){re.escape(h)}(?![A-Za-z0-9_-])"), f"서버-{chr(65 + i)}"))
    # 내부 IP: 서버 IP → 서버IP-n, 사용자 PC IP → PC-nn (공인·문서용 대역은 그대로)
    internal = ips[ips["is_rfc1918"] == "true"]
    srv = sorted(internal[internal["ip_zone"] == "server"]["ip"], key=_ip_key)
    pcs = sorted(internal[internal["ip_zone"] != "server"]["ip"], key=_ip_key)
    for i, ip in enumerate(srv, 1):
        rules.append((re.compile(rf"(?<![\d.]){re.escape(ip)}(?![\d.])"), f"서버IP-{i}"))
    for i, ip in enumerate(pcs, 1):
        rules.append((re.compile(rf"(?<![\d.]){re.escape(ip)}(?![\d.])"), f"PC-{i:02d}"))
    # 남은 사설 IP는 일괄 가림
    rules.append((re.compile(r"(?<![\d.])(?:10\.\d+|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d+\.\d+(?![\d.])"), "내부IP"))
    # 이메일 도메인·내부 도메인, tenancy 값
    rules.append((re.compile(r"@[\w-]+(?:\.[\w-]+)+"), "@도메인"))
    rules.append((re.compile(r"\b[\w-]+\.internal\.lab\b|\blab\.internal\b"), "내부도메인"))
    rules.append((re.compile(r'("tenancy"\s*:\s*")[^"]*(")'), r"\1[가림]\2"))
    return rules


def _ip_key(ip: str):
    return tuple(int(x) for x in ip.split("."))


def _mask_rules() -> list:
    for n in ("ip_inventory", "host_inventory"):
        _check_exists(n)
    return _mask_rules_cached(_signature(FILES["ip_inventory"]), _signature(FILES["host_inventory"]))


def _apply_mask(text: str, rules: list) -> str:
    for pat, rep in rules:
        text = pat.sub(rep, text)
    return text


def mask_text(text: str) -> str:
    """파일 밖에서 만든 글자(설명 문구 등)에 호스트·IP가 들어갈 때 쓴다."""
    return _apply_mask(text, _mask_rules()) if masked() and text else text


# ---------------------------------------------------------------- 형 변환·시각
def num(df: pd.DataFrame, *cols: str) -> pd.DataFrame:
    df = df.copy()
    for c in cols:
        df[c] = pd.to_numeric(df[c], errors="coerce")
    return df


def to_kst(utc: pd.Series) -> pd.Series:
    return pd.to_datetime(utc, format="ISO8601") + KST


def kst_text(utc: str, fmt: str = "%m-%d %H:%M") -> str:
    return (datetime.fromisoformat(utc) + KST).strftime(fmt) if utc else ""


# ---------------------------------------------------------------- 자주 쓰는 결합 테이블
def sessions_full() -> pd.DataFrame:
    """세션 146개 = 세션 + 점수 + 판정. 세션 ID가 유일한지 확인한다."""
    s = load("sessions")
    sr = num(load("session_risk"), "risk_score", "signal_types", "tactic_count", "rank")
    tri = load("triage")[["work_session_id", "activity_verdict", "attribution", "reason"]]
    for name, d in (("sessions", s), ("session_risk", sr), ("triage", tri)):
        if d["work_session_id"].duplicated().any():
            st.error(f"`{name}`에 같은 세션 ID가 여러 번 있습니다. 결과 파일을 확인하세요.")
            st.stop()
    out = s.merge(sr[["work_session_id", "risk_score", "signal_types", "tactic_count", "tactics", "score_breakdown",
                      "alert", "alert_reason", "rank"]], on="work_session_id", how="left", validate="1:1")
    out = out.merge(tri, on="work_session_id", how="left", validate="1:1").fillna(
        {"activity_verdict": "", "attribution": "", "reason": ""})
    out["start_kst"] = to_kst(out["start_utc"])
    out["end_kst"] = to_kst(out["end_utc"])
    out["is_alert"] = out["alert"] == "true"
    out["state"] = out.apply(session_state, axis=1)
    return out.sort_values("rank")


def session_state(r) -> str:
    """세션 상태를 세 가지로 나눈다. 점수 0 세션을 '정상'으로 단정하지 않는다."""
    if r["is_alert"]:
        return "경보"
    if r["risk_score"] > 0:
        return "점수 있음 (비경보)"
    return "현재 규칙의 점수 없음"


def data_period() -> tuple[datetime, datetime]:
    t = to_kst(load("timeline_sessions", ["event_time_utc"])["event_time_utc"])
    return t.min().to_pydatetime(), t.max().to_pydatetime()


def date_range() -> tuple[date, date]:
    """사이드바에서 고른 기간 (KST 날짜). 기본은 데이터 전체 기간. 오늘 날짜로 초기화하지 않는다."""
    lo, hi = data_period()
    r = st.session_state.get("date_range")
    if not r or len(r) != 2:
        return lo.date(), hi.date()
    return r[0], r[1]


def in_range(kst: pd.Series) -> pd.Series:
    a, b = date_range()
    d = kst.dt.date
    return (d >= a) & (d <= b)


def is_full_range() -> bool:
    lo, hi = data_period()
    return date_range() == (lo.date(), hi.date())


def reference_labels() -> dict:
    if not st.session_state.get("show_ref", False):
        return {}
    s = load("sessions")
    start = pd.to_datetime(s["start_utc"], format="ISO8601").dt.floor("s")
    end = pd.to_datetime(s["end_utc"], format="ISO8601")
    out = {}
    for label, person, t in REFERENCE:
        t = pd.Timestamp(t)
        hit = s[(s["person_candidate"] == person) & (start <= t) & (end >= t)]
        if len(hit) == 1:
            out[hit.iloc[0]["work_session_id"]] = f"시나리오 {label}"
    return out


def raw_event(log_source: str, source_row: str) -> pd.DataFrame:
    """원문은 log_source + source_row 복합 키로만 찾는다. 키가 유일하지 않으면 보여주지 않는다."""
    t = load("timeline_sessions", TIMELINE_RAW)
    hit = t[(t["log_source"] == log_source) & (t["source_row"] == source_row)]
    return hit if len(hit) == 1 else hit.iloc[0:0]
