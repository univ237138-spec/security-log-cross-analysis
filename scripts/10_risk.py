"""탐지 신호에 위험점수를 매기고 세션·사람·서버에 쌓아 경보를 정한다 (위험 기반 경보, RBA).

입력: data/09_detections/detections.csv, data/07_sessions/sessions.csv,
      data/05_enriched/host_inventory.csv, data/08_baseline/external_profile.csv
출력: data/10_risk/
  risk_events.csv      신호별 기본 점수·계수·신호 점수·전술
  session_risk.csv     세션별 점수·점수 구성·전술·경보 여부·순위
  entity_risk.csv      사람·서버별 누적 점수
  config_findings.csv  설정 위험 (R16)
  sensitivity.csv      가중치 조합별 상위 10개·경보 세션
계획: docs/06_탐지_위험점수.md (가중치와 경보 기준은 실행 전에 고정)
설명: docs/06_탐지_위험점수.md
"""
import itertools
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta

from common import BASELINE, DETECTIONS, ENRICHED, RISK, SESSIONS, read_rows, write_rows

# ---------------------------------------------------------------- 고정 가중치·기준 (계획 6-1, 6-4)
BASE = {"rule": {"high": 60, "medium": 30, "low": 10}, "behavior": 20}
CRIT = {"high": 1.5, "medium": 1.0}
CONF = {"direct": 1.0, "linked": 0.8}
ALERT_SCORE, ALERT_TACTICS = 100, 3
CONFIG_RULES = {"R16"}

TACTIC = {  # 계획 6-3
    "T1078": "Initial Access", "T1133": "Initial Access", "T1190": "Initial Access", "T1078.004": "Initial Access",
    "T1059": "Execution", "T1059.004": "Execution",
    "T1505.003": "Persistence", "T1098": "Persistence",
    "T1562.001": "Defense Evasion", "T1564.001": "Defense Evasion",
    "T1110": "Credential Access", "T1046": "Discovery", "T1021.004": "Lateral Movement",
    "T1560.001": "Collection", "T1071": "Command and Control", "T1105": "Command and Control",
    "T1571": "Command and Control", "T1567": "Exfiltration", "T1048": "Exfiltration",
    "T1531": "Impact", "T1595": "Reconnaissance",
}

dets = read_rows(DETECTIONS / "detections.csv")
sessions = read_rows(SESSIONS / "sessions.csv")
crit = {h["host"]: h["criticality"] for h in read_rows(ENRICHED / "host_inventory.csv")}
external = read_rows(BASELINE / "external_profile.csv")

for d in dets:
    techs = [t for t in d["attck"].split("|") if t]
    assert all(t in TACTIC for t in techs), techs
    d["_tactics"] = sorted({TACTIC[t] for t in techs}) if d["method"] == "rule" else []

# 신호 → 세션 대상: 직접 소속이거나 5-c 추정 연결 (연결이 여럿이면 각 세션에 하나씩)
targets = []  # (detection, session_id, 연결 종류)
for d in dets:
    if d["detection_type"] in CONFIG_RULES:
        continue
    if d["work_session_id"]:
        targets.append((d, d["work_session_id"], "direct"))
    for link in filter(None, d["linked_sessions"].split("|")):
        targets.append((d, re.match(r"(S\d+)", link).group(1), "linked"))


def signal_score(d, link, base=BASE, conf=CONF):
    b = base["behavior"] if d["method"] == "behavior" else base["rule"][d["severity"]]
    return b, CRIT.get(crit.get(d["host"], ""), 1.0), conf[link]


def score_sessions(base=BASE, conf=CONF):
    """세션별 (점수, 구성, 전술). 같은 탐지 종류는 최고 점수 하나만 센다."""
    best = {}  # (세션, 탐지 종류) → (점수, 근거 문자열, 전술)
    for d, sid, link in targets:
        b, c, f = signal_score(d, link, base, conf)
        s = round(b * c * f, 1)
        key = (sid, d["detection_type"])
        if key not in best or s > best[key][0]:
            best[key] = (s, f"{d['detection_type']} {b}×{c}×{f}={s:g}", d["_tactics"])
    out = defaultdict(lambda: {"score": 0.0, "parts": [], "types": set(), "tactics": set()})
    for (sid, typ), (s, part, tac) in best.items():
        o = out[sid]
        o["score"] += s
        o["parts"].append((s, part))
        o["types"].add(typ)
        o["tactics"].update(tac)
    return out


def alerts_of(scored):
    return {sid for sid, o in scored.items() if o["score"] >= ALERT_SCORE or len(o["tactics"]) >= ALERT_TACTICS}


def top10(scored):
    return [sid for sid, _ in sorted(scored.items(), key=lambda kv: (-kv[1]["score"], kv[0]))[:10]]


# ---------------------------------------------------------------- risk_events
risk_events = []
for d, sid, link in targets:
    b, c, f = signal_score(d, link)
    risk_events.append({"detection_id": d["detection_id"], "detection_type": d["detection_type"], "name": d["name"],
                        "method": d["method"], "severity": d["severity"], "event_time_utc": d["event_time_utc"],
                        "host": d["host"], "work_session_id": sid, "link": link, "base_score": b,
                        "criticality_factor": c, "confidence_factor": f, "signal_score": round(b * c * f, 1),
                        "tactics": "|".join(d["_tactics"])})

# ---------------------------------------------------------------- session_risk
scored = score_sessions()
alerts = alerts_of(scored)
sess_rows = []
for s in sessions:
    o = scored.get(s["work_session_id"], {"score": 0.0, "parts": [], "types": set(), "tactics": set()})
    reasons = []
    if o["score"] >= ALERT_SCORE:
        reasons.append(f"점수 {o['score']:g} ≥ {ALERT_SCORE}")
    if len(o["tactics"]) >= ALERT_TACTICS:
        reasons.append(f"전술 {len(o['tactics'])}개 ≥ {ALERT_TACTICS}")
    sess_rows.append({
        "work_session_id": s["work_session_id"], "person_candidate": s["person_candidate"],
        "session_type": s["session_type"], "client_ip": s["client_ip"], "start_utc": s["start_utc"],
        "risk_score": round(o["score"], 1), "signal_types": len(o["types"]),
        "tactic_count": len(o["tactics"]), "tactics": "|".join(sorted(o["tactics"])),
        "score_breakdown": " + ".join(p for _, p in sorted(o["parts"], reverse=True)),
        "alert": str(bool(reasons)).lower(), "alert_reason": " / ".join(reasons),
    })
sess_rows.sort(key=lambda r: (-r["risk_score"], r["work_session_id"]))
for i, r in enumerate(sess_rows, start=1):
    r["rank"] = i

# ---------------------------------------------------------------- entity_risk (사람: 24시간·7일, 서버)
entity = []
by_person = defaultdict(list)
for r in sess_rows:
    by_person[r["person_candidate"]].append((datetime.fromisoformat(r["start_utc"]), r["risk_score"], r["work_session_id"]))
for p, xs in sorted(by_person.items()):
    xs.sort()
    best = {}
    for win, label in [(timedelta(hours=24), "24h"), (timedelta(days=7), "7d")]:
        sums = [(sum(sc for t2, sc, _ in xs if t - win < t2 <= t), sid) for t, _, sid in xs]
        top = max(v for v, _ in sums)
        best[label] = next((v, sid) for v, sid in sums if v == top)  # 처음 최대에 도달한 세션
    entity.append({"entity_type": "person", "entity": p, "total_score": round(sum(sc for _, sc, _ in xs), 1),
                   "max_24h": round(best["24h"][0], 1), "max_24h_at": best["24h"][1],
                   "max_7d": round(best["7d"][0], 1), "max_7d_at": best["7d"][1],
                   "alert_sessions": "|".join(r["work_session_id"] for r in sess_rows
                                              if r["person_candidate"] == p and r["alert"] == "true"),
                   "signal_types": ""})
host_best = {}
for d in dets:
    if d["host"] and d["detection_type"] not in CONFIG_RULES:
        b, c, _ = signal_score(d, "direct")
        key = (d["host"], d["detection_type"])
        host_best[key] = max(host_best.get(key, 0), b * c)
for h in sorted({h for h, _ in host_best}):
    types = {t: s for (hh, t), s in host_best.items() if hh == h}
    entity.append({"entity_type": "host", "entity": h, "total_score": round(sum(types.values()), 1),
                   "max_24h": "", "max_24h_at": "", "max_7d": "", "max_7d_at": "", "alert_sessions": "",
                   "signal_types": "|".join(sorted(types))})

# ---------------------------------------------------------------- config_findings, 외부 IP
config = []
for acc in sorted({d["account"] for d in dets if d["detection_type"] in CONFIG_RULES}):
    ds = [d for d in dets if d["detection_type"] in CONFIG_RULES and d["account"] == acc]
    config.append({"finding": "MFA 없는 최상위 계정 로그인", "rule": "R16", "account": acc, "count": len(ds),
                   "sessions": len({d["work_session_id"] for d in ds}),
                   "first_seen": min(d["event_time_utc"] for d in ds), "last_seen": max(d["event_time_utc"] for d in ds),
                   "note": "행동 이상이 아니라 계정 설정 위험. 세션 점수에서 제외"})
for e in external:
    config.append({"finding": "외부 IP 로그인 시도 (성공 없음)", "rule": "", "account": e["accounts"],
                   "count": e["attempts"], "sessions": 0, "first_seen": e["first_seen"], "last_seen": e["last_seen"],
                   "note": f"{e['client_ip']}: 노출 위험 참고. 로그인 성공이 없어 점수 없음"})

# ---------------------------------------------------------------- 민감도 확인 (계획 6-6)
sens = []
base_alerts, base_top = alerts, top10(scored)
for rule_w, beh, lc in itertools.product([(40, 20, 5), (60, 30, 10), (80, 40, 20)], [10, 20, 30], [0.5, 0.8, 1.0]):
    b = {"rule": dict(zip(("high", "medium", "low"), rule_w)), "behavior": beh}
    sc = score_sessions(b, {"direct": 1.0, "linked": lc})
    al, tp = alerts_of(sc), top10(sc)
    sens.append({"rule_high_med_low": "/".join(map(str, rule_w)), "behavior": beh, "linked_conf": lc,
                 "alert_sessions": "|".join(sorted(al)), "alert_count": len(al),
                 "same_alerts_as_base": str(al == base_alerts).lower(),
                 "top10": "|".join(tp), "top10_overlap_with_base": len(set(tp) & set(base_top)),
                 "top4": "|".join(sorted(tp[:4]))})

# ---------------------------------------------------------------- 쓰기
RISK.mkdir(parents=True, exist_ok=True)
for name, rows in [("risk_events.csv", risk_events), ("session_risk.csv", sess_rows), ("entity_risk.csv", entity),
                   ("config_findings.csv", config), ("sensitivity.csv", sens)]:
    write_rows(RISK / name, list(rows[0].keys()), rows)
    print(f"{name}: {len(rows)}")

# ---------------------------------------------------------------- 검증
for r in sess_rows:
    parts = [float(p.split("=")[-1]) for p in r["score_breakdown"].split(" + ") if p]
    assert abs(sum(parts) - r["risk_score"]) < 0.05, r["work_session_id"]
    typs = [p.split()[0] for p in r["score_breakdown"].split(" + ") if p]
    assert len(typs) == len(set(typs)), r["work_session_id"]
covered = {d["detection_id"] for d, _, _ in targets} | {d["detection_id"] for d in dets if d["detection_type"] in CONFIG_RULES}
assert covered == {d["detection_id"] for d in dets}, "반영되지 않은 신호"
print("검증 통과\n")

# ---------------------------------------------------------------- 요약
print(f"경보 세션 {len(alerts)}개, 점수 > 0 세션 {sum(r['risk_score'] > 0 for r in sess_rows)}개 / {len(sess_rows)}")
print("\n상위 12개 세션:")
for r in sess_rows[:12]:
    print(f"  {r['rank']:>3}. {r['work_session_id']} {r['person_candidate']:<10} {r['risk_score']:>6g}점 "
          f"전술 {r['tactic_count']} 신호 {r['signal_types']} {'[경보: ' + r['alert_reason'] + ']' if r['alert'] == 'true' else ''}")
    print(f"       {r['score_breakdown']}")
print("\n사람·서버 누적:")
for e in entity:
    extra = f"24h 최대 {e['max_24h']} ({e['max_24h_at']}), 7일 최대 {e['max_7d']}" if e["entity_type"] == "person" \
        else f"신호 {e['signal_types']}"
    print(f"  {e['entity_type']:<6} {e['entity']:<11} 합계 {e['total_score']:>6} | {extra}")
print("\n설정 위험:")
for c in config:
    print(f"  {c['finding']} | {c['account'][:40]} | {c['count']}회 | {c['note'][:40]}")
print(f"\n민감도 확인 ({len(sens)}개 조합):")
print(f"  경보 세션이 기본과 같은 조합: {sum(s['same_alerts_as_base'] == 'true' for s in sens)} / {len(sens)}")
print(f"  경보 세션 수 분포: {dict(Counter(s['alert_count'] for s in sens))}")
print(f"  상위 4개 세션 조합 분포: {dict(Counter(s['top4'] for s in sens))}")
print(f"  상위 10개 중 기본과 겹치는 수: {dict(Counter(s['top10_overlap_with_base'] for s in sens))}")
diff = [s for s in sens if s["same_alerts_as_base"] == "false"]
for s in diff:
    print(f"  다른 조합: 룰 {s['rule_high_med_low']} 행위 {s['behavior']} 연결 {s['linked_conf']} → {s['alert_sessions']}")
