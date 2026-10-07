"""기준선(평소 모습)을 만들고, 세션·시스템 이벤트가 평소와 얼마나 다른지 비교값을 계산한다.
판정(이상 여부)은 하지 않는다. 판정은 5단계, 점수는 6단계에서 한다.

입력: data/07_sessions/sessions.csv, timeline_sessions.csv, data/05_enriched/account_inventory.csv
출력: data/08_baseline/
  session_baseline.csv     세션 146개 + 비교값 (① 사용자 업무 세션)
  background_patterns.csv  서버별 시스템 활동 패턴 목록 (② 시스템 배경 활동)
  background_baseline.csv  ② 이벤트마다 패턴 ID와 그 시점까지 본 횟수
  external_profile.csv     외부 시도 IP별 요약 (③ 세션 없는 외부 시도)
계획: docs/05_세션화_기준선.md
설명: docs/05_세션화_기준선.md

비교 방식: 확장 윈도우. 각 세션은 그 세션 시작 전에 끝난 세션만 기준선으로 쓴다 (미래 데이터 미사용).
기준선 수준: person(본인 과거 ≥ 5) → peer(같은 주 작업 서버 동료 과거 ≥ 5) → global(전체 과거 ≥ 5) → none
"""
import re
from collections import Counter, defaultdict
from datetime import datetime

from common import BASELINE, ENRICHED, SESSIONS, read_rows, write_rows

N_MIN = 5
WEEKEND = {"토", "일"}
VOLUME = ["duration_min", "process_count", "nginx_count", "api_count", "non_get_count"]

sessions = read_rows(SESSIONS / "sessions.csv")
timeline = read_rows(SESSIONS / "timeline_sessions.csv")
accounts = read_rows(ENRICHED / "account_inventory.csv")


def norm(text):
    """숫자 덩어리를 N으로 바꿔 같은 모양의 명령·경로를 하나로 본다. 예: /tmp/health-610274 → /tmp/health-N"""
    return re.sub(r"\d+", "N", text)


def split(value):
    """'a:3|b:1' 또는 'a|b' → {'a', 'b'}"""
    return {x.split(":")[0] for x in value.split("|") if x}


# ---------------------------------------------------------------- ① 세션 특성 준비
cmds = defaultdict(set)  # 세션별 실행 명령 (정규화)
for r in timeline:
    if r["work_session_id"] and r["event_action"] == "process_create":
        cmds[r["work_session_id"]].add(norm(r["CommandLine"]))

home = {a["person_candidate"]: a["home_host"] for a in accounts
        if a["account_system"] == "linux" and a["account_type"] == "human"}
peers = defaultdict(set)
for p, h in home.items():
    peers[h].add(p)

S = []
for s in sessions:
    S.append({
        "row": s, "id": s["work_session_id"], "person": s["person_candidate"],
        "start": datetime.fromisoformat(s["start_utc"]), "end": datetime.fromisoformat(s["end_utc"]),
        "hour": int(s["start_hour_kst"]), "weekend": s["weekday_kst"] in WEEKEND,
        "ip": s["client_ip"], "type": s["session_type"],
        "logins": split(s["web_login_types"]), "auth": split(s["auth_method"]),
        "failed": int(s["failed_before_login"]), "hosts": split(s["hosts"]),
        "cmds": cmds[s["work_session_id"]], "sensitive": split(s["sensitive_actions"]),
        "ext": int(s["external_connections"]),
        "vol": {c: float(s[c]) for c in VOLUME},
    })


def history(x):
    """x 시작 전에 끝난 세션으로 기준선 수준과 과거 세션 목록을 고른다."""
    past = [h for h in S if h["end"] < x["start"]]
    own = [h for h in past if h["person"] == x["person"]]
    if len(own) >= N_MIN:
        return "person", own, past
    group = peers.get(home.get(x["person"], ""), set())
    peer = [h for h in past if h["person"] in group]
    if len(peer) >= N_MIN:
        return "peer", peer, past
    if len(past) >= N_MIN:
        return "global", past, past
    return "none", [], past


def pct_le(values, x):
    """과거 값 중 x 이하인 비율(%). 100이면 과거 최대 이상."""
    return round(100 * sum(v <= x for v in values) / len(values), 1)


def joined(values):
    return "|".join(sorted(values))


out = []
leak_check = []
for x in S:
    level, H, past = history(x)
    o = dict(x["row"])
    o.update(baseline_level=level, baseline_n=len(H))
    if level != "none":
        hours = [h["hour"] for h in H]
        lo, hi = min(hours), max(hours)
        seen = lambda key: set().union(*(h[key] for h in H))
        global_cmds = set().union(*(h["cmds"] for h in past))
        o.update(
            hist_hour_min=lo, hist_hour_max=hi,
            hour_outside=str(not lo <= x["hour"] <= hi).lower(),
            hour_distance=max(lo - x["hour"], x["hour"] - hi, 0),
            hist_weekend_ratio=round(sum(h["weekend"] for h in H) / len(H), 2),
            ip_new=str(x["ip"] not in {h["ip"] for h in H}).lower(),
            hist_session_type_ratio=round(sum(h["type"] == x["type"] for h in H) / len(H), 2),
            login_types_new=joined(x["logins"] - seen("logins")),
            auth_methods_new=joined(x["auth"] - seen("auth")),
            hist_failed_sessions=sum(h["failed"] > 0 for h in H),
            hosts_new=joined(x["hosts"] - seen("hosts")),
            cmds_new_person=joined(x["cmds"] - seen("cmds")),
            cmds_new_count=len(x["cmds"] - seen("cmds")),
            cmds_new_global=joined(x["cmds"] - global_cmds),
            sensitive_new=joined(x["sensitive"] - seen("sensitive")),
            hist_ext_sessions=sum(h["ext"] > 0 for h in H),
            **{f"{c}_pct": pct_le([h["vol"][c] for h in H], x["vol"][c]) for c in VOLUME},
            # 과거 값이 대부분 같으면(예: 0) 백분위가 100에 몰린다. 과거 최대를 넘었는지 따로 남긴다
            **{f"{c}_above_max": str(x["vol"][c] > max(h["vol"][c] for h in H)).lower() for c in VOLUME},
        )
    out.append(o)
    leak_check.append(all(h["end"] < x["start"] for h in H))

CMP_COLS = ["baseline_level", "baseline_n", "hist_hour_min", "hist_hour_max", "hour_outside", "hour_distance",
            "hist_weekend_ratio", "ip_new", "hist_session_type_ratio", "login_types_new", "auth_methods_new",
            "hist_failed_sessions", "hosts_new", "cmds_new_person", "cmds_new_count", "cmds_new_global",
            "sensitive_new", "hist_ext_sessions"] + [f"{c}_{k}" for c in VOLUME for k in ("pct", "above_max")]
SB_COLS = list(sessions[0].keys()) + CMP_COLS

# ---------------------------------------------------------------- ② 시스템 배경 활동 패턴
bg = sorted((r for r in timeline if r["bucket"] == "background"),
            key=lambda r: (r["event_time_utc"], int(r["source_row"])))


def pattern_key(r):
    a = r["event_action"]
    if a == "process_create":
        return (r["host"], r["account"], r["Image"], "cmd", norm(r["CommandLine"]))
    if a == "network_connect":
        return (r["host"], r["account"], r["Image"], "dst", f"{r['dst_zone']}:{r['dpt']}")
    if a == "file_create":
        return (r["host"], r["account"], r["Image"], "file", norm(r["TargetFilename"]))
    return None  # process_terminate: 생성 이벤트의 패턴을 따른다


patterns = {}            # key → {id, kind, count, first, last}
seen_host = Counter()    # key → 그 시점까지 본 횟수
seen_any = Counter()     # 서버 뺀 key → 다른 서버 포함 본 횟수
host_first = {}          # 서버별 첫 ② 이벤트 시각 (기준선이 쌓인 시간 계산용)
guid_info = {}
bg_out = []
for r in bg:
    t = datetime.fromisoformat(r["event_time_utc"])
    host_first.setdefault(r["host"], t)
    key = pattern_key(r)
    if key is None:
        info = guid_info[r["ProcessGuid"]]
        pid, before, other = info["id"], info["before"], info["other"]
        kind = "process_terminate"
    else:
        if key not in patterns:
            patterns[key] = {"id": f"P{len(patterns) + 1:03d}", "count": 0, "first": r["event_time_utc"],
                             "hosts_before": seen_any[key[1:]]}
        p = patterns[key]
        pid, kind = p["id"], r["event_action"]
        before = seen_host[key]
        other = seen_any[key[1:]] - seen_host[key]
        seen_host[key] += 1
        seen_any[key[1:]] += 1
        p["count"] += 1
        p["last"] = r["event_time_utc"]
        if r["event_action"] == "process_create":
            guid_info[r["ProcessGuid"]] = {"id": pid, "before": before, "other": other}
    bg_out.append({
        "event_time_utc": r["event_time_utc"], "source_row": r["source_row"], "host": r["host"],
        "account": r["account"], "event_action": r["event_action"], "Image": r["Image"],
        "CommandLine": r["CommandLine"], "dst": r["dst"], "dpt": r["dpt"], "dst_zone": r["dst_zone"],
        "TargetFilename": r["TargetFilename"], "ProcessGuid": r["ProcessGuid"],
        "pattern_id": pid, "pattern_seen_before": before, "pattern_seen_other_hosts_before": other,
        "host_history_hours": round((t - host_first[r["host"]]).total_seconds() / 3600, 1),
    })

pat_rows = [{"pattern_id": p["id"], "host": k[0], "account": k[1], "Image": k[2], "kind": k[3],
             "detail": k[4], "count": p["count"], "first_seen": p["first"], "last_seen": p["last"]}
            for k, p in sorted(patterns.items(), key=lambda kv: kv[1]["id"])]

# ---------------------------------------------------------------- ③ 외부 시도 프로필
ext = defaultdict(list)
for r in timeline:
    if r["bucket"] == "external":
        ext[r["client_ip"]].append(r)
session_ips = {s["client_ip"] for s in sessions}
ext_rows = []
for ip, rs in sorted(ext.items(), key=lambda kv: -len(kv[1])):
    times = sorted(r["event_time_utc"] for r in rs)
    days = (datetime.fromisoformat(times[-1]) - datetime.fromisoformat(times[0])).total_seconds() / 86400
    accs = Counter(r["account"] for r in rs)
    ext_rows.append({
        "client_ip": ip, "first_seen": times[0], "last_seen": times[-1], "attempts": len(rs),
        "active_days": round(days, 1), "attempts_per_day": round(len(rs) / max(days, 1), 1),
        "distinct_accounts": len(accs), "accounts": "|".join(f"{a}:{n}" for a, n in accs.most_common()),
        "event_actions": joined({r["event_action"] for r in rs}),
        "ever_logged_in": str(ip in session_ips).lower(),
    })

# ---------------------------------------------------------------- 쓰기
BASELINE.mkdir(parents=True, exist_ok=True)
write_rows(BASELINE / "session_baseline.csv", SB_COLS, out)
write_rows(BASELINE / "background_patterns.csv", list(pat_rows[0].keys()), pat_rows)
write_rows(BASELINE / "background_baseline.csv", list(bg_out[0].keys()), bg_out)
write_rows(BASELINE / "external_profile.csv", list(ext_rows[0].keys()), ext_rows)
print(f"session_baseline.csv: {len(out)} / background_patterns.csv: {len(pat_rows)} / "
      f"background_baseline.csv: {len(bg_out)} / external_profile.csv: {len(ext_rows)}\n")

# ---------------------------------------------------------------- 검증
assert all(leak_check), "기준선에 미래 세션이 섞였다"
assert len(out) == 146 and len(bg_out) == 4079, (len(out), len(bg_out))
assert all(o["baseline_level"] for o in out)
assert all(b["pattern_id"] for b in bg_out)
print("검증 통과\n")

# ---------------------------------------------------------------- 결과 요약 (판정 아님)
print("기준선 수준:", dict(Counter(o["baseline_level"] for o in out)))
first_level = {}
for o in sorted(out, key=lambda o: o["start_utc"]):
    first_level.setdefault((o["person_candidate"], o["baseline_level"]), o["work_session_id"])
print("사람별 person 기준선 시작 세션:",
      {p: sid for (p, lv), sid in sorted(first_level.items()) if lv == "person"})

print("\n평소와 다른 비교값이 있는 세션 (person 기준선만):")
for o in out:
    if o["baseline_level"] != "person":
        continue
    diffs = []
    if o["hour_outside"] == "true":
        diffs.append(f"시작 {o['start_hour_kst']}시 (평소 {o['hist_hour_min']}~{o['hist_hour_max']}시)")
    if o["ip_new"] == "true":
        diffs.append(f"처음 보는 IP {o['client_ip']}")
    if float(o["hist_session_type_ratio"]) < 0.1:
        diffs.append(f"{o['session_type']} 과거 비율 {o['hist_session_type_ratio']}")
    for c, label in [("login_types_new", "새 로그인 종류"), ("auth_methods_new", "새 인증 방식"),
                     ("hosts_new", "새 서버"), ("cmds_new_person", "새 명령"), ("sensitive_new", "새 민감 행위")]:
        if o[c]:
            diffs.append(f"{label} {o[c]}")
    if int(o["failed_before_login"]) and not int(o["hist_failed_sessions"]):
        diffs.append("로그인 전 실패 첫 발생")
    if diffs:
        print(f"  {o['work_session_id']} {o['person_candidate']}: " + " / ".join(diffs))

warm = [b for b in bg_out if b["pattern_seen_before"] == 0 and b["event_action"] != "process_terminate"]
print(f"\n② 처음 보는 패턴 이벤트: {len(warm)}건 (서버별 기준선 쌓인 시간과 함께)")
for b in warm:
    detail = b["CommandLine"] or f"{b['dst_zone']}:{b['dpt']}" if b["event_action"] != "file_create" else b["TargetFilename"]
    print(f"  {b['event_time_utc'][:19]} {b['host']:<10} {b['account']:<8} {b['event_action']:<15} "
          f"{b['pattern_id']} 다른서버 {b['pattern_seen_other_hosts_before']:>3} 기준선 {b['host_history_hours']:>6}h | {detail}")

print("\n③ 외부 시도 IP:")
for e in ext_rows:
    print(f"  {e['client_ip']}: {e['attempts']}회, {e['active_days']}일, 계정 {e['distinct_accounts']}종, "
          f"로그인 성공 {e['ever_logged_in']}")
