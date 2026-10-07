"""① 사용자 업무 세션 바구니의 이벤트를 세션 단위로 묶고, 세션 테이블을 만든다.

입력: data/06_classified/timeline_classified.csv
출력: data/07_sessions/
  timeline_sessions.csv  타임라인 + work_session_id, work_session_link (② ③ 바구니는 빈칸)
  sessions.csv           세션 1개 = 1행 요약
계획: docs/05_세션화_기준선.md
설명: docs/05_세션화_기준선.md

규칙 (근거는 실행 시 '규칙 근거' 출력과 설명 문서 2절)
1. 서버 세션: sshd 접속(connection_id)마다 하나. 같은 리눅스 계정 + 같은 접속 IP의 접속이 시간상 겹치면 합친다
2. 웹 이벤트(nginx, 감사로그): 접속 IP가 같고 시각이 서버 세션 안이면 그 세션에 붙인다.
   ssh 종료 뒤에도 같은 IP의 웹 이벤트가 무활동 30분 안에 이어지면 그 세션에 붙이고 세션 끝을 늘린다
   (세션 끝 = 서버·웹 경로가 모두 멈춘 때)
3. Sysmon 사람 계정 이벤트: 리눅스 계정이 같고 시각이 서버 세션 안이면 붙인다.
   process_terminate는 같은 ProcessGuid의 다른 이벤트와 같은 세션으로 둔다
4. sshd 실패 시도(① 바구니): 같은 IP·계정의 다음 서버 세션이 5분 안에 시작하면 그 세션에 붙인다
5. 남은 웹 이벤트: 접속 IP별로 무활동 30분 이상이면 끊어 웹 전용 세션을 만든다

세션 테이블에는 사실만 적는다. 정상·이상 판단은 4단계(기준선)에서 한다.
"""
import statistics
from collections import Counter, defaultdict
from datetime import datetime, timedelta

from common import CLASSIFIED, SESSIONS, read_rows, write_rows

MERGE_GAP = timedelta(0)              # 규칙 1: 겹칠 때만 합친다
FAIL_LOOKAHEAD = timedelta(minutes=5)  # 규칙 4
WEB_IDLE = timedelta(minutes=30)       # 규칙 2(ssh 종료 뒤 웹), 규칙 5
KST = timedelta(hours=9)
WEB_LOGIN = {"IAM_LOGIN_SUCCESS", "ROOT_LOGIN_NO_MFA", "IAM_LOGIN_NEW_DEVICE"}

rows = read_rows(CLASSIFIED / "timeline_classified.csv")
ORIG_COLS = list(rows[0].keys())
original = [dict(r) for r in rows]
for r in rows:
    r["_t"] = datetime.fromisoformat(r["event_time_utc"])
    r["work_session_id"] = r["work_session_link"] = ""

sess_rows = [r for r in rows if r["bucket"] == "session"]
is_web = lambda r: r["log_source"] in ("nginx", "teiren_audit")

# ---------------------------------------------------------------- 1. 서버 세션
conns = defaultdict(list)
for r in sess_rows:
    if r["connection_id"]:
        conns[r["connection_id"]].append(r)
conn_info = [{"cids": [cid], "account": rs[0]["account"], "ip": rs[0]["client_ip"],
              "start": min(x["_t"] for x in rs), "end": max(x["_t"] for x in rs)}
             for cid, rs in conns.items()]

server = []
merged_pairs = []
for key in sorted({(c["account"], c["ip"]) for c in conn_info}):
    group = sorted((c for c in conn_info if (c["account"], c["ip"]) == key), key=lambda c: c["start"])
    cur = None
    for c in group:
        if cur and c["start"] - cur["end"] <= MERGE_GAP:
            merged_pairs.append((cur["cids"][-1], c["cids"][0], cur["end"] - c["start"]))
            cur["cids"] += c["cids"]
            cur["end"] = max(cur["end"], c["end"])
        else:
            cur = dict(c, cids=list(c["cids"]))
            server.append(cur)
for s in server:
    s["ssh_end"] = s["end"]  # 규칙 3은 ssh 시간만 본다. end는 규칙 2에서 웹 활동으로 늘어날 수 있다

cid_to_server = {cid: s for s in server for cid in s["cids"]}
for cid, rs in conns.items():
    for r in rs:
        r["_sess"], r["work_session_link"] = cid_to_server[cid], "ssh 접속"


def find_server(pred, t):
    hits = [s for s in server if pred(s) and s["start"] <= t <= s["ssh_end"]]
    assert len(hits) <= 1, (t, [h["cids"] for h in hits])
    return hits[0] if hits else None


# ---------------------------------------------------------------- 2. 웹 이벤트 → 서버 세션
for r in sess_rows:
    if is_web(r):
        s = find_server(lambda s: s["ip"] == r["client_ip"], r["_t"])
        if s:
            r["_sess"], r["work_session_link"] = s, "접속 IP + 시간"

# ssh 종료 뒤 이어지는 웹 이벤트: 같은 IP의 직전 서버 세션 마지막 활동에서 무활동 30분 안이면 붙인다
trail_lags = []
for r in sorted((r for r in sess_rows if is_web(r) and "_sess" not in r), key=lambda r: r["_t"]):
    prev = [s for s in server if s["ip"] == r["client_ip"] and s["ssh_end"] < r["_t"]]
    if not prev:
        continue
    s = max(prev, key=lambda s: s["ssh_end"])
    if r["_t"] - s["end"] < WEB_IDLE:
        trail_lags.append((r["_t"] - s["ssh_end"]).total_seconds())
        s["end"] = max(s["end"], r["_t"])
        r["_sess"], r["work_session_link"] = s, "접속 IP + ssh 종료 뒤 무활동 30분 이내"

# ---------------------------------------------------------------- 3. Sysmon 사람 계정 → 서버 세션
sysmon_h = [r for r in sess_rows if r["log_source"] == "sysmon"]
guid_sess = {}
for r in sysmon_h:
    if r["event_action"] != "process_terminate":
        s = find_server(lambda s: s["account"] == r["account"], r["_t"])
        assert s, ("서버 세션 밖의 사람 계정 Sysmon 이벤트", r["event_time_utc"], r["account"])
        r["_sess"], r["work_session_link"] = s, "리눅스 계정 + 시간"
        guid_sess.setdefault(r["ProcessGuid"], s)
for r in sysmon_h:
    if r["event_action"] == "process_terminate":
        s = guid_sess.get(r["ProcessGuid"]) or find_server(lambda s: s["account"] == r["account"], r["_t"])
        assert s, ("세션을 못 찾은 process_terminate", r["event_time_utc"])
        r["_sess"] = s
        r["work_session_link"] = "ProcessGuid" if r["ProcessGuid"] in guid_sess else "리눅스 계정 + 시간"

# ---------------------------------------------------------------- 4. sshd 실패 시도 → 다음 서버 세션
fail_lags = []
for r in sess_rows:
    if r["log_source"] == "sshd" and not r["connection_id"]:
        nxt = [s for s in server if s["account"] == r["account"] and s["ip"] == r["client_ip"]
               and timedelta(0) <= s["start"] - r["_t"] <= FAIL_LOOKAHEAD]
        assert len(nxt) == 1, (r["event_time_utc"], r["account"])
        r["_sess"], r["work_session_link"] = nxt[0], "로그인 직전 실패 시도"
        fail_lags.append((nxt[0]["start"] - r["_t"]).total_seconds())

# ---------------------------------------------------------------- 5. 남은 웹 이벤트 → 웹 전용 세션
web_only = []
left = sorted((r for r in sess_rows if is_web(r) and "_sess" not in r), key=lambda r: (r["client_ip"], r["_t"]))
for r in left:
    cur = web_only[-1] if web_only else None
    if cur and cur["ip"] == r["client_ip"] and r["_t"] - cur["end"] < WEB_IDLE:
        cur["end"] = r["_t"]
    else:
        cur = {"cids": [], "account": "", "ip": r["client_ip"], "start": r["_t"], "end": r["_t"]}
        web_only.append(cur)
    r["_sess"], r["work_session_link"] = cur, "웹 전용 (접속 IP + 무활동 30분)"

# ---------------------------------------------------------------- 세션 번호 (시작 시각 순)
all_sess = sorted(server + web_only, key=lambda s: (s["start"], s["ip"]))
for i, s in enumerate(all_sess, start=1):
    s["id"] = f"S{i:03d}"
    s["rows"] = []
for r in sess_rows:
    r["work_session_id"] = r["_sess"]["id"]
    r["_sess"]["rows"].append(r)

# ---------------------------------------------------------------- 세션 테이블
WEEKDAY = ["월", "화", "수", "목", "금", "토", "일"]


def uniq(values):
    return "|".join(sorted({v for v in values if v}))


table = []
for s in all_sess:
    rs = s["rows"]
    by = defaultdict(list)
    for r in rs:
        by[r["log_source"]].append(r)
    persons = {r["person_candidate"] for r in rs if r["person_candidate"]}
    assert len(persons) <= 1, (s["id"], persons)
    has_ssh, has_web = bool(s["cids"]), bool(by["nginx"] or by["teiren_audit"])
    sensitive = [r["event_action"] for r in rs if r["action_sensitivity"] == "high"]
    logins = [r["event_action"] for r in by["teiren_audit"] if r["event_action"] in WEB_LOGIN]
    procs = [r for r in by["sysmon"] if r["event_action"] == "process_create"]
    start_kst = s["start"] + KST
    table.append({
        "work_session_id": s["id"],
        "session_type": "server+web" if has_ssh and has_web else "server_only" if has_ssh else "web_only",
        "person_candidate": persons.pop() if persons else "",
        "linux_account": s["account"],
        "console_accounts": uniq(r["account"] for r in by["teiren_audit"]),
        "client_ip": s["ip"], "client_zone": rs[0]["client_zone"],
        "start_utc": s["start"].isoformat(sep=" "), "end_utc": s["end"].isoformat(sep=" "),
        "ssh_end_utc": s["ssh_end"].isoformat(sep=" ") if s["cids"] else "",
        "start_hour_kst": start_kst.hour, "weekday_kst": WEEKDAY[start_kst.weekday()],
        "duration_min": round((s["end"] - s["start"]).total_seconds() / 60, 1),
        "event_count": len(rs),
        "ssh_connections": len(s["cids"]),
        "auth_method": uniq(r["auth_method"] for r in by["sshd"] if r["event_action"] == "auth_success"),
        "failed_before_login": sum(r["work_session_link"] == "로그인 직전 실패 시도" for r in rs),
        "sysmon_count": len(by["sysmon"]),
        "hosts": "|".join(f"{h}:{n}" for h, n in Counter(r["host"] for r in procs).most_common()),
        "process_count": len(procs),
        "external_connections": sum(r["dst_zone"] == "external" for r in by["sysmon"]),
        "web_login_count": len(logins), "web_login_types": uniq(logins),
        "nginx_count": len(by["nginx"]), "audit_count": len(by["teiren_audit"]),
        "web_after_ssh_count": sum(r["work_session_link"].startswith("접속 IP + ssh 종료 뒤") for r in rs),
        "api_count": sum(r["is_api_request"] == "true" for r in by["nginx"]),
        "non_get_count": sum(r["http_method"] not in ("", "GET") for r in by["nginx"]),
        "sensitive_count": len(sensitive),
        "sensitive_actions": "|".join(f"{a}:{n}" for a, n in Counter(sensitive).most_common()),
    })
SESS_COLS = list(table[0].keys())

# ---------------------------------------------------------------- 쓰기
SESSIONS.mkdir(parents=True, exist_ok=True)
write_rows(SESSIONS / "timeline_sessions.csv", ORIG_COLS + ["work_session_id", "work_session_link"], rows)
write_rows(SESSIONS / "sessions.csv", SESS_COLS, table)
print(f"timeline_sessions.csv: {len(rows)} rows / sessions.csv: {len(table)} rows\n")

# ---------------------------------------------------------------- 검증
assert all(r["work_session_id"] for r in sess_rows), "① 바구니에 세션 없는 행"
assert not any(r["work_session_id"] for r in rows if r["bucket"] != "session"), "②③에 세션이 붙었다"
assert all(all(r[c] == o[c] for c in ORIG_COLS) for r, o in zip(rows, original)), "원래 컬럼이 바뀌었다"
assert sum(t["event_count"] for t in table) == len(sess_rows)
for key in {(s["account"], s["ip"]) for s in server}:  # 같은 계정·IP의 서버 세션은 겹치지 않는다
    g = sorted((s for s in server if (s["account"], s["ip"]) == key), key=lambda s: s["start"])
    assert all(a["end"] < b["start"] for a, b in zip(g, g[1:])), key
print("검증 통과\n")

# ---------------------------------------------------------------- 결과 요약
print("세션 종류:", dict(Counter(t["session_type"] for t in table)))
print("work_session_link:", dict(Counter(r["work_session_link"] for r in sess_rows).most_common()))
print("\n웹 전용 세션:")
for t in table:
    if t["session_type"] == "web_only":
        print(f"  {t['work_session_id']} {t['client_ip']} {t['person_candidate']} {t['start_utc'][:19]} "
              f"{t['duration_min']}분 nginx {t['nginx_count']} audit {t['audit_count']} 로그인 {t['web_login_count']}")
print("\n서버 세션 중 웹 없음:")
for t in table:
    if t["session_type"] == "server_only":
        print(f"  {t['work_session_id']} {t['linux_account']} {t['client_ip']} {t['start_utc'][:19]} {t['duration_min']}분")

# 같은 사람의 세션이 서로 다른 IP·종류로 겹치는 경우 (합치지 않고 사실로만 보고)
overlaps = []
for p in {t["person_candidate"] for t in table if t["person_candidate"]}:
    g = sorted((t for t in table if t["person_candidate"] == p), key=lambda t: t["start_utc"])
    overlaps += [(a["work_session_id"], b["work_session_id"], p) for a, b in zip(g, g[1:]) if b["start_utc"] <= a["end_utc"]]
print("\n같은 사람의 세션 시간 겹침 (다른 IP·종류):", overlaps or "없음")

# ---------------------------------------------------------------- 규칙 근거 (데이터 분포)
print("\n=== 규칙 근거 ===")
durs = [(c["end"] - c["start"]).total_seconds() / 60 for c in conn_info]
print(f"[1] ssh 접속 길이(분): 최소 {min(durs):.1f} / 중앙값 {statistics.median(durs):.1f} / 최대 {max(durs):.1f}")
print(f"[1] 같은 계정·IP 접속 겹침 {len(merged_pairs)}건:")
for a, b, ov in merged_pairs:
    print(f"      {a} ↔ {b} 겹친 시간 {ov.total_seconds() / 60:.1f}분")
gaps = sorted((b["start"] - a["end"]).total_seconds() / 60
              for key in {(c["account"], c["ip"]) for c in conn_info}
              for a, b in zip(*[sorted((c for c in conn_info if (c["account"], c["ip"]) == key),
                                        key=lambda c: c["start"])[i:] for i in (0, 1)])
              if b["start"] > a["end"])
print(f"[1] 겹치지 않는 연속 접속 사이 간격(분): 최소 {gaps[0]:.1f} / 중앙값 {statistics.median(gaps):.0f}")

web_all = [r for r in sess_rows if is_web(r)]
in_srv = [r for r in web_all if r["work_session_link"] == "접속 IP + 시간"]
print(f"[2] 웹 이벤트 중 같은 IP의 서버 세션 안: {len(in_srv)} / {len(web_all)} ({len(in_srv) / len(web_all):.1%})")
first_lag = []
for s in server:
    w = [r["_t"] for r in s["rows"] if is_web(r)]
    if w:
        first_lag.append((min(w) - s["start"]).total_seconds())
print(f"[2] 서버 세션 시작 → 첫 웹 이벤트(초): 중앙값 {statistics.median(first_lag):.1f} / 최대 {max(first_lag):.1f}")
print(f"[2] ssh 종료 뒤 무활동 30분 안에 이어진 같은 IP 웹 이벤트: {len(trail_lags)}건, "
      f"ssh 종료로부터 {min(trail_lags):.0f}~{max(trail_lags):.0f}초, "
      f"세션 {sum(t['web_after_ssh_count'] > 0 for t in table)}개")

sm = [r for r in sysmon_h if r["event_action"] != "process_terminate"]
print(f"[3] 사람 계정 Sysmon 이벤트(종료 제외) 중 같은 계정 서버 세션 안: {len(sm)} / {len(sm)} (밖이면 assert로 멈춤)")
print(f"[3] process_terminate {sum(r['event_action'] == 'process_terminate' for r in sysmon_h)}건 중 "
      f"ProcessGuid로 연결: {sum(r['work_session_link'] == 'ProcessGuid' for r in sysmon_h)}")
print(f"[4] 실패 시도 → 다음 로그인(초): {sorted(fail_lags)}")

intra = []
for s in server:
    w = sorted(r["_t"] for r in s["rows"] if r["work_session_link"] == "접속 IP + 시간")
    intra += [(b - a).total_seconds() for a, b in zip(w, w[1:])]
intra.sort()
q = lambda p: intra[int(p * (len(intra) - 1))]
print(f"[5] 서버 세션 안 웹 이벤트 간격(초): 중앙값 {q(.5):.0f} / 99% {q(.99):.0f} / 최대 {intra[-1]:.0f}")
