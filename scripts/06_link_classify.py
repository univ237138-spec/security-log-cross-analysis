"""통합 타임라인의 모든 이벤트에 엔티티(누가·어디서·어느 서버·무슨 행위)와 바구니를 붙인다.

입력: data/04_integrated/timeline.csv, data/05_enriched/*.csv
출력: data/06_classified/timeline_classified.csv (원래 43개 컬럼 + 새 컬럼 18개)
계획: docs/04_통합_보강_연결.md
설명: docs/04_통합_보강_연결.md

원칙
- 원래 컬럼 값은 바꾸지 않는다. 채운 값은 새 컬럼(client_ip, account)에 넣고 방법을 fill_basis에 적는다
- 이름으로 조인하지 않는다. 같은 로그 안의 키(dpid, src+spt, session_id, ProcessGuid)와 보강 테이블만 쓴다
- 바구니는 계정 종류·로그인 성공 여부 같은 일반 규칙으로만 나눈다. 시스템 계정의 비정상 활동은 4~5단계에서 다룬다

바구니
- session    ① 사용자 업무 세션
- background ② 시스템 배경 활동
- external   ③ 세션 없는 외부 시도
"""
from collections import Counter, defaultdict
from datetime import datetime, timedelta

from common import CLASSIFIED, ENRICHED, INTEGRATED, read_rows, write_rows

rows = read_rows(INTEGRATED / "timeline.csv")
ORIG_COLS = list(rows[0].keys())
original = [dict(r) for r in rows]  # 검증용 사본

ips = {r["ip"]: r for r in read_rows(ENRICHED / "ip_inventory.csv")}
hosts = {r["host"]: r for r in read_rows(ENRICHED / "host_inventory.csv")}
accounts = {r["account"]: r for r in read_rows(ENRICHED / "account_inventory.csv")}
actions = {(r["log_source"], r["event_action"]): r for r in read_rows(ENRICHED / "action_catalog.csv")}


def ts(r):
    return datetime.fromisoformat(r["event_time_utc"])


# ---------------------------------------------------------------- 2-1. sshd 접속 묶기
sshd = [r for r in rows if r["log_source"] == "sshd"]
success = [r for r in sshd if r["event_action"] == "auth_success"]

conn = {}  # connection_id → {"src", "duser"}
by_dpid, by_srcport = {}, {}
for r in success:
    cid = f"{r['dvchost']}|{r['src']}|{r['spt']}"
    assert cid not in conn, cid
    conn[cid] = {"src": r["src"], "duser": r["duser"], "time": ts(r)}
    assert r["dpid"] not in by_dpid, r["dpid"]
    by_dpid[r["dpid"]] = cid
    by_srcport[(r["src"], r["spt"])] = cid

# session_new: 공통 키가 없어 같은 계정의 auth_success 직후 1초 이내로 묶는다 (추정)
by_session = {}
for r in sshd:
    if r["event_action"] != "session_new":
        continue
    cands = [cid for cid, c in conn.items()
             if c["duser"] == r["duser"] and timedelta(0) <= ts(r) - c["time"] <= timedelta(seconds=1)]
    assert len(cands) == 1, (r["event_time_utc"], r["duser"], cands)
    by_session[r["session_id"]] = cands[0]


def sshd_connection(r):
    """(connection_id, fill_basis). 접속에 속하지 않는 줄(실패 시도)은 ('', '원본')."""
    a = r["event_action"]
    if a == "auth_success":
        return f"{r['dvchost']}|{r['src']}|{r['spt']}", "원본"
    if a in ("session_opened", "session_closed"):
        return by_dpid[r["dpid"]], "관측(dpid)"
    if a in ("disconnect_received", "disconnected_user"):
        return by_srcport[(r["src"], r["spt"])], "관측(src+spt)"
    if a == "session_new":
        return by_session[r["session_id"]], "추정(시간근접)"
    if a in ("session_logged_out", "session_removed"):
        return by_session[r["session_id"]], "추정(session_id→session_new 시간근접)"
    return "", "원본"


# Sysmon process_terminate의 계정: 같은 ProcessGuid의 다른 이벤트에서 가져온다
guid_user = {}
for r in rows:
    if r["log_source"] == "sysmon" and r["suser"]:
        guid_user.setdefault(r["ProcessGuid"], r["suser"])

# 실패 시도 뒤 로그인 성공이 있었는가: (접속 IP, 계정)
succeeded = {(c["src"], c["duser"]) for c in conn.values()}

# IP에서 관측된 계정이 하나뿐이면 그 계정의 동일인 후보를 IP에도 붙인다 (nginx용, 추정)
ip_person = {}
for ip, r in ips.items():
    names = {x.split(":")[0] for col in ("linux_login_accounts", "console_accounts")
             for x in r[col].split("|") if x}
    persons = {accounts[n]["person_candidate"] for n in names if accounts[n]["person_candidate"]}
    if len(persons) == 1:
        ip_person[ip] = persons.pop()

# ---------------------------------------------------------------- 2-2, 2-3. 엔티티 + 바구니
NEW_COLS = ["connection_id", "fill_basis", "client_ip", "client_zone",
            "account", "account_system", "account_type", "person_candidate", "person_basis",
            "host", "host_role", "host_criticality", "dst_zone",
            "action_category", "action_sensitivity", "bucket", "bucket_label", "bucket_reason"]
LABEL = {"session": "① 사용자 업무 세션", "background": "② 시스템 배경 활동",
         "external": "③ 세션 없는 외부 시도"}

for r in rows:
    src = r["log_source"]
    n = dict.fromkeys(NEW_COLS, "")
    n["fill_basis"] = "원본"

    if src == "sshd":
        cid, basis = sshd_connection(r)
        n["connection_id"], n["fill_basis"] = cid, basis
        c = conn.get(cid, {})
        n["client_ip"] = r["src"] or c.get("src", "")
        n["account"] = r["duser"] or c.get("duser", "")
        n["host"] = r["dvchost"]
    elif src == "sysmon":
        n["account"] = r["suser"] or guid_user.get(r["ProcessGuid"], "")
        if not r["suser"] and n["account"]:
            n["fill_basis"] = "관측(ProcessGuid)"
        n["host"] = r["dvchost"]
        if r["dst"]:
            n["dst_zone"] = ips[r["dst"]]["ip_zone"]
    else:  # nginx, teiren_audit: 접속자 IP만 있고 서버는 기록되지 않는다
        n["client_ip"] = r["src"]
        n["account"] = r["suser"]  # nginx는 빈칸

    if n["client_ip"]:
        n["client_zone"] = ips[n["client_ip"]]["ip_zone"]
    if n["account"]:
        acc = accounts[n["account"]]
        n["account_system"], n["account_type"] = acc["account_system"], acc["account_type"]
        n["person_candidate"] = acc["person_candidate"]
    elif n["client_ip"] in ip_person:
        n["person_candidate"] = ip_person[n["client_ip"]]
    if n["person_candidate"]:
        n["person_basis"] = "추정"
    if n["host"]:
        n["host_role"] = hosts[n["host"]]["role"]
        n["host_criticality"] = hosts[n["host"]]["criticality"]

    act = actions[(src, r["http_method"] if src == "nginx" else r["event_action"])]
    n["action_category"], n["action_sensitivity"] = act["category"], act["sensitivity"]

    # 바구니
    if src == "sshd":
        if n["connection_id"]:
            b, why = "session", "sshd: 로그인 성공한 접속의 줄"
        elif (r["src"], r["duser"]) in succeeded:
            b, why = "session", "sshd: 실패 시도 뒤 같은 IP·계정으로 로그인 성공"
        else:
            b, why = "external", "sshd: 로그인 성공이 없는 IP·계정의 실패 시도"
    elif src in ("nginx", "teiren_audit"):
        b, why = "session", "웹: 사용자가 브라우저로 보낸 요청"
    elif n["account_type"] == "human":
        b, why = "session", "sysmon: 사람 계정의 활동"
    else:
        assert n["account_type"] == "system", r
        b, why = "background", "sysmon: 시스템 계정의 활동"
    n["bucket"], n["bucket_label"], n["bucket_reason"] = b, LABEL[b], why

    r.update(n)

# ---------------------------------------------------------------- 쓰기
CLASSIFIED.mkdir(parents=True, exist_ok=True)
write_rows(CLASSIFIED / "timeline_classified.csv", ORIG_COLS + NEW_COLS, rows)
print(f"timeline_classified.csv: {len(rows)} rows, {len(ORIG_COLS)} + {len(NEW_COLS)} cols")

# ---------------------------------------------------------------- 2-4. 검증
assert all(r["bucket"] for r in rows), "바구니가 빈 행이 있다"
assert all(all(r[c] == o[c] for c in ORIG_COLS) for r, o in zip(rows, original)), "원래 컬럼이 바뀌었다"

per_conn = Counter(r["connection_id"] for r in rows if r["connection_id"])
assert len(per_conn) == len(success) == 150, len(per_conn)
assert set(per_conn.values()) == {8}, Counter(per_conn.values())
sshd_rows = [r for r in rows if r["log_source"] == "sshd" and r["connection_id"]]
assert all(r["client_ip"] and r["account"] for r in sshd_rows), "접속 줄에 IP·계정 빈칸"

term = [r for r in rows if r["event_action"] == "process_terminate"]
assert len(term) == 1458 and all(r["account"] for r in term), "process_terminate 계정 누락"

print("검증 통과\n")

# 건수표
table = defaultdict(Counter)
for r in rows:
    table[r["log_source"]][r["bucket"]] += 1
order = ["session", "background", "external"]
print(f"{'로그':<14}" + "".join(f"{LABEL[b]:>16}" for b in order) + f"{'합계':>8}")
for src in ["sshd", "nginx", "teiren_audit", "sysmon"]:
    print(f"{src:<14}" + "".join(f"{table[src][b]:>16,}" for b in order) + f"{sum(table[src].values()):>8,}")
tot = Counter(r["bucket"] for r in rows)
print(f"{'합계':<14}" + "".join(f"{tot[b]:>16,}" for b in order) + f"{len(rows):>8,}")
print("\nbucket_reason:")
for k, v in Counter((r["bucket"], r["bucket_reason"]) for r in rows).most_common():
    print(f"  {LABEL[k[0]]} | {k[1]}: {v:,}")
print("\nfill_basis:")
for k, v in Counter(r["fill_basis"] for r in rows).most_common():
    print(f"  {k}: {v:,}")
