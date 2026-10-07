"""원시 로그 → 파싱 → 정규화(event_action 판) 전 구간 검증.

실행: python scripts/99_verify_event_action.py
대상: data/01_raw/*_raw.csv → data/02_parsed/*_parsed.csv → data/03_normalized/*_normalized_event_action.csv

1. 원시 → 파싱: 행 수, LOADED_AT, 파싱 값으로 원문을 글자 그대로 다시 만들 수 있는지 (Sysmon은 XML의 모든 값과 대조)
2. 파싱 → 정규화: rawEvent가 원문과 같은지, rawEvent를 쓰지 않고 독립 컬럼 + unmapped만으로
   파싱 행을 완전히 복원할 수 있는지, 새로 만든 값(event_time_utc, event_action, log_source)이 규칙대로인지
3. 파싱 컬럼마다 정규화 파일의 어디에 있는지 (독립 컬럼 / unmapped / 시각 변환) 표로 출력
"""
import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone

from common import NORMALIZED, PARSED, RAW, read_rows

results = []


def check(name, cond, detail=""):
    print(f"  {'OK  ' if cond else 'FAIL'} {name}{f'  ({detail})' if detail else ''}")
    results.append(bool(cond))
    return cond


def load(name):
    raw = read_rows(RAW / f"{name}_raw.csv")
    parsed = read_rows(PARSED / f"{name}_parsed.csv")
    norm = read_rows(NORMALIZED / f"{name}_normalized_event_action.csv")
    return raw, parsed, norm


def physical_lines(name):
    """한 줄짜리 원시 로그는 파일의 줄 수 - 헤더 = 행 수여야 한다 (CSV 읽기에서 행이 빠지지 않았는지)."""
    with open(RAW / f"{name}_raw.csv", encoding="utf-8-sig", newline="") as f:
        return sum(1 for _ in f) - 1


def common_checks(name, raw, parsed, norm, source, raw_key="RAW_LINE"):
    check("행 수 원시 = 파싱 = 정규화", len(raw) == len(parsed) == len(norm), f"{len(raw)} / {len(parsed)} / {len(norm)}")
    check("빈 원시 행 없음", all(r[raw_key].strip() for r in raw))
    check("LOADED_AT 원시 = 파싱", all(r["LOADED_AT"] == p["LOADED_AT"] for r, p in zip(raw, parsed)))
    check(f"log_source 전 행 '{source}'", all(n["log_source"] == source for n in norm))


def restore_checks(parsed, norm, restore):
    """restore(정규화 행) → 파싱 행. rawEvent는 쓰지 않는다."""
    bad = [i for i, (p, n) in enumerate(zip(parsed, norm)) if restore(n) != dict(p)]
    check("rawEvent 없이 독립 컬럼 + unmapped로 파싱 행 완전 복원", not bad, f"불일치 {len(bad)}행" if bad else "")
    if bad:
        i = bad[0]
        r, p = restore(norm[i]), parsed[i]
        print("    예시:", {k: (p.get(k), r.get(k)) for k in set(p) | set(r) if p.get(k) != r.get(k)})
    keys = set(parsed[0])
    extra = {k for n in norm for k in json.loads(n["unmapped"] or "{}") if k not in keys}
    empty = sum(1 for n in norm for v in json.loads(n["unmapped"] or "{}").values() if v == "")
    check("unmapped 키는 모두 파싱 컬럼 이름", not extra, f"모르는 키 {sorted(extra)}" if extra else "")
    check("unmapped에 빈 값 키 없음", empty == 0)


def show_location(parsed, norm, places):
    """places: {파싱 컬럼: 정규화 위치 설명}. 지정하지 않은 컬럼은 unmapped에 있어야 한다."""
    keys_in_unmapped = {k for n in norm for k in json.loads(n["unmapped"] or "{}")}
    rows = []
    for c in parsed[0]:
        if c in places:
            rows.append((c, places[c]))
        elif c in keys_in_unmapped:
            rows.append((c, f"unmapped.{c}"))
        else:
            # 모든 행에서 빈 값이라 unmapped에 키가 하나도 없는 경우
            assert all(p[c] == "" for p in parsed), c
            rows.append((c, "unmapped (전 행 빈 값이라 키 없음)"))
    print("  파싱 컬럼 → 정규화 위치")
    for c, w in rows:
        print(f"    {c:<28} → {w}")


def unmapped(n):
    return json.loads(n["unmapped"] or "{}")


# =========================================================================== nginx
print("\n[nginx]")
raw, parsed, norm = load("nginx")
common_checks("nginx", raw, parsed, norm, "nginx")
check("원시 파일 줄 수 = 행 수 (줄바꿈 포함 행 없음)", physical_lines("nginx") == len(raw))

check("원시 → 파싱: 파싱 값으로 원문 한 줄 재조립", all(
    f'{p["remote_addr"]} {p["ident"]} {p["remote_user"]} [{p["time_local"]}] "{p["request"]}" '
    f'{p["status"]} {p["body_bytes_sent"]} "{p["http_referer"]}" "{p["http_user_agent"]}"' == r["RAW_LINE"]
    for r, p in zip(raw, parsed)))
check("원시 → 파싱: request = 메서드 + URI + 프로토콜", all(
    p["request"] == f'{p["request_method"]} {p["request_uri"]} {p["server_protocol"]}' for p in parsed))
check("정규화 rawEvent = 원문", all(n["rawEvent"] == r["RAW_LINE"] for n, r in zip(norm, raw)))

offsets = {p["time_local"][-5:] for p in parsed}
check("원본 시각이 모두 +0000 (UTC 변환이 값만 바꾸지 않음)", offsets == {"+0000"}, str(offsets))
check("event_time_utc = time_local의 UTC 변환", all(
    n["event_time_utc"] == datetime.strptime(p["time_local"], "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc)
    .strftime("%Y-%m-%d %H:%M:%S.%f") for n, p in zip(norm, parsed)))
check("event_action 컬럼 없음 (http_method·http_status_code가 대신함)", "event_action" not in norm[0])

MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def r_nginx(n):
    u = unmapped(n)
    t = datetime.strptime(n["event_time_utc"], "%Y-%m-%d %H:%M:%S.%f")
    d = {"remote_addr": n["src"], "time_local": f"{t:%d}/{MONTHS[t.month - 1]}/{t:%Y:%H:%M:%S} +0000",
         "request_method": n["http_method"], "request_uri": n["request"], "status": n["http_status_code"],
         "body_bytes_sent": n["in"], "http_referer": n["requestContext"]}
    return {k: d[k] if k in d else u.get(k, "") for k in parsed[0]}


restore_checks(parsed, norm, r_nginx)
show_location(parsed, norm, {
    "remote_addr": "src", "time_local": "event_time_utc (UTC 변환)", "request_method": "http_method",
    "request_uri": "request", "status": "http_status_code", "body_bytes_sent": "in", "http_referer": "requestContext"})

# =========================================================================== sshd
print("\n[sshd]")
raw, parsed, norm = load("sshd")
common_checks("sshd", raw, parsed, norm, "sshd")
check("원시 파일 줄 수 = 행 수 (줄바꿈 포함 행 없음)", physical_lines("sshd") == len(raw))
check("원시 → 파싱: 헤더 + 메시지로 원문 한 줄 재조립", all(
    f'{p["timestamp"]} {p["hostname"]} {p["program"]}[{p["pid"]}]: {p["message"]}' == r["RAW_LINE"]
    for r, p in zip(raw, parsed)))
# 메시지에서 꺼낸 값은 모두 메시지 원문 안에 글자 그대로 있어야 한다
MSG_VALS = ["user", "src_ip", "src_port", "auth_method", "ssh_protocol", "key_type", "key_fingerprint",
            "uid", "by_user", "by_uid", "session_id", "disconnect_code", "disconnect_reason"]
check("원시 → 파싱: 메시지에서 꺼낸 값이 모두 메시지 원문에 있음", all(
    p[k] in p["message"] for p in parsed for k in MSG_VALS if p[k]))
check("정규화 rawEvent = 원문", all(n["rawEvent"] == r["RAW_LINE"] for n, r in zip(norm, raw)))

offsets = {p["timestamp"][-6:] for p in parsed}
check("원본 시각 오프셋이 하나뿐", len(offsets) == 1, str(offsets))
OFFSET = datetime.fromisoformat(parsed[0]["timestamp"]).utcoffset()
check("event_time_utc = timestamp의 UTC 변환", all(
    n["event_time_utc"] == datetime.fromisoformat(p["timestamp"]).astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")
    for n, p in zip(norm, parsed)))

# event_action: 메시지 첫머리로 독립 판정 (정규화 코드와 다른 방식)
SSHD_RULES = [
    (r"Invalid user \S+ from ", "invalid_user"),
    (r"Failed \S+ for ", "auth_failure"),
    (r"Accepted \S+ for ", "auth_success"),
    (r"pam_unix\(sshd:session\): session opened ", "session_opened"),
    (r"pam_unix\(sshd:session\): session closed ", "session_closed"),
    (r"New session \d+ of user ", "session_new"),
    (r"Session \d+ logged out\.", "session_logged_out"),
    (r"Removed session \d+\.", "session_removed"),
    (r"Received disconnect from ", "disconnect_received"),
    (r"Disconnected from user ", "disconnected_user"),
]


def sshd_expected(m):
    hits = [a for pat, a in SSHD_RULES if re.match(pat, m)]
    return hits[0] if len(hits) == 1 else None


check("event_action = 메시지 템플릿 판정 (10종, 행마다 하나)", all(
    n["event_action"] == sshd_expected(p["message"]) for n, p in zip(norm, parsed)))
check("event_action 값 10종", len({n["event_action"] for n in norm}) == 10)


def r_sshd(n):
    u = unmapped(n)
    t = datetime.strptime(n["event_time_utc"], "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=timezone.utc)
    d = {"timestamp": t.astimezone(timezone(OFFSET)).isoformat(), "program": n["dproc"], "pid": n["dpid"],
         "message": n["msg"], "user": n["duser"], "src_ip": n["src"], "src_port": n["spt"],
         "auth_method": n["auth_method"], "key_fingerprint": n["key_fingerprint"], "session_id": n["session_id"]}
    return {k: d[k] if k in d else u.get(k, "") for k in parsed[0]}


restore_checks(parsed, norm, r_sshd)
check("만든 값(user_exists, connection_id, cat·act·outcome·reason)이 컬럼·unmapped에 없음", not (
    {"user_exists", "connection_id", "cat", "act", "outcome", "reason", "dhost"} & set(norm[0]))
    and not any({"user_exists", "connection_id"} & set(unmapped(n)) for n in norm))
show_location(parsed, norm, {
    "timestamp": "event_time_utc (UTC 변환)", "program": "dproc", "pid": "dpid", "message": "msg", "user": "duser",
    "src_ip": "src", "src_port": "spt", "auth_method": "auth_method", "key_fingerprint": "key_fingerprint",
    "session_id": "session_id"})

# =========================================================================== sysmon
print("\n[sysmon]")
raw, parsed, norm = load("sysmon")
common_checks("sysmon", raw, parsed, norm, "sysmon")
check("원시 파일 줄 수 = 행 수 (줄바꿈 포함 행 없음)", physical_lines("sysmon") == len(raw))


def xml_values(line):
    """XML의 모든 값을 (이름, 값)으로 모은다. 파싱 코드와 별개로 구조를 직접 훑는다."""
    root = ET.fromstring(line)
    assert [c.tag for c in root] == ["System", "EventData"], [c.tag for c in root]
    out = {}
    for el in root.find("System"):
        assert len(el) == 0  # System 아래 2단계 태그 없음
        if el.text and el.text.strip():
            out[el.tag] = el.text
        for a, v in el.attrib.items():
            out[f"{el.tag}_{a}"] = v
    for d in root.find("EventData"):
        assert d.tag == "Data" and list(d.attrib) == ["Name"] and len(d) == 0
        out[d.get("Name")] = d.text or ""
    return out


bad = 0
for r, p in zip(raw, parsed):
    x = xml_values(r["RAW_LINE"])
    # XML에 있는 값은 파싱에 같은 값으로, XML에 없는 파싱 컬럼은 빈 칸이어야 한다
    if any(p[k] != v for k, v in x.items()) or any(p[k] for k in p if k not in x and k != "LOADED_AT"):
        bad += 1
check("원시 → 파싱: XML의 모든 태그 값·속성·Data가 파싱 행과 일치, 그 외 칸은 빈 값", bad == 0, f"불일치 {bad}행" if bad else "")
check("정규화 rawEvent = 원문", all(n["rawEvent"] == r["RAW_LINE"] for n, r in zip(norm, raw)))
check("event_time_utc = UtcTime (UTC 원본, 자릿수만 늘림)", all(n["event_time_utc"] == p["UtcTime"] + "000" for n, p in zip(norm, parsed)))
SYSMON_EXPECT = {"1": "process_create", "3": "network_connect", "5": "process_terminate", "11": "file_create"}
check("event_action = EventID 대응 (4종)", all(n["event_action"] == SYSMON_EXPECT[p["EventID"]] for n, p in zip(norm, parsed)))
check("Computer + EventRecordID 고유", len({(p["Computer"], p["EventRecordID"]) for p in parsed}) == len(parsed))

DIRECT = {"Computer": "dvchost", "SourceIp": "src", "DestinationIp": "dst", "DestinationPort": "dpt"}
UNIQUE = ["EventID", "Image", "ProcessId", "ProcessGuid", "CommandLine", "CurrentDirectory", "ParentProcessGuid",
          "ParentProcessId", "ParentImage", "ParentCommandLine", "ParentUser", "TargetFilename", "EventRecordID"]


def r_sysmon(n):
    u = unmapped(n)
    d = {"UtcTime": n["event_time_utc"][:-3], "User": n["suser"] or "-"}
    d.update({k: n[c] for k, c in DIRECT.items()})
    d.update({k: n[k] for k in UNIQUE})
    return {k: d[k] if k in d else u.get(k, "") for k in parsed[0]}


check("User 원본에 빈 값 없음 ('-'만 빈칸으로 바꿈, 되돌릴 수 있음)", all(p["User"] for p in parsed))
restore_checks(parsed, norm, r_sysmon)
show_location(parsed, norm, {"UtcTime": "event_time_utc (자릿수만 늘림)", "User": "suser ('-' → 빈칸)",
                             **DIRECT, **{k: k for k in UNIQUE}})

# =========================================================================== audit
print("\n[teiren_audit]")
raw, parsed, norm = load("audit")
common_checks("audit", raw, parsed, norm, "teiren_audit", raw_key="EVENT")
events = [json.loads(r["EVENT"]) for r in raw]
check("원시 EVENT가 모두 평평한 JSON (중첩·숫자 없이 문자열 값)", all(
    all(isinstance(v, str) for v in e.values()) for e in events))
check("원시 → 파싱: EVENT의 키·값 = 파싱 행 (키 순서 포함)", all(
    list(e.items()) == [(k, p[k]) for k in p if k != "LOADED_AT"] for e, p in zip(events, parsed)))
check("정규화 rawEvent JSON = 원시 EVENT JSON (키 순서 포함)", all(
    list(json.loads(n["rawEvent"]).items()) == list(e.items()) for n, e in zip(norm, events)))
check("doc_id 고유", len({p["doc_id"] for p in parsed}) == len(parsed))
TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
check("teiren_timestamp가 모두 UTC 밀리초 형식", all(TS.match(p["teiren_timestamp"]) for p in parsed))
check("event_time_utc = teiren_timestamp (형식만 변경)", all(
    n["event_time_utc"] == p["teiren_timestamp"].replace("T", " ").rstrip("Z") + "000" for n, p in zip(norm, parsed)))
check("event_action = tc_act 값 그대로", all(n["event_action"] == p["tc_act"] for n, p in zip(norm, parsed)))


def r_audit(n):
    u = unmapped(n)
    d = {"doc_id": n["doc_id"], "t_event_id": n["t_event_id"], "tc_act": n["event_action"], "tc_msg": n["msg"],
         "tc_request": n["request"], "tc_src": n["src"], "tc_suser": n["suser"],
         "teiren_timestamp": n["event_time_utc"][:23].replace(" ", "T") + "Z"}
    return {k: d[k] if k in d else u.get(k, "") for k in parsed[0]}


restore_checks(parsed, norm, r_audit)
show_location(parsed, norm, {
    "doc_id": "doc_id", "t_event_id": "t_event_id", "tc_act": "event_action", "tc_msg": "msg",
    "tc_request": "request", "tc_src": "src", "tc_suser": "suser", "teiren_timestamp": "event_time_utc (형식 변경)"})

print("\n전체:", f"{len(results)}개 검사 모두 통과" if all(results) else f"실패 {results.count(False)}개")
