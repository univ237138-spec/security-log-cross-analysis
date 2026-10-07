"""sshd 정규화.

입력: data/02_parsed/sshd_parsed.csv, data/01_raw/sshd_raw.csv
출력: data/03_normalized/sshd_normalized.csv (19개 컬럼)
계획: docs/03_파싱_정규화.md
"""
from datetime import datetime, timedelta, timezone

from common import NORMALIZED, PARSED, RAW, pack_unmapped, read_rows, write_rows

UNMAPPED = ["uid", "by_user", "by_uid", "ssh_protocol", "key_type", "disconnect_code", "disconnect_reason", "LOADED_AT"]
COLS = ["event_time_utc", "dhost", "src", "spt", "duser", "dproc", "dpid", "cat", "act", "outcome", "reason", "msg",
        "auth_method", "user_exists", "key_fingerprint", "session_id", "connection_id", "rawEvent", "unmapped"]


def classify(m):
    """메시지 → (cat, act, outcome, reason, user_exists). success는 Accepted에만 붙인다 (멘토 피드백)."""
    if m.startswith("Invalid user "):
        return "authentication", "logon", "failure", "invalid_user", "false"
    if m.startswith("Failed password"):
        return "authentication", "logon", "failure", "wrong_password", "true"
    if m.startswith("Accepted "):
        return "authentication", "logon", "success", "", "true"
    if "session opened for user" in m or m.startswith("New session "):
        return "session", "start", "", "", ""
    if ("session closed for user" in m or " logged out. " in m or m.startswith("Removed session ")
            or m.startswith("Received disconnect") or m.startswith("Disconnected from user")):
        return "session", "end", "", "", ""
    raise ValueError(f"분류되지 않은 메시지: {m}")


parsed = read_rows(PARSED / "sshd_parsed.csv")
raw = read_rows(RAW / "sshd_raw.csv")
assert len(parsed) == len(raw)

out = []
for p, r in zip(parsed, raw):
    header = f"{p['timestamp']} {p['hostname']} {p['program']}[{p['pid']}]: {p['message']}"
    assert header == r["RAW_LINE"]  # 원문과 파싱 행이 같은 이벤트
    t = datetime.fromisoformat(p["timestamp"]).astimezone(timezone.utc)  # +09:00 → UTC
    cat, act, outcome, reason, user_exists = classify(p["message"])
    out.append({
        "event_time_utc": t.strftime("%Y-%m-%d %H:%M:%S.%f"), "_t": t,
        "dhost": p["hostname"], "src": p["src_ip"], "spt": p["src_port"], "duser": p["user"],
        "dproc": p["program"], "dpid": p["pid"],
        "cat": cat, "act": act, "outcome": outcome, "reason": reason, "msg": p["message"],
        "auth_method": p["auth_method"], "user_exists": user_exists,
        "key_fingerprint": p["key_fingerprint"], "session_id": p["session_id"], "connection_id": "",
        "rawEvent": r["RAW_LINE"], "unmapped": pack_unmapped(p, UNMAPPED),
    })

# --- connection_id: 호스트|출발지IP|출발지포트 ---
for o in out:
    if o["src"] and o["spt"]:
        o["connection_id"] = f"{o['dhost']}|{o['src']}|{o['spt']}"

accepted = [o for o in out if o["msg"].startswith("Accepted ")]


def previous_accepted(cond, o):
    cands = [a for a in accepted if cond(a) and a["_t"] <= o["_t"]]
    assert cands, o["msg"]
    return max(cands, key=lambda a: a["_t"])


for o in out:
    m = o["msg"]
    if "session opened for user" in m or "session closed for user" in m:
        # 같은 pid의 직전 Accepted
        o["connection_id"] = previous_accepted(
            lambda a: a["dpid"] == o["dpid"] and a["duser"] == o["duser"], o)["connection_id"]
    elif m.startswith("New session "):
        # 같은 사용자의 1초 안 직전 Accepted (시각 기반 추정 연결, 정확히 하나일 때만)
        cands = [a for a in accepted
                 if a["duser"] == o["duser"] and timedelta(0) <= o["_t"] - a["_t"] <= timedelta(seconds=1)]
        assert len(cands) == 1, (m, len(cands))
        o["connection_id"] = cands[0]["connection_id"]

# logout / removed: 같은 session_id의 New session
session_conn = {o["session_id"]: o["connection_id"] for o in out if o["msg"].startswith("New session ")}
assert len(session_conn) == sum(o["msg"].startswith("New session ") for o in out)  # 세션 번호 중복 없음
for o in out:
    if o["dproc"] == "systemd-logind" and not o["connection_id"]:
        o["connection_id"] = session_conn[o["session_id"]]
assert all(o["connection_id"] for o in out)

write_rows(NORMALIZED / "sshd_normalized.csv", COLS, out)
print(f"sshd_normalized.csv: {len(out)} rows, {len(COLS)} cols")
