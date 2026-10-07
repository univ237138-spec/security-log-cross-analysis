"""정규화 결과 검증: 정규화 CSV만으로 파싱 CSV를 완전히 복원할 수 있는지, 원문이 일치하는지 확인한다.

실행: python scripts/99_verify.py
"""
import json
import re

from common import NORMALIZED, PARSED, RAW, read_rows


def check(name, cond):
    print(f"  {'OK  ' if cond else 'FAIL'} {name}")
    return cond


def restore_ok(norm, parsed, build):
    return len(norm) == len(parsed) and all(build(n) == dict(p) for n, p in zip(norm, parsed))


results = []

# --- sshd ---
print("sshd")
n, p, r = (read_rows(NORMALIZED / "sshd_normalized.csv"), read_rows(PARSED / "sshd_parsed.csv"),
           read_rows(RAW / "sshd_raw.csv"))
U = ["uid", "by_user", "by_uid", "ssh_protocol", "key_type", "disconnect_code", "disconnect_reason", "LOADED_AT"]


def b_sshd(x):
    u = json.loads(x["unmapped"])
    d = {"timestamp": x["rawEvent"].split(" ", 1)[0], "hostname": x["dhost"], "program": x["dproc"],
         "pid": x["dpid"], "message": x["msg"], "user": x["duser"], "src_ip": x["src"], "src_port": x["spt"],
         "auth_method": x["auth_method"], "key_fingerprint": x["key_fingerprint"], "session_id": x["session_id"]}
    d.update({k: u.get(k, "") for k in U})
    return {k: d[k] for k in p[0]}


results += [check("rawEvent == RAW_LINE", all(a["rawEvent"] == b["RAW_LINE"] for a, b in zip(n, r))),
            check("success는 Accepted에만", all((a["outcome"] == "success") == a["msg"].startswith("Accepted ") for a in n)),
            check("모든 행에 connection_id", all(a["connection_id"] for a in n)),
            check("파싱 CSV 완전 복원", restore_ok(n, p, b_sshd))]

# --- nginx ---
print("nginx")
n, p, r = (read_rows(NORMALIZED / "nginx_normalized.csv"), read_rows(PARSED / "nginx_parsed.csv"),
           read_rows(RAW / "nginx_raw.csv"))
U = ["status", "ident", "remote_user", "server_protocol", "request", "LOADED_AT"]
TL = re.compile(r"^\S+ \S+ \S+ \[([^\]]+)\]")


def b_nginx(x):
    u = json.loads(x["unmapped"])
    d = {"remote_addr": x["src"], "time_local": TL.match(x["rawEvent"]).group(1),
         "request_method": x["requestMethod"], "request_uri": x["request"], "body_bytes_sent": x["in"],
         "http_referer": x["requestContext"], "http_user_agent": x["requestClientApplication"]}
    d.update({k: u.get(k, "") for k in U})
    return {k: d[k] for k in p[0]}


results += [check("rawEvent == RAW_LINE", all(a["rawEvent"] == b["RAW_LINE"] for a, b in zip(n, r))),
            check("파싱 CSV 완전 복원", restore_ok(n, p, b_nginx))]

# --- sysmon ---
print("sysmon")
n, p, r = (read_rows(NORMALIZED / "sysmon_normalized.csv"), read_rows(PARSED / "sysmon_parsed.csv"),
           read_rows(RAW / "sysmon_raw.csv"))
UNIQUE = ["EventID", "Image", "ProcessId", "ProcessGuid", "CommandLine", "CurrentDirectory", "ParentProcessGuid",
          "ParentProcessId", "ParentImage", "ParentCommandLine", "ParentUser", "TargetFilename", "EventRecordID"]


def b_sysmon(x):
    u = json.loads(x["unmapped"])
    d = {"UtcTime": x["event_time_utc"][:-3], "Computer": x["dvchost"], "User": x["suser"] or "-",
         "SourceIp": x["src"], "DestinationIp": x["dst"], "DestinationPort": x["dpt"]}
    d.update({k: x[k] for k in UNIQUE})
    return {k: d.get(k, u.get(k, "")) for k in p[0]}


results += [check("rawEvent == RAW_LINE", all(a["rawEvent"] == b["RAW_LINE"] for a, b in zip(n, r))),
            check("dvchost+EventRecordID 고유", len({(a["dvchost"], a["EventRecordID"]) for a in n}) == len(n)),
            check("파싱 CSV 완전 복원", restore_ok(n, p, b_sysmon))]

# --- audit ---
print("audit")
n, p, r = (read_rows(NORMALIZED / "audit_normalized.csv"), read_rows(PARSED / "audit_parsed.csv"),
           read_rows(RAW / "audit_raw.csv"))
U = ["t_user_id", "system", "tag_name", "tenancy", "tc_deviceVendor", "tc_deviceProduct", "LOADED_AT"]


def b_audit(x):
    u, ev = json.loads(x["unmapped"]), json.loads(x["rawEvent"])
    d = {"doc_id": x["doc_id"], "t_event_id": x["t_event_id"], "tc_act": x["tc_act"], "tc_msg": x["msg"],
         "tc_request": x["request"], "tc_requestClientApplication": x["requestClientApplication"],
         "tc_src": x["src"], "tc_suser": x["suser"], "teiren_timestamp": ev["teiren_timestamp"]}
    d.update({k: u.get(k, "") for k in U})
    return {k: d[k] for k in p[0]}


results += [check("rawEvent JSON == EVENT JSON", all(json.loads(a["rawEvent"]) == json.loads(b["EVENT"]) for a, b in zip(n, r))),
            check("파싱 CSV 완전 복원", restore_ok(n, p, b_audit))]

print("\n전체:", "모두 통과" if all(results) else "실패 있음")
