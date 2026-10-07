"""감사로그 정규화.

입력: data/02_parsed/audit_parsed.csv, data/01_raw/audit_raw.csv
출력: data/03_normalized/audit_normalized.csv (15개 컬럼)
계획: docs/03_파싱_정규화.md
"""
import json
from datetime import datetime

from common import NORMALIZED, PARSED, RAW, pack_unmapped, read_rows, to_json, write_rows

UNMAPPED = ["t_user_id", "system", "tag_name", "tenancy", "tc_deviceVendor", "tc_deviceProduct", "LOADED_AT"]
COLS = ["event_time_utc", "src", "suser", "cat", "act", "outcome", "reason", "msg", "request",
        "requestClientApplication", "tc_act", "t_event_id", "doc_id", "rawEvent", "unmapped"]

# tc_act → (cat, act, reason). cat은 ECS event.category 허용 값
CLASSIFY = {
    "IAM_LOGIN_SUCCESS": ("authentication", "logon", ""),
    "ROOT_LOGIN_NO_MFA": ("authentication", "logon", "no_mfa"),
    "IAM_LOGIN_NEW_DEVICE": ("authentication", "logon", "new_device"),
    "SESSION_REFRESH": ("session", "change", ""),
    "DASHBOARD_LAYOUT_VIEW_UPDATE": ("configuration", "change", ""),
    "LOG_COLUMN_VIEW_UPDATE": ("configuration", "change", ""),
    "INTEGRATION_STATUS_UPDATE": ("configuration", "change", ""),
    "RULE_DELETE": ("configuration", "deletion", ""),
    "IAM_POLICY_DETACH": ("iam", "change", ""),
    "IAM_USER_DELETE": ("iam", "deletion", ""),
    "DEBUG_EXEC": ("api", "access", ""),
    "GENERAL_BAD_REQUEST": ("api", "access", "bad_request"),
}
# t_event_id 코드의 첫 글자 (추정, 멘토 확인 대기)
OUTCOME = {"S": "success", "G": "failure"}

parsed = read_rows(PARSED / "audit_parsed.csv")
raw = read_rows(RAW / "audit_raw.csv")
assert len(parsed) == len(raw)

out = []
for p, r in zip(parsed, raw):
    event = json.loads(r["EVENT"])
    assert all(event[k] == p[k] for k in event)  # 원문과 파싱 행이 같은 이벤트
    cat, act, reason = CLASSIFY[p["tc_act"]]
    code = p["t_event_id"].split("-", 1)[1]
    t = datetime.strptime(p["teiren_timestamp"], "%Y-%m-%dT%H:%M:%S.%fZ")
    out.append({
        "event_time_utc": t.strftime("%Y-%m-%d %H:%M:%S.%f"),
        "src": p["tc_src"],
        "suser": p["tc_suser"],
        "cat": cat, "act": act, "outcome": OUTCOME[code[0]], "reason": reason,
        "msg": p["tc_msg"],
        "request": p["tc_request"],
        "requestClientApplication": p["tc_requestClientApplication"],
        "tc_act": p["tc_act"], "t_event_id": p["t_event_id"], "doc_id": p["doc_id"],
        "rawEvent": to_json(event),  # 한 줄 JSON (키 순서 유지)
        "unmapped": pack_unmapped(p, UNMAPPED),
    })

write_rows(NORMALIZED / "audit_normalized.csv", COLS, out)
print(f"audit_normalized.csv: {len(out)} rows, {len(COLS)} cols")
