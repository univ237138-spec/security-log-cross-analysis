"""행위 컬럼을 event_action으로 바꾸고 수정본 기준을 일부 반영한 정규화 CSV를 만든다.

입력: data/03_normalized/{nginx,sshd,sysmon,audit}_normalized.csv
출력: data/03_normalized/*_normalized_event_action.csv (기존 파일은 그대로 둔다)
근거: docs/03_파싱_정규화.md

- cat·act·outcome·reason을 지우고, 원시 로그의 행위 수준을 그대로 담는 event_action 하나를 둔다.
  - sshd: 메시지 템플릿 10종 → 수정본의 세부 행동 이름
  - Sysmon: EventID 4종 → 수정본의 행동 이름
  - 감사로그: 원본 행동 코드 tc_act를 값 그대로 event_action으로 옮긴다
- nginx는 원시 로그에 행위 필드가 없으므로 event_action을 두지 않는다.
  http_method(= $request의 메서드)와 http_status_code(= $status, unmapped에서 꺼냄)가 행위 정보를 대신한다.
- 지운 분류값은 event_action에서 다시 만들 수 있어야 한다. 원본의 각 event_action 값이
  (cat, act, outcome, reason) 조합 하나에만 대응하는지 확인한다.
- 네 테이블 모두 log_source(출처 구분 고정값)를 event_time_utc 다음에 둔다.
- 분석에 쓰지 않는 원본 컬럼은 unmapped로 옮긴다. 키는 unmapped의 다른 항목처럼 파싱 원본 필드 이름을 쓴다.
  - nginx requestClientApplication → unmapped.http_user_agent
  - sshd dhost → unmapped.hostname
  - 감사로그 requestClientApplication → unmapped.tc_requestClientApplication
- 우리가 만든 값은 unmapped에 넣지 않고 지운다 (unmapped = 쓰지 않은 원본 필드).
  - sshd user_exists: 메시지 분류값. event_action(invalid_user / auth_failure)과 같은 정보
  - sshd connection_id: 추정 연결값. IP·포트는 src·spt에 원문 값으로 있다
"""
import json
from collections import defaultdict

from common import NORMALIZED, read_rows, to_json, write_rows

DROP = ["cat", "act", "outcome", "reason"]

# sshd 메시지 → event_action. 순서대로 비교한다.
SSHD_ACTION = [
    (lambda m: m.startswith("Invalid user "), "invalid_user"),
    (lambda m: m.startswith("Failed password"), "auth_failure"),
    (lambda m: m.startswith("Accepted "), "auth_success"),
    (lambda m: "session opened for user" in m, "session_opened"),
    (lambda m: m.startswith("New session "), "session_new"),
    (lambda m: m.startswith("Received disconnect"), "disconnect_received"),
    (lambda m: m.startswith("Disconnected from user"), "disconnected_user"),
    (lambda m: "session closed for user" in m, "session_closed"),
    (lambda m: " logged out. " in m, "session_logged_out"),
    (lambda m: m.startswith("Removed session "), "session_removed"),
]
SYSMON_ACTION = {"1": "process_create", "3": "network_connect", "5": "process_terminate", "11": "file_create"}


def sshd_action(m):
    hits = [a for match, a in SSHD_ACTION if match(m)]
    assert len(hits) == 1, (m, hits)
    return hits[0]


def check_lossless(name, rows):
    """event_action 값 하나가 원본 분류 조합 하나에만 대응하는지 확인하고 대응표를 돌려준다."""
    combos = defaultdict(set)
    for r in rows:
        combos[r["event_action"]].add(tuple(r.get(k, "") for k in DROP))
    bad = {a: c for a, c in combos.items() if len(c) != 1}
    assert not bad, (name, bad)
    return {a: next(iter(c)) for a, c in combos.items()}


def replace_cols(cols, new, anchor, removed):
    """event_time_utc 다음에 log_source, anchor 자리에 new 컬럼들을 넣고 removed 컬럼은 뺀다."""
    out = []
    for c in cols:
        if c == anchor:
            out += new
        if c not in removed:
            out.append(c)
        if c == "event_time_utc":
            out.append("log_source")
    return out


def run(name, source, transform, new_cols, anchor="cat", renamed=(), to_unmapped=None, drop=()):
    """renamed: transform에서 새 이름으로 옮긴 컬럼, to_unmapped: {컬럼: unmapped 키}, drop: 지우는 생성 컬럼."""
    to_unmapped = to_unmapped or {}
    rows = read_rows(NORMALIZED / f"{name}_normalized.csv")
    cols = list(rows[0].keys())
    for r in rows:
        transform(r)
        r["log_source"] = source
        if to_unmapped:
            un = json.loads(r["unmapped"])
            assert not set(to_unmapped.values()) & set(un), (name, un)
            un.update({k: r[c] for c, k in to_unmapped.items() if r[c]})  # 빈 값은 키째로 넣지 않는다
            r["unmapped"] = to_json(un)
    mapping = check_lossless(name, rows) if "event_action" in new_cols else None
    cols = replace_cols(cols, new_cols, anchor, set(DROP) | set(renamed) | set(to_unmapped) | set(drop))
    write_rows(NORMALIZED / f"{name}_normalized_event_action.csv", cols, rows)
    print(f"{name}_normalized_event_action.csv: {len(rows)} rows, {len(cols)} cols")
    print(f"  cols: {', '.join(cols)}")
    if mapping:
        counts = defaultdict(int)
        for r in rows:
            counts[r["event_action"]] += 1
        for a, combo in sorted(mapping.items(), key=lambda x: -counts[x[0]]):
            print(f"  {a:<30} {counts[a]:>5}  ← {'/'.join(v or '-' for v in combo)}")
    return rows


# --- nginx: requestMethod → http_method, unmapped.status → http_status_code ---
def nginx(r):
    r["http_method"] = r.pop("requestMethod")
    un = json.loads(r["unmapped"])
    r["http_status_code"] = un.pop("status")
    r["unmapped"] = to_json(un)


run("nginx", "nginx", nginx, ["http_method", "http_status_code"], anchor="requestMethod",
    renamed=["requestMethod"], to_unmapped={"requestClientApplication": "http_user_agent"})


# --- sshd ---
def sshd(r):
    r["event_action"] = sshd_action(r["msg"])


run("sshd", "sshd", sshd, ["event_action"], to_unmapped={"dhost": "hostname"}, drop=["user_exists", "connection_id"])


# --- Sysmon ---
def sysmon(r):
    r["event_action"] = SYSMON_ACTION[r["EventID"]]


run("sysmon", "sysmon", sysmon, ["event_action"])


# --- 감사로그: tc_act를 값 그대로 event_action으로 옮긴다 ---
def audit(r):
    r["event_action"] = r.pop("tc_act")


run("audit", "teiren_audit", audit, ["event_action"], renamed=["tc_act"],
    to_unmapped={"requestClientApplication": "tc_requestClientApplication"})
