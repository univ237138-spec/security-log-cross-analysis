"""4개 로그를 시각순 타임라인 하나로 이어 붙인다 (조인하지 않는다).

입력: data/03_normalized/*_normalized_event_action.csv
출력: data/04_integrated/timeline.csv
계획: docs/04_통합_보강_연결.md

컬럼 순서
1. 공통 컬럼: 여러 로그에 있거나 타임라인을 읽는 데 필요한 컬럼. 해당 로그에 없으면 빈칸
2. 로그별 고유 컬럼: NGINX → SSHD → Sysmon → 감사로그 순. 컬럼 이름은 정규화 파일 그대로(CEF)
3. rawEvent, unmapped: 네 로그 모두 같은 컬럼에 그대로

통합 단계에서 바꾸거나 만드는 값
- Sysmon src는 접속자가 아니라 이벤트를 남긴 서버 자신의 IP라 dvc로 옮긴다. 통합 src는 접속자 IP만 담는다
- SSHD dvchost: unmapped.hostname 값을 꺼내 쓴다 (unmapped에도 그대로 남긴다)
- time_precision: 원본 시각의 정밀도. 같은 초 안의 순서를 해석하지 않기 위한 표시
- user_type: suser·duser가 어떤 계정 체계인지. 같은 이름이어도 다른 계정이다
- source_row: 원래 정규화 파일의 몇 번째 데이터 행인지 (1부터)

정렬: event_time_utc → log_source(LOGS 순서) → source_row
"""
import json

from common import INTEGRATED, NORMALIZED, read_rows, write_rows

# (파일 이름, log_source, time_precision, user_type)
LOGS = [
    ("nginx", "nginx", "s", ""),
    ("sshd", "sshd", "us", "linux"),
    ("sysmon", "sysmon", "ms", "linux"),
    ("audit", "teiren_audit", "ms", "teiren_console"),
]
COMMON = ["event_time_utc", "log_source", "time_precision", "source_row", "event_action",
          "src", "dvc", "dvchost", "suser", "duser", "user_type", "msg", "request"]
TAIL = ["rawEvent", "unmapped"]


def to_common(name, row):
    """정규화 행 → 공통 컬럼 값. 로그별로 이름이 다른 컬럼만 여기서 맞춘다."""
    out = {}
    if name == "sysmon":
        out["dvc"] = row["src"]
        out["src"] = ""
    if name == "sshd":
        out["dvchost"] = json.loads(row["unmapped"])["hostname"]
    return out


data, unique = {}, {}
for name, source, _, _ in LOGS:
    rows = read_rows(NORMALIZED / f"{name}_normalized_event_action.csv")
    assert all(r["log_source"] == source for r in rows), name
    data[name] = rows
    unique[name] = [c for c in rows[0] if c not in COMMON and c not in TAIL]

# 고유 컬럼 이름이 로그끼리 겹치지 않아야 한 표에 펼칠 수 있다
all_unique = [c for name, *_ in LOGS for c in unique[name]]
assert len(all_unique) == len(set(all_unique)), all_unique
COLS = COMMON + all_unique + TAIL

order = {source: i for i, (_, source, _, _) in enumerate(LOGS)}
out = []
for name, source, precision, user_type in LOGS:
    for i, r in enumerate(data[name], start=1):
        o = dict(r)
        o.update({"time_precision": precision, "source_row": str(i),
                  "user_type": user_type if (r.get("suser") or r.get("duser")) else ""})
        o.update(to_common(name, r))
        out.append(o)

out.sort(key=lambda o: (o["event_time_utc"], order[o["log_source"]], int(o["source_row"])))

INTEGRATED.mkdir(parents=True, exist_ok=True)
write_rows(INTEGRATED / "timeline.csv", COLS, out)
print(f"timeline.csv: {len(out)} rows, {len(COLS)} cols")
print(f"  공통 {len(COMMON)}: {', '.join(COMMON)}")
for name, *_ in LOGS:
    print(f"  {name} 고유 {len(unique[name])}: {', '.join(unique[name])}")
print(f"  끝 {len(TAIL)}: {', '.join(TAIL)}")
