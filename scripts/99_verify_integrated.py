"""통합 타임라인 검증.

실행: python scripts/99_verify_integrated.py
대상: data/04_integrated/timeline.csv ← data/03_normalized/*_normalized_event_action.csv

1. 행 수, log_source + source_row 고유, 로그별 행 수
2. 통합 표를 log_source로 다시 나눠 정규화 파일 4개를 값 그대로 되살릴 수 있는지
3. 정렬 순서
4. 통합 단계에서 만든 값(dvc, dvchost, time_precision, user_type)이 규칙대로인지
5. 기준 사건이 타임라인에 기대한 순서로 나오는지 (docs/04_통합_보강_연결.md 5절)
"""
import json

from common import INTEGRATED, NORMALIZED, read_rows

results = []


def check(name, cond, detail=""):
    print(f"  {'OK  ' if cond else 'FAIL'} {name}{f'  ({detail})' if detail else ''}")
    results.append(bool(cond))


LOGS = [("nginx", "nginx", "s"), ("sshd", "sshd", "us"), ("sysmon", "sysmon", "ms"), ("audit", "teiren_audit", "ms")]
USER_TYPE = {"nginx": "", "sshd": "linux", "sysmon": "linux", "teiren_audit": "teiren_console"}
ADDED = {"time_precision", "source_row", "user_type", "dvc"}

tl = read_rows(INTEGRATED / "timeline.csv")
cols = list(tl[0].keys())
src_files = {name: read_rows(NORMALIZED / f"{name}_normalized_event_action.csv") for name, *_ in LOGS}

print("[행]")
total = sum(len(v) for v in src_files.values())
check("통합 행 수 = 네 파일 행 수 합", len(tl) == total, f"{len(tl)} = {' + '.join(str(len(v)) for v in src_files.values())}")
keys = [(r["log_source"], r["source_row"]) for r in tl]
check("log_source + source_row 고유 (중복 없음)", len(set(keys)) == len(keys))
for name, source, _ in LOGS:
    n = sum(r["log_source"] == source for r in tl)
    rows_no = sorted(int(r["source_row"]) for r in tl if r["log_source"] == source)
    check(f"{source}: {n}행, source_row 1..{len(src_files[name])} 빠짐 없음", rows_no == list(range(1, len(src_files[name]) + 1)))

print("[값 보존: 통합 표 → 정규화 파일 복원]")
for name, source, _ in LOGS:
    orig = src_files[name]
    part = sorted((r for r in tl if r["log_source"] == source), key=lambda r: int(r["source_row"]))
    ocols = list(orig[0].keys())

    def restore(r):
        d = {c: r[c] for c in ocols}
        if name == "sysmon":
            d["src"] = r["dvc"]
        return d

    bad = sum(restore(r) != o for r, o in zip(part, orig))
    check(f"{source}: 원래 컬럼 {len(ocols)}개 값 모두 일치", bad == 0, f"불일치 {bad}행" if bad else "")
    # 원래 파일에 없는 컬럼은 통합 단계에서 만든 값 말고는 비어 있어야 한다
    extra = [c for c in cols if c not in ocols and c not in ADDED and not (name == "sshd" and c == "dvchost")
             and not (name == "sysmon" and c == "src")]
    filled = {c for r in part for c in extra if r[c]}
    check(f"{source}: 다른 로그의 고유 컬럼은 모두 빈칸", not filled, str(sorted(filled)) if filled else "")

print("[정렬]")
order = {s: i for i, (_, s, _) in enumerate(LOGS)}
sk = [(r["event_time_utc"], order[r["log_source"]], int(r["source_row"])) for r in tl]
check("event_time_utc → log_source → source_row 순 정렬", sk == sorted(sk))

print("[통합 단계에서 만든 값]")
check("Sysmon src는 모두 비고 dvc로 이동, 다른 로그 dvc는 빈칸", all(
    r["src"] == "" if r["log_source"] == "sysmon" else r["dvc"] == "" for r in tl))
sy = [r for r in tl if r["log_source"] == "sysmon"]
check("Sysmon dvc 값은 network_connect 행에만 있음 (원본 SourceIp가 네트워크 이벤트에만 있음)",
      all(bool(r["dvc"]) == (r["event_action"] == "network_connect") for r in sy),
      f"dvc 있는 행 {sum(bool(r['dvc']) for r in sy)}")
check("SSHD dvchost = unmapped.hostname", all(
    r["dvchost"] == json.loads(r["unmapped"])["hostname"] for r in tl if r["log_source"] == "sshd"))
check("time_precision 규칙 (nginx s / sshd us / sysmon·audit ms)", all(
    r["time_precision"] == dict((s, p) for _, s, p in LOGS)[r["log_source"]] for r in tl))
check("NGINX 시각은 모두 .000000 (초 단위 원본)", all(
    r["event_time_utc"].endswith(".000000") for r in tl if r["log_source"] == "nginx"))
check("user_type: 사용자 값이 있을 때만 계정 체계 표시", all(
    r["user_type"] == (USER_TYPE[r["log_source"]] if (r["suser"] or r["duser"]) else "") for r in tl))

print("[기준 사건]")


def window(start, end, cond=lambda r: True):
    return [r for r in tl if start <= r["event_time_utc"] < end and cond(r)]


def show(rows, limit=12):
    for r in rows[:limit]:
        who = r["suser"] or r["duser"]
        where = r["dvchost"] or r["src"]
        what = r["event_action"] or f'{r["http_method"]} {r["http_status_code"]}'
        extra = r["request"] or (f'{r["dst"]}:{r["dpt"]}' if r["dst"] else "")
        print(f"    {r['event_time_utc'][5:23]}  {r['log_source']:<13} {what:<22} {who:<22} {where:<15} {extra}")


# 1) analyst01 디버그 실행: 감사로그와 NGINX가 같은 초
rows = window("2026-10-15 05:08:14", "2026-10-15 05:08:15")
srcs = {r["log_source"] for r in rows}
check("디버그 실행(10-15 05:08:14): 감사로그와 NGINX가 같은 초", {"teiren_audit", "nginx"} <= srcs, str(sorted(srcs)))
show(rows)

# 2) intern01 탐지 규칙·계정 삭제
rows = window("2026-10-16 06:19:43", "2026-10-16 06:21:07",
              lambda r: r["log_source"] == "teiren_audit" and r["event_action"] in ("RULE_DELETE", "IAM_USER_DELETE"))
check("intern01 규칙·계정 삭제(10-16 06:19:43~06:21:06)가 감사로그에 있음", len(rows) >= 2, f"{len(rows)}건")
show(rows)

# 3) 외부 IP dev02 로그인 → app-01 외부 연결
login = window("2026-10-14 18:12:18", "2026-10-14 18:12:19",
               lambda r: r["log_source"] == "sshd" and r["event_action"] == "auth_success" and r["duser"] == "dev02")
conn = window("2026-10-14 18:13:29", "2026-10-14 18:13:30",
              lambda r: r["log_source"] == "sysmon" and r["dvchost"] == "app-01" and r["dst"] == "203.0.113.80")
check("dev02 외부 로그인(18:12:18) → app-01에서 203.0.113.80 연결(18:13:29) 순서",
      login and conn and login[0]["event_time_utc"] < conn[0]["event_time_utc"])
show(login + conn)

# 4) ops02 로그인 → node-01 서버 간 SSH → 198.51.100.10:4444
login = window("2026-10-15 17:41:09", "2026-10-15 17:41:10",
               lambda r: r["log_source"] == "sshd" and r["event_action"] == "auth_success" and r["duser"] == "ops02")
ssh = window("2026-10-15 17:42:29", "2026-10-15 17:42:44",
             lambda r: r["log_source"] == "sysmon" and r["dvchost"] == "node-01" and r["dpt"] == "22")
c2 = window("2026-10-15 17:42:50", "2026-10-15 17:42:51",
            lambda r: r["log_source"] == "sysmon" and r["dst"] == "198.51.100.10" and r["dpt"] == "4444")
check("ops02 로그인(17:41:09) → node-01 22번 포트 연결(17:42:29~43) → 198.51.100.10:4444(17:42:50) 순서",
      login and ssh and c2 and login[0]["event_time_utc"] < ssh[0]["event_time_utc"] <= ssh[-1]["event_time_utc"] < c2[0]["event_time_utc"],
      f"로그인 {len(login)} / SSH 연결 {len(ssh)} / 4444 연결 {len(c2)}")
show(login + ssh + c2)

print("\n전체:", f"{len(results)}개 검사 모두 통과" if all(results) else f"실패 {results.count(False)}개")
