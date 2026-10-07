"""Snowflake에서 내려받은 정규화 결과 CSV가 data/03_normalized/의 최종 정규화 결과와 같은지 비교한다.

실행: python scripts/98_compare_snowflake_normalized.py <로그이름> <내려받은 CSV 경로>
  예) python scripts/98_compare_snowflake_normalized.py sshd C:/Users/me/Downloads/sshd_normalized.csv
로그이름: sshd / nginx / sysmon / audit
기준 파일: data/03_normalized/<로그이름>_normalized_event_action.csv
SQL: sql/snow/11~14_*_normalize.sql

비교 내용:
  1. 컬럼 이름과 순서
  2. 행 수
  3. 행 내용 (순서와 상관없이 같은 행이 같은 개수만큼 있는지)
     - SQL은 빈 값을 NULL로 내보낸다. 내려받은 파일의 빈칸·'NULL'·'\\N'은 모두 빈 값으로 본다.
     - JSON 컬럼(unmapped, 감사로그 rawEvent)은 글자까지 같은지 먼저 보고,
       다르면 JSON으로 풀어 내용이 같은지 다시 본다 (키 순서·이스케이프 차이만 있는 경우).
  4. 행 순서 (참고용. nginx는 같은 초에 찍힌 5쌍의 순서가 다를 수 있다)
"""
import json
import sys
from collections import Counter

from common import NORMALIZED, read_rows

NULLISH = {"", "NULL", "\\N"}
JSON_COLS = {"unmapped"}
JSON_COLS_BY_LOG = {"audit": {"rawEvent"}}

if len(sys.argv) != 3 or sys.argv[1] not in ("sshd", "nginx", "sysmon", "audit"):
    sys.exit(__doc__)

name, export_path = sys.argv[1], sys.argv[2]
expected = read_rows(NORMALIZED / f"{name}_normalized_event_action.csv")
actual = read_rows(export_path)
json_cols = JSON_COLS | JSON_COLS_BY_LOG.get(name, set())

exp_cols = list(expected[0].keys())
act_cols = list(actual[0].keys()) if actual else []
print(f"[{name}] 기준: {len(expected)}행 × {len(exp_cols)}열 / 내려받은 파일: {len(actual)}행 × {len(act_cols)}열")

ok_cols = exp_cols == act_cols
print(f"  {'OK  ' if ok_cols else 'FAIL'} 컬럼 이름·순서")
if not ok_cols:
    print("    기준에만 있음:", [c for c in exp_cols if c not in act_cols])
    print("    내려받은 파일에만 있음:", [c for c in act_cols if c not in exp_cols])
    sys.exit(1)

print(f"  {'OK  ' if len(expected) == len(actual) else 'FAIL'} 행 수")


def cell(v):
    return "" if v in NULLISH else v


def as_tuple(r, semantic=False):
    out = []
    for c in exp_cols:
        v = cell(r[c])
        if semantic and c in json_cols and v:
            v = json.dumps(json.loads(v), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        out.append(v)
    return tuple(out)


def compare(semantic):
    exp_cnt = Counter(as_tuple(r, semantic) for r in expected)
    act_cnt = Counter(as_tuple(r, semantic) for r in actual)
    return exp_cnt - act_cnt, act_cnt - exp_cnt


missing, extra = compare(semantic=False)
exact = not missing and not extra
ok_rows = exact
if exact:
    print("  OK   행 내용 (순서 무관, 글자까지 같음)")
else:
    sem_missing, sem_extra = compare(semantic=True)
    if not sem_missing and not sem_extra:
        ok_rows = True
        print(f"  OK   행 내용 (순서 무관). 단 JSON 컬럼 {sorted(json_cols)}은 키 순서·이스케이프만 다르다")
    else:
        missing, extra = sem_missing, sem_extra
        print("  FAIL 행 내용 (순서 무관)")
        print(f"    기준에만 있는 행 {sum(missing.values())}개 / 내려받은 파일에만 있는 행 {sum(extra.values())}개")
        extra_rows = list(extra)
        for row in list(missing)[:3]:
            # 내려받은 파일에만 있는 행 중 칸이 가장 많이 같은 행과 비교해 다른 칸만 보여 준다
            best = max(extra_rows, key=lambda e: sum(a == b for a, b in zip(row, e)), default=None)
            diffs = {c: (a, b) for c, a, b in zip(exp_cols, row, best or ()) if a != b}
            print("    예시 차이 {컬럼: (기준값, 내려받은 값)}:", diffs if best else dict(zip(exp_cols, row)))

same_order = [as_tuple(r, True) for r in expected] == [as_tuple(r, True) for r in actual]
print(f"  {'OK  ' if same_order else '참고'} 행 순서{'' if same_order else ' (같은 시각의 행 순서만 다르면 문제없음)'}")

print("\n결과:", "일치" if ok_cols and ok_rows else "불일치")
