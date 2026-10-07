"""Snowflake에서 내려받은 파싱 결과 CSV가 data/02_parsed/의 파싱 결과와 같은지 비교한다.

실행: python scripts/98_compare_snowflake_export.py <로그이름> <내려받은 CSV 경로>
  예) python scripts/98_compare_snowflake_export.py sshd C:/Users/me/Downloads/sshd_snowflake.csv
로그이름: sshd / nginx / sysmon / audit

비교 내용:
  1. 컬럼 이름과 순서
  2. 행 수
  3. 행 내용 (순서와 상관없이 같은 행이 같은 개수만큼 있는지)
  4. 행 순서 (참고용. nginx는 같은 초에 찍힌 5쌍의 순서가 다를 수 있다)
"""
import sys
from collections import Counter

from common import PARSED, read_rows

if len(sys.argv) != 3 or sys.argv[1] not in ("sshd", "nginx", "sysmon", "audit"):
    sys.exit(__doc__)

name, export_path = sys.argv[1], sys.argv[2]
expected = read_rows(PARSED / f"{name}_parsed.csv")
actual = read_rows(export_path)

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

as_tuple = lambda r: tuple(r[c] for c in exp_cols)
exp_cnt, act_cnt = Counter(map(as_tuple, expected)), Counter(map(as_tuple, actual))
missing, extra = exp_cnt - act_cnt, act_cnt - exp_cnt
ok_rows = not missing and not extra
print(f"  {'OK  ' if ok_rows else 'FAIL'} 행 내용 (순서 무관)")
if not ok_rows:
    print(f"    기준에만 있는 행 {sum(missing.values())}개 / 내려받은 파일에만 있는 행 {sum(extra.values())}개")
    extra_rows = list(extra)
    for row in list(missing)[:3]:
        # 내려받은 파일에만 있는 행 중 칸이 가장 많이 같은 행과 비교해 다른 칸만 보여 준다
        best = max(extra_rows, key=lambda e: sum(a == b for a, b in zip(row, e)), default=None)
        diffs = {c: (a, b) for c, a, b in zip(exp_cols, row, best or ()) if a != b}
        print("    예시 차이 {컬럼: (기준값, 내려받은 값)}:", diffs if best else dict(zip(exp_cols, row)))

same_order = [as_tuple(r) for r in expected] == [as_tuple(r) for r in actual]
print(f"  {'OK  ' if same_order else '참고'} 행 순서{'' if same_order else ' (같은 시각의 행 순서만 다르면 문제없음)'}")

print("\n결과:", "일치" if ok_cols and ok_rows else "불일치")
