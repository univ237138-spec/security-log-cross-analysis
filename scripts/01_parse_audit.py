"""감사로그 파싱: EVENT(JSON)의 키 15개를 컬럼으로 펼친다.

입력: data/01_raw/audit_raw.csv (EVENT, LOADED_AT)
출력: data/02_parsed/audit_parsed.csv (원본 키 15개 + LOADED_AT)
기준: docs/03_파싱_정규화.md 2절
"""
import json

from common import PARSED, RAW, read_rows, write_rows

rows = read_rows(RAW / "audit_raw.csv")
events = [json.loads(r["EVENT"]) for r in rows]

keys = list(events[0].keys())
assert all(list(e.keys()) == keys for e in events), "행마다 키 구성이 다르다"

out = [[e[k] for k in keys] + [r["LOADED_AT"]] for e, r in zip(events, rows)]
write_rows(PARSED / "audit_parsed.csv", keys + ["LOADED_AT"], out)
print(f"audit_parsed.csv: {len(out)} rows, {len(keys) + 1} cols")
