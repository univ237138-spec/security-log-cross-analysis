"""공통 경로와 CSV 입출력 규칙.

- 모든 CSV는 UTF-8 BOM(utf-8-sig)으로 읽고 쓴다 (엑셀에서 한글이 깨지지 않게).
- JSON 컬럼(unmapped, rawEvent)은 공백 없는 한 줄 JSON, 한글은 그대로 쓴다.
"""
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "01_raw"
PARSED = ROOT / "data" / "02_parsed"
NORMALIZED = ROOT / "data" / "03_normalized"
INTEGRATED = ROOT / "data" / "04_integrated"
ENRICHED = ROOT / "data" / "05_enriched"
CLASSIFIED = ROOT / "data" / "06_classified"
SESSIONS = ROOT / "data" / "07_sessions"
BASELINE = ROOT / "data" / "08_baseline"
DETECTIONS = ROOT / "data" / "09_detections"
RISK = ROOT / "data" / "10_risk"
INVESTIGATION = ROOT / "data" / "11_investigation"
STATS = ROOT / "data" / "12_stats"

csv.field_size_limit(10**9)  # Sysmon XML 원문이 길다
sys.stdout.reconfigure(encoding="utf-8")


def read_rows(path):
    with open(path, encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def write_rows(path, header, rows):
    """rows: list 또는 dict의 리스트."""
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        if rows and isinstance(rows[0], dict):
            w = csv.DictWriter(f, fieldnames=header, extrasaction="ignore")
            w.writeheader()
            w.writerows(rows)
        else:
            w = csv.writer(f)
            w.writerow(header)
            w.writerows(rows)


def to_json(obj):
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def pack_unmapped(row, keys):
    """빈 값은 키째로 넣지 않고, 값은 원본 문자열 그대로 담는다."""
    return to_json({k: row[k] for k in keys if row[k]})
