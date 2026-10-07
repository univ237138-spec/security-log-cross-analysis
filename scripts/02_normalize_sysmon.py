"""Sysmon 정규화.

입력: data/02_parsed/sysmon_parsed.csv, data/01_raw/sysmon_raw.csv
출력: data/03_normalized/sysmon_normalized.csv (23개 컬럼)
계획: docs/03_파싱_정규화.md
"""
import re
import xml.etree.ElementTree as ET

from common import NORMALIZED, PARSED, RAW, pack_unmapped, read_rows, write_rows

COMMON = {"UtcTime", "Computer", "User", "SourceIp", "DestinationIp", "DestinationPort"}
UNIQUE = ["EventID", "Image", "ProcessId", "ProcessGuid", "CommandLine", "CurrentDirectory",
          "ParentProcessGuid", "ParentProcessId", "ParentImage", "ParentCommandLine", "ParentUser",
          "TargetFilename", "EventRecordID"]
COLS = ["event_time_utc", "dvchost", "suser", "src", "dst", "dpt", "cat", "act"] + UNIQUE + ["rawEvent", "unmapped"]
# EventID → (cat, act). cat은 ECS event.category 허용 값
CLASSIFY = {"1": ("process", "start"), "3": ("network", "start"),
            "5": ("process", "end"), "11": ("file", "creation")}
MS = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}$")

parsed = read_rows(PARSED / "sysmon_parsed.csv")
raw = read_rows(RAW / "sysmon_raw.csv")
assert len(parsed) == len(raw)
UNMAPPED = [c for c in parsed[0] if c not in COMMON and c not in UNIQUE]
assert len(UNMAPPED) == 35

out = []
for p, r in zip(parsed, raw):
    s = ET.fromstring(r["RAW_LINE"]).find("System")  # 원문과 파싱 행이 같은 이벤트
    assert (s.findtext("Computer"), s.findtext("EventRecordID")) == (p["Computer"], p["EventRecordID"])
    assert MS.match(p["UtcTime"]) and p["User"] != ""
    cat, act = CLASSIFY[p["EventID"]]
    o = {
        "event_time_utc": p["UtcTime"] + "000",  # 밀리초 → 마이크로초 자릿수
        "dvchost": p["Computer"],
        "suser": "" if p["User"] == "-" else p["User"],
        "src": p["SourceIp"],  # 주의: 연결을 시작한 서버 자신의 IP (원격 접속자 IP 아님)
        "dst": p["DestinationIp"], "dpt": p["DestinationPort"],
        "cat": cat, "act": act,
    }
    o.update({k: p[k] for k in UNIQUE})
    o["rawEvent"] = r["RAW_LINE"]
    o["unmapped"] = pack_unmapped(p, UNMAPPED)
    out.append(o)

write_rows(NORMALIZED / "sysmon_normalized.csv", COLS, out)
print(f"sysmon_normalized.csv: {len(out)} rows, {len(COLS)} cols")
