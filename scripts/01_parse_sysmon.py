"""Sysmon 파싱: 이벤트 XML의 System과 EventData를 모두 펼친다 (원본 보존).

입력: data/01_raw/sysmon_raw.csv (RAW_LINE, LOADED_AT)
출력: data/02_parsed/sysmon_parsed.csv (System 16 + EventData 37 + LOADED_AT = 54개)
규칙:
- System 하위 태그의 값은 태그 이름, 속성은 '태그_속성' 이름으로 컬럼을 만든다.
- 값도 속성도 없는 빈 태그(Correlation)도 컬럼으로 남긴다.
- EventData의 <Data Name="…">은 Name을 컬럼 이름으로 쓴다. 해당 EventID에 없는 필드는 빈 칸.
- 값은 원본 그대로 ('-'도 그대로).
"""
import xml.etree.ElementTree as ET

from common import PARSED, RAW, read_rows, write_rows

rows = read_rows(RAW / "sysmon_raw.csv")
sys_cols, ed_cols, parsed = [], [], []


def add(cols, k):
    if k not in cols:
        cols.append(k)


for r in rows:
    root = ET.fromstring(r["RAW_LINE"])
    rec = {}
    for el in root.find("System"):
        if el.text is not None and el.text.strip():
            add(sys_cols, el.tag)
            rec[el.tag] = el.text
        for a, v in el.attrib.items():
            k = f"{el.tag}_{a}"
            add(sys_cols, k)
            rec[k] = v
        if el.text is None and not el.attrib:
            add(sys_cols, el.tag)
            rec[el.tag] = ""
    for d in root.find("EventData"):
        k = d.get("Name")
        assert k not in rec, k
        add(ed_cols, k)
        rec[k] = d.text if d.text is not None else ""
    parsed.append((rec, r["LOADED_AT"]))

assert not set(sys_cols) & set(ed_cols)
cols = sys_cols + ed_cols
out = [[rec.get(c, "") for c in cols] + [la] for rec, la in parsed]
write_rows(PARSED / "sysmon_parsed.csv", cols + ["LOADED_AT"], out)
print(f"sysmon_parsed.csv: {len(out)} rows, {len(cols) + 1} cols")
