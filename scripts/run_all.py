"""raw → parsed → normalized 전체를 다시 만들고 검증한다.

실행: python scripts/run_all.py
"""
import runpy
from pathlib import Path

HERE = Path(__file__).resolve().parent
STEPS = [
    "01_parse_audit.py", "01_parse_nginx.py", "01_parse_sshd.py", "01_parse_sysmon.py",
    "02_normalize_audit.py", "02_normalize_nginx.py", "02_normalize_sshd.py", "02_normalize_sysmon.py",
    "99_verify.py",
]

for step in STEPS:
    print(f"\n=== {step}")
    runpy.run_path(str(HERE / step), run_name="__main__")
