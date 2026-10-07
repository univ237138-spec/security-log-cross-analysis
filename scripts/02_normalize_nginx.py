"""nginx 정규화.

입력: data/02_parsed/nginx_parsed.csv, data/01_raw/nginx_raw.csv
출력: data/03_normalized/nginx_normalized.csv (13개 컬럼)
계획: docs/03_파싱_정규화.md
"""
from datetime import datetime, timezone

from common import NORMALIZED, PARSED, RAW, pack_unmapped, read_rows, write_rows

UNMAPPED = ["status", "ident", "remote_user", "server_protocol", "request", "LOADED_AT"]
COLS = ["event_time_utc", "src", "requestMethod", "request", "requestClientApplication", "requestContext", "in",
        "cat", "act", "outcome", "is_api_request", "rawEvent", "unmapped"]

parsed = read_rows(PARSED / "nginx_parsed.csv")
raw = read_rows(RAW / "nginx_raw.csv")
assert len(parsed) == len(raw)

out = []
for p, r in zip(parsed, raw):
    line = (f'{p["remote_addr"]} {p["ident"]} {p["remote_user"]} [{p["time_local"]}] "{p["request"]}" '
            f'{p["status"]} {p["body_bytes_sent"]} "{p["http_referer"]}" "{p["http_user_agent"]}"')
    assert line == r["RAW_LINE"]  # 원문과 파싱 행이 같은 이벤트
    assert p["body_bytes_sent"].isdigit()
    t = datetime.strptime(p["time_local"], "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc)
    out.append({
        "event_time_utc": t.strftime("%Y-%m-%d %H:%M:%S.%f"),  # 원본은 초 단위
        "src": p["remote_addr"],
        "requestMethod": p["request_method"],
        "request": p["request_uri"],
        "requestClientApplication": p["http_user_agent"],
        "requestContext": p["http_referer"],
        "in": p["body_bytes_sent"],  # CEF bytesIn: 클라이언트(src) 기준으로 받은 바이트
        "cat": "web", "act": "access",
        "outcome": "",  # 멘토 피드백: status는 보지 않음 (unmapped에 보관)
        "is_api_request": "true" if p["request_uri"].startswith("/api") else "false",
        "rawEvent": r["RAW_LINE"],
        "unmapped": pack_unmapped(p, UNMAPPED),
    })

write_rows(NORMALIZED / "nginx_normalized.csv", COLS, out)
print(f"nginx_normalized.csv: {len(out)} rows, {len(COLS)} cols")
