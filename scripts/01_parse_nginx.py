"""nginx 파싱: combined 로그 포맷 정의대로 나누고, request를 메서드·URI·프로토콜로 추가 분리한다.

입력: data/01_raw/nginx_raw.csv (RAW_LINE, LOADED_AT)
출력: data/02_parsed/nginx_parsed.csv (13개 컬럼)
기준: nginx log_format combined
  '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"'
"""
import re

from common import PARSED, RAW, read_rows, write_rows

COMBINED = re.compile(
    r'^(\S+) (\S+) (\S+) \[(\S+ [+-]\d{4})\] "([^"]*)" (\d{3}) (\S+) "([^"]*)" "([^"]*)"(.*)$'
)
REQUEST = re.compile(r"^(\S+) (\S+) (\S+)$")
HEADER = ["remote_addr", "ident", "remote_user", "time_local", "request",
          "request_method", "request_uri", "server_protocol",
          "status", "body_bytes_sent", "http_referer", "http_user_agent", "LOADED_AT"]

out = []
for r in read_rows(RAW / "nginx_raw.csv"):
    m = COMBINED.match(r["RAW_LINE"])
    assert m and m.group(10) == "", r["RAW_LINE"]  # UA 뒤 추가 필드 없음
    ip, ident, user, t, req, status, size, ref, ua, _ = m.groups()
    q = REQUEST.match(req)
    assert q, req
    out.append([ip, ident, user, t, req, *q.groups(), status, size, ref, ua, r["LOADED_AT"]])

    # 검증: 원문 재조립
    assert f'{ip} {ident} {user} [{t}] "{req}" {status} {size} "{ref}" "{ua}"' == r["RAW_LINE"]

write_rows(PARSED / "nginx_parsed.csv", HEADER, out)
print(f"nginx_parsed.csv: {len(out)} rows, {len(HEADER)} cols")
