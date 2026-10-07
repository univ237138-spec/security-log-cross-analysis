-- =====================================================================
-- nginx 파싱 (Snowflake) — scripts/01_parse_nginx.py와 같은 결과를 만든다
-- 입력: security_logs.raw.nginx_raw (RAW_LINE, LOADED_AT)
-- 출력: data/02_parsed/nginx_parsed.csv와 같은 13개 컬럼
-- 기준: nginx log_format combined
--   접속IP - 사용자 [시각] "요청" 상태코드 응답크기 "이전페이지" "브라우저정보"
--   (변수: remote_addr, remote_user, time_local, request, status, body_bytes_sent, http_referer, http_user_agent)
--   정규식은 작은따옴표 문자열로 쓰므로 백슬래시를 두 번 쓴다.
-- 규칙: 값은 원문 글자 그대로 ('-'도 그대로), request는 원본을 남기고 메서드·URI·프로토콜로 추가 분리
-- 주의:
--   - 정규식은 Python으로 같은 데이터에 시뮬레이션해 parsed CSV와 일치함을 확인했다.
--     Snowflake에서 직접 실행해 확인한 것은 아니다 (README.md 참고).
--   - 같은 초에 찍힌 행 5쌍은 원본 순서를 정할 기준이 없어, 그 쌍 안에서는 순서가 다를 수 있다.
-- =====================================================================


-- ---------------------------------------------------------------------
-- 0. 점검: 아래 세 값이 모두 0이어야 한다
-- ---------------------------------------------------------------------
SELECT
    COUNT(*)                                                     AS n_rows,
    COUNT_IF(NOT REGEXP_LIKE(raw_line, '^(\\S+) (\\S+) (\\S+) \\[(\\S+ [+-][0-9]{4})\\] "([^"]*)" ([0-9]{3}) (\\S+) "([^"]*)" "([^"]*)"(.*)'))                  AS n_format_fail,
    COUNT_IF(REGEXP_SUBSTR(raw_line, '^(\\S+) (\\S+) (\\S+) \\[(\\S+ [+-][0-9]{4})\\] "([^"]*)" ([0-9]{3}) (\\S+) "([^"]*)" "([^"]*)"(.*)', 1, 1, 'e', 10) <> '')                                      AS n_extra_fields,     -- UA 뒤에 붙은 추가 필드
    COUNT_IF(NOT REGEXP_LIKE(REGEXP_SUBSTR(raw_line, '^(\\S+) (\\S+) (\\S+) \\[(\\S+ [+-][0-9]{4})\\] "([^"]*)" ([0-9]{3}) (\\S+) "([^"]*)" "([^"]*)"(.*)', 1, 1, 'e', 5), '^(\\S+) (\\S+) (\\S+)'))                   AS n_request_split_fail
FROM security_logs.raw.nginx_raw;


-- ---------------------------------------------------------------------
-- 1. 파싱 (결과를 CSV로 내려받아 scripts/98_compare_snowflake_export.py로 비교)
-- ---------------------------------------------------------------------
-- CREATE OR REPLACE VIEW <내_DB>.<내_스키마>.nginx_parsed AS
WITH f AS (
    SELECT
        raw_line,
        loaded_at,
        REGEXP_SUBSTR(raw_line, '^(\\S+) (\\S+) (\\S+) \\[(\\S+ [+-][0-9]{4})\\] "([^"]*)" ([0-9]{3}) (\\S+) "([^"]*)" "([^"]*)"(.*)', 1, 1, 'e', 1) AS remote_addr,
        REGEXP_SUBSTR(raw_line, '^(\\S+) (\\S+) (\\S+) \\[(\\S+ [+-][0-9]{4})\\] "([^"]*)" ([0-9]{3}) (\\S+) "([^"]*)" "([^"]*)"(.*)', 1, 1, 'e', 2) AS ident,
        REGEXP_SUBSTR(raw_line, '^(\\S+) (\\S+) (\\S+) \\[(\\S+ [+-][0-9]{4})\\] "([^"]*)" ([0-9]{3}) (\\S+) "([^"]*)" "([^"]*)"(.*)', 1, 1, 'e', 3) AS remote_user,
        REGEXP_SUBSTR(raw_line, '^(\\S+) (\\S+) (\\S+) \\[(\\S+ [+-][0-9]{4})\\] "([^"]*)" ([0-9]{3}) (\\S+) "([^"]*)" "([^"]*)"(.*)', 1, 1, 'e', 4) AS time_local,
        REGEXP_SUBSTR(raw_line, '^(\\S+) (\\S+) (\\S+) \\[(\\S+ [+-][0-9]{4})\\] "([^"]*)" ([0-9]{3}) (\\S+) "([^"]*)" "([^"]*)"(.*)', 1, 1, 'e', 5) AS request,
        REGEXP_SUBSTR(raw_line, '^(\\S+) (\\S+) (\\S+) \\[(\\S+ [+-][0-9]{4})\\] "([^"]*)" ([0-9]{3}) (\\S+) "([^"]*)" "([^"]*)"(.*)', 1, 1, 'e', 6) AS status,
        REGEXP_SUBSTR(raw_line, '^(\\S+) (\\S+) (\\S+) \\[(\\S+ [+-][0-9]{4})\\] "([^"]*)" ([0-9]{3}) (\\S+) "([^"]*)" "([^"]*)"(.*)', 1, 1, 'e', 7) AS body_bytes_sent,
        REGEXP_SUBSTR(raw_line, '^(\\S+) (\\S+) (\\S+) \\[(\\S+ [+-][0-9]{4})\\] "([^"]*)" ([0-9]{3}) (\\S+) "([^"]*)" "([^"]*)"(.*)', 1, 1, 'e', 8) AS http_referer,
        REGEXP_SUBSTR(raw_line, '^(\\S+) (\\S+) (\\S+) \\[(\\S+ [+-][0-9]{4})\\] "([^"]*)" ([0-9]{3}) (\\S+) "([^"]*)" "([^"]*)"(.*)', 1, 1, 'e', 9) AS http_user_agent
    FROM security_logs.raw.nginx_raw
)
SELECT
    remote_addr      AS "remote_addr",
    ident            AS "ident",
    remote_user      AS "remote_user",
    time_local       AS "time_local",
    request          AS "request",
    REGEXP_SUBSTR(request, '^(\\S+) (\\S+) (\\S+)', 1, 1, 'e', 1) AS "request_method",
    REGEXP_SUBSTR(request, '^(\\S+) (\\S+) (\\S+)', 1, 1, 'e', 2) AS "request_uri",
    REGEXP_SUBSTR(request, '^(\\S+) (\\S+) (\\S+)', 1, 1, 'e', 3) AS "server_protocol",
    status           AS "status",
    body_bytes_sent  AS "body_bytes_sent",
    COALESCE(http_referer, '')    AS "http_referer",      -- 따옴표 안이 비어 있으면 '' (현재 데이터에는 없음)
    COALESCE(http_user_agent, '') AS "http_user_agent",
    TO_VARCHAR(loaded_at, 'YYYY-MM-DD HH24:MI:SS.FF3') AS "LOADED_AT"
FROM f
ORDER BY TO_TIMESTAMP_TZ(time_local, 'DD/MON/YYYY:HH24:MI:SS TZHTZM'), raw_line;
