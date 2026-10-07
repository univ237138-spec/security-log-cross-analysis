-- =====================================================================
-- nginx 정규화 (Snowflake) — 원시 로그에서 최종 정규화 결과를 한 번에 만든다
-- 입력: security_logs.raw.nginx_raw (RAW_LINE, LOADED_AT)
-- 출력: data/03_normalized/nginx_normalized_event_action.csv와 같은 11개 컬럼
--   event_time_utc, log_source, src, http_method, http_status_code, request,
--   requestContext, in, is_api_request, rawEvent, unmapped
-- 단계: 파싱(02_nginx_parse.sql과 같은 정규식) → 정규화(scripts/02_normalize_nginx.py
--       + scripts/03_apply_event_action.py와 같은 규칙)
-- 규칙:
--   - event_time_utc: time_local(+0000)을 UTC로 바꿔 'YYYY-MM-DD HH:MM:SS.ffffff' 문자열로 만든다 (원본은 초 단위)
--   - nginx는 원본에 행위 필드가 없어 event_action을 두지 않는다. http_method·http_status_code가 대신한다
--   - is_api_request: 요청 URI가 /api로 시작하면 'true', 아니면 'false'
--   - unmapped: 분석 컬럼으로 꺼내지 않은 원본 필드를 Python과 같은 키 순서의 한 줄 JSON 문자열로 만든다.
--     값이 빈 키는 넣지 않는다. ('-'는 원본 값이므로 그대로 넣는다)
--   - 값이 없는 칸은 NULL이다 (현재 데이터에는 없음)
-- 주의:
--   - Snowflake에서 직접 실행해 확인한 것은 아니다. 처음 실행하면
--     scripts/98_compare_snowflake_normalized.py로 결과를 반드시 비교한다.
--   - 같은 초에 찍힌 행 5쌍은 원본 순서를 정할 기준이 없어, 그 쌍 안에서는 순서가 다를 수 있다.
-- =====================================================================


-- ---------------------------------------------------------------------
-- 0. 점검: 아래 세 값이 모두 0이어야 한다 (02_nginx_parse.sql의 0번 쿼리와 같다)
-- ---------------------------------------------------------------------
SELECT
    COUNT(*)                                                     AS n_rows,
    COUNT_IF(NOT REGEXP_LIKE(raw_line, '^(\\S+) (\\S+) (\\S+) \\[(\\S+ [+-][0-9]{4})\\] "([^"]*)" ([0-9]{3}) (\\S+) "([^"]*)" "([^"]*)"(.*)'))                  AS n_format_fail,
    COUNT_IF(REGEXP_SUBSTR(raw_line, '^(\\S+) (\\S+) (\\S+) \\[(\\S+ [+-][0-9]{4})\\] "([^"]*)" ([0-9]{3}) (\\S+) "([^"]*)" "([^"]*)"(.*)', 1, 1, 'e', 10) <> '')                                      AS n_extra_fields,     -- UA 뒤에 붙은 추가 필드
    COUNT_IF(NOT REGEXP_LIKE(REGEXP_SUBSTR(raw_line, '^(\\S+) (\\S+) (\\S+) \\[(\\S+ [+-][0-9]{4})\\] "([^"]*)" ([0-9]{3}) (\\S+) "([^"]*)" "([^"]*)"(.*)', 1, 1, 'e', 5), '^(\\S+) (\\S+) (\\S+)'))                   AS n_request_split_fail
FROM security_logs.raw.nginx_raw;


-- ---------------------------------------------------------------------
-- 1. 정규화
--    테이블로 저장하려면 아래 주석을 풀고 DB·스키마 이름을 바꾼다 (쓰기 권한 필요)
-- ---------------------------------------------------------------------
-- CREATE OR REPLACE TABLE <내_DB>.<내_스키마>.nginx_normalized AS
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
        COALESCE(REGEXP_SUBSTR(raw_line, '^(\\S+) (\\S+) (\\S+) \\[(\\S+ [+-][0-9]{4})\\] "([^"]*)" ([0-9]{3}) (\\S+) "([^"]*)" "([^"]*)"(.*)', 1, 1, 'e', 8), '') AS http_referer,
        COALESCE(REGEXP_SUBSTR(raw_line, '^(\\S+) (\\S+) (\\S+) \\[(\\S+ [+-][0-9]{4})\\] "([^"]*)" ([0-9]{3}) (\\S+) "([^"]*)" "([^"]*)"(.*)', 1, 1, 'e', 9), '') AS http_user_agent
    FROM security_logs.raw.nginx_raw
),
-- 파싱 결과 (02_nginx_parse.sql과 같은 값)
p AS (
    SELECT
        f.*,
        REGEXP_SUBSTR(request, '^(\\S+) (\\S+) (\\S+)', 1, 1, 'e', 1) AS request_method,
        REGEXP_SUBSTR(request, '^(\\S+) (\\S+) (\\S+)', 1, 1, 'e', 2) AS request_uri,
        REGEXP_SUBSTR(request, '^(\\S+) (\\S+) (\\S+)', 1, 1, 'e', 3) AS server_protocol,
        TO_VARCHAR(loaded_at, 'YYYY-MM-DD HH24:MI:SS.FF3')           AS loaded_at_str
    FROM f
)
SELECT
    TO_VARCHAR(CONVERT_TIMEZONE('UTC', TO_TIMESTAMP_TZ(time_local, 'DD/MON/YYYY:HH24:MI:SS TZHTZM'))::TIMESTAMP_NTZ,
               'YYYY-MM-DD HH24:MI:SS.FF6')                     AS "event_time_utc",
    'nginx'                                                     AS "log_source",
    remote_addr                                                 AS "src",
    request_method                                              AS "http_method",
    status                                                      AS "http_status_code",
    request_uri                                                 AS "request",
    NULLIF(http_referer, '')                                    AS "requestContext",
    body_bytes_sent                                             AS "in",      -- 응답 본문 바이트 = 클라이언트(src)가 받은 바이트
    IFF(STARTSWITH(request_uri, '/api'), 'true', 'false')       AS "is_api_request",
    raw_line                                                    AS "rawEvent",
    -- 한 줄 JSON. 키 순서는 Python 결과와 같다. 값이 ''인 키는 빠진다
    '{' || ARRAY_TO_STRING(ARRAY_CONSTRUCT_COMPACT(
        IFF(ident <> '',           '"ident":'           || TO_JSON(TO_VARIANT(ident)), NULL),
        IFF(remote_user <> '',     '"remote_user":'     || TO_JSON(TO_VARIANT(remote_user)), NULL),
        IFF(server_protocol <> '', '"server_protocol":' || TO_JSON(TO_VARIANT(server_protocol)), NULL),
        IFF(request <> '',         '"request":'         || TO_JSON(TO_VARIANT(request)), NULL),
        IFF(loaded_at_str <> '',   '"LOADED_AT":'       || TO_JSON(TO_VARIANT(loaded_at_str)), NULL),
        IFF(http_user_agent <> '', '"http_user_agent":' || TO_JSON(TO_VARIANT(http_user_agent)), NULL)
    ), ',') || '}'                                              AS "unmapped"
FROM p
ORDER BY TO_TIMESTAMP_TZ(time_local, 'DD/MON/YYYY:HH24:MI:SS TZHTZM'), raw_line;
