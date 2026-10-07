-- =====================================================================
-- 감사로그 정규화 (Snowflake) — 원시 로그에서 최종 정규화 결과를 한 번에 만든다
-- 입력: security_logs.raw.teiren_audit_raw (EVENT: VARIANT, LOADED_AT)
-- 출력: data/03_normalized/audit_normalized_event_action.csv와 같은 11개 컬럼
--   event_time_utc, log_source, src, suser, event_action, msg, request, t_event_id, doc_id, rawEvent, unmapped
-- 단계: 파싱(04_audit_parse.sql과 같은 JSON 키 추출) → 정규화(scripts/02_normalize_audit.py
--       + scripts/03_apply_event_action.py와 같은 규칙)
-- 규칙:
--   - event_time_utc: teiren_timestamp('…Z', 밀리초 3자리, 이미 UTC)를 'YYYY-MM-DD HH:MM:SS.ffffff' 문자열로 만든다
--   - event_action: 원본 행동 코드 tc_act를 값 그대로 옮긴다
--   - rawEvent: 원본 JSON을 공백 없는 한 줄로 만든다 (TO_JSON). 원본 키가 이미 알파벳 순서라
--     Snowflake가 키를 정렬해도 Python 결과와 순서가 같다
--   - unmapped: 분석 컬럼으로 꺼내지 않은 원본 필드를 Python과 같은 키 순서의 한 줄 JSON 문자열로 만든다.
--     값이 빈 키는 넣지 않는다
-- 주의:
--   - EVENT가 VARIANT라서 PARSE_JSON 없이 바로 꺼낸다. VARCHAR라면 맨 아래 FROM 절의 event를
--     PARSE_JSON(event)로 바꾼다 (주석 참고)
--   - Snowflake에서 직접 실행해 확인한 것은 아니다. 처음 실행하면
--     scripts/98_compare_snowflake_normalized.py로 결과를 반드시 비교한다.
-- =====================================================================


-- ---------------------------------------------------------------------
-- 0. 점검: 키 개수가 15개가 아닌 행 0, 고유 doc_id 수 = 행 수, 목록에 없는 키/tc_act 0행
-- ---------------------------------------------------------------------
SELECT
    COUNT(*)                                                AS n_rows,
    COUNT_IF(ARRAY_SIZE(OBJECT_KEYS(event)) <> 15)          AS n_key_count_diff,
    COUNT(DISTINCT event:"doc_id"::STRING)                  AS n_distinct_doc_id,   -- n_rows와 같아야 한다
    COUNT_IF(NOT REGEXP_LIKE(event:"teiren_timestamp"::STRING,
             '[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[.][0-9]{3}Z')) AS n_time_format_diff
FROM security_logs.raw.teiren_audit_raw;

SELECT f.key AS unknown_key, COUNT(*) AS n
FROM security_logs.raw.teiren_audit_raw t, LATERAL FLATTEN(input => t.event) f
WHERE f.key NOT IN ('doc_id', 'system', 't_event_id', 't_user_id', 'tag_name', 'tc_act', 'tc_deviceProduct', 'tc_deviceVendor', 'tc_msg', 'tc_request', 'tc_requestClientApplication', 'tc_src', 'tc_suser', 'teiren_timestamp', 'tenancy')
GROUP BY 1;


-- ---------------------------------------------------------------------
-- 1. 정규화
--    테이블로 저장하려면 아래 주석을 풀고 DB·스키마 이름을 바꾼다 (쓰기 권한 필요)
-- ---------------------------------------------------------------------
-- CREATE OR REPLACE TABLE <내_DB>.<내_스키마>.audit_normalized AS
WITH j AS (
    SELECT
        event AS ev,                -- EVENT가 VARCHAR라면: PARSE_JSON(event) AS ev
        loaded_at
    FROM security_logs.raw.teiren_audit_raw
),
-- 파싱 결과 (04_audit_parse.sql과 같은 값. 해당 없는 칸은 '')
p AS (
    SELECT
        ev,
        COALESCE(ev:"doc_id"::STRING, '')                       AS doc_id,
        COALESCE(ev:"system"::STRING, '')                       AS system_name,
        COALESCE(ev:"t_event_id"::STRING, '')                   AS t_event_id,
        COALESCE(ev:"t_user_id"::STRING, '')                    AS t_user_id,
        COALESCE(ev:"tag_name"::STRING, '')                     AS tag_name,
        COALESCE(ev:"tc_act"::STRING, '')                       AS tc_act,
        COALESCE(ev:"tc_deviceProduct"::STRING, '')             AS tc_deviceProduct,
        COALESCE(ev:"tc_deviceVendor"::STRING, '')              AS tc_deviceVendor,
        COALESCE(ev:"tc_msg"::STRING, '')                       AS tc_msg,
        COALESCE(ev:"tc_request"::STRING, '')                   AS tc_request,
        COALESCE(ev:"tc_requestClientApplication"::STRING, '')  AS tc_requestClientApplication,
        COALESCE(ev:"tc_src"::STRING, '')                       AS tc_src,
        COALESCE(ev:"tc_suser"::STRING, '')                     AS tc_suser,
        COALESCE(ev:"teiren_timestamp"::STRING, '')             AS teiren_timestamp,
        COALESCE(ev:"tenancy"::STRING, '')                      AS tenancy,
        TO_VARCHAR(loaded_at, 'YYYY-MM-DD HH24:MI:SS.FF3')      AS loaded_at_str
    FROM j
)
SELECT
    TO_VARCHAR(TO_TIMESTAMP_NTZ(teiren_timestamp, 'YYYY-MM-DD"T"HH24:MI:SS.FF"Z"'),
               'YYYY-MM-DD HH24:MI:SS.FF6')                     AS "event_time_utc",
    'teiren_audit'                                              AS "log_source",
    NULLIF(tc_src, '')                                          AS "src",
    NULLIF(tc_suser, '')                                        AS "suser",
    NULLIF(tc_act, '')                                          AS "event_action",
    NULLIF(tc_msg, '')                                          AS "msg",
    NULLIF(tc_request, '')                                      AS "request",
    NULLIF(t_event_id, '')                                      AS "t_event_id",
    doc_id                                                      AS "doc_id",
    TO_JSON(ev)                                                 AS "rawEvent",
    -- 한 줄 JSON. 키 순서는 Python 결과와 같다. 값이 ''인 키는 빠진다
    '{' || ARRAY_TO_STRING(ARRAY_CONSTRUCT_COMPACT(
        IFF(t_user_id <> '',                   '"t_user_id":'                   || TO_JSON(TO_VARIANT(t_user_id)), NULL),
        IFF(system_name <> '',                 '"system":'                      || TO_JSON(TO_VARIANT(system_name)), NULL),
        IFF(tag_name <> '',                    '"tag_name":'                    || TO_JSON(TO_VARIANT(tag_name)), NULL),
        IFF(tenancy <> '',                     '"tenancy":'                     || TO_JSON(TO_VARIANT(tenancy)), NULL),
        IFF(tc_deviceVendor <> '',             '"tc_deviceVendor":'             || TO_JSON(TO_VARIANT(tc_deviceVendor)), NULL),
        IFF(tc_deviceProduct <> '',            '"tc_deviceProduct":'            || TO_JSON(TO_VARIANT(tc_deviceProduct)), NULL),
        IFF(loaded_at_str <> '',               '"LOADED_AT":'                   || TO_JSON(TO_VARIANT(loaded_at_str)), NULL),
        IFF(tc_requestClientApplication <> '', '"tc_requestClientApplication":' || TO_JSON(TO_VARIANT(tc_requestClientApplication)), NULL)
    ), ',') || '}'                                              AS "unmapped"
FROM p
ORDER BY teiren_timestamp;   -- 원본 파일 순서 = teiren_timestamp 순서 (같은 시각의 행 없음)
