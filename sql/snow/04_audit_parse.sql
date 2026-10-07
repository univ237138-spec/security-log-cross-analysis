-- =====================================================================
-- 감사로그 파싱 (Snowflake) — scripts/01_parse_audit.py와 같은 결과를 만든다
-- 입력: security_logs.raw.teiren_audit_raw (EVENT: VARIANT, LOADED_AT)
-- 출력: data/02_parsed/audit_parsed.csv와 같은 16개 컬럼 (원본 키 15 + LOADED_AT)
-- 규칙: JSON 키 하나를 컬럼 하나로 그대로 옮긴다. 키 이름도 값도 바꾸지 않는다.
-- 주의:
--   - EVENT가 VARIANT라서 PARSE_JSON 없이 바로 꺼낸다.
--     (VARCHAR라면 event 대신 PARSE_JSON(event)를 쓴다)
--   - JSON 키는 대소문자를 구분하므로 큰따옴표로 감싼다 (예: event:"tc_deviceProduct")
--   - Snowflake에서 직접 실행해 확인한 것은 아니다 (README.md 참고).
--   - 원본 파일 순서 = teiren_timestamp 순서 (같은 시각의 행 없음)
-- =====================================================================


-- ---------------------------------------------------------------------
-- 0. 점검: 키 개수가 15개가 아닌 행, 목록에 없는 키 → 모두 0이어야 한다
-- ---------------------------------------------------------------------
SELECT
    COUNT(*)                                                AS n_rows,
    COUNT_IF(ARRAY_SIZE(OBJECT_KEYS(event)) <> 15)          AS n_key_count_diff,
    COUNT(DISTINCT event:"doc_id"::STRING)                  AS n_distinct_doc_id   -- n_rows와 같아야 한다
FROM security_logs.raw.teiren_audit_raw;

SELECT f.key AS unknown_key, COUNT(*) AS n
FROM security_logs.raw.teiren_audit_raw t, LATERAL FLATTEN(input => t.event) f
WHERE f.key NOT IN ('doc_id', 'system', 't_event_id', 't_user_id', 'tag_name', 'tc_act', 'tc_deviceProduct', 'tc_deviceVendor', 'tc_msg', 'tc_request', 'tc_requestClientApplication', 'tc_src', 'tc_suser', 'teiren_timestamp', 'tenancy')
GROUP BY 1;


-- ---------------------------------------------------------------------
-- 1. 파싱 (결과를 CSV로 내려받아 scripts/98_compare_snowflake_export.py로 비교)
-- ---------------------------------------------------------------------
-- CREATE OR REPLACE VIEW <내_DB>.<내_스키마>.audit_parsed AS
SELECT
    COALESCE(event:"doc_id"::STRING, '')                         AS "doc_id",
    COALESCE(event:"system"::STRING, '')                         AS "system",
    COALESCE(event:"t_event_id"::STRING, '')                     AS "t_event_id",
    COALESCE(event:"t_user_id"::STRING, '')                      AS "t_user_id",
    COALESCE(event:"tag_name"::STRING, '')                       AS "tag_name",
    COALESCE(event:"tc_act"::STRING, '')                         AS "tc_act",
    COALESCE(event:"tc_deviceProduct"::STRING, '')               AS "tc_deviceProduct",
    COALESCE(event:"tc_deviceVendor"::STRING, '')                AS "tc_deviceVendor",
    COALESCE(event:"tc_msg"::STRING, '')                         AS "tc_msg",
    COALESCE(event:"tc_request"::STRING, '')                     AS "tc_request",
    COALESCE(event:"tc_requestClientApplication"::STRING, '')    AS "tc_requestClientApplication",
    COALESCE(event:"tc_src"::STRING, '')                         AS "tc_src",
    COALESCE(event:"tc_suser"::STRING, '')                       AS "tc_suser",
    COALESCE(event:"teiren_timestamp"::STRING, '')               AS "teiren_timestamp",
    COALESCE(event:"tenancy"::STRING, '')                        AS "tenancy",
    TO_VARCHAR(loaded_at, 'YYYY-MM-DD HH24:MI:SS.FF3') AS "LOADED_AT"
FROM security_logs.raw.teiren_audit_raw
ORDER BY event:"teiren_timestamp"::STRING;
