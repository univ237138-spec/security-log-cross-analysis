-- =====================================================================
-- sshd 정규화 (Snowflake) — 원시 로그에서 최종 정규화 결과를 한 번에 만든다
-- 입력: security_logs.raw.sshd_raw (RAW_LINE, LOADED_AT)
-- 출력: data/03_normalized/sshd_normalized_event_action.csv와 같은 14개 컬럼
--   event_time_utc, log_source, src, spt, duser, dproc, dpid, event_action, msg,
--   auth_method, key_fingerprint, session_id, rawEvent, unmapped
-- 단계: 파싱(01_sshd_parse.sql과 같은 정규식) → 정규화(scripts/02_normalize_sshd.py
--       + scripts/03_apply_event_action.py와 같은 규칙)
-- 규칙:
--   - event_time_utc: 원본 KST(+09:00) 시각을 UTC로 바꿔 'YYYY-MM-DD HH:MM:SS.ffffff' 문자열로 만든다
--   - event_action: 메시지 템플릿 10종 → 행동 이름 10종
--   - unmapped: 분석 컬럼으로 꺼내지 않은 원본 필드를 Python과 같은 키 순서의 한 줄 JSON 문자열로 만든다.
--     값이 빈 키는 넣지 않는다. (OBJECT_CONSTRUCT는 키를 정렬하므로 쓰지 않고 문자열로 이어 붙인다)
--   - 값이 없는 칸은 NULL이다 (CSV에서는 빈칸)
-- 주의: Snowflake에서 직접 실행해 확인한 것은 아니다. 처음 실행하면
--       scripts/98_compare_snowflake_normalized.py로 결과를 반드시 비교한다.
-- =====================================================================


-- ---------------------------------------------------------------------
-- 0. 점검: 아래 세 값이 모두 0이어야 한다 (0이 아니면 새 형식의 로그가 들어온 것)
--    헤더 실패 / event_action을 정할 수 없는 메시지 / 두 개 이상에 걸리는 메시지
-- ---------------------------------------------------------------------
WITH h AS (
    SELECT raw_line, REGEXP_SUBSTR(raw_line, '^(\\S+) (\\S+) ([a-zA-Z0-9_.-]+)\\[([0-9]+)\\]: (.*)', 1, 1, 'e', 5) AS msg
    FROM security_logs.raw.sshd_raw
)
SELECT
    COUNT(*)                     AS n_rows,
    COUNT_IF(msg IS NULL)        AS n_header_fail,
    COUNT_IF(n_action = 0)       AS n_no_action,
    COUNT_IF(n_action > 1)       AS n_multi_action
FROM (
    SELECT msg,
           0
           + IFF(STARTSWITH(msg, 'Invalid user '), 1, 0)
           + IFF(STARTSWITH(msg, 'Failed password'), 1, 0)
           + IFF(STARTSWITH(msg, 'Accepted '), 1, 0)
           + IFF(CONTAINS(msg, 'session opened for user'), 1, 0)
           + IFF(STARTSWITH(msg, 'New session '), 1, 0)
           + IFF(STARTSWITH(msg, 'Received disconnect'), 1, 0)
           + IFF(STARTSWITH(msg, 'Disconnected from user'), 1, 0)
           + IFF(CONTAINS(msg, 'session closed for user'), 1, 0)
           + IFF(CONTAINS(msg, ' logged out. '), 1, 0)
           + IFF(STARTSWITH(msg, 'Removed session '), 1, 0)
           AS n_action
    FROM h
);
-- 메시지 템플릿 점검(값 추출이 되는지)은 01_sshd_parse.sql의 0번 쿼리로 한다.


-- ---------------------------------------------------------------------
-- 1. 정규화
--    테이블로 저장하려면 아래 주석을 풀고 DB·스키마 이름을 바꾼다 (쓰기 권한 필요)
-- ---------------------------------------------------------------------
-- CREATE OR REPLACE TABLE <내_DB>.<내_스키마>.sshd_normalized AS
WITH h AS (
    SELECT
        raw_line,
        loaded_at,
        REGEXP_SUBSTR(raw_line, '^(\\S+) (\\S+) ([a-zA-Z0-9_.-]+)\\[([0-9]+)\\]: (.*)', 1, 1, 'e', 1) AS ts,
        REGEXP_SUBSTR(raw_line, '^(\\S+) (\\S+) ([a-zA-Z0-9_.-]+)\\[([0-9]+)\\]: (.*)', 1, 1, 'e', 2) AS host,
        REGEXP_SUBSTR(raw_line, '^(\\S+) (\\S+) ([a-zA-Z0-9_.-]+)\\[([0-9]+)\\]: (.*)', 1, 1, 'e', 3) AS program,
        REGEXP_SUBSTR(raw_line, '^(\\S+) (\\S+) ([a-zA-Z0-9_.-]+)\\[([0-9]+)\\]: (.*)', 1, 1, 'e', 4) AS pid,
        REGEXP_SUBSTR(raw_line, '^(\\S+) (\\S+) ([a-zA-Z0-9_.-]+)\\[([0-9]+)\\]: (.*)', 1, 1, 'e', 5) AS msg
    FROM security_logs.raw.sshd_raw
),
-- 메시지 템플릿 번호 (01_sshd_parse.sql과 같다)
t AS (
    SELECT h.*,
        CASE
            WHEN REGEXP_LIKE(msg, '^Invalid user (\\S+) from ([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}) port ([0-9]+)') THEN 1   -- Invalid user
            WHEN REGEXP_LIKE(msg, '^Accepted (\\S+) for (\\S+) from ([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}) port ([0-9]+) (ssh[0-9]): (\\S+) (\\S+)') THEN 2   -- Accepted
            WHEN REGEXP_LIKE(msg, '^Failed (\\S+) for (\\S+) from ([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}) port ([0-9]+) (ssh[0-9])') THEN 3   -- Failed
            WHEN REGEXP_LIKE(msg, '^pam_unix\\(sshd:session\\): session opened for user ([^( ]+)\\(uid=([0-9]+)\\) by ([^( ]+)\\(uid=([0-9]+)\\)') THEN 4   -- session opened
            WHEN REGEXP_LIKE(msg, '^pam_unix\\(sshd:session\\): session closed for user (\\S+)') THEN 5   -- session closed
            WHEN REGEXP_LIKE(msg, '^Received disconnect from ([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}) port ([0-9]+):([0-9]+): (.+)') THEN 6   -- Received disconnect
            WHEN REGEXP_LIKE(msg, '^Disconnected from user (\\S+) ([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}) port ([0-9]+)') THEN 7   -- Disconnected
            WHEN REGEXP_LIKE(msg, '^New session ([0-9]+) of user ([^ .]+)[.]') THEN 8   -- New session
            WHEN REGEXP_LIKE(msg, '^Session ([0-9]+) logged out[.] Waiting for processes to exit[.]') THEN 9   -- logged out
            WHEN REGEXP_LIKE(msg, '^Removed session ([0-9]+)[.]') THEN 10   -- Removed session
        END AS tpl
    FROM h
),
-- 파싱 결과 (01_sshd_parse.sql과 같은 값. 해당 없는 칸은 '')
p AS (
    SELECT
        raw_line,
        ts, host, program, pid, msg,
        COALESCE(CASE tpl
            WHEN 1 THEN REGEXP_SUBSTR(msg, '^Invalid user (\\S+) from ([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}) port ([0-9]+)', 1, 1, 'e', 1)
            WHEN 2 THEN REGEXP_SUBSTR(msg, '^Accepted (\\S+) for (\\S+) from ([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}) port ([0-9]+) (ssh[0-9]): (\\S+) (\\S+)', 1, 1, 'e', 2)
            WHEN 3 THEN REGEXP_SUBSTR(msg, '^Failed (\\S+) for (\\S+) from ([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}) port ([0-9]+) (ssh[0-9])', 1, 1, 'e', 2)
            WHEN 4 THEN REGEXP_SUBSTR(msg, '^pam_unix\\(sshd:session\\): session opened for user ([^( ]+)\\(uid=([0-9]+)\\) by ([^( ]+)\\(uid=([0-9]+)\\)', 1, 1, 'e', 1)
            WHEN 5 THEN REGEXP_SUBSTR(msg, '^pam_unix\\(sshd:session\\): session closed for user (\\S+)', 1, 1, 'e', 1)
            WHEN 7 THEN REGEXP_SUBSTR(msg, '^Disconnected from user (\\S+) ([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}) port ([0-9]+)', 1, 1, 'e', 1)
            WHEN 8 THEN REGEXP_SUBSTR(msg, '^New session ([0-9]+) of user ([^ .]+)[.]', 1, 1, 'e', 2)
        END, '') AS user_name,
        COALESCE(CASE tpl
            WHEN 1 THEN REGEXP_SUBSTR(msg, '^Invalid user (\\S+) from ([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}) port ([0-9]+)', 1, 1, 'e', 2)
            WHEN 2 THEN REGEXP_SUBSTR(msg, '^Accepted (\\S+) for (\\S+) from ([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}) port ([0-9]+) (ssh[0-9]): (\\S+) (\\S+)', 1, 1, 'e', 3)
            WHEN 3 THEN REGEXP_SUBSTR(msg, '^Failed (\\S+) for (\\S+) from ([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}) port ([0-9]+) (ssh[0-9])', 1, 1, 'e', 3)
            WHEN 6 THEN REGEXP_SUBSTR(msg, '^Received disconnect from ([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}) port ([0-9]+):([0-9]+): (.+)', 1, 1, 'e', 1)
            WHEN 7 THEN REGEXP_SUBSTR(msg, '^Disconnected from user (\\S+) ([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}) port ([0-9]+)', 1, 1, 'e', 2)
        END, '') AS src_ip,
        COALESCE(CASE tpl
            WHEN 1 THEN REGEXP_SUBSTR(msg, '^Invalid user (\\S+) from ([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}) port ([0-9]+)', 1, 1, 'e', 3)
            WHEN 2 THEN REGEXP_SUBSTR(msg, '^Accepted (\\S+) for (\\S+) from ([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}) port ([0-9]+) (ssh[0-9]): (\\S+) (\\S+)', 1, 1, 'e', 4)
            WHEN 3 THEN REGEXP_SUBSTR(msg, '^Failed (\\S+) for (\\S+) from ([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}) port ([0-9]+) (ssh[0-9])', 1, 1, 'e', 4)
            WHEN 6 THEN REGEXP_SUBSTR(msg, '^Received disconnect from ([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}) port ([0-9]+):([0-9]+): (.+)', 1, 1, 'e', 2)
            WHEN 7 THEN REGEXP_SUBSTR(msg, '^Disconnected from user (\\S+) ([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}) port ([0-9]+)', 1, 1, 'e', 3)
        END, '') AS src_port,
        COALESCE(CASE tpl
            WHEN 2 THEN REGEXP_SUBSTR(msg, '^Accepted (\\S+) for (\\S+) from ([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}) port ([0-9]+) (ssh[0-9]): (\\S+) (\\S+)', 1, 1, 'e', 1)
            WHEN 3 THEN REGEXP_SUBSTR(msg, '^Failed (\\S+) for (\\S+) from ([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}) port ([0-9]+) (ssh[0-9])', 1, 1, 'e', 1)
        END, '') AS auth_method,
        COALESCE(CASE tpl
            WHEN 2 THEN REGEXP_SUBSTR(msg, '^Accepted (\\S+) for (\\S+) from ([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}) port ([0-9]+) (ssh[0-9]): (\\S+) (\\S+)', 1, 1, 'e', 5)
            WHEN 3 THEN REGEXP_SUBSTR(msg, '^Failed (\\S+) for (\\S+) from ([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}) port ([0-9]+) (ssh[0-9])', 1, 1, 'e', 5)
        END, '') AS ssh_protocol,
        COALESCE(CASE tpl
            WHEN 2 THEN REGEXP_SUBSTR(msg, '^Accepted (\\S+) for (\\S+) from ([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}) port ([0-9]+) (ssh[0-9]): (\\S+) (\\S+)', 1, 1, 'e', 6)
        END, '') AS key_type,
        COALESCE(CASE tpl
            WHEN 2 THEN REGEXP_SUBSTR(msg, '^Accepted (\\S+) for (\\S+) from ([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}) port ([0-9]+) (ssh[0-9]): (\\S+) (\\S+)', 1, 1, 'e', 7)
        END, '') AS key_fingerprint,
        COALESCE(CASE tpl
            WHEN 4 THEN REGEXP_SUBSTR(msg, '^pam_unix\\(sshd:session\\): session opened for user ([^( ]+)\\(uid=([0-9]+)\\) by ([^( ]+)\\(uid=([0-9]+)\\)', 1, 1, 'e', 2)
        END, '') AS uid,
        COALESCE(CASE tpl
            WHEN 4 THEN REGEXP_SUBSTR(msg, '^pam_unix\\(sshd:session\\): session opened for user ([^( ]+)\\(uid=([0-9]+)\\) by ([^( ]+)\\(uid=([0-9]+)\\)', 1, 1, 'e', 3)
        END, '') AS by_user,
        COALESCE(CASE tpl
            WHEN 4 THEN REGEXP_SUBSTR(msg, '^pam_unix\\(sshd:session\\): session opened for user ([^( ]+)\\(uid=([0-9]+)\\) by ([^( ]+)\\(uid=([0-9]+)\\)', 1, 1, 'e', 4)
        END, '') AS by_uid,
        COALESCE(CASE tpl
            WHEN 8 THEN REGEXP_SUBSTR(msg, '^New session ([0-9]+) of user ([^ .]+)[.]', 1, 1, 'e', 1)
            WHEN 9 THEN REGEXP_SUBSTR(msg, '^Session ([0-9]+) logged out[.] Waiting for processes to exit[.]', 1, 1, 'e', 1)
            WHEN 10 THEN REGEXP_SUBSTR(msg, '^Removed session ([0-9]+)[.]', 1, 1, 'e', 1)
        END, '') AS session_id,
        COALESCE(CASE tpl
            WHEN 6 THEN REGEXP_SUBSTR(msg, '^Received disconnect from ([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}) port ([0-9]+):([0-9]+): (.+)', 1, 1, 'e', 3)
        END, '') AS disconnect_code,
        COALESCE(CASE tpl
            WHEN 6 THEN REGEXP_SUBSTR(msg, '^Received disconnect from ([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}) port ([0-9]+):([0-9]+): (.+)', 1, 1, 'e', 4)
        END, '') AS disconnect_reason,
        TO_VARCHAR(loaded_at, 'YYYY-MM-DD HH24:MI:SS.FF3') AS loaded_at_str
    FROM t
)
SELECT
    -- +09:00 → UTC, 소수점 6자리
    TO_VARCHAR(CONVERT_TIMEZONE('UTC', TO_TIMESTAMP_TZ(ts, 'YYYY-MM-DD"T"HH24:MI:SS.FFTZH:TZM'))::TIMESTAMP_NTZ,
               'YYYY-MM-DD HH24:MI:SS.FF6')                     AS "event_time_utc",
    'sshd'                                                      AS "log_source",
    NULLIF(src_ip, '')                                          AS "src",
    NULLIF(src_port, '')                                        AS "spt",
    NULLIF(user_name, '')                                       AS "duser",
    program                                                     AS "dproc",
    pid                                                         AS "dpid",
    CASE   -- scripts/03_apply_event_action.py의 SSHD_ACTION과 같은 순서
        WHEN STARTSWITH(msg, 'Invalid user ')              THEN 'invalid_user'
        WHEN STARTSWITH(msg, 'Failed password')            THEN 'auth_failure'
        WHEN STARTSWITH(msg, 'Accepted ')                  THEN 'auth_success'
        WHEN CONTAINS(msg, 'session opened for user')      THEN 'session_opened'
        WHEN STARTSWITH(msg, 'New session ')               THEN 'session_new'
        WHEN STARTSWITH(msg, 'Received disconnect')        THEN 'disconnect_received'
        WHEN STARTSWITH(msg, 'Disconnected from user')     THEN 'disconnected_user'
        WHEN CONTAINS(msg, 'session closed for user')      THEN 'session_closed'
        WHEN CONTAINS(msg, ' logged out. ')                THEN 'session_logged_out'
        WHEN STARTSWITH(msg, 'Removed session ')           THEN 'session_removed'
    END                                                         AS "event_action",
    msg                                                         AS "msg",
    NULLIF(auth_method, '')                                     AS "auth_method",
    NULLIF(key_fingerprint, '')                                 AS "key_fingerprint",
    NULLIF(session_id, '')                                      AS "session_id",
    raw_line                                                    AS "rawEvent",
    -- 한 줄 JSON. 키 순서는 Python 결과와 같다. 값이 ''인 키는 빠진다 (ARRAY_CONSTRUCT_COMPACT가 NULL을 버림)
    '{' || ARRAY_TO_STRING(ARRAY_CONSTRUCT_COMPACT(
        IFF(uid <> '',               '"uid":'               || TO_JSON(TO_VARIANT(uid)), NULL),
        IFF(by_user <> '',           '"by_user":'           || TO_JSON(TO_VARIANT(by_user)), NULL),
        IFF(by_uid <> '',            '"by_uid":'            || TO_JSON(TO_VARIANT(by_uid)), NULL),
        IFF(ssh_protocol <> '',      '"ssh_protocol":'      || TO_JSON(TO_VARIANT(ssh_protocol)), NULL),
        IFF(key_type <> '',          '"key_type":'          || TO_JSON(TO_VARIANT(key_type)), NULL),
        IFF(disconnect_code <> '',   '"disconnect_code":'   || TO_JSON(TO_VARIANT(disconnect_code)), NULL),
        IFF(disconnect_reason <> '', '"disconnect_reason":' || TO_JSON(TO_VARIANT(disconnect_reason)), NULL),
        IFF(loaded_at_str <> '',     '"LOADED_AT":'         || TO_JSON(TO_VARIANT(loaded_at_str)), NULL),
        IFF(host <> '',              '"hostname":'          || TO_JSON(TO_VARIANT(host)), NULL)
    ), ',') || '}'                                              AS "unmapped"
FROM p
ORDER BY "event_time_utc";   -- 원본 파일 순서 = 시각 순서 (같은 시각의 행 없음)
