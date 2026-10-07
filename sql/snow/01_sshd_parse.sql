-- =====================================================================
-- sshd 파싱 (Snowflake) — scripts/01_parse_sshd.py와 같은 결과를 만든다
-- 입력: security_logs.raw.sshd_raw (RAW_LINE, LOADED_AT)
-- 출력: data/02_parsed/sshd_parsed.csv와 같은 19개 컬럼 (헤더 5 + 메시지 값 13 + LOADED_AT)
-- 규칙:
--   - 헤더: 시각 호스트 프로그램[pid]: 메시지
--   - 메시지: 템플릿 10종 중 정확히 하나와 일치해야 한다 (0번 점검 쿼리로 확인)
--   - 값은 원문 글자 그대로, 해당 없는 칸은 빈 문자열('')
-- 주의:
--   - 이 파일의 정규식은 Python으로 같은 데이터에 시뮬레이션해 parsed CSV와 일치함을 확인했다.
--     Snowflake에서 직접 실행해 확인한 것은 아니다 (README.md 참고).
--   - 정규식은 작은따옴표 문자열로 쓰므로 백슬래시를 두 번 쓴다 (예: 공백이 아닌 문자 \\S).
--     Snowsight가 문장 범위를 잘못 나누지 않도록 달러 두 개로 감싼 문자열은 쓰지 않는다.
--     REGEXP_LIKE는 문자열 전체와 일치해야 참이므로 끝 앵커가 없어도 전체 일치를 검사한다.
-- =====================================================================


-- ---------------------------------------------------------------------
-- 0. 점검: 헤더 실패 0건, 템플릿 미일치 0건, 템플릿 중복 일치 0건이어야 한다
-- ---------------------------------------------------------------------
WITH h AS (
    SELECT raw_line, REGEXP_SUBSTR(raw_line, '^(\\S+) (\\S+) ([a-zA-Z0-9_.-]+)\\[([0-9]+)\\]: (.*)', 1, 1, 'e', 5) AS msg
    FROM security_logs.raw.sshd_raw
)
SELECT
    COUNT(*)                                     AS n_rows,
    COUNT_IF(NOT REGEXP_LIKE(raw_line, '^(\\S+) (\\S+) ([a-zA-Z0-9_.-]+)\\[([0-9]+)\\]: (.*)')) AS n_header_fail,
    COUNT_IF(n_match = 0)                        AS n_no_template,
    COUNT_IF(n_match > 1)                        AS n_multi_template
FROM (
    SELECT raw_line,
           0
           + IFF(REGEXP_LIKE(msg, '^Invalid user (\\S+) from ([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}) port ([0-9]+)'), 1, 0)
           + IFF(REGEXP_LIKE(msg, '^Accepted (\\S+) for (\\S+) from ([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}) port ([0-9]+) (ssh[0-9]): (\\S+) (\\S+)'), 1, 0)
           + IFF(REGEXP_LIKE(msg, '^Failed (\\S+) for (\\S+) from ([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}) port ([0-9]+) (ssh[0-9])'), 1, 0)
           + IFF(REGEXP_LIKE(msg, '^pam_unix\\(sshd:session\\): session opened for user ([^( ]+)\\(uid=([0-9]+)\\) by ([^( ]+)\\(uid=([0-9]+)\\)'), 1, 0)
           + IFF(REGEXP_LIKE(msg, '^pam_unix\\(sshd:session\\): session closed for user (\\S+)'), 1, 0)
           + IFF(REGEXP_LIKE(msg, '^Received disconnect from ([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}) port ([0-9]+):([0-9]+): (.+)'), 1, 0)
           + IFF(REGEXP_LIKE(msg, '^Disconnected from user (\\S+) ([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}) port ([0-9]+)'), 1, 0)
           + IFF(REGEXP_LIKE(msg, '^New session ([0-9]+) of user ([^ .]+)[.]'), 1, 0)
           + IFF(REGEXP_LIKE(msg, '^Session ([0-9]+) logged out[.] Waiting for processes to exit[.]'), 1, 0)
           + IFF(REGEXP_LIKE(msg, '^Removed session ([0-9]+)[.]'), 1, 0)
           AS n_match
    FROM h
);


-- ---------------------------------------------------------------------
-- 1. 파싱 (결과를 CSV로 내려받아 scripts/98_compare_snowflake_export.py로 비교)
--    뷰로 저장하려면 아래 주석을 풀고 DB·스키마 이름을 바꾼다
-- ---------------------------------------------------------------------
-- CREATE OR REPLACE VIEW <내_DB>.<내_스키마>.sshd_parsed AS
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
)
SELECT
    ts      AS "timestamp",
    host    AS "hostname",
    program AS "program",
    pid     AS "pid",
    msg     AS "message",
    COALESCE(CASE tpl
        WHEN 1 THEN REGEXP_SUBSTR(msg, '^Invalid user (\\S+) from ([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}) port ([0-9]+)', 1, 1, 'e', 1)
        WHEN 2 THEN REGEXP_SUBSTR(msg, '^Accepted (\\S+) for (\\S+) from ([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}) port ([0-9]+) (ssh[0-9]): (\\S+) (\\S+)', 1, 1, 'e', 2)
        WHEN 3 THEN REGEXP_SUBSTR(msg, '^Failed (\\S+) for (\\S+) from ([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}) port ([0-9]+) (ssh[0-9])', 1, 1, 'e', 2)
        WHEN 4 THEN REGEXP_SUBSTR(msg, '^pam_unix\\(sshd:session\\): session opened for user ([^( ]+)\\(uid=([0-9]+)\\) by ([^( ]+)\\(uid=([0-9]+)\\)', 1, 1, 'e', 1)
        WHEN 5 THEN REGEXP_SUBSTR(msg, '^pam_unix\\(sshd:session\\): session closed for user (\\S+)', 1, 1, 'e', 1)
        WHEN 7 THEN REGEXP_SUBSTR(msg, '^Disconnected from user (\\S+) ([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}) port ([0-9]+)', 1, 1, 'e', 1)
        WHEN 8 THEN REGEXP_SUBSTR(msg, '^New session ([0-9]+) of user ([^ .]+)[.]', 1, 1, 'e', 2)
    END, '') AS "user",
    COALESCE(CASE tpl
        WHEN 1 THEN REGEXP_SUBSTR(msg, '^Invalid user (\\S+) from ([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}) port ([0-9]+)', 1, 1, 'e', 2)
        WHEN 2 THEN REGEXP_SUBSTR(msg, '^Accepted (\\S+) for (\\S+) from ([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}) port ([0-9]+) (ssh[0-9]): (\\S+) (\\S+)', 1, 1, 'e', 3)
        WHEN 3 THEN REGEXP_SUBSTR(msg, '^Failed (\\S+) for (\\S+) from ([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}) port ([0-9]+) (ssh[0-9])', 1, 1, 'e', 3)
        WHEN 6 THEN REGEXP_SUBSTR(msg, '^Received disconnect from ([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}) port ([0-9]+):([0-9]+): (.+)', 1, 1, 'e', 1)
        WHEN 7 THEN REGEXP_SUBSTR(msg, '^Disconnected from user (\\S+) ([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}) port ([0-9]+)', 1, 1, 'e', 2)
    END, '') AS "src_ip",
    COALESCE(CASE tpl
        WHEN 1 THEN REGEXP_SUBSTR(msg, '^Invalid user (\\S+) from ([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}) port ([0-9]+)', 1, 1, 'e', 3)
        WHEN 2 THEN REGEXP_SUBSTR(msg, '^Accepted (\\S+) for (\\S+) from ([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}) port ([0-9]+) (ssh[0-9]): (\\S+) (\\S+)', 1, 1, 'e', 4)
        WHEN 3 THEN REGEXP_SUBSTR(msg, '^Failed (\\S+) for (\\S+) from ([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}) port ([0-9]+) (ssh[0-9])', 1, 1, 'e', 4)
        WHEN 6 THEN REGEXP_SUBSTR(msg, '^Received disconnect from ([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}) port ([0-9]+):([0-9]+): (.+)', 1, 1, 'e', 2)
        WHEN 7 THEN REGEXP_SUBSTR(msg, '^Disconnected from user (\\S+) ([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}) port ([0-9]+)', 1, 1, 'e', 3)
    END, '') AS "src_port",
    COALESCE(CASE tpl
        WHEN 2 THEN REGEXP_SUBSTR(msg, '^Accepted (\\S+) for (\\S+) from ([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}) port ([0-9]+) (ssh[0-9]): (\\S+) (\\S+)', 1, 1, 'e', 1)
        WHEN 3 THEN REGEXP_SUBSTR(msg, '^Failed (\\S+) for (\\S+) from ([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}) port ([0-9]+) (ssh[0-9])', 1, 1, 'e', 1)
    END, '') AS "auth_method",
    COALESCE(CASE tpl
        WHEN 2 THEN REGEXP_SUBSTR(msg, '^Accepted (\\S+) for (\\S+) from ([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}) port ([0-9]+) (ssh[0-9]): (\\S+) (\\S+)', 1, 1, 'e', 5)
        WHEN 3 THEN REGEXP_SUBSTR(msg, '^Failed (\\S+) for (\\S+) from ([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}) port ([0-9]+) (ssh[0-9])', 1, 1, 'e', 5)
    END, '') AS "ssh_protocol",
    COALESCE(CASE tpl
        WHEN 2 THEN REGEXP_SUBSTR(msg, '^Accepted (\\S+) for (\\S+) from ([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}) port ([0-9]+) (ssh[0-9]): (\\S+) (\\S+)', 1, 1, 'e', 6)
    END, '') AS "key_type",
    COALESCE(CASE tpl
        WHEN 2 THEN REGEXP_SUBSTR(msg, '^Accepted (\\S+) for (\\S+) from ([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}) port ([0-9]+) (ssh[0-9]): (\\S+) (\\S+)', 1, 1, 'e', 7)
    END, '') AS "key_fingerprint",
    COALESCE(CASE tpl
        WHEN 4 THEN REGEXP_SUBSTR(msg, '^pam_unix\\(sshd:session\\): session opened for user ([^( ]+)\\(uid=([0-9]+)\\) by ([^( ]+)\\(uid=([0-9]+)\\)', 1, 1, 'e', 2)
    END, '') AS "uid",
    COALESCE(CASE tpl
        WHEN 4 THEN REGEXP_SUBSTR(msg, '^pam_unix\\(sshd:session\\): session opened for user ([^( ]+)\\(uid=([0-9]+)\\) by ([^( ]+)\\(uid=([0-9]+)\\)', 1, 1, 'e', 3)
    END, '') AS "by_user",
    COALESCE(CASE tpl
        WHEN 4 THEN REGEXP_SUBSTR(msg, '^pam_unix\\(sshd:session\\): session opened for user ([^( ]+)\\(uid=([0-9]+)\\) by ([^( ]+)\\(uid=([0-9]+)\\)', 1, 1, 'e', 4)
    END, '') AS "by_uid",
    COALESCE(CASE tpl
        WHEN 8 THEN REGEXP_SUBSTR(msg, '^New session ([0-9]+) of user ([^ .]+)[.]', 1, 1, 'e', 1)
        WHEN 9 THEN REGEXP_SUBSTR(msg, '^Session ([0-9]+) logged out[.] Waiting for processes to exit[.]', 1, 1, 'e', 1)
        WHEN 10 THEN REGEXP_SUBSTR(msg, '^Removed session ([0-9]+)[.]', 1, 1, 'e', 1)
    END, '') AS "session_id",
    COALESCE(CASE tpl
        WHEN 6 THEN REGEXP_SUBSTR(msg, '^Received disconnect from ([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}) port ([0-9]+):([0-9]+): (.+)', 1, 1, 'e', 3)
    END, '') AS "disconnect_code",
    COALESCE(CASE tpl
        WHEN 6 THEN REGEXP_SUBSTR(msg, '^Received disconnect from ([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}) port ([0-9]+):([0-9]+): (.+)', 1, 1, 'e', 4)
    END, '') AS "disconnect_reason",
    TO_VARCHAR(loaded_at, 'YYYY-MM-DD HH24:MI:SS.FF3') AS "LOADED_AT"
FROM t
ORDER BY ts;   -- 원본 파일 순서 = 시각 순서 (같은 시각의 행 없음)
