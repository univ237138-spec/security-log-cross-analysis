-- =====================================================================
-- Sysmon 파싱 (Snowflake) — scripts/01_parse_sysmon.py와 같은 결과를 만든다
-- 입력: security_logs.raw.sysmon_raw (RAW_LINE, LOADED_AT)
-- 출력: data/02_parsed/sysmon_parsed.csv와 같은 54개 컬럼 (System 16 + EventData 37 + LOADED_AT)
-- 규칙:
--   - System 하위 태그의 값은 태그 이름, 속성은 '태그_속성' 이름으로 컬럼을 만든다
--     (예: <TimeCreated SystemTime="…"/> → "TimeCreated_SystemTime")
--   - 값도 속성도 없는 빈 태그(Correlation)도 컬럼으로 남긴다 (모든 행 '')
--   - EventData의 <Data Name="…">은 Name을 컬럼 이름으로 쓴다. 해당 EventID에 없는 필드는 ''
--   - 값은 원본 문자열 그대로 ('-'도 그대로). PARSE_XML의 숫자·불리언 자동 변환을 끈다(TRUE)
-- 주의:
--   - Snowflake에서 직접 실행해 확인한 것은 아니다 (README.md 참고).
--   - 원본 파일 순서 = UtcTime → EventRecordID 순서 (Python으로 확인)
-- =====================================================================


-- ---------------------------------------------------------------------
-- 0. 점검: 아래 값이 모두 0이어야 한다
-- ---------------------------------------------------------------------
-- 0-1. XML 오류, System·EventData 누락
SELECT
    COUNT(*)                                                         AS n_rows,
    COUNT_IF(CHECK_XML(raw_line) IS NOT NULL)                        AS n_invalid_xml,
    COUNT_IF(XMLGET(PARSE_XML(raw_line, TRUE), 'System') IS NULL)    AS n_no_system,
    COUNT_IF(XMLGET(PARSE_XML(raw_line, TRUE), 'EventData') IS NULL) AS n_no_eventdata
FROM security_logs.raw.sysmon_raw;

-- 0-2. 37개 목록에 없는 EventData 필드 (0행이어야 한다. 나오면 컬럼을 추가해야 한다)
WITH x AS (SELECT XMLGET(PARSE_XML(raw_line, TRUE), 'EventData'):"$" AS d FROM security_logs.raw.sysmon_raw)
SELECT f.value:"@Name"::STRING AS unknown_field, COUNT(*) AS n
FROM x, LATERAL FLATTEN(input => IFF(IS_ARRAY(x.d), x.d, ARRAY_CONSTRUCT(x.d))) f
WHERE f.value:"@Name"::STRING NOT IN ('RuleName', 'UtcTime', 'ProcessGuid', 'ProcessId', 'Image', 'User', 'Protocol', 'Initiated', 'SourceIsIpv6', 'SourceIp', 'SourceHostname', 'SourcePort', 'SourcePortName', 'DestinationIsIpv6', 'DestinationIp', 'DestinationHostname', 'DestinationPort', 'DestinationPortName', 'FileVersion', 'Description', 'Product', 'Company', 'OriginalFileName', 'CommandLine', 'CurrentDirectory', 'LogonGuid', 'LogonId', 'TerminalSessionId', 'IntegrityLevel', 'Hashes', 'ParentProcessGuid', 'ParentProcessId', 'ParentImage', 'ParentCommandLine', 'ParentUser', 'TargetFilename', 'CreationUtcTime')
GROUP BY 1;


-- ---------------------------------------------------------------------
-- 1. 파싱 (결과를 CSV로 내려받아 scripts/98_compare_snowflake_export.py로 비교)
-- ---------------------------------------------------------------------
-- CREATE OR REPLACE VIEW <내_DB>.<내_스키마>.sysmon_parsed AS
WITH src AS (
    SELECT raw_line, loaded_at, PARSE_XML(raw_line, TRUE) AS doc
    FROM security_logs.raw.sysmon_raw
),
-- EventData의 <Data Name="…">값</Data> 목록을 {Name: 값} 객체 하나로 모은다 (raw_line은 5,082개 모두 고유)
e AS (
    SELECT
        s.raw_line,
        ANY_VALUE(s.loaded_at) AS loaded_at,
        OBJECT_AGG(f.value:"@Name"::STRING, COALESCE(f.value:"$"::STRING, '')::VARIANT) AS ed
    FROM src s,
         LATERAL FLATTEN(input => IFF(IS_ARRAY(XMLGET(s.doc, 'EventData'):"$"),
                                      XMLGET(s.doc, 'EventData'):"$",
                                      ARRAY_CONSTRUCT(XMLGET(s.doc, 'EventData'):"$"))) f
    GROUP BY s.raw_line
),
t AS (
    SELECT e.*, XMLGET(PARSE_XML(e.raw_line, TRUE), 'System') AS sys
    FROM e
)
SELECT
    -- System (16)
    COALESCE(XMLGET(sys, 'Provider'):"@Name"::STRING, '')                       AS "Provider_Name",
    COALESCE(XMLGET(sys, 'Provider'):"@Guid"::STRING, '')                       AS "Provider_Guid",
    COALESCE(XMLGET(sys, 'EventID'):"$"::STRING, '')                            AS "EventID",
    COALESCE(XMLGET(sys, 'Version'):"$"::STRING, '')                            AS "Version",
    COALESCE(XMLGET(sys, 'Level'):"$"::STRING, '')                              AS "Level",
    COALESCE(XMLGET(sys, 'Task'):"$"::STRING, '')                               AS "Task",
    COALESCE(XMLGET(sys, 'Opcode'):"$"::STRING, '')                             AS "Opcode",
    COALESCE(XMLGET(sys, 'Keywords'):"$"::STRING, '')                           AS "Keywords",
    COALESCE(XMLGET(sys, 'TimeCreated'):"@SystemTime"::STRING, '')              AS "TimeCreated_SystemTime",
    COALESCE(XMLGET(sys, 'EventRecordID'):"$"::STRING, '')                      AS "EventRecordID",
    COALESCE(XMLGET(sys, 'Correlation'):"$"::STRING, '')                        AS "Correlation",
    COALESCE(XMLGET(sys, 'Execution'):"@ProcessID"::STRING, '')                 AS "Execution_ProcessID",
    COALESCE(XMLGET(sys, 'Execution'):"@ThreadID"::STRING, '')                  AS "Execution_ThreadID",
    COALESCE(XMLGET(sys, 'Channel'):"$"::STRING, '')                            AS "Channel",
    COALESCE(XMLGET(sys, 'Computer'):"$"::STRING, '')                           AS "Computer",
    COALESCE(XMLGET(sys, 'Security'):"@UserId"::STRING, '')                     AS "Security_UserId",
    -- EventData (37)
    COALESCE(ed:"RuleName"::STRING, '')                     AS "RuleName",
    COALESCE(ed:"UtcTime"::STRING, '')                      AS "UtcTime",
    COALESCE(ed:"ProcessGuid"::STRING, '')                  AS "ProcessGuid",
    COALESCE(ed:"ProcessId"::STRING, '')                    AS "ProcessId",
    COALESCE(ed:"Image"::STRING, '')                        AS "Image",
    COALESCE(ed:"User"::STRING, '')                         AS "User",
    COALESCE(ed:"Protocol"::STRING, '')                     AS "Protocol",
    COALESCE(ed:"Initiated"::STRING, '')                    AS "Initiated",
    COALESCE(ed:"SourceIsIpv6"::STRING, '')                 AS "SourceIsIpv6",
    COALESCE(ed:"SourceIp"::STRING, '')                     AS "SourceIp",
    COALESCE(ed:"SourceHostname"::STRING, '')               AS "SourceHostname",
    COALESCE(ed:"SourcePort"::STRING, '')                   AS "SourcePort",
    COALESCE(ed:"SourcePortName"::STRING, '')               AS "SourcePortName",
    COALESCE(ed:"DestinationIsIpv6"::STRING, '')            AS "DestinationIsIpv6",
    COALESCE(ed:"DestinationIp"::STRING, '')                AS "DestinationIp",
    COALESCE(ed:"DestinationHostname"::STRING, '')          AS "DestinationHostname",
    COALESCE(ed:"DestinationPort"::STRING, '')              AS "DestinationPort",
    COALESCE(ed:"DestinationPortName"::STRING, '')          AS "DestinationPortName",
    COALESCE(ed:"FileVersion"::STRING, '')                  AS "FileVersion",
    COALESCE(ed:"Description"::STRING, '')                  AS "Description",
    COALESCE(ed:"Product"::STRING, '')                      AS "Product",
    COALESCE(ed:"Company"::STRING, '')                      AS "Company",
    COALESCE(ed:"OriginalFileName"::STRING, '')             AS "OriginalFileName",
    COALESCE(ed:"CommandLine"::STRING, '')                  AS "CommandLine",
    COALESCE(ed:"CurrentDirectory"::STRING, '')             AS "CurrentDirectory",
    COALESCE(ed:"LogonGuid"::STRING, '')                    AS "LogonGuid",
    COALESCE(ed:"LogonId"::STRING, '')                      AS "LogonId",
    COALESCE(ed:"TerminalSessionId"::STRING, '')            AS "TerminalSessionId",
    COALESCE(ed:"IntegrityLevel"::STRING, '')               AS "IntegrityLevel",
    COALESCE(ed:"Hashes"::STRING, '')                       AS "Hashes",
    COALESCE(ed:"ParentProcessGuid"::STRING, '')            AS "ParentProcessGuid",
    COALESCE(ed:"ParentProcessId"::STRING, '')              AS "ParentProcessId",
    COALESCE(ed:"ParentImage"::STRING, '')                  AS "ParentImage",
    COALESCE(ed:"ParentCommandLine"::STRING, '')            AS "ParentCommandLine",
    COALESCE(ed:"ParentUser"::STRING, '')                   AS "ParentUser",
    COALESCE(ed:"TargetFilename"::STRING, '')               AS "TargetFilename",
    COALESCE(ed:"CreationUtcTime"::STRING, '')              AS "CreationUtcTime",
    TO_VARCHAR(loaded_at, 'YYYY-MM-DD HH24:MI:SS.FF3') AS "LOADED_AT"
FROM t
ORDER BY "UtcTime", TO_NUMBER("EventRecordID");
