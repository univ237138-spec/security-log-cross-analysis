-- =====================================================================
-- Sysmon 정규화 (Snowflake) — 원시 로그에서 최종 정규화 결과를 한 번에 만든다
-- 입력: security_logs.raw.sysmon_raw (RAW_LINE, LOADED_AT)
-- 출력: data/03_normalized/sysmon_normalized_event_action.csv와 같은 23개 컬럼
--   event_time_utc, log_source, dvchost, suser, src, dst, dpt, event_action, EventID, Image,
--   ProcessId, ProcessGuid, CommandLine, CurrentDirectory, ParentProcessGuid, ParentProcessId,
--   ParentImage, ParentCommandLine, ParentUser, TargetFilename, EventRecordID, rawEvent, unmapped
-- 단계: 파싱(03_sysmon_parse.sql과 같은 XML 처리) → 정규화(scripts/02_normalize_sysmon.py
--       + scripts/03_apply_event_action.py와 같은 규칙)
-- 규칙:
--   - event_time_utc: UtcTime(밀리초 3자리, 이미 UTC) 뒤에 '000'을 붙여 소수점 6자리로 맞춘다
--   - suser: 원본 User가 '-'이면 NULL
--   - event_action: EventID 1/3/5/11 → process_create / network_connect / process_terminate / file_create
--   - unmapped: 분석 컬럼으로 꺼내지 않은 원본 필드 35개를 Python과 같은 키 순서의 한 줄 JSON 문자열로 만든다.
--     값이 빈 키는 넣지 않는다. ('-'는 원본 값이므로 그대로 넣는다)
--   - 해당 EventID에 없는 칸은 NULL이다 (CSV에서는 빈칸)
-- 주의: Snowflake에서 직접 실행해 확인한 것은 아니다. 처음 실행하면
--       scripts/98_compare_snowflake_normalized.py로 결과를 반드시 비교한다.
-- =====================================================================


-- ---------------------------------------------------------------------
-- 0. 점검: 아래 값이 모두 0이어야 한다
-- ---------------------------------------------------------------------
-- 0-1. XML 오류, System·EventData 누락, event_action을 정할 수 없는 EventID
SELECT
    COUNT(*)                                                         AS n_rows,
    COUNT_IF(CHECK_XML(raw_line) IS NOT NULL)                        AS n_invalid_xml,
    COUNT_IF(XMLGET(PARSE_XML(raw_line, TRUE), 'System') IS NULL)    AS n_no_system,
    COUNT_IF(XMLGET(PARSE_XML(raw_line, TRUE), 'EventData') IS NULL) AS n_no_eventdata,
    COUNT_IF(XMLGET(XMLGET(PARSE_XML(raw_line, TRUE), 'System'), 'EventID'):"$"::STRING
             NOT IN ('1', '3', '5', '11'))                           AS n_unknown_eventid
FROM security_logs.raw.sysmon_raw;

-- 0-2. 37개 목록에 없는 EventData 필드 (0행이어야 한다. 나오면 컬럼을 추가해야 한다)
WITH x AS (SELECT XMLGET(PARSE_XML(raw_line, TRUE), 'EventData'):"$" AS d FROM security_logs.raw.sysmon_raw)
SELECT f.value:"@Name"::STRING AS unknown_field, COUNT(*) AS n
FROM x, LATERAL FLATTEN(input => IFF(IS_ARRAY(x.d), x.d, ARRAY_CONSTRUCT(x.d))) f
WHERE f.value:"@Name"::STRING NOT IN ('RuleName', 'UtcTime', 'ProcessGuid', 'ProcessId', 'Image', 'User', 'Protocol', 'Initiated', 'SourceIsIpv6', 'SourceIp', 'SourceHostname', 'SourcePort', 'SourcePortName', 'DestinationIsIpv6', 'DestinationIp', 'DestinationHostname', 'DestinationPort', 'DestinationPortName', 'FileVersion', 'Description', 'Product', 'Company', 'OriginalFileName', 'CommandLine', 'CurrentDirectory', 'LogonGuid', 'LogonId', 'TerminalSessionId', 'IntegrityLevel', 'Hashes', 'ParentProcessGuid', 'ParentProcessId', 'ParentImage', 'ParentCommandLine', 'ParentUser', 'TargetFilename', 'CreationUtcTime')
GROUP BY 1;


-- ---------------------------------------------------------------------
-- 1. 정규화
--    테이블로 저장하려면 아래 주석을 풀고 DB·스키마 이름을 바꾼다 (쓰기 권한 필요)
-- ---------------------------------------------------------------------
-- CREATE OR REPLACE TABLE <내_DB>.<내_스키마>.sysmon_normalized AS
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
),
-- 파싱 결과 (03_sysmon_parse.sql과 같은 값. 해당 없는 칸은 '')
p AS (
    SELECT
        raw_line,
        -- System (16)
        COALESCE(XMLGET(sys, 'Provider'):"@Name"::STRING, '')            AS Provider_Name,
        COALESCE(XMLGET(sys, 'Provider'):"@Guid"::STRING, '')            AS Provider_Guid,
        COALESCE(XMLGET(sys, 'EventID'):"$"::STRING, '')                 AS EventID,
        COALESCE(XMLGET(sys, 'Version'):"$"::STRING, '')                 AS Version,
        COALESCE(XMLGET(sys, 'Level'):"$"::STRING, '')                   AS Level,
        COALESCE(XMLGET(sys, 'Task'):"$"::STRING, '')                    AS Task,
        COALESCE(XMLGET(sys, 'Opcode'):"$"::STRING, '')                  AS Opcode,
        COALESCE(XMLGET(sys, 'Keywords'):"$"::STRING, '')                AS Keywords,
        COALESCE(XMLGET(sys, 'TimeCreated'):"@SystemTime"::STRING, '')   AS TimeCreated_SystemTime,
        COALESCE(XMLGET(sys, 'EventRecordID'):"$"::STRING, '')           AS EventRecordID,
        COALESCE(XMLGET(sys, 'Correlation'):"$"::STRING, '')             AS Correlation,
        COALESCE(XMLGET(sys, 'Execution'):"@ProcessID"::STRING, '')      AS Execution_ProcessID,
        COALESCE(XMLGET(sys, 'Execution'):"@ThreadID"::STRING, '')       AS Execution_ThreadID,
        COALESCE(XMLGET(sys, 'Channel'):"$"::STRING, '')                 AS Channel,
        COALESCE(XMLGET(sys, 'Computer'):"$"::STRING, '')                AS Computer,
        COALESCE(XMLGET(sys, 'Security'):"@UserId"::STRING, '')          AS Security_UserId,
        -- EventData (37)
        COALESCE(ed:"RuleName"::STRING, '')             AS RuleName,
        COALESCE(ed:"UtcTime"::STRING, '')              AS UtcTime,
        COALESCE(ed:"ProcessGuid"::STRING, '')          AS ProcessGuid,
        COALESCE(ed:"ProcessId"::STRING, '')            AS ProcessId,
        COALESCE(ed:"Image"::STRING, '')                AS Image,
        COALESCE(ed:"User"::STRING, '')                 AS user_name,      -- 원본 필드 이름 User
        COALESCE(ed:"Protocol"::STRING, '')             AS Protocol,
        COALESCE(ed:"Initiated"::STRING, '')            AS Initiated,
        COALESCE(ed:"SourceIsIpv6"::STRING, '')         AS SourceIsIpv6,
        COALESCE(ed:"SourceIp"::STRING, '')             AS SourceIp,
        COALESCE(ed:"SourceHostname"::STRING, '')       AS SourceHostname,
        COALESCE(ed:"SourcePort"::STRING, '')           AS SourcePort,
        COALESCE(ed:"SourcePortName"::STRING, '')       AS SourcePortName,
        COALESCE(ed:"DestinationIsIpv6"::STRING, '')    AS DestinationIsIpv6,
        COALESCE(ed:"DestinationIp"::STRING, '')        AS DestinationIp,
        COALESCE(ed:"DestinationHostname"::STRING, '')  AS DestinationHostname,
        COALESCE(ed:"DestinationPort"::STRING, '')      AS DestinationPort,
        COALESCE(ed:"DestinationPortName"::STRING, '')  AS DestinationPortName,
        COALESCE(ed:"FileVersion"::STRING, '')          AS FileVersion,
        COALESCE(ed:"Description"::STRING, '')          AS Description,
        COALESCE(ed:"Product"::STRING, '')              AS Product,
        COALESCE(ed:"Company"::STRING, '')              AS Company,
        COALESCE(ed:"OriginalFileName"::STRING, '')     AS OriginalFileName,
        COALESCE(ed:"CommandLine"::STRING, '')          AS CommandLine,
        COALESCE(ed:"CurrentDirectory"::STRING, '')     AS CurrentDirectory,
        COALESCE(ed:"LogonGuid"::STRING, '')            AS LogonGuid,
        COALESCE(ed:"LogonId"::STRING, '')              AS LogonId,
        COALESCE(ed:"TerminalSessionId"::STRING, '')    AS TerminalSessionId,
        COALESCE(ed:"IntegrityLevel"::STRING, '')       AS IntegrityLevel,
        COALESCE(ed:"Hashes"::STRING, '')               AS Hashes,
        COALESCE(ed:"ParentProcessGuid"::STRING, '')    AS ParentProcessGuid,
        COALESCE(ed:"ParentProcessId"::STRING, '')      AS ParentProcessId,
        COALESCE(ed:"ParentImage"::STRING, '')          AS ParentImage,
        COALESCE(ed:"ParentCommandLine"::STRING, '')    AS ParentCommandLine,
        COALESCE(ed:"ParentUser"::STRING, '')           AS ParentUser,
        COALESCE(ed:"TargetFilename"::STRING, '')       AS TargetFilename,
        COALESCE(ed:"CreationUtcTime"::STRING, '')      AS CreationUtcTime,
        TO_VARCHAR(loaded_at, 'YYYY-MM-DD HH24:MI:SS.FF3') AS loaded_at_str
    FROM t
)
SELECT
    UtcTime || '000'                                AS "event_time_utc",   -- 밀리초 → 마이크로초 자릿수
    'sysmon'                                        AS "log_source",
    Computer                                        AS "dvchost",
    NULLIF(NULLIF(user_name, '-'), '')              AS "suser",
    NULLIF(SourceIp, '')                            AS "src",              -- 주의: 연결을 시작한 서버 자신의 IP
    NULLIF(DestinationIp, '')                       AS "dst",
    NULLIF(DestinationPort, '')                     AS "dpt",
    CASE EventID
        WHEN '1'  THEN 'process_create'
        WHEN '3'  THEN 'network_connect'
        WHEN '5'  THEN 'process_terminate'
        WHEN '11' THEN 'file_create'
    END                                             AS "event_action",
    EventID                                         AS "EventID",
    NULLIF(Image, '')                               AS "Image",
    NULLIF(ProcessId, '')                           AS "ProcessId",
    NULLIF(ProcessGuid, '')                         AS "ProcessGuid",
    NULLIF(CommandLine, '')                         AS "CommandLine",
    NULLIF(CurrentDirectory, '')                    AS "CurrentDirectory",
    NULLIF(ParentProcessGuid, '')                   AS "ParentProcessGuid",
    NULLIF(ParentProcessId, '')                     AS "ParentProcessId",
    NULLIF(ParentImage, '')                         AS "ParentImage",
    NULLIF(ParentCommandLine, '')                   AS "ParentCommandLine",
    NULLIF(ParentUser, '')                          AS "ParentUser",
    NULLIF(TargetFilename, '')                      AS "TargetFilename",
    EventRecordID                                   AS "EventRecordID",
    raw_line                                        AS "rawEvent",
    -- 한 줄 JSON. 키 순서는 Python 결과(파싱 컬럼 순서)와 같다. 값이 ''인 키는 빠진다
    '{' || ARRAY_TO_STRING(ARRAY_CONSTRUCT_COMPACT(
        IFF(Provider_Name          <> '', '"Provider_Name":'          || TO_JSON(TO_VARIANT(Provider_Name)), NULL),
        IFF(Provider_Guid          <> '', '"Provider_Guid":'          || TO_JSON(TO_VARIANT(Provider_Guid)), NULL),
        IFF(Version                <> '', '"Version":'                || TO_JSON(TO_VARIANT(Version)), NULL),
        IFF(Level                  <> '', '"Level":'                  || TO_JSON(TO_VARIANT(Level)), NULL),
        IFF(Task                   <> '', '"Task":'                   || TO_JSON(TO_VARIANT(Task)), NULL),
        IFF(Opcode                 <> '', '"Opcode":'                 || TO_JSON(TO_VARIANT(Opcode)), NULL),
        IFF(Keywords               <> '', '"Keywords":'               || TO_JSON(TO_VARIANT(Keywords)), NULL),
        IFF(TimeCreated_SystemTime <> '', '"TimeCreated_SystemTime":' || TO_JSON(TO_VARIANT(TimeCreated_SystemTime)), NULL),
        IFF(Correlation            <> '', '"Correlation":'            || TO_JSON(TO_VARIANT(Correlation)), NULL),
        IFF(Execution_ProcessID    <> '', '"Execution_ProcessID":'    || TO_JSON(TO_VARIANT(Execution_ProcessID)), NULL),
        IFF(Execution_ThreadID     <> '', '"Execution_ThreadID":'     || TO_JSON(TO_VARIANT(Execution_ThreadID)), NULL),
        IFF(Channel                <> '', '"Channel":'                || TO_JSON(TO_VARIANT(Channel)), NULL),
        IFF(Security_UserId        <> '', '"Security_UserId":'        || TO_JSON(TO_VARIANT(Security_UserId)), NULL),
        IFF(RuleName               <> '', '"RuleName":'               || TO_JSON(TO_VARIANT(RuleName)), NULL),
        IFF(Protocol               <> '', '"Protocol":'               || TO_JSON(TO_VARIANT(Protocol)), NULL),
        IFF(Initiated              <> '', '"Initiated":'              || TO_JSON(TO_VARIANT(Initiated)), NULL),
        IFF(SourceIsIpv6           <> '', '"SourceIsIpv6":'           || TO_JSON(TO_VARIANT(SourceIsIpv6)), NULL),
        IFF(SourceHostname         <> '', '"SourceHostname":'         || TO_JSON(TO_VARIANT(SourceHostname)), NULL),
        IFF(SourcePort             <> '', '"SourcePort":'             || TO_JSON(TO_VARIANT(SourcePort)), NULL),
        IFF(SourcePortName         <> '', '"SourcePortName":'         || TO_JSON(TO_VARIANT(SourcePortName)), NULL),
        IFF(DestinationIsIpv6      <> '', '"DestinationIsIpv6":'      || TO_JSON(TO_VARIANT(DestinationIsIpv6)), NULL),
        IFF(DestinationHostname    <> '', '"DestinationHostname":'    || TO_JSON(TO_VARIANT(DestinationHostname)), NULL),
        IFF(DestinationPortName    <> '', '"DestinationPortName":'    || TO_JSON(TO_VARIANT(DestinationPortName)), NULL),
        IFF(FileVersion            <> '', '"FileVersion":'            || TO_JSON(TO_VARIANT(FileVersion)), NULL),
        IFF(Description            <> '', '"Description":'            || TO_JSON(TO_VARIANT(Description)), NULL),
        IFF(Product                <> '', '"Product":'                || TO_JSON(TO_VARIANT(Product)), NULL),
        IFF(Company                <> '', '"Company":'                || TO_JSON(TO_VARIANT(Company)), NULL),
        IFF(OriginalFileName       <> '', '"OriginalFileName":'       || TO_JSON(TO_VARIANT(OriginalFileName)), NULL),
        IFF(LogonGuid              <> '', '"LogonGuid":'              || TO_JSON(TO_VARIANT(LogonGuid)), NULL),
        IFF(LogonId                <> '', '"LogonId":'                || TO_JSON(TO_VARIANT(LogonId)), NULL),
        IFF(TerminalSessionId      <> '', '"TerminalSessionId":'      || TO_JSON(TO_VARIANT(TerminalSessionId)), NULL),
        IFF(IntegrityLevel         <> '', '"IntegrityLevel":'         || TO_JSON(TO_VARIANT(IntegrityLevel)), NULL),
        IFF(Hashes                 <> '', '"Hashes":'                 || TO_JSON(TO_VARIANT(Hashes)), NULL),
        IFF(CreationUtcTime        <> '', '"CreationUtcTime":'        || TO_JSON(TO_VARIANT(CreationUtcTime)), NULL),
        IFF(loaded_at_str          <> '', '"LOADED_AT":'              || TO_JSON(TO_VARIANT(loaded_at_str)), NULL)
    ), ',') || '}'                                  AS "unmapped"
FROM p
ORDER BY UtcTime, TO_NUMBER(EventRecordID);   -- 원본 파일 순서 = UtcTime → EventRecordID
