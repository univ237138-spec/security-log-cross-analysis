# 02_parsed: 파싱

[전체 데이터](../README.md) · [전체 흐름](../../README.md) · [처리 규칙·분석 근거](../../docs/03_파싱_정규화.md)

- 입력: [01_raw](../01_raw/README.md)
- 생성 코드: [01_parse_audit.py](../../scripts/01_parse_audit.py), [01_parse_nginx.py](../../scripts/01_parse_nginx.py), [01_parse_sshd.py](../../scripts/01_parse_sshd.py), [01_parse_sysmon.py](../../scripts/01_parse_sysmon.py)
- 다음 사용 단계: [03_normalized](../03_normalized/README.md)

CSV는 UTF-8 BOM이다. 아래 자료형은 현재 CSV의 비어 있지 않은 값을 관찰한 형식이며 강제 스키마가 아니다. 코드의 기본 CSV 읽기는 문자열이다. 식별자·포트는 숫자처럼 보여도 문자열로 보존하고, 계산할 컬럼만 명시적으로 변환한다. 빈칸은 미관측·비해당·기준선 부족 등을 뜻하므로 0과 구분한다.

## 파일 찾기

| 파일 | 행 × 열 | 용도 |
|---|---:|---|
| [audit_parsed.csv](audit_parsed.csv) | 456 × 16 | audit 로그의 파싱 데이터 |
| [nginx_parsed.csv](nginx_parsed.csv) | 2,223 × 13 | nginx 로그의 파싱 데이터 |
| [sshd_parsed.csv](sshd_parsed.csv) | 1,364 × 19 | sshd 로그의 파싱 데이터 |
| [sysmon_parsed.csv](sysmon_parsed.csv) | 5,082 × 54 | sysmon 로그의 파싱 데이터 |

## audit_parsed.csv

- 용도: audit 로그의 파싱 데이터
- 한 행: 원시 로그 한 건을 필드로 나눈 행
- 연결 키: `행 위치로 원시·파싱·정규화 파일과 대응; ID는 로그별로 다름`
- 생성 코드: [01_parse_audit.py](../../scripts/01_parse_audit.py)

| 순서 | 컬럼 | 관찰 형식 | 의미 |
|---:|---|---|---|
| 1 | `doc_id` | 문자열 | 감사 사건 **한 건**의 고유 ID |
| 2 | `system` | 문자열 | 원본 감사로그 시스템 필드 |
| 3 | `t_event_id` | 문자열 | 감사 사건 **종류** 코드. 원본 그대로이며, S/G를 성공·실패로 해석하는 것은 아직 추정이다 (멘토 확인 대기) |
| 4 | `t_user_id` | 문자열 | 원본 사용자 식별자 |
| 5 | `tag_name` | 문자열 | 원본 태그 |
| 6 | `tc_act` | 문자열 | 원본 감사로그 행동 코드 |
| 7 | `tc_deviceProduct` | 문자열 | 로그 제품명 |
| 8 | `tc_deviceVendor` | 문자열 | 로그 공급자 |
| 9 | `tc_msg` | 문자열 | 감사로그 메시지 |
| 10 | `tc_request` | 문자열 | 감사로그 요청 경로 |
| 11 | `tc_requestClientApplication` | 문자열 | 감사로그 클라이언트 앱 |
| 12 | `tc_src` | 문자열 | 감사로그 접속자 IP |
| 13 | `tc_suser` | 문자열 | 감사로그 콘솔 계정 |
| 14 | `teiren_timestamp` | 시각 문자열 | 감사로그 이벤트 UTC 시각 |
| 15 | `tenancy` | 문자열 | 고객사 식별값 |
| 16 | `LOADED_AT` | 시각 문자열 | Snowflake 적재 시각(이벤트 발생 시각과 구분) |

## nginx_parsed.csv

- 용도: nginx 로그의 파싱 데이터
- 한 행: 원시 로그 한 건을 필드로 나눈 행
- 연결 키: `행 위치로 원시·파싱·정규화 파일과 대응; ID는 로그별로 다름`
- 생성 코드: [01_parse_nginx.py](../../scripts/01_parse_nginx.py)

| 순서 | 컬럼 | 관찰 형식 | 의미 |
|---:|---|---|---|
| 1 | `remote_addr` | 문자열 | 접속자 IP |
| 2 | `ident` | 문자열 | nginx ident 필드 |
| 3 | `remote_user` | 문자열 | HTTP 인증 사용자 |
| 4 | `time_local` | 문자열 | nginx 원문 시각 |
| 5 | `request` | 문자열 | nginx 원본 HTTP 요청 줄(메서드·URI·프로토콜 포함) |
| 6 | `request_method` | 문자열 | HTTP 메서드 |
| 7 | `request_uri` | 문자열 | 요청 URI |
| 8 | `server_protocol` | 문자열 | HTTP 프로토콜 |
| 9 | `status` | 정수형 문자열 | HTTP 응답 코드 |
| 10 | `body_bytes_sent` | 정수형 문자열 | 응답 본문 바이트 수 |
| 11 | `http_referer` | 문자열 | Referer |
| 12 | `http_user_agent` | 문자열 | User-Agent |
| 13 | `LOADED_AT` | 시각 문자열 | Snowflake 적재 시각(이벤트 발생 시각과 구분) |

## sshd_parsed.csv

- 용도: sshd 로그의 파싱 데이터
- 한 행: 원시 로그 한 건을 필드로 나눈 행
- 연결 키: `행 위치로 원시·파싱·정규화 파일과 대응; ID는 로그별로 다름`
- 생성 코드: [01_parse_sshd.py](../../scripts/01_parse_sshd.py)

| 순서 | 컬럼 | 관찰 형식 | 의미 |
|---:|---|---|---|
| 1 | `timestamp` | 시각 문자열 | 원문 시각 |
| 2 | `hostname` | 문자열 | 로그를 기록한 호스트 |
| 3 | `program` | 문자열 | 로그를 기록한 프로그램 |
| 4 | `pid` | 정수형 문자열 | 프로그램 프로세스 번호 |
| 5 | `message` | 문자열 | 원문 메시지 본문 |
| 6 | `user` | 문자열 | 로그인 대상 계정 |
| 7 | `src_ip` | 문자열 | 접속자 IP |
| 8 | `src_port` | 정수형 문자열 | 접속자 포트 |
| 9 | `auth_method` | 문자열 | 인증 방식 |
| 10 | `ssh_protocol` | 문자열 | SSH 프로토콜 |
| 11 | `key_type` | 문자열 | 공개키 종류 |
| 12 | `key_fingerprint` | 문자열 | 로그인에 쓴 공개키 지문 |
| 13 | `uid` | 정수형 문자열 | 대상 사용자 UID |
| 14 | `by_user` | 문자열 | 세션을 연 사용자 |
| 15 | `by_uid` | 정수형 문자열 | 세션을 연 사용자 UID |
| 16 | `session_id` | 정수형 문자열 | 원본 systemd-logind 세션 번호(업무 세션 ID와 다름) |
| 17 | `disconnect_code` | 정수형 문자열 | 접속 종료 코드 |
| 18 | `disconnect_reason` | 문자열 | 접속 종료 사유 |
| 19 | `LOADED_AT` | 시각 문자열 | Snowflake 적재 시각(이벤트 발생 시각과 구분) |

## sysmon_parsed.csv

- 용도: sysmon 로그의 파싱 데이터
- 한 행: 원시 로그 한 건을 필드로 나눈 행
- 연결 키: `행 위치로 원시·파싱·정규화 파일과 대응; ID는 로그별로 다름`
- 생성 코드: [01_parse_sysmon.py](../../scripts/01_parse_sysmon.py)

| 순서 | 컬럼 | 관찰 형식 | 의미 |
|---:|---|---|---|
| 1 | `Provider_Name` | 문자열 | 이벤트 공급자 이름 |
| 2 | `Provider_Guid` | 문자열 | 이벤트 공급자 GUID |
| 3 | `EventID` | 정수형 문자열 | Sysmon 사건 종류 번호 |
| 4 | `Version` | 정수형 문자열 | 이벤트 스키마 버전 |
| 5 | `Level` | 정수형 문자열 | 이벤트 수준 |
| 6 | `Task` | 정수형 문자열 | 작업 분류 코드 |
| 7 | `Opcode` | 정수형 문자열 | 작업 코드 |
| 8 | `Keywords` | 문자열 | 이벤트 키워드 비트값 |
| 9 | `TimeCreated_SystemTime` | 시각 문자열 | System 헤더 생성 UTC 시각 |
| 10 | `EventRecordID` | 정수형 문자열 | Sysmon 원본 레코드 번호. `dvchost`와 함께 쓰면 행마다 고유하다 |
| 11 | `Correlation` | 빈 값만 존재 | 상관관계 헤더 |
| 12 | `Execution_ProcessID` | 정수형 문자열 | 이벤트 공급자의 프로세스 ID |
| 13 | `Execution_ThreadID` | 정수형 문자열 | 이벤트 공급자의 스레드 ID |
| 14 | `Channel` | 문자열 | 이벤트 채널 |
| 15 | `Computer` | 문자열 | 로그 발생 서버 |
| 16 | `Security_UserId` | 정수형 문자열 | 보안 컨텍스트 사용자 ID |
| 17 | `RuleName` | 문자열 | 원본 규칙 이름 |
| 18 | `UtcTime` | 시각 문자열 | 원본 이벤트 UTC 시각 |
| 19 | `ProcessGuid` | 문자열 | 프로세스 고유 식별자 |
| 20 | `ProcessId` | 정수형 문자열 | 프로세스 번호 |
| 21 | `Image` | 문자열 | 실행 파일 경로 |
| 22 | `User` | 문자열 | 프로세스 사용자 |
| 23 | `Protocol` | 문자열 | 네트워크 프로토콜 |
| 24 | `Initiated` | 불리언 문자열 | 연결 시작 주체 여부 |
| 25 | `SourceIsIpv6` | 불리언 문자열 | 출발지 IPv6 여부 |
| 26 | `SourceIp` | 문자열 | 이벤트 서버의 출발지 IP |
| 27 | `SourceHostname` | 문자열 | 출발지 호스트 |
| 28 | `SourcePort` | 정수형 문자열 | 출발지 포트 |
| 29 | `SourcePortName` | 문자열 | 출발지 포트 서비스명 |
| 30 | `DestinationIsIpv6` | 불리언 문자열 | 목적지 IPv6 여부 |
| 31 | `DestinationIp` | 문자열 | 목적지 IP |
| 32 | `DestinationHostname` | 문자열 | 목적지 호스트 |
| 33 | `DestinationPort` | 정수형 문자열 | 목적지 포트 |
| 34 | `DestinationPortName` | 문자열 | 목적지 서비스명 |
| 35 | `FileVersion` | 문자열 | 실행 파일 버전 |
| 36 | `Description` | 문자열 | 실행 파일 설명 |
| 37 | `Product` | 문자열 | 실행 파일 제품명 |
| 38 | `Company` | 문자열 | 실행 파일 회사명 |
| 39 | `OriginalFileName` | 문자열 | 원본 실행 파일명 |
| 40 | `CommandLine` | 문자열 | 실행 명령과 인수 |
| 41 | `CurrentDirectory` | 문자열 | 실행한 위치 (작업 디렉터리) |
| 42 | `LogonGuid` | 문자열 | 로그온 GUID |
| 43 | `LogonId` | 정수형 문자열 | 로그온 ID |
| 44 | `TerminalSessionId` | 정수형 문자열 | 터미널 세션 ID |
| 45 | `IntegrityLevel` | 문자열 | 무결성 수준 |
| 46 | `Hashes` | 문자열 | 실행 파일 해시 |
| 47 | `ParentProcessGuid` | 문자열 | 부모 프로세스 고유 식별자 |
| 48 | `ParentProcessId` | 정수형 문자열 | 부모 프로세스 번호 |
| 49 | `ParentImage` | 문자열 | 부모 실행 파일 경로 |
| 50 | `ParentCommandLine` | 문자열 | 부모 실행 명령 |
| 51 | `ParentUser` | 문자열 | 부모 프로세스 실행 계정 |
| 52 | `TargetFilename` | 문자열 | 생성된 파일 경로 |
| 53 | `CreationUtcTime` | 시각 문자열 | 파일 생성 UTC 시각 |
| 54 | `LOADED_AT` | 시각 문자열 | Snowflake 적재 시각(이벤트 발생 시각과 구분) |
