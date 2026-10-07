# 03_normalized: 정규화·행위 분류

[전체 데이터](../README.md) · [전체 흐름](../../README.md) · [처리 규칙·분석 근거](../../docs/03_파싱_정규화.md)

- 입력: [01_raw](../01_raw/README.md), [02_parsed](../02_parsed/README.md)
- 생성 코드: [02_normalize_audit.py](../../scripts/02_normalize_audit.py), [02_normalize_nginx.py](../../scripts/02_normalize_nginx.py), [02_normalize_sshd.py](../../scripts/02_normalize_sshd.py), [02_normalize_sysmon.py](../../scripts/02_normalize_sysmon.py), [03_apply_event_action.py](../../scripts/03_apply_event_action.py)
- 다음 사용 단계: [04_integrated](../04_integrated/README.md), [05_enriched](../05_enriched/README.md)

CSV는 UTF-8 BOM이다. 아래 자료형은 현재 CSV의 비어 있지 않은 값을 관찰한 형식이며 강제 스키마가 아니다. 코드의 기본 CSV 읽기는 문자열이다. 식별자·포트는 숫자처럼 보여도 문자열로 보존하고, 계산할 컬럼만 명시적으로 변환한다. 빈칸은 미관측·비해당·기준선 부족 등을 뜻하므로 0과 구분한다.

## 파일 찾기

| 파일 | 행 × 열 | 용도 |
|---|---:|---|
| [audit_normalized.csv](audit_normalized.csv) | 456 × 15 | audit 로그의 정규화·행위 분류 데이터 |
| [audit_normalized_event_action.csv](audit_normalized_event_action.csv) | 456 × 11 | audit 로그의 정규화·행위 분류 데이터 |
| [nginx_normalized.csv](nginx_normalized.csv) | 2,223 × 13 | nginx 로그의 정규화·행위 분류 데이터 |
| [nginx_normalized_event_action.csv](nginx_normalized_event_action.csv) | 2,223 × 11 | nginx 로그의 정규화·행위 분류 데이터 |
| [sshd_normalized.csv](sshd_normalized.csv) | 1,364 × 19 | sshd 로그의 정규화·행위 분류 데이터 |
| [sshd_normalized_event_action.csv](sshd_normalized_event_action.csv) | 1,364 × 14 | sshd 로그의 정규화·행위 분류 데이터 |
| [sysmon_normalized.csv](sysmon_normalized.csv) | 5,082 × 23 | sysmon 로그의 정규화·행위 분류 데이터 |
| [sysmon_normalized_event_action.csv](sysmon_normalized_event_action.csv) | 5,082 × 23 | sysmon 로그의 정규화·행위 분류 데이터 |

`*_normalized.csv`는 초기 정규화 결과이며 `03_apply_event_action.py`의 입력이다. 통합·보강에는 `*_normalized_event_action.csv` 4개를 사용한다. 두 버전을 모두 보존한다.

## audit_normalized.csv

- 용도: audit 로그의 정규화·행위 분류 데이터
- 한 행: 정규화한 로그 이벤트 한 건
- 연결 키: `행 위치로 원시·파싱·정규화 파일과 대응; ID는 로그별로 다름`
- 생성 코드: [02_normalize_audit.py](../../scripts/02_normalize_audit.py)

| 순서 | 컬럼 | 관찰 형식 | 의미 |
|---:|---|---|---|
| 1 | `event_time_utc` | 시각 문자열 | 사건이 일어난 시각 (UTC). 형식 `YYYY-MM-DD HH:MM:SS.ffffff` |
| 2 | `src` | 문자열 | sshd/nginx/audit는 접속자 IP; sysmon은 서버 자신의 SourceIp(통합 시 dvc로 이동) |
| 3 | `suser` | 문자열 | 행위를 한 계정. Sysmon은 리눅스 계정, 감사로그는 콘솔 계정이다 |
| 4 | `cat` | 문자열 | 초기 정규화 이벤트 범주 |
| 5 | `act` | 문자열 | 초기 정규화 행동 분류 |
| 6 | `outcome` | 문자열 | 초기 정규화 성공·실패 분류 |
| 7 | `reason` | 문자열 | 판정 또는 정규화 사유 |
| 8 | `msg` | 문자열 | 로그 본문 메시지 |
| 9 | `request` | 문자열 | 요청 경로 (URI) |
| 10 | `requestClientApplication` | 문자열 | 요청 클라이언트 앱(User-Agent) |
| 11 | `tc_act` | 문자열 | 원본 감사로그 행동 코드 |
| 12 | `t_event_id` | 문자열 | 감사 사건 **종류** 코드. 원본 그대로이며, S/G를 성공·실패로 해석하는 것은 아직 추정이다 (멘토 확인 대기) |
| 13 | `doc_id` | 문자열 | 감사 사건 **한 건**의 고유 ID |
| 14 | `rawEvent` | 문자열 | 보존한 원본 로그 |
| 15 | `unmapped` | JSON 문자열 | 독립 컬럼으로 사용하지 않은 원본 필드 JSON |

## audit_normalized_event_action.csv

- 용도: audit 로그의 정규화·행위 분류 데이터
- 한 행: 정규화한 로그 이벤트 한 건
- 연결 키: `행 위치로 원시·파싱·정규화 파일과 대응; ID는 로그별로 다름`
- 생성 코드: [03_apply_event_action.py](../../scripts/03_apply_event_action.py)

| 순서 | 컬럼 | 관찰 형식 | 의미 |
|---:|---|---|---|
| 1 | `event_time_utc` | 시각 문자열 | 사건이 일어난 시각 (UTC). 형식 `YYYY-MM-DD HH:MM:SS.ffffff` |
| 2 | `log_source` | 문자열 | 어느 로그에서 온 행인지 |
| 3 | `src` | 문자열 | sshd/nginx/audit는 접속자 IP; sysmon은 서버 자신의 SourceIp(통합 시 dvc로 이동) |
| 4 | `suser` | 문자열 | 행위를 한 계정. Sysmon은 리눅스 계정, 감사로그는 콘솔 계정이다 |
| 5 | `event_action` | 문자열 | 원본 로그의 행위 이름. 로그마다 값 종류가 다르다 (SSHD 10종, Sysmon 4종, 감사로그 12종). NGINX는 원본에 행위 필드가 없어 빈칸이며, `http_method`·`http_status_code`가 대신한다 |
| 6 | `msg` | 문자열 | 로그 본문 메시지 |
| 7 | `request` | 문자열 | 요청 경로 (URI) |
| 8 | `t_event_id` | 문자열 | 감사 사건 **종류** 코드. 원본 그대로이며, S/G를 성공·실패로 해석하는 것은 아직 추정이다 (멘토 확인 대기) |
| 9 | `doc_id` | 문자열 | 감사 사건 **한 건**의 고유 ID |
| 10 | `rawEvent` | 문자열 | 보존한 원본 로그 |
| 11 | `unmapped` | JSON 문자열 | 독립 컬럼으로 사용하지 않은 원본 필드 JSON |

## nginx_normalized.csv

- 용도: nginx 로그의 정규화·행위 분류 데이터
- 한 행: 정규화한 로그 이벤트 한 건
- 연결 키: `행 위치로 원시·파싱·정규화 파일과 대응; ID는 로그별로 다름`
- 생성 코드: [02_normalize_nginx.py](../../scripts/02_normalize_nginx.py)

| 순서 | 컬럼 | 관찰 형식 | 의미 |
|---:|---|---|---|
| 1 | `event_time_utc` | 시각 문자열 | 사건이 일어난 시각 (UTC). 형식 `YYYY-MM-DD HH:MM:SS.ffffff` |
| 2 | `src` | 문자열 | sshd/nginx/audit는 접속자 IP; sysmon은 서버 자신의 SourceIp(통합 시 dvc로 이동) |
| 3 | `requestMethod` | 문자열 | 초기 HTTP 메서드 |
| 4 | `request` | 문자열 | 요청 경로 (URI) |
| 5 | `requestClientApplication` | 문자열 | 요청 클라이언트 앱(User-Agent) |
| 6 | `requestContext` | 문자열 | 이 요청을 보낸 이전 페이지 주소 (Referer) |
| 7 | `in` | 정수형 문자열 | 원문에 기록된 응답 크기 (바이트, `$body_bytes_sent`) |
| 8 | `cat` | 문자열 | 초기 정규화 이벤트 범주 |
| 9 | `act` | 문자열 | 초기 정규화 행동 분류 |
| 10 | `outcome` | 빈 값만 존재 | 초기 정규화 성공·실패 분류 |
| 11 | `is_api_request` | 불리언 문자열 | 요청 경로가 `/api`로 시작하는지 |
| 12 | `rawEvent` | 문자열 | 보존한 원본 로그 |
| 13 | `unmapped` | JSON 문자열 | 독립 컬럼으로 사용하지 않은 원본 필드 JSON |

## nginx_normalized_event_action.csv

- 용도: nginx 로그의 정규화·행위 분류 데이터
- 한 행: 정규화한 로그 이벤트 한 건
- 연결 키: `행 위치로 원시·파싱·정규화 파일과 대응; ID는 로그별로 다름`
- 생성 코드: [03_apply_event_action.py](../../scripts/03_apply_event_action.py)

| 순서 | 컬럼 | 관찰 형식 | 의미 |
|---:|---|---|---|
| 1 | `event_time_utc` | 시각 문자열 | 사건이 일어난 시각 (UTC). 형식 `YYYY-MM-DD HH:MM:SS.ffffff` |
| 2 | `log_source` | 문자열 | 어느 로그에서 온 행인지 |
| 3 | `src` | 문자열 | sshd/nginx/audit는 접속자 IP; sysmon은 서버 자신의 SourceIp(통합 시 dvc로 이동) |
| 4 | `http_method` | 문자열 | HTTP 요청 방식. 원문 요청 줄의 첫 단어 |
| 5 | `http_status_code` | 정수형 문자열 | 서버의 응답 코드 |
| 6 | `request` | 문자열 | 요청 경로 (URI) |
| 7 | `requestContext` | 문자열 | 이 요청을 보낸 이전 페이지 주소 (Referer) |
| 8 | `in` | 정수형 문자열 | 원문에 기록된 응답 크기 (바이트, `$body_bytes_sent`) |
| 9 | `is_api_request` | 불리언 문자열 | 요청 경로가 `/api`로 시작하는지 |
| 10 | `rawEvent` | 문자열 | 보존한 원본 로그 |
| 11 | `unmapped` | JSON 문자열 | 독립 컬럼으로 사용하지 않은 원본 필드 JSON |

## sshd_normalized.csv

- 용도: sshd 로그의 정규화·행위 분류 데이터
- 한 행: 정규화한 로그 이벤트 한 건
- 연결 키: `행 위치로 원시·파싱·정규화 파일과 대응; ID는 로그별로 다름`
- 생성 코드: [02_normalize_sshd.py](../../scripts/02_normalize_sshd.py)

| 순서 | 컬럼 | 관찰 형식 | 의미 |
|---:|---|---|---|
| 1 | `event_time_utc` | 시각 문자열 | 사건이 일어난 시각 (UTC). 형식 `YYYY-MM-DD HH:MM:SS.ffffff` |
| 2 | `dhost` | 문자열 | 초기 SSHD 호스트 |
| 3 | `src` | 문자열 | sshd/nginx/audit는 접속자 IP; sysmon은 서버 자신의 SourceIp(통합 시 dvc로 이동) |
| 4 | `spt` | 정수형 문자열 | 접속자 포트 |
| 5 | `duser` | 문자열 | SSHD에서 로그인·세션 대상이 된 리눅스 계정 |
| 6 | `dproc` | 문자열 | 로그를 기록한 프로그램 |
| 7 | `dpid` | 정수형 문자열 | 로그를 기록한 프로그램의 프로세스 번호 |
| 8 | `cat` | 문자열 | 초기 정규화 이벤트 범주 |
| 9 | `act` | 문자열 | 초기 정규화 행동 분류 |
| 10 | `outcome` | 문자열 | 초기 정규화 성공·실패 분류 |
| 11 | `reason` | 문자열 | 판정 또는 정규화 사유 |
| 12 | `msg` | 문자열 | 로그 본문 메시지 |
| 13 | `auth_method` | 문자열 | 인증 방식 |
| 14 | `user_exists` | 불리언 문자열 | 초기 정규화 사용자 존재 분류 |
| 15 | `key_fingerprint` | 문자열 | 로그인에 쓴 공개키 지문 |
| 16 | `session_id` | 정수형 문자열 | 원본 systemd-logind 세션 번호(업무 세션 ID와 다름) |
| 17 | `connection_id` | 문자열 | SSHD 접속 연결 식별자 |
| 18 | `rawEvent` | 시각 문자열 | 보존한 원본 로그 |
| 19 | `unmapped` | JSON 문자열 | 독립 컬럼으로 사용하지 않은 원본 필드 JSON |

## sshd_normalized_event_action.csv

- 용도: sshd 로그의 정규화·행위 분류 데이터
- 한 행: 정규화한 로그 이벤트 한 건
- 연결 키: `행 위치로 원시·파싱·정규화 파일과 대응; ID는 로그별로 다름`
- 생성 코드: [03_apply_event_action.py](../../scripts/03_apply_event_action.py)

| 순서 | 컬럼 | 관찰 형식 | 의미 |
|---:|---|---|---|
| 1 | `event_time_utc` | 시각 문자열 | 사건이 일어난 시각 (UTC). 형식 `YYYY-MM-DD HH:MM:SS.ffffff` |
| 2 | `log_source` | 문자열 | 어느 로그에서 온 행인지 |
| 3 | `src` | 문자열 | sshd/nginx/audit는 접속자 IP; sysmon은 서버 자신의 SourceIp(통합 시 dvc로 이동) |
| 4 | `spt` | 정수형 문자열 | 접속자 포트 |
| 5 | `duser` | 문자열 | SSHD에서 로그인·세션 대상이 된 리눅스 계정 |
| 6 | `dproc` | 문자열 | 로그를 기록한 프로그램 |
| 7 | `dpid` | 정수형 문자열 | 로그를 기록한 프로그램의 프로세스 번호 |
| 8 | `event_action` | 문자열 | 원본 로그의 행위 이름. 로그마다 값 종류가 다르다 (SSHD 10종, Sysmon 4종, 감사로그 12종). NGINX는 원본에 행위 필드가 없어 빈칸이며, `http_method`·`http_status_code`가 대신한다 |
| 9 | `msg` | 문자열 | 로그 본문 메시지 |
| 10 | `auth_method` | 문자열 | 인증 방식 |
| 11 | `key_fingerprint` | 문자열 | 로그인에 쓴 공개키 지문 |
| 12 | `session_id` | 정수형 문자열 | 원본 systemd-logind 세션 번호(업무 세션 ID와 다름) |
| 13 | `rawEvent` | 시각 문자열 | 보존한 원본 로그 |
| 14 | `unmapped` | JSON 문자열 | 독립 컬럼으로 사용하지 않은 원본 필드 JSON |

## sysmon_normalized.csv

- 용도: sysmon 로그의 정규화·행위 분류 데이터
- 한 행: 정규화한 로그 이벤트 한 건
- 연결 키: `행 위치로 원시·파싱·정규화 파일과 대응; ID는 로그별로 다름`
- 생성 코드: [02_normalize_sysmon.py](../../scripts/02_normalize_sysmon.py)

| 순서 | 컬럼 | 관찰 형식 | 의미 |
|---:|---|---|---|
| 1 | `event_time_utc` | 시각 문자열 | 사건이 일어난 시각 (UTC). 형식 `YYYY-MM-DD HH:MM:SS.ffffff` |
| 2 | `dvchost` | 문자열 | 로그를 남긴 서버 이름 |
| 3 | `suser` | 문자열 | 행위를 한 계정. Sysmon은 리눅스 계정, 감사로그는 콘솔 계정이다 |
| 4 | `src` | 문자열 | sshd/nginx/audit는 접속자 IP; sysmon은 서버 자신의 SourceIp(통합 시 dvc로 이동) |
| 5 | `dst` | 문자열 | 네트워크 연결의 목적지 IP |
| 6 | `dpt` | 정수형 문자열 | 네트워크 연결의 목적지 포트 |
| 7 | `cat` | 문자열 | 초기 정규화 이벤트 범주 |
| 8 | `act` | 문자열 | 초기 정규화 행동 분류 |
| 9 | `EventID` | 정수형 문자열 | Sysmon 사건 종류 번호 |
| 10 | `Image` | 문자열 | 실행 파일 경로 |
| 11 | `ProcessId` | 정수형 문자열 | 프로세스 번호 |
| 12 | `ProcessGuid` | 문자열 | 프로세스 고유 식별자 |
| 13 | `CommandLine` | 문자열 | 실행 명령과 인수 |
| 14 | `CurrentDirectory` | 문자열 | 실행한 위치 (작업 디렉터리) |
| 15 | `ParentProcessGuid` | 문자열 | 부모 프로세스 고유 식별자 |
| 16 | `ParentProcessId` | 정수형 문자열 | 부모 프로세스 번호 |
| 17 | `ParentImage` | 문자열 | 부모 실행 파일 경로 |
| 18 | `ParentCommandLine` | 문자열 | 부모 실행 명령 |
| 19 | `ParentUser` | 문자열 | 부모 프로세스 실행 계정 |
| 20 | `TargetFilename` | 문자열 | 생성된 파일 경로 |
| 21 | `EventRecordID` | 정수형 문자열 | Sysmon 원본 레코드 번호. `dvchost`와 함께 쓰면 행마다 고유하다 |
| 22 | `rawEvent` | 문자열 | 보존한 원본 로그 |
| 23 | `unmapped` | JSON 문자열 | 독립 컬럼으로 사용하지 않은 원본 필드 JSON |

## sysmon_normalized_event_action.csv

- 용도: sysmon 로그의 정규화·행위 분류 데이터
- 한 행: 정규화한 로그 이벤트 한 건
- 연결 키: `행 위치로 원시·파싱·정규화 파일과 대응; ID는 로그별로 다름`
- 생성 코드: [03_apply_event_action.py](../../scripts/03_apply_event_action.py)

| 순서 | 컬럼 | 관찰 형식 | 의미 |
|---:|---|---|---|
| 1 | `event_time_utc` | 시각 문자열 | 사건이 일어난 시각 (UTC). 형식 `YYYY-MM-DD HH:MM:SS.ffffff` |
| 2 | `log_source` | 문자열 | 어느 로그에서 온 행인지 |
| 3 | `dvchost` | 문자열 | 로그를 남긴 서버 이름 |
| 4 | `suser` | 문자열 | 행위를 한 계정. Sysmon은 리눅스 계정, 감사로그는 콘솔 계정이다 |
| 5 | `src` | 문자열 | sshd/nginx/audit는 접속자 IP; sysmon은 서버 자신의 SourceIp(통합 시 dvc로 이동) |
| 6 | `dst` | 문자열 | 네트워크 연결의 목적지 IP |
| 7 | `dpt` | 정수형 문자열 | 네트워크 연결의 목적지 포트 |
| 8 | `event_action` | 문자열 | 원본 로그의 행위 이름. 로그마다 값 종류가 다르다 (SSHD 10종, Sysmon 4종, 감사로그 12종). NGINX는 원본에 행위 필드가 없어 빈칸이며, `http_method`·`http_status_code`가 대신한다 |
| 9 | `EventID` | 정수형 문자열 | Sysmon 사건 종류 번호 |
| 10 | `Image` | 문자열 | 실행 파일 경로 |
| 11 | `ProcessId` | 정수형 문자열 | 프로세스 번호 |
| 12 | `ProcessGuid` | 문자열 | 프로세스 고유 식별자 |
| 13 | `CommandLine` | 문자열 | 실행 명령과 인수 |
| 14 | `CurrentDirectory` | 문자열 | 실행한 위치 (작업 디렉터리) |
| 15 | `ParentProcessGuid` | 문자열 | 부모 프로세스 고유 식별자 |
| 16 | `ParentProcessId` | 정수형 문자열 | 부모 프로세스 번호 |
| 17 | `ParentImage` | 문자열 | 부모 실행 파일 경로 |
| 18 | `ParentCommandLine` | 문자열 | 부모 실행 명령 |
| 19 | `ParentUser` | 문자열 | 부모 프로세스 실행 계정 |
| 20 | `TargetFilename` | 문자열 | 생성된 파일 경로 |
| 21 | `EventRecordID` | 정수형 문자열 | Sysmon 원본 레코드 번호. `dvchost`와 함께 쓰면 행마다 고유하다 |
| 22 | `rawEvent` | 문자열 | 보존한 원본 로그 |
| 23 | `unmapped` | JSON 문자열 | 독립 컬럼으로 사용하지 않은 원본 필드 JSON |
