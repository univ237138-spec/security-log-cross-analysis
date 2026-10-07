# 07_sessions: 세션화

[전체 데이터](../README.md) · [전체 흐름](../../README.md) · [처리 규칙·분석 근거](../../docs/05_세션화_기준선.md)

- 입력: [06_classified](../06_classified/README.md)
- 생성 코드: [07_sessionize.py](../../scripts/07_sessionize.py)
- 다음 사용 단계: [08_baseline](../08_baseline/README.md), [09_detections](../09_detections/README.md), [10_risk](../10_risk/README.md), [11_investigation](../11_investigation/README.md), [12_stats](../12_stats/README.md)

CSV는 UTF-8 BOM이다. 아래 자료형은 현재 CSV의 비어 있지 않은 값을 관찰한 형식이며 강제 스키마가 아니다. 코드의 기본 CSV 읽기는 문자열이다. 식별자·포트는 숫자처럼 보여도 문자열로 보존하고, 계산할 컬럼만 명시적으로 변환한다. 빈칸은 미관측·비해당·기준선 부족 등을 뜻하므로 0과 구분한다.

## 파일 찾기

| 파일 | 행 × 열 | 용도 |
|---|---:|---|
| [sessions.csv](sessions.csv) | 146 × 30 | 업무 세션의 시간·접속·행위 집계 |
| [timeline_sessions.csv](timeline_sessions.csv) | 9,125 × 63 | 이벤트와 업무 세션의 연결 |

## sessions.csv

- 용도: 업무 세션의 시간·접속·행위 집계
- 한 행: 업무 세션 하나
- 연결 키: `work_session_id`
- 생성 코드: [07_sessionize.py](../../scripts/07_sessionize.py)

| 순서 | 컬럼 | 관찰 형식 | 의미 |
|---:|---|---|---|
| 1 | `work_session_id` | 문자열 | 분석에서 만든 업무 세션 ID |
| 2 | `session_type` | 문자열 | server+web / server_only / web_only |
| 3 | `person_candidate` | 문자열 | 동일인 후보(확정 인물 ID가 아님) |
| 4 | `linux_account` | 문자열 | 리눅스 계정 |
| 5 | `console_accounts` | 문자열 | 관측된 콘솔 계정 목록 |
| 6 | `client_ip` | 문자열 | 접속자 IP |
| 7 | `client_zone` | 문자열 | 접속자 IP 구역 |
| 8 | `start_utc` | 시각 문자열 | 세션 시작 UTC |
| 9 | `end_utc` | 시각 문자열 | 세션 종료 UTC |
| 10 | `ssh_end_utc` | 시각 문자열 | SSH 접속 종료 UTC |
| 11 | `start_hour_kst` | 정수형 문자열 | 시작 시각을 KST 시간 단위로 표현 |
| 12 | `weekday_kst` | 문자열 | 시작일의 KST 요일 이름(월~일) |
| 13 | `duration_min` | 실수형 문자열 | 세션 지속 시간(분) |
| 14 | `event_count` | 정수형 문자열 | 관측 이벤트 수 |
| 15 | `ssh_connections` | 정수형 문자열 | 세션에 합친 SSH 접속 수 |
| 16 | `auth_method` | 문자열 | 인증 방식 |
| 17 | `failed_before_login` | 정수형 문자열 | 로그인 직전 실패 수 |
| 18 | `sysmon_count` | 정수형 문자열 | Sysmon 이벤트 수 |
| 19 | `hosts` | 문자열 | 관측 서버별 집계 |
| 20 | `process_count` | 정수형 문자열 | 프로세스 생성 수 |
| 21 | `external_connections` | 정수형 문자열 | 외부 연결 수 |
| 22 | `web_login_count` | 정수형 문자열 | 콘솔 로그인 수 |
| 23 | `web_login_types` | 문자열 | 콘솔 로그인 행위 종류 |
| 24 | `nginx_count` | 정수형 문자열 | nginx 이벤트 수 |
| 25 | `audit_count` | 정수형 문자열 | 감사로그 이벤트 수 |
| 26 | `web_after_ssh_count` | 정수형 문자열 | SSH 종료 뒤 연결한 웹 이벤트 수 |
| 27 | `api_count` | 정수형 문자열 | API 요청 수 |
| 28 | `non_get_count` | 정수형 문자열 | GET 외 HTTP 요청 수 |
| 29 | `sensitive_count` | 정수형 문자열 | 민감 행위 수 |
| 30 | `sensitive_actions` | 문자열 | 민감 행위 목록 |

## timeline_sessions.csv

- 용도: 이벤트와 업무 세션의 연결
- 한 행: 이벤트 한 건
- 연결 키: `log_source + source_row; work_session_id는 다대일 연결`
- 생성 코드: [07_sessionize.py](../../scripts/07_sessionize.py)

| 순서 | 컬럼 | 관찰 형식 | 의미 |
|---:|---|---|---|
| 1 | `event_time_utc` | 시각 문자열 | 사건이 일어난 시각 (UTC). 형식 `YYYY-MM-DD HH:MM:SS.ffffff` |
| 2 | `log_source` | 문자열 | 어느 로그에서 온 행인지 |
| 3 | `time_precision` | 문자열 | 원본 시각의 정밀도. 이 값보다 작은 단위의 순서는 해석하지 않는다 |
| 4 | `source_row` | 정수형 문자열 | 원래 정규화 파일에서 몇 번째 데이터 행이었는지 (1부터). `log_source`와 함께 쓰면 원래 행을 찾을 수 있다 |
| 5 | `event_action` | 문자열 | 원본 로그의 행위 이름. 로그마다 값 종류가 다르다 (SSHD 10종, Sysmon 4종, 감사로그 12종). NGINX는 원본에 행위 필드가 없어 빈칸이며, `http_method`·`http_status_code`가 대신한다 |
| 6 | `src` | 문자열 | 접속자(요청자) IP. Sysmon의 IP는 접속자가 아니라서 여기에 넣지 않고 `dvc`에 둔다 |
| 7 | `dvc` | 문자열 | 이벤트를 남긴 서버 자신의 IP (Sysmon 원본 `SourceIp`). 네트워크 연결 이벤트에만 있다 |
| 8 | `dvchost` | 문자열 | 로그를 남긴 서버 이름 |
| 9 | `suser` | 문자열 | 행위를 한 계정. Sysmon은 리눅스 계정, 감사로그는 콘솔 계정이다 |
| 10 | `duser` | 문자열 | SSHD에서 로그인·세션 대상이 된 리눅스 계정 |
| 11 | `user_type` | 문자열 | `suser`·`duser`가 어떤 계정 체계인지. 사용자 값이 있는 행에만 있다 |
| 12 | `msg` | 문자열 | 로그 본문 메시지 |
| 13 | `request` | 문자열 | 요청 경로 (URI) |
| 14 | `http_method` | 문자열 | HTTP 요청 방식. 원문 요청 줄의 첫 단어 |
| 15 | `http_status_code` | 정수형 문자열 | 서버의 응답 코드 |
| 16 | `requestContext` | 문자열 | 이 요청을 보낸 이전 페이지 주소 (Referer) |
| 17 | `in` | 정수형 문자열 | 원문에 기록된 응답 크기 (바이트, `$body_bytes_sent`) |
| 18 | `is_api_request` | 불리언 문자열 | 요청 경로가 `/api`로 시작하는지 |
| 19 | `spt` | 정수형 문자열 | 접속자 포트 |
| 20 | `dproc` | 문자열 | 로그를 기록한 프로그램 |
| 21 | `dpid` | 정수형 문자열 | 로그를 기록한 프로그램의 프로세스 번호 |
| 22 | `auth_method` | 문자열 | 인증 방식 |
| 23 | `key_fingerprint` | 문자열 | 로그인에 쓴 공개키 지문 |
| 24 | `session_id` | 정수형 문자열 | 원본 systemd-logind 세션 번호(업무 세션 ID와 다름) |
| 25 | `dst` | 문자열 | 네트워크 연결의 목적지 IP |
| 26 | `dpt` | 정수형 문자열 | 네트워크 연결의 목적지 포트 |
| 27 | `EventID` | 정수형 문자열 | Sysmon 사건 종류 번호 |
| 28 | `Image` | 문자열 | 실행 파일 경로 |
| 29 | `ProcessId` | 정수형 문자열 | 프로세스 번호 |
| 30 | `ProcessGuid` | 문자열 | 프로세스 고유 식별자 |
| 31 | `CommandLine` | 문자열 | 실행 명령과 인수 |
| 32 | `CurrentDirectory` | 문자열 | 실행한 위치 (작업 디렉터리) |
| 33 | `ParentProcessGuid` | 문자열 | 부모 프로세스 고유 식별자 |
| 34 | `ParentProcessId` | 정수형 문자열 | 부모 프로세스 번호 |
| 35 | `ParentImage` | 문자열 | 부모 실행 파일 경로 |
| 36 | `ParentCommandLine` | 문자열 | 부모 실행 명령 |
| 37 | `ParentUser` | 문자열 | 부모 프로세스 실행 계정 |
| 38 | `TargetFilename` | 문자열 | 생성된 파일 경로 |
| 39 | `EventRecordID` | 정수형 문자열 | Sysmon 원본 레코드 번호. `dvchost`와 함께 쓰면 행마다 고유하다 |
| 40 | `t_event_id` | 문자열 | 감사 사건 **종류** 코드. 원본 그대로이며, S/G를 성공·실패로 해석하는 것은 아직 추정이다 (멘토 확인 대기) |
| 41 | `doc_id` | 문자열 | 감사 사건 **한 건**의 고유 ID |
| 42 | `rawEvent` | 문자열 | 보존한 원본 로그 |
| 43 | `unmapped` | JSON 문자열 | 독립 컬럼으로 사용하지 않은 원본 필드 JSON |
| 44 | `connection_id` | 문자열 | SSHD 접속 연결 식별자 |
| 45 | `fill_basis` | 문자열 | 원본에 없는 연결값을 채운 방법·근거 |
| 46 | `client_ip` | 문자열 | 접속자 IP |
| 47 | `client_zone` | 문자열 | 접속자 IP 구역 |
| 48 | `account` | 문자열 | 관측·연결한 계정 |
| 49 | `account_system` | 문자열 | linux 또는 콘솔 계정 체계 |
| 50 | `account_type` | 문자열 | 사용자·시스템 등 계정 종류 |
| 51 | `person_candidate` | 문자열 | 동일인 후보(확정 인물 ID가 아님) |
| 52 | `person_basis` | 문자열 | 동일인 후보 연결 근거 |
| 53 | `host` | 문자열 | 대상 서버 |
| 54 | `host_role` | 문자열 | 서버 역할 |
| 55 | `host_criticality` | 문자열 | 서버 중요도 |
| 56 | `dst_zone` | 문자열 | 목적지 IP 구역 |
| 57 | `action_category` | 문자열 | 행위 범주 |
| 58 | `action_sensitivity` | 문자열 | 행위 민감도 |
| 59 | `bucket` | 문자열 | session / background / external 분류 |
| 60 | `bucket_label` | 문자열 | 분류의 설명 이름 |
| 61 | `bucket_reason` | 문자열 | 분류한 규칙·근거 |
| 62 | `work_session_id` | 문자열 | 분석에서 만든 업무 세션 ID |
| 63 | `work_session_link` | 문자열 | 이벤트를 업무 세션에 연결한 방법 |
