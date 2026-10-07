# 04_integrated: 타임라인 통합

[전체 데이터](../README.md) · [전체 흐름](../../README.md) · [처리 규칙·분석 근거](../../docs/04_통합_보강_연결.md)

- 입력: [03_normalized](../03_normalized/README.md)
- 생성 코드: [04_integrate.py](../../scripts/04_integrate.py)
- 다음 사용 단계: [06_classified](../06_classified/README.md)

CSV는 UTF-8 BOM이다. 아래 자료형은 현재 CSV의 비어 있지 않은 값을 관찰한 형식이며 강제 스키마가 아니다. 코드의 기본 CSV 읽기는 문자열이다. 식별자·포트는 숫자처럼 보여도 문자열로 보존하고, 계산할 컬럼만 명시적으로 변환한다. 빈칸은 미관측·비해당·기준선 부족 등을 뜻하므로 0과 구분한다.

## 파일 찾기

| 파일 | 행 × 열 | 용도 |
|---|---:|---|
| [timeline.csv](timeline.csv) | 9,125 × 43 | 전체 로그를 시각순으로 통합 |

## timeline.csv

- 용도: 전체 로그를 시각순으로 통합
- 한 행: 이벤트 한 건
- 연결 키: `log_source + source_row`
- 생성 코드: [04_integrate.py](../../scripts/04_integrate.py)

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
