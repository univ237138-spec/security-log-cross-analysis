# 08_baseline: 기준선

[전체 데이터](../README.md) · [전체 흐름](../../README.md) · [처리 규칙·분석 근거](../../docs/05_세션화_기준선.md)

- 입력: [07_sessions](../07_sessions/README.md), [05_enriched](../05_enriched/README.md)
- 생성 코드: [08_baseline.py](../../scripts/08_baseline.py)
- 다음 사용 단계: [09_detections](../09_detections/README.md), [10_risk](../10_risk/README.md), [11_investigation](../11_investigation/README.md)

CSV는 UTF-8 BOM이다. 아래 자료형은 현재 CSV의 비어 있지 않은 값을 관찰한 형식이며 강제 스키마가 아니다. 코드의 기본 CSV 읽기는 문자열이다. 식별자·포트는 숫자처럼 보여도 문자열로 보존하고, 계산할 컬럼만 명시적으로 변환한다. 빈칸은 미관측·비해당·기준선 부족 등을 뜻하므로 0과 구분한다.

## 파일 찾기

| 파일 | 행 × 열 | 용도 |
|---|---:|---|
| [background_baseline.csv](background_baseline.csv) | 4,079 × 16 | 시스템 이벤트 발생 전 패턴 관측 횟수 |
| [background_patterns.csv](background_patterns.csv) | 34 × 9 | 서버·계정·행위별 시스템 패턴 |
| [external_profile.csv](external_profile.csv) | 3 × 10 | 세션 없는 외부 로그인 시도 집계 |
| [session_baseline.csv](session_baseline.csv) | 146 × 58 | 각 세션과 과거 세션의 비교 |

## background_baseline.csv

- 용도: 시스템 이벤트 발생 전 패턴 관측 횟수
- 한 행: 시스템 배경 이벤트 한 건
- 연결 키: `source_row (sysmon); pattern_id로 패턴 연결`
- 생성 코드: [08_baseline.py](../../scripts/08_baseline.py)

| 순서 | 컬럼 | 관찰 형식 | 의미 |
|---:|---|---|---|
| 1 | `event_time_utc` | 시각 문자열 | 사건이 일어난 시각 (UTC). 형식 `YYYY-MM-DD HH:MM:SS.ffffff` |
| 2 | `source_row` | 정수형 문자열 | 원래 정규화 파일에서 몇 번째 데이터 행이었는지 (1부터). `log_source`와 함께 쓰면 원래 행을 찾을 수 있다 |
| 3 | `host` | 문자열 | 대상 서버 |
| 4 | `account` | 문자열 | 관측·연결한 계정 |
| 5 | `event_action` | 문자열 | 원본 로그의 행위 이름. 로그마다 값 종류가 다르다 (SSHD 10종, Sysmon 4종, 감사로그 12종). NGINX는 원본에 행위 필드가 없어 빈칸이며, `http_method`·`http_status_code`가 대신한다 |
| 6 | `Image` | 문자열 | 실행 파일 경로 |
| 7 | `CommandLine` | 문자열 | 실행 명령과 인수 |
| 8 | `dst` | 문자열 | 네트워크 연결의 목적지 IP |
| 9 | `dpt` | 정수형 문자열 | 네트워크 연결의 목적지 포트 |
| 10 | `dst_zone` | 문자열 | 목적지 IP 구역 |
| 11 | `TargetFilename` | 문자열 | 생성된 파일 경로 |
| 12 | `ProcessGuid` | 문자열 | 프로세스 고유 식별자 |
| 13 | `pattern_id` | 문자열 | 시스템 활동 패턴 ID |
| 14 | `pattern_seen_before` | 정수형 문자열 | 같은 서버에서 그 시점 전에 패턴을 본 횟수 |
| 15 | `pattern_seen_other_hosts_before` | 정수형 문자열 | 다른 서버에서 그 시점 전에 패턴을 본 횟수 |
| 16 | `host_history_hours` | 실수형 문자열 | 서버 배경 활동의 관측 누적 시간(시간) |

## background_patterns.csv

- 용도: 서버·계정·행위별 시스템 패턴
- 한 행: 시스템 패턴 하나
- 연결 키: `pattern_id`
- 생성 코드: [08_baseline.py](../../scripts/08_baseline.py)

| 순서 | 컬럼 | 관찰 형식 | 의미 |
|---:|---|---|---|
| 1 | `pattern_id` | 문자열 | 시스템 활동 패턴 ID |
| 2 | `host` | 문자열 | 대상 서버 |
| 3 | `account` | 문자열 | 관측·연결한 계정 |
| 4 | `Image` | 문자열 | 실행 파일 경로 |
| 5 | `kind` | 문자열 | 패턴 종류(cmd/dst/file) |
| 6 | `detail` | 문자열 | 패턴을 정의하는 명령·목적지·파일 |
| 7 | `count` | 정수형 문자열 | 해당 항목 관측 횟수 |
| 8 | `first_seen` | 시각 문자열 | 최초 관측 UTC |
| 9 | `last_seen` | 시각 문자열 | 최종 관측 UTC |

## external_profile.csv

- 용도: 세션 없는 외부 로그인 시도 집계
- 한 행: 외부 접속 IP 하나
- 연결 키: `client_ip`
- 생성 코드: [08_baseline.py](../../scripts/08_baseline.py)

| 순서 | 컬럼 | 관찰 형식 | 의미 |
|---:|---|---|---|
| 1 | `client_ip` | 문자열 | 접속자 IP |
| 2 | `first_seen` | 시각 문자열 | 최초 관측 UTC |
| 3 | `last_seen` | 시각 문자열 | 최종 관측 UTC |
| 4 | `attempts` | 정수형 문자열 | 외부 로그인 시도 수 |
| 5 | `active_days` | 실수형 문자열 | 최초~최종 관측 간격(일) |
| 6 | `attempts_per_day` | 실수형 문자열 | 관측 기간으로 나눈 일평균 시도 수 |
| 7 | `distinct_accounts` | 정수형 문자열 | 시도한 서로 다른 계정 수 |
| 8 | `accounts` | 문자열 | 계정별 횟수 |
| 9 | `event_actions` | 문자열 | 관측 행위 목록 |
| 10 | `ever_logged_in` | 불리언 문자열 | 세션에 같은 접속 IP가 있는지 |

## session_baseline.csv

- 용도: 각 세션과 과거 세션의 비교
- 한 행: 업무 세션 하나
- 연결 키: `work_session_id`
- 생성 코드: [08_baseline.py](../../scripts/08_baseline.py)

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
| 31 | `baseline_level` | 문자열 | person / peer / global / none 기준선 수준 |
| 32 | `baseline_n` | 정수형 문자열 | 비교에 쓴 과거 세션 수 |
| 33 | `hist_hour_min` | 정수형 문자열 | 과거 시작 시각 최솟값(KST 시간) |
| 34 | `hist_hour_max` | 정수형 문자열 | 과거 시작 시각 최댓값(KST 시간) |
| 35 | `hour_outside` | 불리언 문자열 | 과거 시작 시각 범위 밖인지 |
| 36 | `hour_distance` | 정수형 문자열 | 과거 시작 시각 범위에서 벗어난 시간(시간 단위) |
| 37 | `hist_weekend_ratio` | 실수형 문자열 | 과거 주말 세션 비율 |
| 38 | `ip_new` | 불리언 문자열 | 과거 기준선에 없던 접속 IP인지 |
| 39 | `hist_session_type_ratio` | 실수형 문자열 | 과거 같은 경로 유형의 비율 |
| 40 | `login_types_new` | 문자열 | 과거에 없던 콘솔 로그인 유형 |
| 41 | `auth_methods_new` | 빈 값만 존재 | 과거에 없던 인증 방식 |
| 42 | `hist_failed_sessions` | 정수형 문자열 | 과거 로그인 실패 동반 세션 수 |
| 43 | `hosts_new` | 문자열 | 과거에 없던 대상 서버 |
| 44 | `cmds_new_person` | 문자열 | 개인 기준선에서 새로 나타난 명령 |
| 45 | `cmds_new_count` | 정수형 문자열 | 개인 기준선에서 새 명령 수 |
| 46 | `cmds_new_global` | 문자열 | 전체 기준선에서도 새 명령 |
| 47 | `sensitive_new` | 문자열 | 과거에 없던 민감 행위 |
| 48 | `hist_ext_sessions` | 정수형 문자열 | 과거 외부 연결 동반 세션 수 |
| 49 | `duration_min_pct` | 실수형 문자열 | 세션 지속 시간(분)의 과거 분포 내 백분위 |
| 50 | `duration_min_above_max` | 불리언 문자열 | 세션 지속 시간(분)가 과거 최댓값을 초과하는지 |
| 51 | `process_count_pct` | 실수형 문자열 | 프로세스 생성 수의 과거 분포 내 백분위 |
| 52 | `process_count_above_max` | 불리언 문자열 | 프로세스 생성 수가 과거 최댓값을 초과하는지 |
| 53 | `nginx_count_pct` | 실수형 문자열 | nginx 이벤트 수의 과거 분포 내 백분위 |
| 54 | `nginx_count_above_max` | 불리언 문자열 | nginx 이벤트 수가 과거 최댓값을 초과하는지 |
| 55 | `api_count_pct` | 실수형 문자열 | API 요청 수의 과거 분포 내 백분위 |
| 56 | `api_count_above_max` | 불리언 문자열 | API 요청 수가 과거 최댓값을 초과하는지 |
| 57 | `non_get_count_pct` | 실수형 문자열 | GET 외 HTTP 요청 수의 과거 분포 내 백분위 |
| 58 | `non_get_count_above_max` | 불리언 문자열 | GET 외 HTTP 요청 수가 과거 최댓값을 초과하는지 |
