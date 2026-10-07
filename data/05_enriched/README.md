# 05_enriched: 맥락 보강

[전체 데이터](../README.md) · [전체 흐름](../../README.md) · [처리 규칙·분석 근거](../../docs/04_통합_보강_연결.md)

- 입력: [03_normalized](../03_normalized/README.md)
- 생성 코드: [05_enrich.py](../../scripts/05_enrich.py)
- 다음 사용 단계: [06_classified](../06_classified/README.md), [08_baseline](../08_baseline/README.md), [09_detections](../09_detections/README.md), [10_risk](../10_risk/README.md), [11_investigation](../11_investigation/README.md)

CSV는 UTF-8 BOM이다. 아래 자료형은 현재 CSV의 비어 있지 않은 값을 관찰한 형식이며 강제 스키마가 아니다. 코드의 기본 CSV 읽기는 문자열이다. 식별자·포트는 숫자처럼 보여도 문자열로 보존하고, 계산할 컬럼만 명시적으로 변환한다. 빈칸은 미관측·비해당·기준선 부족 등을 뜻하므로 0과 구분한다.

## 파일 찾기

| 파일 | 행 × 열 | 용도 |
|---|---:|---|
| [account_inventory.csv](account_inventory.csv) | 23 × 18 | 계정 체계·역할·동일인 후보 |
| [action_catalog.csv](action_catalog.csv) | 30 × 10 | 로그별 행위의 의미·분류·민감도 |
| [host_inventory.csv](host_inventory.csv) | 4 × 11 | 서버별 역할·중요도·관측 근거 |
| [ip_inventory.csv](ip_inventory.csv) | 21 × 14 | IP별 구역·계정·관측 기간 |

## account_inventory.csv

- 용도: 계정 체계·역할·동일인 후보
- 한 행: 계정 체계 내 계정 하나
- 연결 키: `account_system + account`
- 생성 코드: [05_enrich.py](../../scripts/05_enrich.py)

| 순서 | 컬럼 | 관찰 형식 | 의미 |
|---:|---|---|---|
| 1 | `account` | 문자열 | 관측·연결한 계정 |
| 2 | `account_system` | 문자열 | linux 또는 콘솔 계정 체계 |
| 3 | `account_type` | 문자열 | 사용자·시스템 등 계정 종류 |
| 4 | `type_basis` | 문자열 | 계정 종류의 근거(공식·관측·추정 등) |
| 5 | `role` | 문자열 | 추정 역할 |
| 6 | `role_basis` | 문자열 | 역할의 근거(공식·관측·추정 등) |
| 7 | `is_privileged` | 불리언 문자열 | 특권 계정 여부 |
| 8 | `login_success` | 정수형 문자열 | 로그인 성공 수 |
| 9 | `login_fail` | 정수형 문자열 | 로그인 실패 수 |
| 10 | `console_events` | 정수형 문자열 | 콘솔 이벤트 수 |
| 11 | `primary_client_ip` | 문자열 | 주로 관측된 접속 IP |
| 12 | `other_client_ips` | 문자열 | 그 외 접속 IP |
| 13 | `active_hosts` | 문자열 | 활동 서버 |
| 14 | `home_host` | 문자열 | 주 작업 서버(추정) |
| 15 | `home_host_basis` | 문자열 | 주 작업 서버의 근거(공식·관측·추정 등) |
| 16 | `person_candidate` | 문자열 | 동일인 후보(확정 인물 ID가 아님) |
| 17 | `person_basis` | 문자열 | 동일인 후보 연결 근거 |
| 18 | `note` | 문자열 | 해석 참고 |

## action_catalog.csv

- 용도: 로그별 행위의 의미·분류·민감도
- 한 행: 로그 출처별 행위 하나
- 연결 키: `log_source + event_action`
- 생성 코드: [05_enrich.py](../../scripts/05_enrich.py)

| 순서 | 컬럼 | 관찰 형식 | 의미 |
|---:|---|---|---|
| 1 | `log_source` | 문자열 | 어느 로그에서 온 행인지 |
| 2 | `event_action` | 문자열 | 원본 로그의 행위 이름. 로그마다 값 종류가 다르다 (SSHD 10종, Sysmon 4종, 감사로그 12종). NGINX는 원본에 행위 필드가 없어 빈칸이며, `http_method`·`http_status_code`가 대신한다 |
| 3 | `vendor_code` | 문자열 | 원본 공급자 이벤트 코드 |
| 4 | `category` | 문자열 | 행위 범주 |
| 5 | `description` | 문자열 | 행위 의미 |
| 6 | `sensitivity` | 문자열 | 행위 민감도 |
| 7 | `meaning_basis` | 문자열 | 행위 의미의 근거(공식·관측·추정 등) |
| 8 | `sensitivity_basis` | 문자열 | 행위 민감도의 근거(공식·관측·추정 등) |
| 9 | `event_count` | 정수형 문자열 | 관측 이벤트 수 |
| 10 | `sample_request` | 문자열 | 대표 요청 경로 |

## host_inventory.csv

- 용도: 서버별 역할·중요도·관측 근거
- 한 행: 서버 하나
- 연결 키: `host`
- 생성 코드: [05_enrich.py](../../scripts/05_enrich.py)

| 순서 | 컬럼 | 관찰 형식 | 의미 |
|---:|---|---|---|
| 1 | `host` | 문자열 | 대상 서버 |
| 2 | `ip` | 문자열 | IP 주소 |
| 3 | `ip_basis` | 문자열 | IP 연결의 근거(공식·관측·추정 등) |
| 4 | `role` | 문자열 | 추정 역할 |
| 5 | `role_basis` | 문자열 | 역할의 근거(공식·관측·추정 등) |
| 6 | `criticality` | 문자열 | 자산 중요도 |
| 7 | `criticality_basis` | 문자열 | 중요도의 근거(공식·관측·추정 등) |
| 8 | `role_evidence` | 문자열 | 역할 추정 근거 |
| 9 | `collected_logs` | 문자열 | 서버에서 수집된 로그 종류 |
| 10 | `interactive_accounts` | 문자열 | 대화형 사용자 계정 |
| 11 | `service_accounts` | 문자열 | 서비스 계정 |

## ip_inventory.csv

- 용도: IP별 구역·계정·관측 기간
- 한 행: IP 하나
- 연결 키: `ip`
- 생성 코드: [05_enrich.py](../../scripts/05_enrich.py)

| 순서 | 컬럼 | 관찰 형식 | 의미 |
|---:|---|---|---|
| 1 | `ip` | 문자열 | IP 주소 |
| 2 | `ip_zone` | 문자열 | IP 구역 |
| 3 | `zone_basis` | 문자열 | IP 구역의 근거(공식·관측·추정 등) |
| 4 | `host` | 문자열 | 대상 서버 |
| 5 | `host_basis` | 문자열 | 호스트 연결의 근거(공식·관측·추정 등) |
| 6 | `is_rfc1918` | 불리언 문자열 | RFC1918 사설 대역 여부 |
| 7 | `is_documentation_range` | 불리언 문자열 | 문서 예시용 IP 대역 여부 |
| 8 | `linux_login_accounts` | 문자열 | 리눅스 로그인 계정 |
| 9 | `console_accounts` | 문자열 | 관측된 콘솔 계정 목록 |
| 10 | `failed_login_accounts` | 문자열 | 실패 시도 계정 |
| 11 | `seen_in_logs` | 문자열 | 관측 로그 종류 |
| 12 | `event_count` | 정수형 문자열 | 관측 이벤트 수 |
| 13 | `first_seen` | 시각 문자열 | 최초 관측 UTC |
| 14 | `last_seen` | 시각 문자열 | 최종 관측 UTC |
