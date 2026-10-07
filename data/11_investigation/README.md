# 11_investigation: 조사

[전체 데이터](../README.md) · [전체 흐름](../../README.md) · [처리 규칙·분석 근거](../../docs/07_조사_결과.md)

- 입력: [10_risk](../10_risk/README.md), [09_detections](../09_detections/README.md), [08_baseline](../08_baseline/README.md), [07_sessions](../07_sessions/README.md), [05_enriched](../05_enriched/README.md)
- 생성 코드: [11_investigate.py](../../scripts/11_investigate.py)
- 다음 사용 단계: 최종 결과 해석·보고

CSV는 UTF-8 BOM이다. 아래 자료형은 현재 CSV의 비어 있지 않은 값을 관찰한 형식이며 강제 스키마가 아니다. 코드의 기본 CSV 읽기는 문자열이다. 식별자·포트는 숫자처럼 보여도 문자열로 보존하고, 계산할 컬럼만 명시적으로 변환한다. 빈칸은 미관측·비해당·기준선 부족 등을 뜻하므로 0과 구분한다.

## 파일 찾기

| 파일 | 행 × 열 | 용도 |
|---|---:|---|
| [alert_context.csv](alert_context.csv) | 4 × 25 | 경보에 붙일 시간·접속·행위·공백 요약 |
| [incident_timeline.csv](incident_timeline.csv) | 129 × 12 | 경보별 사건 흐름과 탐지 근거 |
| [pivots.csv](pivots.csv) | 130 × 5 | 조사 질문별 항목·답·근거 |
| [triage.csv](triage.csv) | 11 × 7 | 경보·비경보 상위 세션의 활동·귀속 판정 |

사고 카드 Markdown은 저장소 추적에서 제외했다. 조사 코드 실행 시 로컬에 생성될 수 있지만 `.gitignore`가 업로드를 막는다. CSV 4개는 모두 포함한다.

## alert_context.csv

- 용도: 경보에 붙일 시간·접속·행위·공백 요약
- 한 행: 경보 세션 하나
- 연결 키: `work_session_id`
- 생성 코드: [11_investigate.py](../../scripts/11_investigate.py)

| 순서 | 컬럼 | 관찰 형식 | 의미 |
|---:|---|---|---|
| 1 | `work_session_id` | 문자열 | 분석에서 만든 업무 세션 ID |
| 2 | `person_candidate` | 문자열 | 동일인 후보(확정 인물 ID가 아님) |
| 3 | `risk_score` | 실수형 문자열 | 중복 집계 규칙 적용 후 세션 위험점수 |
| 4 | `tactic_chain` | 문자열 | 시간순 공격 전술 흐름 |
| 5 | `top_signals` | 문자열 | 주요 신호 |
| 6 | `start_kst` | 문자열 | 세션 시작 KST |
| 7 | `usual_hours_kst` | 문자열 | 평소 시작 시각 범위(KST) |
| 8 | `hour_distance` | 정수형 문자열 | 과거 시작 시각 범위에서 벗어난 시간(시간 단위) |
| 9 | `client_ip` | 문자열 | 접속자 IP |
| 10 | `ip_zone` | 문자열 | IP 구역 |
| 11 | `ip_first_time_for_person` | 불리언 문자열 | 개인 과거에서 처음 본 접속 IP인지 |
| 12 | `session_type` | 문자열 | server+web / server_only / web_only |
| 13 | `usual_session_types` | 문자열 | 평소 접속 경로 유형 |
| 14 | `hours_since_prev_session` | 실수형 문자열 | 직전 세션 이후 경과 시간 |
| 15 | `failed_before_login` | 정수형 문자열 | 로그인 직전 실패 수 |
| 16 | `web_login` | 문자열 | 콘솔 로그인 정보 |
| 17 | `linked_system_activity` | 문자열 | 추정 연결한 시스템 활동 |
| 18 | `files_created` | 문자열 | 관측된 생성 파일 |
| 19 | `external_destinations` | 문자열 | 외부 목적지 |
| 20 | `external_dest_seen_elsewhere` | 문자열 | 같은 외부 목적지가 다른 곳에서도 관측됐는지 |
| 21 | `config_changes` | 문자열 | 계정·설정 변경 |
| 22 | `concurrent_sessions_same_host` | 문자열 | 같은 서버의 동시간대 세션 |
| 23 | `data_gaps` | 정수형 문자열 | 현재 로그로 확인할 수 없는 항목 |
| 24 | `activity_verdict` | 문자열 | 활동에 대한 조사 판정 |
| 25 | `attribution` | 문자열 | 활동의 세션 귀속 근거 |

## incident_timeline.csv

- 용도: 경보별 사건 흐름과 탐지 근거
- 한 행: 경보에 포함된 타임라인 항목
- 연결 키: `incident → work_session_id; log_source + source_row`
- 생성 코드: [11_investigate.py](../../scripts/11_investigate.py)

| 순서 | 컬럼 | 관찰 형식 | 의미 |
|---:|---|---|---|
| 1 | `incident` | 문자열 | 조사 대상 경보 세션 ID |
| 2 | `event_time_utc` | 시각 문자열 | 사건이 일어난 시각 (UTC). 형식 `YYYY-MM-DD HH:MM:SS.ffffff` |
| 3 | `time_kst` | 문자열 | 사건 시각 KST |
| 4 | `log_source` | 문자열 | 어느 로그에서 온 행인지 |
| 5 | `source_row` | 정수형 문자열 | 원래 정규화 파일에서 몇 번째 데이터 행이었는지 (1부터). `log_source`와 함께 쓰면 원래 행을 찾을 수 있다 |
| 6 | `basis` | 문자열 | 관측·추정·모름·판정 등 근거 구분 |
| 7 | `host` | 문자열 | 대상 서버 |
| 8 | `client_ip` | 문자열 | 접속자 IP |
| 9 | `account` | 문자열 | 관측·연결한 계정 |
| 10 | `event_action` | 문자열 | 원본 로그의 행위 이름. 로그마다 값 종류가 다르다 (SSHD 10종, Sysmon 4종, 감사로그 12종). NGINX는 원본에 행위 필드가 없어 빈칸이며, `http_method`·`http_status_code`가 대신한다 |
| 11 | `summary` | 문자열 | 타임라인 항목 요약 |
| 12 | `detection_ids` | 문자열 | 관련 탐지 신호 ID 목록 |

## pivots.csv

- 용도: 조사 질문별 항목·답·근거
- 한 행: 세션별 조사 질문의 항목 하나
- 연결 키: `work_session_id + question + item (중복 가능)`
- 생성 코드: [11_investigate.py](../../scripts/11_investigate.py)

| 순서 | 컬럼 | 관찰 형식 | 의미 |
|---:|---|---|---|
| 1 | `work_session_id` | 문자열 | 분석에서 만든 업무 세션 ID |
| 2 | `question` | 문자열 | 조사 질문 번호 |
| 3 | `item` | 문자열 | 조사 항목 |
| 4 | `value` | 문자열 | 조사 결과 값 |
| 5 | `basis` | 문자열 | 관측·추정·모름·판정 등 근거 구분 |

## triage.csv

- 용도: 경보·비경보 상위 세션의 활동·귀속 판정
- 한 행: 조사 대상 세션 하나
- 연결 키: `work_session_id`
- 생성 코드: [11_investigate.py](../../scripts/11_investigate.py)

| 순서 | 컬럼 | 관찰 형식 | 의미 |
|---:|---|---|---|
| 1 | `work_session_id` | 문자열 | 분석에서 만든 업무 세션 ID |
| 2 | `alert` | 불리언 문자열 | 경보 여부 |
| 3 | `person_candidate` | 문자열 | 동일인 후보(확정 인물 ID가 아님) |
| 4 | `risk_score` | 실수형 문자열 | 중복 집계 규칙 적용 후 세션 위험점수 |
| 5 | `activity_verdict` | 문자열 | 활동에 대한 조사 판정 |
| 6 | `attribution` | 문자열 | 활동의 세션 귀속 근거 |
| 7 | `reason` | 문자열 | 판정 또는 정규화 사유 |
