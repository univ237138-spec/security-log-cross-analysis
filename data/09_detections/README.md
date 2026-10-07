# 09_detections: 탐지

[전체 데이터](../README.md) · [전체 흐름](../../README.md) · [처리 규칙·분석 근거](../../docs/06_탐지_위험점수.md)

- 입력: [07_sessions](../07_sessions/README.md), [08_baseline](../08_baseline/README.md), [05_enriched](../05_enriched/README.md)
- 생성 코드: [09_detect.py](../../scripts/09_detect.py)
- 다음 사용 단계: [10_risk](../10_risk/README.md), [11_investigation](../11_investigation/README.md)

CSV는 UTF-8 BOM이다. 아래 자료형은 현재 CSV의 비어 있지 않은 값을 관찰한 형식이며 강제 스키마가 아니다. 코드의 기본 CSV 읽기는 문자열이다. 식별자·포트는 숫자처럼 보여도 문자열로 보존하고, 계산할 컬럼만 명시적으로 변환한다. 빈칸은 미관측·비해당·기준선 부족 등을 뜻하므로 0과 구분한다.

## 파일 찾기

| 파일 | 행 × 열 | 용도 |
|---|---:|---|
| [detection_rules.csv](detection_rules.csv) | 25 × 8 | 룰·행위 탐지 조건과 임계값 |
| [detections.csv](detections.csv) | 76 × 18 | 이벤트·세션에서 발견한 탐지 신호 |

## detection_rules.csv

- 용도: 룰·행위 탐지 조건과 임계값
- 한 행: 탐지 정의 하나
- 연결 키: `id → detections.detection_type`
- 생성 코드: [09_detect.py](../../scripts/09_detect.py)

| 순서 | 컬럼 | 관찰 형식 | 의미 |
|---:|---|---|---|
| 1 | `id` | 문자열 | 탐지 규칙 ID |
| 2 | `method` | 문자열 | rule 또는 behavior |
| 3 | `name` | 문자열 | 탐지 규칙 이름 |
| 4 | `condition` | 문자열 | 탐지 조건 |
| 5 | `attck` | 문자열 | MITRE ATT&CK 기법 매핑 |
| 6 | `severity` | 문자열 | 신호 심각도 |
| 7 | `data_source` | 문자열 | 규칙이 사용하는 로그·기준선 |
| 8 | `threshold_note` | 문자열 | 임계값 결정 근거 |

## detections.csv

- 용도: 이벤트·세션에서 발견한 탐지 신호
- 한 행: 탐지 신호 한 건
- 연결 키: `detection_id; detection_type; work_session_id`
- 생성 코드: [09_detect.py](../../scripts/09_detect.py)

| 순서 | 컬럼 | 관찰 형식 | 의미 |
|---:|---|---|---|
| 1 | `detection_id` | 문자열 | 탐지 신호 고유 ID |
| 2 | `method` | 문자열 | rule 또는 behavior |
| 3 | `detection_type` | 문자열 | 탐지 규칙 ID(R/B) |
| 4 | `name` | 문자열 | 탐지 규칙 이름 |
| 5 | `attck` | 문자열 | MITRE ATT&CK 기법 매핑 |
| 6 | `severity` | 문자열 | 신호 심각도 |
| 7 | `event_time_utc` | 시각 문자열 | 사건이 일어난 시각 (UTC). 형식 `YYYY-MM-DD HH:MM:SS.ffffff` |
| 8 | `log_source` | 문자열 | 어느 로그에서 온 행인지 |
| 9 | `source_row` | 정수형 문자열 | 원래 정규화 파일에서 몇 번째 데이터 행이었는지 (1부터). `log_source`와 함께 쓰면 원래 행을 찾을 수 있다 |
| 10 | `bucket` | 문자열 | session / background / external 분류 |
| 11 | `host` | 문자열 | 대상 서버 |
| 12 | `client_ip` | 문자열 | 접속자 IP |
| 13 | `account` | 문자열 | 관측·연결한 계정 |
| 14 | `person_candidate` | 문자열 | 동일인 후보(확정 인물 ID가 아님) |
| 15 | `work_session_id` | 문자열 | 분석에서 만든 업무 세션 ID |
| 16 | `linked_sessions` | 문자열 | 추정 연결된 업무 세션 목록 |
| 17 | `link_basis` | 문자열 | 세션 추정 연결의 근거 |
| 18 | `evidence` | 문자열 | 탐지 근거 |
