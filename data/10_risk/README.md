# 10_risk: 위험점수·경보

[전체 데이터](../README.md) · [전체 흐름](../../README.md) · [처리 규칙·분석 근거](../../docs/06_탐지_위험점수.md)

- 입력: [09_detections](../09_detections/README.md), [07_sessions](../07_sessions/README.md), [05_enriched](../05_enriched/README.md), [08_baseline](../08_baseline/README.md)
- 생성 코드: [10_risk.py](../../scripts/10_risk.py)
- 다음 사용 단계: [11_investigation](../11_investigation/README.md)

CSV는 UTF-8 BOM이다. 아래 자료형은 현재 CSV의 비어 있지 않은 값을 관찰한 형식이며 강제 스키마가 아니다. 코드의 기본 CSV 읽기는 문자열이다. 식별자·포트는 숫자처럼 보여도 문자열로 보존하고, 계산할 컬럼만 명시적으로 변환한다. 빈칸은 미관측·비해당·기준선 부족 등을 뜻하므로 0과 구분한다.

## 파일 찾기

| 파일 | 행 × 열 | 용도 |
|---|---:|---|
| [config_findings.csv](config_findings.csv) | 4 × 8 | MFA 설정 위험·외부 로그인 시도 참고 |
| [entity_risk.csv](entity_risk.csv) | 12 × 9 | 사람 후보·서버별 위험점수 집계 |
| [risk_events.csv](risk_events.csv) | 53 × 14 | 세션에 반영되는 탐지 신호 점수 |
| [sensitivity.csv](sensitivity.csv) | 27 × 9 | 가중치 변화에 따른 경보 안정성 |
| [session_risk.csv](session_risk.csv) | 146 × 13 | 세션별 위험점수·경보·우선순위 |

## config_findings.csv

- 용도: MFA 설정 위험·외부 로그인 시도 참고
- 한 행: 계정 또는 외부 IP 관련 발견 항목
- 연결 키: `finding + account (명시적 고유 ID 없음)`
- 생성 코드: [10_risk.py](../../scripts/10_risk.py)

| 순서 | 컬럼 | 관찰 형식 | 의미 |
|---:|---|---|---|
| 1 | `finding` | 문자열 | 설정 위험 또는 외부 시도 항목 |
| 2 | `rule` | 문자열 | 관련 탐지 규칙 |
| 3 | `account` | 문자열 | 관측·연결한 계정 |
| 4 | `count` | 정수형 문자열 | 해당 항목 관측 횟수 |
| 5 | `sessions` | 정수형 문자열 | 관련 세션 수 |
| 6 | `first_seen` | 시각 문자열 | 최초 관측 UTC |
| 7 | `last_seen` | 시각 문자열 | 최종 관측 UTC |
| 8 | `note` | 문자열 | 해석 참고 |

## entity_risk.csv

- 용도: 사람 후보·서버별 위험점수 집계
- 한 행: 사람 후보 또는 서버 하나
- 연결 키: `entity_type + entity`
- 생성 코드: [10_risk.py](../../scripts/10_risk.py)

| 순서 | 컬럼 | 관찰 형식 | 의미 |
|---:|---|---|---|
| 1 | `entity_type` | 문자열 | person 또는 host |
| 2 | `entity` | 문자열 | 사람 후보 또는 서버 이름 |
| 3 | `total_score` | 실수형 문자열 | 대상별 누적 위험점수 |
| 4 | `max_24h` | 실수형 문자열 | 24시간 창 최대 누적 점수 |
| 5 | `max_24h_at` | 문자열 | 24시간 최대 점수에 최초 도달한 세션 ID |
| 6 | `max_7d` | 실수형 문자열 | 7일 창 최대 누적 점수 |
| 7 | `max_7d_at` | 문자열 | 7일 최대 점수에 최초 도달한 세션 ID |
| 8 | `alert_sessions` | 문자열 | 경보 세션 ID 목록 |
| 9 | `signal_types` | 문자열 | 세션에서는 신호 종류 수; 서버 집계에서는 종류 목록 |

## risk_events.csv

- 용도: 세션에 반영되는 탐지 신호 점수
- 한 행: 탐지 신호와 연결 세션의 조합
- 연결 키: `detection_id + work_session_id`
- 생성 코드: [10_risk.py](../../scripts/10_risk.py)

| 순서 | 컬럼 | 관찰 형식 | 의미 |
|---:|---|---|---|
| 1 | `detection_id` | 문자열 | 탐지 신호 고유 ID |
| 2 | `detection_type` | 문자열 | 탐지 규칙 ID(R/B) |
| 3 | `name` | 문자열 | 탐지 규칙 이름 |
| 4 | `method` | 문자열 | rule 또는 behavior |
| 5 | `severity` | 문자열 | 신호 심각도 |
| 6 | `event_time_utc` | 시각 문자열 | 사건이 일어난 시각 (UTC). 형식 `YYYY-MM-DD HH:MM:SS.ffffff` |
| 7 | `host` | 문자열 | 대상 서버 |
| 8 | `work_session_id` | 문자열 | 분석에서 만든 업무 세션 ID |
| 9 | `link` | 문자열 | direct 또는 linked 연결 종류 |
| 10 | `base_score` | 정수형 문자열 | 신호 기본 점수 |
| 11 | `criticality_factor` | 실수형 문자열 | 서버 중요도 계수 |
| 12 | `confidence_factor` | 실수형 문자열 | 연결 신뢰 계수 |
| 13 | `signal_score` | 실수형 문자열 | 기본점수 × 중요도 × 연결 신뢰 계수 |
| 14 | `tactics` | 문자열 | ATT&CK 전술 목록 |

## sensitivity.csv

- 용도: 가중치 변화에 따른 경보 안정성
- 한 행: 가중치 조합 하나
- 연결 키: `rule_high_med_low + behavior + linked_conf`
- 생성 코드: [10_risk.py](../../scripts/10_risk.py)

| 순서 | 컬럼 | 관찰 형식 | 의미 |
|---:|---|---|---|
| 1 | `rule_high_med_low` | 문자열 | 룰 심각도별 점수 조합 |
| 2 | `behavior` | 정수형 문자열 | 행위 탐지 기본점수 |
| 3 | `linked_conf` | 실수형 문자열 | 추정 연결 계수 |
| 4 | `alert_sessions` | 문자열 | 경보 세션 ID 목록 |
| 5 | `alert_count` | 정수형 문자열 | 경보 세션 수 |
| 6 | `same_alerts_as_base` | 불리언 문자열 | 기준 가중치와 경보 집합이 같은지 |
| 7 | `top10` | 문자열 | 상위 10개 세션 |
| 8 | `top10_overlap_with_base` | 정수형 문자열 | 기준 상위 10개와 겹치는 세션 수 |
| 9 | `top4` | 문자열 | 상위 4개 세션 집합 |

## session_risk.csv

- 용도: 세션별 위험점수·경보·우선순위
- 한 행: 업무 세션 하나
- 연결 키: `work_session_id`
- 생성 코드: [10_risk.py](../../scripts/10_risk.py)

| 순서 | 컬럼 | 관찰 형식 | 의미 |
|---:|---|---|---|
| 1 | `work_session_id` | 문자열 | 분석에서 만든 업무 세션 ID |
| 2 | `person_candidate` | 문자열 | 동일인 후보(확정 인물 ID가 아님) |
| 3 | `session_type` | 문자열 | server+web / server_only / web_only |
| 4 | `client_ip` | 문자열 | 접속자 IP |
| 5 | `start_utc` | 시각 문자열 | 세션 시작 UTC |
| 6 | `risk_score` | 실수형 문자열 | 중복 집계 규칙 적용 후 세션 위험점수 |
| 7 | `signal_types` | 정수형 문자열 | 세션에서는 신호 종류 수; 서버 집계에서는 종류 목록 |
| 8 | `tactic_count` | 정수형 문자열 | 서로 다른 전술 수 |
| 9 | `tactics` | 문자열 | ATT&CK 전술 목록 |
| 10 | `score_breakdown` | 문자열 | 위험점수 구성 근거 |
| 11 | `alert` | 불리언 문자열 | 경보 여부 |
| 12 | `alert_reason` | 문자열 | 경보 기준 충족 사유 |
| 13 | `rank` | 정수형 문자열 | 위험점수 정렬 순위 |
