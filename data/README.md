# 데이터 찾기

[프로젝트 안내](../README.md) · [코드 목록](../scripts/README.md)

현재 원시·중간·최종 CSV **45개**를 보관한다. 각 단계 README에서 행의 의미·컬럼·연결 키·생성 코드를 확인할 수 있다.

## 관리 원칙

- `01_raw`는 수신 원본이며 수정하지 않는다.
- CSV는 UTF-8 BOM, 쉼표 구분이다. 원문에 쉼표·개행이 있으므로 단순 줄 수로 행 수를 세지 않는다.
- 정규화 이후 `event_time_utc`는 UTC다. `_kst` 필드는 한국 시각이다. 원시 시각과 적재 시각은 별도 의미를 가진다.
- `rawEvent`와 `unmapped`를 보존한다. 고객 식별값·계정·내부 IP가 포함된 팀 공유 스냅샷이다.
- 입력·코드를 수정하면 영향받는 다음 단계를 순서대로 재생성하고 데이터·설명 문서를 함께 갱신한다.
- 아래 행 수와 컬럼 수는 현재 업로드 파일을 직접 읽어 계산했다.

| 단계 | 파일 | 행 × 열 | 용도 |
|---|---|---:|---|
| [01_raw](01_raw/README.md) | [audit_raw.csv](01_raw/audit_raw.csv) | 456 × 2 | audit 로그의 원시 로그 데이터 |
| [01_raw](01_raw/README.md) | [nginx_raw.csv](01_raw/nginx_raw.csv) | 2,223 × 2 | nginx 로그의 원시 로그 데이터 |
| [01_raw](01_raw/README.md) | [sshd_raw.csv](01_raw/sshd_raw.csv) | 1,364 × 2 | sshd 로그의 원시 로그 데이터 |
| [01_raw](01_raw/README.md) | [sysmon_raw.csv](01_raw/sysmon_raw.csv) | 5,082 × 2 | sysmon 로그의 원시 로그 데이터 |
| [02_parsed](02_parsed/README.md) | [audit_parsed.csv](02_parsed/audit_parsed.csv) | 456 × 16 | audit 로그의 파싱 데이터 |
| [02_parsed](02_parsed/README.md) | [nginx_parsed.csv](02_parsed/nginx_parsed.csv) | 2,223 × 13 | nginx 로그의 파싱 데이터 |
| [02_parsed](02_parsed/README.md) | [sshd_parsed.csv](02_parsed/sshd_parsed.csv) | 1,364 × 19 | sshd 로그의 파싱 데이터 |
| [02_parsed](02_parsed/README.md) | [sysmon_parsed.csv](02_parsed/sysmon_parsed.csv) | 5,082 × 54 | sysmon 로그의 파싱 데이터 |
| [03_normalized](03_normalized/README.md) | [audit_normalized.csv](03_normalized/audit_normalized.csv) | 456 × 15 | audit 로그의 정규화·행위 분류 데이터 |
| [03_normalized](03_normalized/README.md) | [audit_normalized_event_action.csv](03_normalized/audit_normalized_event_action.csv) | 456 × 11 | audit 로그의 정규화·행위 분류 데이터 |
| [03_normalized](03_normalized/README.md) | [nginx_normalized.csv](03_normalized/nginx_normalized.csv) | 2,223 × 13 | nginx 로그의 정규화·행위 분류 데이터 |
| [03_normalized](03_normalized/README.md) | [nginx_normalized_event_action.csv](03_normalized/nginx_normalized_event_action.csv) | 2,223 × 11 | nginx 로그의 정규화·행위 분류 데이터 |
| [03_normalized](03_normalized/README.md) | [sshd_normalized.csv](03_normalized/sshd_normalized.csv) | 1,364 × 19 | sshd 로그의 정규화·행위 분류 데이터 |
| [03_normalized](03_normalized/README.md) | [sshd_normalized_event_action.csv](03_normalized/sshd_normalized_event_action.csv) | 1,364 × 14 | sshd 로그의 정규화·행위 분류 데이터 |
| [03_normalized](03_normalized/README.md) | [sysmon_normalized.csv](03_normalized/sysmon_normalized.csv) | 5,082 × 23 | sysmon 로그의 정규화·행위 분류 데이터 |
| [03_normalized](03_normalized/README.md) | [sysmon_normalized_event_action.csv](03_normalized/sysmon_normalized_event_action.csv) | 5,082 × 23 | sysmon 로그의 정규화·행위 분류 데이터 |
| [04_integrated](04_integrated/README.md) | [timeline.csv](04_integrated/timeline.csv) | 9,125 × 43 | 전체 로그를 시각순으로 통합 |
| [05_enriched](05_enriched/README.md) | [account_inventory.csv](05_enriched/account_inventory.csv) | 23 × 18 | 계정 체계·역할·동일인 후보 |
| [05_enriched](05_enriched/README.md) | [action_catalog.csv](05_enriched/action_catalog.csv) | 30 × 10 | 로그별 행위의 의미·분류·민감도 |
| [05_enriched](05_enriched/README.md) | [host_inventory.csv](05_enriched/host_inventory.csv) | 4 × 11 | 서버별 역할·중요도·관측 근거 |
| [05_enriched](05_enriched/README.md) | [ip_inventory.csv](05_enriched/ip_inventory.csv) | 21 × 14 | IP별 구역·계정·관측 기간 |
| [06_classified](06_classified/README.md) | [timeline_classified.csv](06_classified/timeline_classified.csv) | 9,125 × 61 | 이벤트의 엔티티·세 가지 분석 분류 |
| [07_sessions](07_sessions/README.md) | [sessions.csv](07_sessions/sessions.csv) | 146 × 30 | 업무 세션의 시간·접속·행위 집계 |
| [07_sessions](07_sessions/README.md) | [timeline_sessions.csv](07_sessions/timeline_sessions.csv) | 9,125 × 63 | 이벤트와 업무 세션의 연결 |
| [08_baseline](08_baseline/README.md) | [background_baseline.csv](08_baseline/background_baseline.csv) | 4,079 × 16 | 시스템 이벤트 발생 전 패턴 관측 횟수 |
| [08_baseline](08_baseline/README.md) | [background_patterns.csv](08_baseline/background_patterns.csv) | 34 × 9 | 서버·계정·행위별 시스템 패턴 |
| [08_baseline](08_baseline/README.md) | [external_profile.csv](08_baseline/external_profile.csv) | 3 × 10 | 세션 없는 외부 로그인 시도 집계 |
| [08_baseline](08_baseline/README.md) | [session_baseline.csv](08_baseline/session_baseline.csv) | 146 × 58 | 각 세션과 과거 세션의 비교 |
| [09_detections](09_detections/README.md) | [detection_rules.csv](09_detections/detection_rules.csv) | 25 × 8 | 룰·행위 탐지 조건과 임계값 |
| [09_detections](09_detections/README.md) | [detections.csv](09_detections/detections.csv) | 76 × 18 | 이벤트·세션에서 발견한 탐지 신호 |
| [10_risk](10_risk/README.md) | [config_findings.csv](10_risk/config_findings.csv) | 4 × 8 | MFA 설정 위험·외부 로그인 시도 참고 |
| [10_risk](10_risk/README.md) | [entity_risk.csv](10_risk/entity_risk.csv) | 12 × 9 | 사람 후보·서버별 위험점수 집계 |
| [10_risk](10_risk/README.md) | [risk_events.csv](10_risk/risk_events.csv) | 53 × 14 | 세션에 반영되는 탐지 신호 점수 |
| [10_risk](10_risk/README.md) | [sensitivity.csv](10_risk/sensitivity.csv) | 27 × 9 | 가중치 변화에 따른 경보 안정성 |
| [10_risk](10_risk/README.md) | [session_risk.csv](10_risk/session_risk.csv) | 146 × 13 | 세션별 위험점수·경보·우선순위 |
| [11_investigation](11_investigation/README.md) | [alert_context.csv](11_investigation/alert_context.csv) | 4 × 25 | 경보에 붙일 시간·접속·행위·공백 요약 |
| [11_investigation](11_investigation/README.md) | [incident_timeline.csv](11_investigation/incident_timeline.csv) | 129 × 12 | 경보별 사건 흐름과 탐지 근거 |
| [11_investigation](11_investigation/README.md) | [pivots.csv](11_investigation/pivots.csv) | 130 × 5 | 조사 질문별 항목·답·근거 |
| [11_investigation](11_investigation/README.md) | [triage.csv](11_investigation/triage.csv) | 11 × 7 | 경보·비경보 상위 세션의 활동·귀속 판정 |
| [12_stats](12_stats/README.md) | [summary.csv](12_stats/summary.csv) | 2 × 6 | 두 가정 검정의 보정 p값·결론 |
| [12_stats](12_stats/README.md) | [test1_path.csv](12_stats/test1_path.csv) | 4 × 9 | 표본별 웹·서버 경로 동시 사용 비율 |
| [12_stats](12_stats/README.md) | [test1_per_person.csv](12_stats/test1_per_person.csv) | 8 × 4 | 개인별 경로 동시 사용 비율 |
| [12_stats](12_stats/README.md) | [test2_describe.csv](12_stats/test2_describe.csv) | 8 × 8 | 개인별 세션 시작 시각 기술통계 |
| [12_stats](12_stats/README.md) | [test2_hour.csv](12_stats/test2_hour.csv) | 2 × 7 | 시작 시각 분포의 Kruskal–Wallis 검정 |
| [12_stats](12_stats/README.md) | [test2_posthoc.csv](12_stats/test2_posthoc.csv) | 28 × 8 | 개인 쌍별 시작 시각 사후 비교 |

## 자주 쓰는 연결

- 이벤트: `log_source + source_row`로 정규화 원본 행을 찾는다.
- 세션: `work_session_id`로 세션·기준선·위험점수·조사 결과를 연결한다.
- 탐지: `detections.detection_type → detection_rules.id`, `risk_events.detection_id → detections.detection_id`.
- 계정: `account_system + account`를 함께 확인한다. `person_candidate`는 추정 연결이다.
- 시스템 활동: `ProcessGuid` 및 `pattern_id`로 프로세스·패턴을 확인한다.
