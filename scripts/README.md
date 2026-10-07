# 스크립트 찾기

[전체 흐름](../README.md) · [데이터 목록](../data/README.md) · [실행 가이드](../docs/09_실행_가이드.md)

모든 명령은 저장소 최상위에서 실행한다. 단계 처리 코드는 출력 CSV를 덮어쓴다. 아래 검증·비교 코드는 결과를 읽어서 검사한다.

| 코드 | 역할 | 입력 | 출력 | 실행 |
|---|---|---|---|---|
| [01_parse_audit.py](01_parse_audit.py) | 파싱 | [01_raw](../data/01_raw) | [02_parsed](../data/02_parsed) | `python scripts/01_parse_audit.py` |
| [01_parse_nginx.py](01_parse_nginx.py) | 파싱 | [01_raw](../data/01_raw) | [02_parsed](../data/02_parsed) | `python scripts/01_parse_nginx.py` |
| [01_parse_sshd.py](01_parse_sshd.py) | 파싱 | [01_raw](../data/01_raw) | [02_parsed](../data/02_parsed) | `python scripts/01_parse_sshd.py` |
| [01_parse_sysmon.py](01_parse_sysmon.py) | 파싱 | [01_raw](../data/01_raw) | [02_parsed](../data/02_parsed) | `python scripts/01_parse_sysmon.py` |
| [02_normalize_audit.py](02_normalize_audit.py) | 정규화·행위 분류 | [01_raw](../data/01_raw)<br>[02_parsed](../data/02_parsed) | [03_normalized](../data/03_normalized) | `python scripts/02_normalize_audit.py` |
| [02_normalize_nginx.py](02_normalize_nginx.py) | 정규화·행위 분류 | [01_raw](../data/01_raw)<br>[02_parsed](../data/02_parsed) | [03_normalized](../data/03_normalized) | `python scripts/02_normalize_nginx.py` |
| [02_normalize_sshd.py](02_normalize_sshd.py) | 정규화·행위 분류 | [01_raw](../data/01_raw)<br>[02_parsed](../data/02_parsed) | [03_normalized](../data/03_normalized) | `python scripts/02_normalize_sshd.py` |
| [02_normalize_sysmon.py](02_normalize_sysmon.py) | 정규화·행위 분류 | [01_raw](../data/01_raw)<br>[02_parsed](../data/02_parsed) | [03_normalized](../data/03_normalized) | `python scripts/02_normalize_sysmon.py` |
| [03_apply_event_action.py](03_apply_event_action.py) | 정규화·행위 분류 | [03_normalized](../data/03_normalized) | [03_normalized](../data/03_normalized) | `python scripts/03_apply_event_action.py` |
| [04_integrate.py](04_integrate.py) | 타임라인 통합 | [03_normalized](../data/03_normalized) | [04_integrated](../data/04_integrated) | `python scripts/04_integrate.py` |
| [05_enrich.py](05_enrich.py) | 맥락 보강 | [03_normalized](../data/03_normalized) | [05_enriched](../data/05_enriched) | `python scripts/05_enrich.py` |
| [06_link_classify.py](06_link_classify.py) | 엔티티 연결·분류 | [04_integrated](../data/04_integrated)<br>[05_enriched](../data/05_enriched) | [06_classified](../data/06_classified) | `python scripts/06_link_classify.py` |
| [07_sessionize.py](07_sessionize.py) | 세션화 | [06_classified](../data/06_classified) | [07_sessions](../data/07_sessions) | `python scripts/07_sessionize.py` |
| [08_baseline.py](08_baseline.py) | 기준선 | [07_sessions](../data/07_sessions)<br>[05_enriched](../data/05_enriched) | [08_baseline](../data/08_baseline) | `python scripts/08_baseline.py` |
| [09_detect.py](09_detect.py) | 탐지 | [07_sessions](../data/07_sessions)<br>[08_baseline](../data/08_baseline)<br>[05_enriched](../data/05_enriched) | [09_detections](../data/09_detections) | `python scripts/09_detect.py` |
| [10_risk.py](10_risk.py) | 위험점수·경보 | [09_detections](../data/09_detections)<br>[07_sessions](../data/07_sessions)<br>[05_enriched](../data/05_enriched)<br>[08_baseline](../data/08_baseline) | [10_risk](../data/10_risk) | `python scripts/10_risk.py` |
| [11_investigate.py](11_investigate.py) | 조사 | [10_risk](../data/10_risk)<br>[09_detections](../data/09_detections)<br>[08_baseline](../data/08_baseline)<br>[07_sessions](../data/07_sessions)<br>[05_enriched](../data/05_enriched) | [11_investigation](../data/11_investigation) | `python scripts/11_investigate.py` |
| [12_stat_tests.py](12_stat_tests.py) | 통계 검정 | [07_sessions](../data/07_sessions) | [12_stats](../data/12_stats) | `python scripts/12_stat_tests.py` |

## 실행 도우미와 검증

| 코드 | 역할·입력 | 파일 변경 |
|---|---|---|
| [common.py](common.py) | 경로 상수·UTF-8 BOM CSV 읽기/쓰기·JSON 직렬화 | 단독 실행용 아님 |
| [run_all.py](run_all.py) | 로그 4종 파싱 → 초기 정규화 → 99_verify | 파싱·초기 정규화 CSV 덮어쓰기 |
| [99_verify.py](99_verify.py) | 초기 정규화 → 파싱 복원·원문 일치 | 없음 |
| [99_verify_event_action.py](99_verify_event_action.py) | 원시 → 파싱 → 최종 정규화의 보존·매핑 | 없음 |
| [99_verify_integrated.py](99_verify_integrated.py) | 통합 행 수·정렬·원본 복원·생성값 | 없음 |
| [98_compare_snowflake_export.py](98_compare_snowflake_export.py) | `로그명 내보낸CSV경로`를 인자로 받아 파싱 결과 비교 | 없음 |
| [98_compare_snowflake_normalized.py](98_compare_snowflake_normalized.py) | `로그명 내보낸CSV경로`를 인자로 받아 최종 정규화 결과 비교 | 없음 |

## 선행 조건과 주의할 출력

- 초기 파싱·정규화 코드는 `data/02_parsed`, `data/03_normalized` 폴더가 필요하다. 저장소에는 두 폴더가 포함돼 있다.
- `03_apply_event_action.py`는 같은 폴더의 `*_normalized.csv`를 읽어 `*_normalized_event_action.csv`를 만든다.
- `04_integrate.py`와 `05_enrich.py`는 모두 최종 정규화를 읽는다. `06_link_classify.py` 전에 둘 다 필요하다.
- `11_investigate.py`는 조사 CSV 4개와 로컬 사고 카드 Markdown을 만든다. 사고 카드 파일은 `.gitignore`로 저장소에서 제외된다.
- `12_stat_tests.py`는 세션 표와 scipy가 필요하다. 탐지·조사 CSV를 입력으로 사용하지 않는다.
- [그래프 생성 코드](../assets/analysis/make_eda.py)는 단계 결과를 읽어 PNG를 덮어쓴다.
