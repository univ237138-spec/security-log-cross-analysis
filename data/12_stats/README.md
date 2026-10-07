# 12_stats: 통계 검정

[전체 데이터](../README.md) · [전체 흐름](../../README.md) · [처리 규칙·분석 근거](../../docs/08_통계검정.md)

- 입력: [07_sessions](../07_sessions/README.md)
- 생성 코드: [12_stat_tests.py](../../scripts/12_stat_tests.py)
- 다음 사용 단계: 최종 결과 해석·보고

CSV는 UTF-8 BOM이다. 아래 자료형은 현재 CSV의 비어 있지 않은 값을 관찰한 형식이며 강제 스키마가 아니다. 코드의 기본 CSV 읽기는 문자열이다. 식별자·포트는 숫자처럼 보여도 문자열로 보존하고, 계산할 컬럼만 명시적으로 변환한다. 빈칸은 미관측·비해당·기준선 부족 등을 뜻하므로 0과 구분한다.

## 파일 찾기

| 파일 | 행 × 열 | 용도 |
|---|---:|---|
| [summary.csv](summary.csv) | 2 × 6 | 두 가정 검정의 보정 p값·결론 |
| [test1_path.csv](test1_path.csv) | 4 × 9 | 표본별 웹·서버 경로 동시 사용 비율 |
| [test1_per_person.csv](test1_per_person.csv) | 8 × 4 | 개인별 경로 동시 사용 비율 |
| [test2_describe.csv](test2_describe.csv) | 8 × 8 | 개인별 세션 시작 시각 기술통계 |
| [test2_hour.csv](test2_hour.csv) | 2 × 7 | 시작 시각 분포의 Kruskal–Wallis 검정 |
| [test2_posthoc.csv](test2_posthoc.csv) | 28 × 8 | 개인 쌍별 시작 시각 사후 비교 |

## summary.csv

- 용도: 두 가정 검정의 보정 p값·결론
- 한 행: 주 분석 검정 하나
- 연결 키: `test`
- 생성 코드: [12_stat_tests.py](../../scripts/12_stat_tests.py)

| 순서 | 컬럼 | 관찰 형식 | 의미 |
|---:|---|---|---|
| 1 | `test` | 문자열 | 검정 이름 |
| 2 | `sample` | 문자열 | 분석 표본 정의 |
| 3 | `p_value` | 실수형 문자열 | 보정 전 p값 |
| 4 | `p_holm` | 실수형 문자열 | Holm 다중검정 보정 p값 |
| 5 | `decision` | 문자열 | 검정 결론 |
| 6 | `effect` | 문자열 | 검정별 효과 크기·차이 설명 |

## test1_path.csv

- 용도: 표본별 웹·서버 경로 동시 사용 비율
- 한 행: 분석 표본 하나
- 연결 키: `sample`
- 생성 코드: [12_stat_tests.py](../../scripts/12_stat_tests.py)

| 순서 | 컬럼 | 관찰 형식 | 의미 |
|---:|---|---|---|
| 1 | `sample` | 문자열 | 분석 표본 정의 |
| 2 | `k` | 정수형 문자열 | 두 경로를 함께 쓴 세션 수 |
| 3 | `n` | 정수형 문자열 | 표본 수 |
| 4 | `proportion` | 실수형 문자열 | k/n 비율 |
| 5 | `p0` | 실수형 문자열 | 귀무가설 기준 비율 |
| 6 | `effect` | 실수형 문자열 | 검정별 효과 크기·차이 설명 |
| 7 | `ci95_low` | 실수형 문자열 | 비율 95% 신뢰구간 하한 |
| 8 | `ci95_high` | 실수형 문자열 | 비율 95% 신뢰구간 상한 |
| 9 | `p_value` | 실수형 문자열 | 보정 전 p값 |

## test1_per_person.csv

- 용도: 개인별 경로 동시 사용 비율
- 한 행: 사람 후보 하나
- 연결 키: `person`
- 생성 코드: [12_stat_tests.py](../../scripts/12_stat_tests.py)

| 순서 | 컬럼 | 관찰 형식 | 의미 |
|---:|---|---|---|
| 1 | `person` | 문자열 | 사람 후보 |
| 2 | `k` | 정수형 문자열 | 두 경로를 함께 쓴 세션 수 |
| 3 | `n` | 정수형 문자열 | 표본 수 |
| 4 | `proportion` | 실수형 문자열 | k/n 비율 |

## test2_describe.csv

- 용도: 개인별 세션 시작 시각 기술통계
- 한 행: 사람 후보 하나
- 연결 키: `person`
- 생성 코드: [12_stat_tests.py](../../scripts/12_stat_tests.py)

| 순서 | 컬럼 | 관찰 형식 | 의미 |
|---:|---|---|---|
| 1 | `person` | 문자열 | 사람 후보 |
| 2 | `n` | 정수형 문자열 | 표본 수 |
| 3 | `min` | 문자열 | 시작 시각 최솟값(KST HH:MM) |
| 4 | `q1` | 문자열 | 시작 시각 1사분위(KST HH:MM) |
| 5 | `median` | 문자열 | 시작 시각 중앙값(KST HH:MM) |
| 6 | `q3` | 문자열 | 시작 시각 3사분위(KST HH:MM) |
| 7 | `max` | 문자열 | 시작 시각 최댓값(KST HH:MM) |
| 8 | `iqr_min` | 정수형 문자열 | 시작 시각 사분위 범위(분) |

## test2_hour.csv

- 용도: 시작 시각 분포의 Kruskal–Wallis 검정
- 한 행: 분석 표본 하나
- 연결 키: `sample`
- 생성 코드: [12_stat_tests.py](../../scripts/12_stat_tests.py)

| 순서 | 컬럼 | 관찰 형식 | 의미 |
|---:|---|---|---|
| 1 | `sample` | 문자열 | 분석 표본 정의 |
| 2 | `groups` | 정수형 문자열 | 비교 집단 수 |
| 3 | `n` | 정수형 문자열 | 표본 수 |
| 4 | `H` | 실수형 문자열 | Kruskal–Wallis 검정 통계량 |
| 5 | `df` | 정수형 문자열 | 자유도 |
| 6 | `epsilon_sq` | 실수형 문자열 | epsilon squared 효과 크기 |
| 7 | `p_value` | 실수형 문자열 | 보정 전 p값 |

## test2_posthoc.csv

- 용도: 개인 쌍별 시작 시각 사후 비교
- 한 행: 사람 후보 두 명의 쌍
- 연결 키: `a + b`
- 생성 코드: [12_stat_tests.py](../../scripts/12_stat_tests.py)

| 순서 | 컬럼 | 관찰 형식 | 의미 |
|---:|---|---|---|
| 1 | `a` | 문자열 | 비교 집단 A |
| 2 | `b` | 문자열 | 비교 집단 B |
| 3 | `median_a` | 문자열 | A 중앙값(KST HH:MM) |
| 4 | `median_b` | 문자열 | B 중앙값(KST HH:MM) |
| 5 | `median_diff_min` | 정수형 문자열 | 중앙값 차이(분) |
| 6 | `p_raw` | 실수형 문자열 | 사후 비교 보정 전 p값 |
| 7 | `p_holm` | 실수형 문자열 | Holm 다중검정 보정 p값 |
| 8 | `significant` | 불리언 문자열 | 보정 후 유의수준 충족 여부 |
