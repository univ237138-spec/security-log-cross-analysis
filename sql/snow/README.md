# Snowflake 파싱·정규화 SQL

Snowflake 안의 원시 로그 테이블에서 **`data/02_parsed/`와 같은 파싱 결과**를 만드는 SQL이다. 기준은 Python 파싱 코드(`scripts/01_parse_*.py`)다.

| 파일 | 입력 테이블 | 결과 (같아야 하는 파일) |
|---|---|---|
| [01_sshd_parse.sql](01_sshd_parse.sql) | `security_logs.raw.sshd_raw` | `data/02_parsed/sshd_parsed.csv` (1,364행 × 19열) |
| [02_nginx_parse.sql](02_nginx_parse.sql) | `security_logs.raw.nginx_raw` | `data/02_parsed/nginx_parsed.csv` (2,223행 × 13열) |
| [03_sysmon_parse.sql](03_sysmon_parse.sql) | `security_logs.raw.sysmon_raw` | `data/02_parsed/sysmon_parsed.csv` (5,082행 × 54열) |
| [04_audit_parse.sql](04_audit_parse.sql) | `security_logs.raw.teiren_audit_raw` | `data/02_parsed/audit_parsed.csv` (456행 × 16열) |


## 정규화 SQL (원시 로그 → 최종 정규화 결과를 한 번에)

파싱 SQL(01~04)과 같은 파싱 단계를 CTE로 안에 넣고, 그 위에서 정규화(`scripts/02_normalize_*.py` + `scripts/03_apply_event_action.py`)까지 한 쿼리로 처리한다. 결과는 **`data/03_normalized/*_normalized_event_action.csv`(최종 정규화 데이터셋)와 같다.**

| 파일 | 입력 테이블 | 결과 (같아야 하는 파일) |
|---|---|---|
| [11_sshd_normalize.sql](11_sshd_normalize.sql) | `security_logs.raw.sshd_raw` | `sshd_normalized_event_action.csv` (1,364행 × 14열) |
| [12_nginx_normalize.sql](12_nginx_normalize.sql) | `security_logs.raw.nginx_raw` | `nginx_normalized_event_action.csv` (2,223행 × 11열) |
| [13_sysmon_normalize.sql](13_sysmon_normalize.sql) | `security_logs.raw.sysmon_raw` | `sysmon_normalized_event_action.csv` (5,082행 × 23열) |
| [14_audit_normalize.sql](14_audit_normalize.sql) | `security_logs.raw.teiren_audit_raw` | `audit_normalized_event_action.csv` (456행 × 11열) |

사용 방법은 파싱 SQL과 같다. **0번 점검 쿼리**(모두 0) → **1번 정규화 쿼리** 실행 → CSV로 내려받아 비교한다.

```bash
python scripts/98_compare_snowflake_normalized.py sshd   <내려받은 CSV 경로>
python scripts/98_compare_snowflake_normalized.py nginx  <내려받은 CSV 경로>
python scripts/98_compare_snowflake_normalized.py sysmon <내려받은 CSV 경로>
python scripts/98_compare_snowflake_normalized.py audit  <내려받은 CSV 경로>
```

결과를 테이블로 저장하려면 1번 쿼리 위의 `CREATE OR REPLACE TABLE` 주석을 풀고 DB·스키마 이름을 바꾼다.

| 항목 | 내용 |
|---|---|
| 빈 값 | 파싱 SQL과 달리 **NULL**로 내보낸다 (분석할 때 `COUNT`, `IS NULL`이 바로 동작하도록). 비교 스크립트는 빈칸·`NULL`·`\N`을 같은 빈 값으로 본다. |
| 컬럼 타입 | 모든 컬럼이 VARCHAR다. `event_time_utc`는 `YYYY-MM-DD HH:MM:SS.ffffff` 문자열이라 문자열 정렬이 곧 시간순이다. 시각 계산이 필요하면 `TO_TIMESTAMP_NTZ("event_time_utc")`로 바꾼다. |
| `unmapped` | Python 결과와 **키 순서까지 같은** 한 줄 JSON 문자열이다. `OBJECT_CONSTRUCT`는 키를 알파벳순으로 정렬하므로 쓰지 않고, `ARRAY_CONSTRUCT_COMPACT` + `ARRAY_TO_STRING`으로 이어 붙였다 (값이 빈 키는 빠짐). 값은 `TO_JSON`으로 이스케이프한다. 안의 값을 쓰려면 `PARSE_JSON("unmapped"):"LOADED_AT"::STRING`처럼 꺼낸다. |
| 감사로그 `rawEvent` | `TO_JSON(event)`로 만든다. Snowflake가 키를 정렬하지만 원본 키가 이미 알파벳순이라 Python 결과와 같다. |
| 시각 변환 | sshd는 `+09:00` → UTC (`CONVERT_TIMEZONE`), nginx는 `+0000` → UTC, Sysmon은 `UtcTime` 뒤에 `000`, 감사로그는 `…Z`를 소수점 6자리로 맞춘다. |
| 로컬 검증 | SQL 파일에서 출력 컬럼 목록과 `unmapped` 키 목록을 읽어 파싱 CSV에 적용하고, 시각·`event_action`·NULL 처리 규칙을 Python으로 흉내 내 최종 CSV와 4종 모두 일치함을 확인했다 (2026-10-02). |
| **Snowflake에서 직접 실행** | ❌ **아직 하지 않았다.** 처음 실행할 때 비교 스크립트로 반드시 확인한다. |

## 사용 방법

1. 파일마다 **0번 점검 쿼리**를 먼저 실행한다. 표시된 값이 모두 0이어야 한다. 0이 아니면 새로운 형식의 로그가 들어온 것이라 규칙을 고쳐야 한다.
2. **1번 파싱 쿼리**를 실행하고, 결과를 CSV로 내려받는다.
3. 내려받은 CSV를 지금 파싱 결과와 비교한다.

```bash
python scripts/98_compare_snowflake_export.py sshd   <내려받은 CSV 경로>
python scripts/98_compare_snowflake_export.py nginx  <내려받은 CSV 경로>
python scripts/98_compare_snowflake_export.py sysmon <내려받은 CSV 경로>
python scripts/98_compare_snowflake_export.py audit  <내려받은 CSV 경로>
```

- 비교 스크립트는 컬럼 이름·순서, 행 수, 행 내용(순서 무관)을 확인한다. "결과: 일치"가 나오면 같은 파싱 결과다.
- 결과를 뷰로 저장하려면 1번 쿼리 위의 `CREATE OR REPLACE VIEW` 주석을 풀고 DB·스키마 이름을 바꾼다. 쓰기 권한이 필요하다.

## 검증 상태

| 항목 | 상태 |
|---|---|
| sshd, nginx 정규식 | ✅ SQL과 같은 정규식을 Python으로 원시 로그 전체에 적용해, 파싱 CSV와 모든 행이 같음을 확인했다 (Snowflake 규칙에 맞춰 `REGEXP_LIKE` = 전체 일치, `REGEXP_SUBSTR` = 앞에서부터 일치로 흉내 냄). |
| Sysmon, 감사로그 | 컬럼 목록은 파싱 CSV 헤더에서 자동으로 가져와 이름·순서가 같다. XML·JSON 처리는 Snowflake 함수(`PARSE_XML`, `XMLGET`, `FLATTEN`, VARIANT 경로)를 쓴다. |
| **Snowflake에서 직접 실행** | ❌ **아직 하지 않았다.** 처음 실행할 때 비교 스크립트로 반드시 확인한다. |

## 주의할 점

| 항목 | 내용 |
|---|---|
| 행 순서 | Snowflake 테이블에는 정해진 순서가 없어서 `ORDER BY`로 원본 파일 순서를 맞췄다 (sshd·감사로그는 시각, Sysmon은 시각 → `EventRecordID`). **nginx는 같은 초에 찍힌 5쌍의 순서를 정할 기준이 없어** 그 쌍 안에서는 순서가 다를 수 있다. 비교 스크립트는 순서와 상관없이 내용을 비교한다. |
| 빈 값 | 해당 없는 칸은 NULL 대신 빈 문자열(`''`)로 만들어 CSV와 맞췄다. |
| `LOADED_AT` | `TO_VARCHAR(loaded_at, 'YYYY-MM-DD HH24:MI:SS.FF3')`로 원본 CSV와 같은 모양(`2026-09-27 02:16:48.225`)을 만든다. 컬럼 타입이 `TIMESTAMP_LTZ`이면 세션 시간대에 따라 표시가 달라질 수 있다. 다르게 나오면 원본 CSV를 내려받을 때와 같은 시간대로 세션을 맞춘다 (`ALTER SESSION SET TIMEZONE = '…'`). |
| 컬럼 이름 대소문자 | Snowflake는 따옴표 없는 이름을 대문자로 바꾸므로, 모든 출력 컬럼 이름을 큰따옴표로 감쌌다 (예: `"user"`, `"Provider_Name"`). |
| 정규식 문자열 | 정규식은 작은따옴표(`'…'`) 문자열로 쓰고 백슬래시를 두 번 쓴다 (예: `'\\S+'`). 달러 두 개로 감싼 문자열은 Snowsight가 실행할 문장 범위를 잘못 나눠 `unexpected 'AS'` 오류가 났기 때문에 쓰지 않는다 (2026-10-01 수정). |
| 감사로그 `EVENT` 타입 | VARIANT 기준이다. VARCHAR라면 `event` 대신 `PARSE_JSON(event)`를 쓴다. |