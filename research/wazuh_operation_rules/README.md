# Wazuh 원본 룰 YAML

Wazuh **v4.14.8**의 탐지 룰 **4,512개 / XML 168개**를 원본 조건 그대로 YAML로 표현했습니다. 데이터에 맞춘 조건 수정, 컬럼 매핑, Sigma 변환, 룰 선별, ID·심각도·정규식·임계값 변경은 하지 않았습니다.

원본 커밋: `f470ad7db717b18db7feeed568949643698f0f34`  
[공식 릴리스](https://github.com/wazuh/wazuh/releases/tag/v4.14.8) · [고정된 원본 룰 폴더](https://github.com/wazuh/wazuh/tree/f470ad7db717b18db7feeed568949643698f0f34/ruleset/rules)

## 파일 열기

- [전체 룰 YAML](wazuh_original_rules.yml): 168개 원본 파일의 룰을 한 파일에 보관.
- [파일별 YAML 목록](RULE_FILES.md): 제품·로그 종류별 원본 파일을 찾아서 열기.
- [룰 ID별 목록 CSV](rule_inventory.csv): ID, level, 설명, 의존 룰, ATT&CK, 출처 검색.
- [검토 결과](검토결과.md): 보존 검증과 실제 실행 범위.
- [자동 검증 결과 JSON](verification_results.json): 검사 개수와 발견 사항.
- [원본 출처·SHA-256](source_manifest.json): 가져온 모든 파일의 고정된 출처와 해시.

자주 찾는 원본 YAML:

| 구분 | 파일 |
| --- | --- |
| SSHD | [0095-sshd_rules.yml](yml/0095-sshd_rules.yml) |
| 일반 웹 로그 | [0245-web_rules.yml](yml/0245-web_rules.yml) |
| NGINX | [0260-nginx_rules.yml](yml/0260-nginx_rules.yml) |
| 웹 애플리케이션 보안 | [0270-web_appsec_rules.yml](yml/0270-web_appsec_rules.yml) |
| Sysmon 기본 | [0330-sysmon_rules.yml](yml/0330-sysmon_rules.yml) |
| Windows Sysmon | [0595-win-sysmon_rules.yml](yml/0595-win-sysmon_rules.yml) |
| Sysmon 프로세스 생성 | [0800-sysmon_id_1.yml](yml/0800-sysmon_id_1.yml) |
| Sysmon 네트워크 연결 | [0810-sysmon_id_3.yml](yml/0810-sysmon_id_3.yml) |
| Sysmon 파일 생성 | [0830-sysmon_id_11.yml](yml/0830-sysmon_id_11.yml) |
| Linux auditd | [0365-auditd_rules.yml](yml/0365-auditd_rules.yml) |

## YAML 구조와 원본 보존

이 YAML은 **원본 XML 보관·열람용 표현 형식**입니다. Wazuh Manager가 읽는 일반 탐지 룰 형식은 XML입니다. Wazuh SCA 정책의 YAML 형식이나 Sigma YAML 형식과는 별개입니다.

각 `sources` 항목은 다음을 포함합니다.

- `file`, `url`, `sha256`: 원본 파일명, 고정 커밋 출처, 원본 바이트 해시.
- `elements`: XML 요소의 순서, 속성, 텍스트를 구조화한 열람용 트리. 반복되는 `field`, `description`, `group`를 합치지 않습니다.
- `original_xml`: **원본 XML 전체 문자열**. 주석·공백·정규식·엔티티 표현도 이 필드에 그대로 보존합니다. 복원 시 이 필드를 사용합니다.

모든 XML 속성 값은 문자열로 보존합니다. `frequency`, `timeframe`도 새로운 임계값으로 해석하거나 계산하지 않습니다. `if_sid`, `if_matched_sid`, `same_source_ip`, 정규식 엔진 종류, `noalert`, `level=0`, `<var>` 및 `$변수`를 유지합니다. level=0 기반 룰은 다른 룰의 동작에 필요할 수 있어 제외하지 않았습니다. 원본의 주석 처리된 룰은 XML 본문에 보존하되 활성 룰 개수에는 포함하지 않습니다.

## Wazuh에서 사용

실행에는 `original/ruleset/rules/`의 **원본 XML**을 사용합니다. 디코더와 목록 파일도 `original/ruleset/`에 원본 그대로 보관했습니다. SCA, rootcheck, 원본 테스트 자료와 라이선스도 같은 버전의 원본을 유지합니다.

이미 같은 버전의 기본 룰이 설치된 Manager에는 이 룰이 포함돼 있을 수 있습니다. 룰을 `local_rules.xml` 등에 중복 추가하면 ID가 충돌하므로, 설치된 기본 룰과 버전을 먼저 확인해야 합니다. 이 작업에서는 Manager 설정 변경·배포를 수행하지 않았습니다.

Manager에서 원본 XML을 읽도록 구성한 뒤 구문 및 로그 테스트를 수행합니다.

```sh
/var/ossec/bin/wazuh-analysisd -t
/var/ossec/bin/wazuh-logtest
```

`wazuh-logtest`에는 해당 룰의 원래 디코더가 처리하는 **원시 로그**를 넣어야 합니다. 프로젝트 정규화 CSV를 직접 입력하는 형태로 바꾸지 않았습니다. 테스트 자료는 `original/ruleset/testing/`에 있습니다. 운영 활성화 여부는 Manager 버전, 로드 설정, 디코더, 수집 로그에 따라 달라집니다.

## 재검증과 XML 복원

Python과 PyYAML 6.0.3을 사용합니다. PyYAML은 이번 작업에서 프로젝트 임시 폴더에만 설치했으며 시스템 환경은 변경하지 않았습니다. 다른 환경에서는 해당 환경에 `requirements.txt`를 설치합니다.

이 폴더에서:

```sh
python verify_yaml.py
python restore_xml.py --output restored_xml
```

`restore_xml.py`는 YAML의 `original_xml`을 SHA-256 대조 후 새 디렉터리에 복원합니다. 이미 있는 디렉터리를 덮어쓰거나 Wazuh에 배포하지 않습니다. YAML의 열람용 `elements`를 편집해도 원본 XML의 탐지 동작은 바뀌지 않습니다.

## 라이선스

원본의 저작권 주석과 [LICENSE](original/LICENSE)를 유지했습니다. 배포·재사용에는 해당 원본 라이선스와 파일별 고지를 적용합니다.
