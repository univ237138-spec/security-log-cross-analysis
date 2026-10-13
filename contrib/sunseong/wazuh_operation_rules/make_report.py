"""Write the navigation index and the evidence-backed Korean review report."""
import argparse
import hashlib
import json
from pathlib import Path
from build_yaml import ROOT
import yaml


def main():
    results = json.loads((ROOT / "verification_results.json").read_text(encoding="utf-8"))
    if results["status"] != "PASS":
        raise RuntimeError("Cannot report success for failed verification")
    data = yaml.load((ROOT / "wazuh_original_rules.yml").read_text(encoding="utf-8"),
                     Loader=getattr(yaml, "CSafeLoader", yaml.SafeLoader))
    parser = argparse.ArgumentParser()
    parser.add_argument("--restored", type=Path, default=ROOT / "restored_xml")
    restored = parser.parse_args().restored.resolve()
    checks = []
    for source in data["sources"]:
        path = restored / source["file"]
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        checks.append({"source_file": source["file"], "sha256": digest,
                       "matches_original": digest == source["sha256"]})
    if not all(check["matches_original"] for check in checks):
        raise RuntimeError("XML restoration byte mismatch")
    restore_result = {"status": "PASS", "restored_xml_files": len(checks),
                      "output_directory": str(restored), "checks": checks}
    (ROOT / "xml_roundtrip_results.json").write_text(
        json.dumps(restore_result, indent=2), encoding="utf-8")
    index = ["# Wazuh 원본 파일별 YAML 목록", "",
             f"원본 {results['tag']} · XML {results['rule_xml_files']}개 · 활성 룰 정의 {results['rule_count']:,}개.", "",
             "원본 파일별로 분리했으며 룰의 조건을 수정하지 않았습니다. level=0 기반 룰도 포함합니다.", "",
             "[전체 YAML](wazuh_original_rules.yml) · [검토 결과](검토결과.md) · [룰 ID별 CSV](rule_inventory.csv)", "",
             "| 원본 파일 | 룰 수 | YAML | 원본 XML |", "| --- | ---: | --- | --- |"]
    for source in data["sources"]:
        name = Path(source["file"]).name
        index.append(f"| `{name}` | {source['rule_count']} | [열기](yml/{Path(name).stem}.yml) | [열기](original/{source['file']}) |")
    (ROOT / "RULE_FILES.md").write_text("\n".join(index) + "\n", encoding="utf-8")
    review = f"""# Wazuh 원본 룰 검토 결과

원본 보존 검증은 **통과**했습니다. Wazuh `{results['tag']}`의 XML **{results['rule_xml_files']}개 / 룰 {results['rule_count']:,}개**를 조건 수정 없이 YAML로 표현했습니다. 정규화 CSV에 맞춘 매핑이나 탐지 로직 변경은 없습니다.

## 원본과 출처

- 저장소: [wazuh/wazuh](https://github.com/wazuh/wazuh).
- 고정 커밋: `{results['commit']}`.
- 검토일: 2026-10-12 (Asia/Seoul 기준).
- 내려받은 원본: {results['original_files']}개. 룰 외에 디코더·목록·SCA·rootcheck·원본 테스트 자료·라이선스도 보존했습니다.
- 변환 대상: `ruleset/rules/*.xml` 전체. 원본 SCA YAML 등은 `original/`에 그대로 보관했습니다.

## 확인 결과

| 확인 항목 | 결과 |
| --- | --- |
| 원본 파일 SHA-256 | {results['original_files']}개 모두 출처 매니페스트와 일치 |
| 전체·파일별 YAML 로딩 | {results['yaml_files_checked']}개 모두 성공 |
| YAML 내 원본 XML 바이트와 해시 | 168개 모두 원본과 일치 |
| XML 요소 순서·속성·텍스트 | 168개 모두 원본을 해석한 구조와 일치 |
| 파일별 YAML과 전체 YAML | 168개 모두 내용 일치 |
| 룰 개수 및 ID | {results['rule_count']:,}개 보존, ID 중복 0개 |
| 숫자 SID 의존 룰 참조 | 누락 0개 |
| level=0 기반 룰 | {results['level_zero_rules_retained']}개 보존 |
| `if_matched_sid` / `if_matched_group` 상관분석 룰 | {results['correlation_rules_retained']}개 보존 |
| YAML → XML 실제 파일 복원 | 168개 모두 원본 SHA-256과 일치 |

자동 원본 대조 검사 **{results['successful_checks']:,}개 통과**, 별도 XML 복원 대조 **168개 통과**입니다. [대조 결과 JSON](verification_results.json) · [XML 복원 결과 JSON](xml_roundtrip_results.json)

`if_sid`, `if_matched_sid`, 같은 IP·사용자 조건, `frequency`, `timeframe`, `ignore`, `noalert`, 정규식 엔진 속성, 변수, ATT&CK·규정 매핑을 새로운 의미로 바꾸지 않았습니다. 반복되는 XML 태그를 딕셔너리 키 하나로 합치지 않고 순서 있는 리스트로 보존했습니다. 주석·공백·엔티티 표기는 `original_xml`에 원본 그대로 있습니다.

## 원본에서 발견한 파서 차이

`0910-ms-exchange-proxylogon_rules.xml`의 룰 `91003` 정규식은 문자 `\\<`를 포함합니다. Python 표준 XML 파서는 이 문자열을 XML 문법으로 해석하며 오류를 냅니다. 열람용 트리를 만드는 동안 메모리의 파싱 복사본에서만 `<`를 XML 이스케이프해 같은 정규식 문자열을 얻었습니다. **원본 XML과 YAML의 `original_xml`은 변경하지 않았으며 복원 해시도 일치합니다.** 이 항목은 원본을 자동 수정한 것이 아니라 파서 차이를 기록한 것입니다.

## 운영 적용 검토 범위

Wazuh의 일반 탐지 룰 실행 형식은 **XML**입니다. 이 YAML은 원본 보관·열람용 형식이므로 Wazuh Manager에 그대로 로드하는 파일은 아닙니다. 실행용 원본은 `original/ruleset/rules/`에 있으며, YAML에서 동일한 XML을 복원할 수도 있습니다.

원본에는 여러 제품·운영체제·로그 종류에 대한 룰이 포함돼 있습니다. 각 룰은 원래의 디코더와 로그 수집, 관련 목록·변수·기반 룰이 있어야 동작합니다. 숫자 SID 참조가 모두 존재한다는 확인만으로 디코더와 수집 환경까지 충족됐다고 판단하지 않았습니다.

**Wazuh Manager 실행 검증은 수행하지 않았습니다.** 이 작업 환경에는 연결된 Wazuh Manager가 없으므로 `wazuh-analysisd -t`와 원시 로그를 사용한 `wazuh-logtest` 결과는 확인하지 못했습니다. 설치된 버전 및 룰 로드 설정에 따른 동작과 오탐률은 해당 운영 환경에서 확인해야 합니다. 기존 기본 룰과 중복되는 ID를 추가 등록하지 않도록 설치된 룰을 확인해야 합니다.

이 작업에서는 탐지 성능·공격 성공 여부를 평가하거나 운영 서버에 배포하지 않았습니다. 제공 범위는 **원본 수집, YAML 표현, 원본 대조, XML 복원 검증**입니다.

## 위치

- [전체 YAML](wazuh_original_rules.yml)
- [파일별 YAML 목록](RULE_FILES.md)
- [룰 ID별 CSV](rule_inventory.csv)
- [사용 방법](README.md)
- [원본 라이선스](original/LICENSE)
"""
    (ROOT / "검토결과.md").write_text(review, encoding="utf-8")
    print(json.dumps({"review": "PASS", "xml_restoration_checks": len(checks),
                      "index_entries": len(data["sources"])}, indent=2))


if __name__ == "__main__":
    main()
