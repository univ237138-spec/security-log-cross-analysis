"""Verify full YAML round trip, exact source bytes and rule dependencies."""
import collections
import hashlib
import json
import re
import sys
from pathlib import Path
from build_yaml import ROOT, make_source, node, parse_source
import yaml
Loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)


def main():
    manifest = json.loads((ROOT / "source_manifest.json").read_text(encoding="utf-8"))
    checks = collections.Counter()
    errors = []
    def check(name, good, detail=""):
        checks[name] += bool(good)
        if not good:
            errors.append({"check": name, "detail": detail})

    for entry in manifest["files"]:
        data = (ROOT / "original" / entry["file"]).read_bytes()
        check("original_file_sha256", hashlib.sha256(data).hexdigest() == entry["sha256"], entry["file"])

    aggregate = yaml.load((ROOT / "wazuh_original_rules.yml").read_text(encoding="utf-8"), Loader=Loader)
    entries = {e["file"]: e for e in manifest["files"] if e["file"].startswith("ruleset/rules/")}
    check("aggregate_file_coverage", set(entries) == {s["file"] for s in aggregate["sources"]})
    ids = []
    references = []
    correlation = 0
    level_zero = 0
    notices = []
    rules_total = 0
    for source in aggregate["sources"]:
        name = source["file"]
        raw = (ROOT / "original" / name).read_bytes()
        check("aggregate_xml_exact_bytes", source["original_xml"].encode("utf-8") == raw, name)
        check("aggregate_xml_sha256", hashlib.sha256(source["original_xml"].encode("utf-8")).hexdigest() == entries[name]["sha256"], name)
        original_tree, note = parse_source(raw.decode("utf-8"))
        check("ordered_element_attributes_text", source["elements"] == [node(c) for c in original_tree], name)
        per_file = yaml.load((ROOT / "yml" / (Path(name).stem + ".yml")).read_text(encoding="utf-8"), Loader=Loader)
        check("individual_matches_aggregate", per_file["sources"] == [source], name)
        check("individual_metadata_matches", all(per_file[k] == v for k, v in aggregate.items() if k != "sources"), name)
        count = 0
        for r in original_tree.iter("rule"):
            count += 1
            ids.append(r.attrib["id"])
            level_zero += r.get("level") == "0"
            correlation += r.find("if_matched_sid") is not None or r.find("if_matched_group") is not None
            for key in ("if_sid", "if_matched_sid"):
                for dependency in r.findall(key):
                    for ref in re.findall(r"\d+", dependency.text or ""):
                        references.append({"rule": r.attrib["id"], "dependency": ref,
                                           "type": key, "source": name})
        check("rule_count_preserved", count == source["rule_count"], name)
        rules_total += count
        if note:
            notices.append({"source": name, **note})
    check("rule_ids_unique", len(ids) == len(set(ids)))
    missing = [r for r in references if r["dependency"] not in set(ids)]
    result = {"status": "PASS" if not errors else "FAIL", "tag": manifest["tag"],
        "commit": manifest["commit"], "original_files": len(manifest["files"]),
        "rule_xml_files": len(entries), "rule_count": rules_total,
        "level_zero_rules_retained": level_zero, "correlation_rules_retained": correlation,
        "yaml_files_checked": len(entries) + 1, "successful_checks": sum(checks.values()),
        "checks": dict(checks), "errors": errors,
        "unresolved_numeric_sid_references": missing,
        "inspection_parser_notices": notices,
        "wazuh_runtime_test": "NOT_RUN: no Wazuh Manager session in this workspace",
        "log_data_adaptation": False, "detection_logic_changes": False}
    (ROOT / "verification_results.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({k: v for k, v in result.items() if k not in ("checks", "errors")}, ensure_ascii=False, indent=2))
    if errors:
        print(json.dumps(errors, ensure_ascii=False, indent=2))
        sys.exit(1)


if __name__ == "__main__":
    main()
