"""Represent upstream rules in YAML without changing their detection logic.

The exact original_xml string is authoritative and can restore the source bytes.
The ordered element tree is an inspection aid, not a new detection engine.
"""
import csv
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent
import yaml


class Literal(str):
    pass


class Dumper(getattr(yaml, "CSafeDumper", yaml.SafeDumper)):
    def ignore_aliases(self, data):
        return True


Dumper.add_representer(Literal, lambda dumper, value: dumper.represent_scalar(
    "tag:yaml.org,2002:str", value, style="|"))


def parse_source(text):
    """Interpret XML text; never modify the stored original source.

    One upstream regex contains literal backslash-< sequences which Wazuh's
    parser accepts but the standard XML parser does not. Escaping the < in an
    in-memory parsing copy preserves the resulting regex string exactly.
    """
    body = re.sub(r"<\?xml[^>]*\?>", "", text)
    note = None
    try:
        tree = ET.fromstring("<ruleset>" + body + "</ruleset>")
    except ET.ParseError as error:
        shadow = body.replace("\\<", "\\&lt;")
        tree = ET.fromstring("<ruleset>" + shadow + "</ruleset>")
        note = {"stdlib_xml_error": str(error),
                "inspection_parser": "escape literal backslash-< in memory only",
                "original_xml_changed": False}
    return tree, note


def node(element):
    out = {"element": element.tag}
    if element.attrib:
        out["attributes"] = dict(element.attrib)
    # A list retains repeated field/description/group tags and their order.
    if len(element):
        if element.text and element.text.strip():
            out["text"] = element.text
        out["children"] = [node(child) for child in element]
    else:
        out["text"] = element.text if element.text is not None else ""
    return out


def write_yaml(path, data):
    content = yaml.dump(data, Dumper=Dumper, allow_unicode=True, sort_keys=False,
                        width=110, default_flow_style=False)
    path.write_text(content, encoding="utf-8", newline="\n")


def make_source(entry):
    raw = (ROOT / "original" / entry["file"]).read_bytes()
    # bytes.decode, rather than read_text, avoids newline conversion.
    text = raw.decode("utf-8")
    tree, note = parse_source(text)
    rules = list(tree.iter("rule"))
    active_xml = re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)
    if len(rules) != len(re.findall(r"<rule\s", active_xml)):
        raise ValueError("Rule count mismatch: " + entry["file"])
    source = {"file": entry["file"], "url": entry["url"], "sha256": entry["sha256"],
              "rule_count": len(rules), "elements": [node(child) for child in tree],
              "original_xml": Literal(text)}
    if note:
        source["inspection_parser_note"] = note
    return source, rules


def main():
    manifest = json.loads((ROOT / "source_manifest.json").read_text(encoding="utf-8"))
    metadata = {"schema": "wazuh-original-rules-yaml/v1", "format_only_conversion": True,
                "native_runtime_format": "Wazuh XML",
                "authoritative_field": "sources[].original_xml",
                "upstream": {k: manifest[k] for k in ("repository", "tag", "commit")}}
    sources = []
    inventory = []
    directory = ROOT / "yml"
    directory.mkdir(exist_ok=True)
    entries = sorted((e for e in manifest["files"]
                      if e["file"].startswith("ruleset/rules/") and e["file"].endswith(".xml")),
                     key=lambda e: e["file"])
    for entry in entries:
        source, rules = make_source(entry)
        sources.append(source)
        write_yaml(directory / (Path(entry["file"]).stem + ".yml"),
                   {**metadata, "sources": [source]})
        for rule in rules:
            inventory.append({"source_file": entry["file"], "rule_id": rule.get("id", ""),
                "level": rule.get("level", ""), "noalert": rule.get("noalert", ""),
                "frequency": rule.get("frequency", ""), "timeframe": rule.get("timeframe", ""),
                "description": " | ".join(x.text or "" for x in rule.findall("description")),
                "if_sid": " | ".join(x.text or "" for x in rule.findall("if_sid")),
                "if_matched_sid": " | ".join(x.text or "" for x in rule.findall("if_matched_sid")),
                "mitre": ",".join(x.text or "" for x in rule.findall("mitre/id")),
                "source_url": entry["url"]})
    write_yaml(ROOT / "wazuh_original_rules.yml", {**metadata, "sources": sources})
    with (ROOT / "rule_inventory.csv").open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(inventory[0]))
        writer.writeheader()
        writer.writerows(inventory)
    print(json.dumps({"xml_files": len(sources), "rules": len(inventory),
                      "yml_files": len(sources) + 1, "tag": manifest["tag"]}, indent=2))


if __name__ == "__main__":
    main()
