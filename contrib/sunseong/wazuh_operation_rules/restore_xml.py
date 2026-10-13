"""Restore authoritative XML bytes from YAML to a NEW directory, without deployment."""
import argparse
import hashlib
from pathlib import Path
from build_yaml import ROOT
import yaml


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--yaml", type=Path, default=ROOT / "wazuh_original_rules.yml")
    parser.add_argument("--output", type=Path, required=True, help="A new, nonexistent directory")
    args = parser.parse_args()
    if args.output.exists():
        parser.error("Output directory already exists; existing files will not be overwritten.")
    data = yaml.load(args.yaml.read_text(encoding="utf-8"), Loader=getattr(yaml, "CSafeLoader", yaml.SafeLoader))
    if data.get("schema") != "wazuh-original-rules-yaml/v1":
        parser.error("Unexpected schema")
    files = []
    for source in data["sources"]:
        path = (args.output / source["file"]).resolve()
        if not path.is_relative_to(args.output.resolve()):
            parser.error("Unsafe path")
        raw = source["original_xml"].encode("utf-8")
        if hashlib.sha256(raw).hexdigest() != source["sha256"]:
            parser.error("Source hash mismatch: " + source["file"])
        files.append((path, raw))
    for path, raw in files:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    print(f"Restored {len(files)} unchanged XML files to {args.output.resolve()}")


if __name__ == "__main__":
    main()
