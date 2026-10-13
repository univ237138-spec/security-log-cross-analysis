"""Fetch unchanged public Wazuh ruleset files at a pinned release."""
import hashlib
import io
import json
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TAG = "v4.14.8"

def get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Codex-Wazuh-Rule-Review"})
    return urllib.request.urlopen(req, timeout=45).read()

def main():
    commit = json.loads(get(f"https://api.github.com/repos/wazuh/wazuh/commits/{TAG}"))["sha"]
    target = ROOT / "original"
    target.mkdir(parents=True, exist_ok=True)
    archive = get(f"https://codeload.github.com/wazuh/wazuh/zip/{commit}")
    manifest = {"repository": "https://github.com/wazuh/wazuh", "tag": TAG,
                "commit": commit, "review_date": "2026-10-12",
                "archive_sha256": hashlib.sha256(archive).hexdigest(), "files": []}
    with zipfile.ZipFile(io.BytesIO(archive)) as z:
        for info in z.infolist():
            if info.is_dir():
                continue
            relative = info.filename.split("/", 1)[1]
            if not (relative.startswith("ruleset/") or relative == "LICENSE"):
                continue
            destination = (target / relative).resolve()
            if not destination.is_relative_to(target.resolve()):
                raise ValueError("Unsafe archive path")
            data = z.read(info)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
            url = f"https://github.com/wazuh/wazuh/blob/{commit}/{relative}"
            manifest["files"].append({"file": relative, "url": url,
                                     "sha256": hashlib.sha256(data).hexdigest()})
    (ROOT / "source_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps({"tag": TAG, "commit": commit, "files": len(manifest["files"])}, indent=2))

if __name__ == "__main__":
    main()
