"""Refresh tracked integration hashes without including installed/generated files."""
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PREFIX = "integrations/osint-tool-typescript/"
MANIFEST = ROOT / "integrations/osint-tool-typescript.traceatlas-manifest.json"


def main():
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    tracked = subprocess.check_output(
        ["git", "ls-files", "-z", "--", PREFIX], cwd=ROOT
    ).decode("utf-8").split("\0")
    files = []
    for relative in sorted(p for p in tracked if p):
        content = (ROOT / relative).read_bytes()
        files.append({"path": relative[len(PREFIX):], "size": len(content),
                      "sha256": hashlib.sha256(content).hexdigest()})
    manifest.update(files=files, file_count=len(files),
                    total_bytes=sum(item["size"] for item in files))
    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
