from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


EXCLUDED_PARTS = {".git", ".planning", "build", "dist", "__pycache__", ".venv"}
TEXT_SUFFIXES = {".py", ".sh", ".md", ".json", ".toml", ".yml", ".yaml", ".txt", ""}
DUMMY_UUIDS = {
    "11111111-1111-4111-8111-111111111111",
    "22222222-2222-4222-8222-222222222222",
    "33333333-3333-4333-8333-333333333333",
    "44444444-4444-4444-8444-444444444444",
}
RULES = {
    "private-key": re.compile(r"-----BEGIN (?:OPENSSH |EC |RSA )?PRIVATE KEY-----"),
    "cloudflare-token": re.compile(r"\bcf(?:ut|at|k)_[A-Za-z0-9_-]{30,}\b"),
    "github-token": re.compile(r"\bgh[opusr]_[A-Za-z0-9_]{30,}\b"),
    "openai-key": re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
    "real-domain": re.compile(r"(?i)enrpiglink\.top"),
    "uuid": re.compile(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b"),
}


def scan(root: Path) -> list[str]:
    findings = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or any(part in EXCLUDED_PARTS for part in path.parts):
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES and path.name not in {"sparklinkctl"}:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for name, pattern in RULES.items():
            for match in pattern.finditer(text):
                if name == "uuid" and match.group(0).lower() in DUMMY_UUIDS:
                    continue
                line = text.count("\n", 0, match.start()) + 1
                findings.append(f"{path.relative_to(root)}:{line}: {name}")
    return findings


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    args = parser.parse_args()
    findings = scan(args.root.resolve())
    if findings:
        print("secret scan failed", file=sys.stderr)
        for finding in findings:
            print(finding, file=sys.stderr)
        return 1
    print("secret scan passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
