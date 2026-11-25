#!/usr/bin/env python3
"""Package an mcp-hookd binary and smoke-test the extracted archive."""

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

binary, version, platform = sys.argv[1:]
name = f"mcp-hookd-{version}-{platform}"
dist = Path("dist").resolve()
dist.mkdir(exist_ok=True)

with tempfile.TemporaryDirectory(prefix="hookd-release-") as work:
    root = Path(work)
    package = root / name
    package.mkdir()
    for source in (binary, "LICENSE", "NOTICE", "README.md"):
        shutil.copy2(source, package)

    archive = shutil.make_archive(
        str(dist / name),
        "zip" if platform.startswith("windows-") else "gztar",
        root_dir=root,
        base_dir=name,
    )
    extracted = root / "extracted"
    shutil.unpack_archive(archive, extracted)
    exe = extracted / name / Path(binary).name
    actual = subprocess.check_output([exe, "--version"], text=True, timeout=30).strip()
    expected = f"mcp-hookd {version}"
    if actual != expected:
        raise SystemExit(f"expected {expected!r}, got {actual!r}")

    config = extracted / "hookd.json"
    config.write_text(
        json.dumps(
            {
                "listen": "127.0.0.1:8081",
                "state_path": str(extracted / "subscriptions.json"),
                "profile": "sep3415",
                "inbound_tokens": ["release-smoke-inbound-token"],
                "ingest": {
                    "tokens": ["release-smoke-ingest-token"],
                    "events": [
                        {
                            "name": "smoke.ping",
                            "description": "Release smoke test event.",
                            "payload_schema": {"type": "object"},
                        }
                    ],
                },
            }
        ),
        encoding="utf-8",
    )
    subprocess.run([exe, "check", "--config", config], check=True, timeout=30)
