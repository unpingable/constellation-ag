#!/usr/bin/env python3
"""Verify the staged AG cohort and record its exact executable bytes."""

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

BINARIES = {
    "ag-loopctl": "agent-governor-ng-operator-tools/usr/bin/ag-loopctl",
    "ag-standing-resolver": "agent-governor-ng-operator-tools/usr/bin/ag-standing-resolver",
    "ag-operator-ui": "agent-governor-ng-operator-tools/usr/bin/ag-operator-ui",
    "ag-effectd": "agent-governor-ng-systemd-executor/usr/libexec/agent-governor-ng/ag-effectd",
}


def record(binary_dir, package_version, architecture):
    source = os.environ.get("AG_SOURCE_COMMIT", "")
    build_id = os.environ.get("AG_BUILD_IDENTITY", "")
    if not re.fullmatch(r"[0-9a-f]{40}", source):
        raise ValueError("AG_SOURCE_COMMIT must name the full expected lowercase commit")
    if not re.fullmatch(r"[!-~]{1,256}", build_id):
        raise ValueError("AG_BUILD_IDENTITY must name the expected build (1..256 ASCII bytes, no spaces)")
    target_prefix = {"amd64": "x86_64-", "arm64": "aarch64-"}[architecture]
    executables = {}
    cohort = None
    for name in BINARIES:
        path = Path(binary_dir) / BINARIES[name]
        before = hashlib.sha256(path.read_bytes()).hexdigest()
        output = subprocess.run([str(path), "--build-info"], check=True,
                                capture_output=True, timeout=10)
        if output.stderr:
            raise ValueError(f"{name}: build probe wrote to stderr")
        info = json.loads(output.stdout)
        if not isinstance(info, dict):
            raise ValueError(f"{name}: build probe is not an object")
        if info.get("schema") != "ag.build_info.v1" or info.get("component") != name:
            raise ValueError(f"{name}: unexpected build-info identity")
        if info.get("source_commit") != source or info.get("build_id") != build_id:
            raise ValueError(f"{name}: missing or mismatched source/build identity")
        version = info.get("version")
        if not isinstance(version, str) or not version or not (
                package_version == version or package_version.startswith(version + "+")):
            raise ValueError(f"{name}: package version does not extend its crate version")
        target, rustc = info.get("target"), info.get("rustc")
        if not isinstance(target, str) or not target.startswith(target_prefix):
            raise ValueError(f"{name}: target does not match package architecture")
        if not isinstance(rustc, str) or not rustc.startswith("rustc "):
            raise ValueError(f"{name}: missing compiler identity")
        if type(info.get("debug_assertions")) is not bool:
            raise ValueError(f"{name}: missing build-profile flag")
        if type(info.get("systemd_dbus")) is not bool:
            raise ValueError(f"{name}: missing systemd-dbus build-feature flag")
        if name == "ag-effectd" and not info["systemd_dbus"]:
            raise ValueError("ag-effectd: systemd-dbus is required for the packaged executor")
        identity = (version, target, rustc, info["debug_assertions"])
        if cohort is not None and identity != cohort:
            raise ValueError(f"{name}: executable cohort has inconsistent build inputs")
        cohort = identity
        after = hashlib.sha256(path.read_bytes()).hexdigest()
        if before != after:
            raise ValueError(f"{name}: staged bytes changed during the build probe")
        executables[name] = {"sha256": after, "build_info": info}
    return {
        "schema": "ag.package_build_identity.v1",
        "package_version": package_version,
        "architecture": architecture,
        "source_commit": source,
        "build_id": build_id,
        "executables": executables,
    }


def main():
    if len(sys.argv) != 5:
        raise ValueError("usage: record-build-identity.py STAGED_PACKAGES_DIR VERSION ARCH OUTPUT")
    binary_dir, version, architecture, output = sys.argv[1:]
    receipt = record(binary_dir, version, architecture)
    Path(output).write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
        sys.exit(f"AG package identity refused: {error}")
