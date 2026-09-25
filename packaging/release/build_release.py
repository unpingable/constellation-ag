#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Offline, reproducible release build of the AG governed-loop tarball.

The tarball carries the canonical governed-loop executables that the
reviewed-local-copy/v1 cohort runs, and nothing from the daemon lineage:

- ``bin/ag-loopctl``: the exact-occurrence governed-loop controller;
- ``bin/ag-standing-resolver``: the one-shot standing authority;
- ``bin/ag-operator-ui``: the optional loopback-only read-only inspector;
- ``share/seal-standing-resolver-launcher.py``: the standing-launcher sealer,
  byte-identical to ``tools/seal-standing-resolver-launcher.py`` at the source
  commit. It answers no ``--build-info``; its identity is the artifact's
  ``BUILD-INFO.json`` entry plus ``SHA256SUMS``. Run it as
  ``/usr/bin/python3.11 -I -S``; it imports only the standard library.

Every executable answers ``--version`` and ``--build-info`` with the source
commit baked in through ``AG_SOURCE_COMMIT``.

Host mode clones the source twice from the pushed remote, checks out the exact
commit in each clone, builds each clone separately in the pinned Debian 12 Rust
1.94.0 image with ``--network none`` against a vendored dependency tree,
assembles each tarball deterministically, and refuses unless both builds are
byte-equal. It then writes ``SHA256SUMS`` and the JSON build receipt.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from typing import Any

COMPONENT = "ag"
VERSION = "0.1.0"
ARCH = "amd64"
SOURCE_REPOSITORY = "https://github.com/unpingable/constellation-ag"
DEFAULT_REMOTE = "git@github-unpingable:unpingable/constellation-ag.git"
SOURCE_DATE_EPOCH = 1700000000
IMAGE_ID = "sha256:fb7a58d0482a24e269ba85636ce46cb06aaaef3aea0e868154ed0ae7c18fa379"
IMAGE_REPO_DIGEST = "rust@sha256:365468470075493dc4583f47387001854321c5a8583ea9604b297e67f01c5a4f"
BUILD_USER = "1000:1000"
TOOLCHAIN = "1.94.0"
TOP = f"{COMPONENT}-{VERSION}"
TARBALL = f"{TOP}-linux-{ARCH}.tar.gz"
RECEIPT = "build-receipt.v1.json"
RECEIPT_SCHEMA = "constellation.ag-release-build-receipt/v1"
BUILD_INFO_SCHEMA = "constellation.ag-release-artifact-build-info/v1"
PACKAGING_FILES = ("packaging/release/build_release.py", "packaging/release/README.md")
EXECUTABLES = {
    "ag-loopctl": "ag-app",
    "ag-standing-resolver": "ag-app",
    "ag-operator-ui": "ag-operator-ui",
}
SCRIPTS = {
    "share/seal-standing-resolver-launcher.py": "tools/seal-standing-resolver-launcher.py",
}
TRACKED_INPUTS = ("Cargo.lock", "Cargo.toml", "rust-toolchain.toml")
CARGO_ARGUMENTS = [
    "build", "--release", "--locked", "--offline", "--jobs", "4",
    "-p", "ag-app", "-p", "ag-operator-ui",
    *[item for name in EXECUTABLES for item in ("--bin", name)],
]
TREE_ARGUMENTS = [
    "tree", "--locked", "--offline", "--edges", "normal,build", "--prefix", "none",
    "--format", "{p} {l}", "-p", "ag-app", "-p", "ag-operator-ui",
]
FORBIDDEN_CRATES = ("ag-migrate", "ag-providerd", "reqwest", "hyper", "rustls", "tokio")
FORBIDDEN_STRINGS = (b"agent_gov", b"ag_shell_client", b"agent_governor", b"shell_client")
BUILD_ENV = {
    "AG_SOURCE_COMMIT": "<SOURCE_COMMIT>",
    "CARGO_HOME": "/cargo-home",
    "CARGO_INCREMENTAL": "0",
    "CARGO_PROFILE_RELEASE_CODEGEN_UNITS": "1",
    "CARGO_TARGET_DIR": "/build",
    "HOME": "/tmp/ag-builder-home",
    "LC_ALL": "C.UTF-8",
    "RUSTFLAGS": "--remap-path-prefix=/src=. --remap-path-prefix=/vendor=/cargo-vendor "
                 "--remap-path-prefix=/cargo-home=/cargo-home",
    "RUSTUP_TOOLCHAIN": TOOLCHAIN,
    "SOURCE_DATE_EPOCH": str(SOURCE_DATE_EPOCH),
    "TZ": "UTC",
    "USER": "ag-builder",
}
CARGO_CONFIG = """[net]
offline = true

[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "/vendor"
"""
LIMITATIONS = [
    "The sealer script answers no --build-info; BUILD-INFO.json and SHA256SUMS carry its identity.",
    "Only ag-loopctl, ag-standing-resolver and ag-operator-ui are shipped; the daemon lineage "
    "(agd, ag-effectd, ag-providerd, agctl) is not in this artifact.",
    "No accounts, units, keys or configuration are installed; the setup driver writes them.",
]


class Refusal(RuntimeError):
    pass


def run(command: list[str], *, cwd: pathlib.Path | None = None,
        env: dict[str, str] | None = None) -> subprocess.CompletedProcess[bytes]:
    done = subprocess.run(command, cwd=cwd, env=env, capture_output=True, check=False)
    if done.returncode != 0:
        raise Refusal(f"command refused ({done.returncode}): {command!r}\n"
                      + done.stderr.decode(errors="replace")[-4000:])
    return done


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def tree_digest(root: pathlib.Path) -> tuple[str, int]:
    """Digest of a vendored tree: sorted relative path, mode and bytes."""
    if not root.is_dir() or root.is_symlink():
        raise Refusal("vendor input is not one physical directory")
    digest = hashlib.sha256(b"ag-release-vendor-tree-v1\0")
    count = 0
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        meta = path.lstat()
        if stat.S_ISDIR(meta.st_mode):
            continue
        if not stat.S_ISREG(meta.st_mode):
            raise Refusal(f"vendor input contains a non-regular entry: {path}")
        relative = path.relative_to(root).as_posix().encode()
        data = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "big") + relative)
        digest.update((meta.st_mode & 0o777).to_bytes(4, "big"))
        digest.update(len(data).to_bytes(8, "big") + data)
        count += 1
    if count == 0:
        raise Refusal("vendor input is empty")
    return digest.hexdigest(), count


def image_facts() -> dict[str, Any]:
    records = json.loads(run(["docker", "image", "inspect", IMAGE_ID]).stdout)
    if len(records) != 1 or records[0].get("Id") != IMAGE_ID:
        raise Refusal("local builder image identity differs")
    if IMAGE_REPO_DIGEST not in records[0].get("RepoDigests", []):
        raise Refusal("local builder repository digest is absent")
    return {"image_id": IMAGE_ID, "repository_digest": IMAGE_REPO_DIGEST,
            "network": "none", "pull": "never", "read_only_root": True, "user": BUILD_USER}


def clone(remote: str, commit: str, destination: pathlib.Path, branch: str | None) -> dict[str, Any]:
    run(["git", "clone", "--quiet", "--no-checkout", remote, str(destination)])
    run(["git", "-C", str(destination), "checkout", "--quiet", "--detach", commit])
    head = run(["git", "-C", str(destination), "rev-parse", "HEAD"]).stdout.decode().strip()
    tree = run(["git", "-C", str(destination), "rev-parse", "HEAD^{tree}"]).stdout.decode().strip()
    if head != commit:
        raise Refusal("clone HEAD differs from the requested commit")
    if run(["git", "-C", str(destination), "status", "--porcelain", "--ignored"]).stdout:
        raise Refusal("fresh clone is not clean")
    contained = None
    if branch is not None:
        refs = run(["git", "-C", str(destination), "branch", "-r", "--contains", commit]).stdout.decode().split()
        if f"origin/{branch}" not in refs:
            raise Refusal(f"commit is not reachable from pushed origin/{branch}")
        contained = f"origin/{branch}"
    return {"commit": head, "tree": tree, "clean": True, "reachable_from": contained}


def docker_command(source: pathlib.Path, vendor: pathlib.Path, case: pathlib.Path,
                   commit: str, argv: list[str]) -> list[str]:
    command = ["docker", "run", "--rm", "--pull", "never", "--network", "none", "--read-only",
               "--tmpfs", "/tmp:rw,exec,size=1g", "--hostname", "ag-release-builder", "--user", BUILD_USER]
    for key, value in sorted(BUILD_ENV.items()):
        command += ["-e", f"{key}={commit if value == '<SOURCE_COMMIT>' else value}"]
    command += ["-v", f"{source}:/src:ro", "-v", f"{vendor}:/vendor:ro",
                "-v", f"{case / 'cargo-home'}:/cargo-home:rw", "-v", f"{case / 'build'}:/build:rw",
                "-w", "/src", IMAGE_ID, "cargo", *argv]
    return command


def normalized_docker_argv(argv: list[str]) -> list[str]:
    placeholder = docker_command(pathlib.Path("<SOURCE>"), pathlib.Path("<VENDOR>"),
                                 pathlib.Path("<CASE>"), "<SOURCE_COMMIT>", argv)
    return placeholder


def glibc_ceiling(path: pathlib.Path) -> str | None:
    text = run(["readelf", "--version-info", "--wide", str(path)]).stdout.decode()
    versions = [(int(a), int(b)) for a, b in re.findall(r"GLIBC_(\d+)\.(\d+)", text)]
    if not versions:
        return None
    newest = max(versions)
    if newest > (2, 36):
        raise Refusal(f"{path.name} requires glibc {newest}, beyond Debian 12")
    return f"GLIBC_{newest[0]}.{newest[1]}"


def third_party(tree_output: str, vendor: pathlib.Path) -> tuple[list[dict[str, str]], str]:
    crates: dict[tuple[str, str], str] = {}
    for line in tree_output.splitlines():
        words = line.replace("(*)", "").split()
        if len(words) < 2 or not words[1].startswith("v"):
            continue
        name, version = words[0], words[1][1:]
        if not (vendor / f"{name}-{version}").is_dir():
            continue  # workspace path crate, not third-party
        crates[(name, version)] = " ".join(w for w in words[2:] if not w.startswith("(")) or "UNSPECIFIED"
    for name in FORBIDDEN_CRATES:
        if any(crate == name for crate, _ in crates):
            raise Refusal(f"shipped dependency graph contains forbidden crate {name}")
    listing = [{"name": n, "version": v, "license": licence} for (n, v), licence in sorted(crates.items())]
    text = ("Third-party Rust crates statically linked into the AG release executables.\n"
            "Each crate's license text is in its published source; this list is generated\n"
            "from `cargo tree` over the shipped packages at the source commit.\n\n"
            + "".join(f"{item['name']} {item['version']}: {item['license']}\n" for item in listing))
    return listing, text


def readme(commit: str) -> str:
    return f"""# AG {VERSION} governed-loop release (reviewed-local-copy/v1)

Source: {SOURCE_REPOSITORY} at {commit}.

Contents:

- `bin/ag-loopctl`: canonical exact-occurrence governed-loop controller.
- `bin/ag-standing-resolver`: one-shot standing authority over a mandate store.
- `bin/ag-operator-ui`: optional loopback-only read-only inspector (Phosphor).
- `share/seal-standing-resolver-launcher.py`: writes the sealed zero-argument
  standing launcher. Run it with `/usr/bin/python3.11 -I -S`. It uses only the
  standard library, and the launcher it writes starts with `-IS`.
- `BUILD-INFO.json`: component, version, source commit and tree, and the
  sha256 of every shipped file. The sealer answers no `--build-info`; this
  document and `SHA256SUMS` are its identity.

Every executable answers `--version` and `--build-info` (JSON, schema
`ag.build-info/v1`) with the full source commit. Verify with
`sha256sum --check --strict SHA256SUMS` from this directory.

Install by extracting as root to a fixed root-owned prefix. Nothing else is
installed: no accounts, units, keys or configuration. Enroll the installed
files by sha256 after extraction.

This artifact contains no agent_gov / agent_governor classic client, RPC
path or library, and none of the AG daemon lineage.
New spends mint `ag.governed-loop.issuance/v2` with a signed
`not_after_unix_ms`; no new setup input is needed for it.
"""


def inside_build(source: pathlib.Path, vendor: pathlib.Path, case: pathlib.Path, commit: str) -> bytes:
    (case / "cargo-home").mkdir(parents=True)
    (case / "build").mkdir()
    (case / "cargo-home" / "config.toml").write_text(CARGO_CONFIG, encoding="utf-8")
    built = run(docker_command(source, vendor, case, commit, CARGO_ARGUMENTS))
    tree = run(docker_command(source, vendor, case, commit, TREE_ARGUMENTS))
    (case / "cargo-tree.txt").write_bytes(tree.stdout)
    return built.stdout + built.stderr


def assemble(source: pathlib.Path, case: pathlib.Path, facts: dict[str, Any], vendor: pathlib.Path) -> dict[str, Any]:
    stage = case / "stage" / TOP
    (stage / "bin").mkdir(parents=True)
    (stage / "share").mkdir()
    executables: dict[str, Any] = {}
    for name, package in EXECUTABLES.items():
        built = case / "build" / "release" / name
        target = stage / "bin" / name
        shutil.copyfile(built, target)
        data = target.read_bytes()
        for forbidden in FORBIDDEN_STRINGS:
            if forbidden in data:
                raise Refusal(f"{name} contains forbidden classic reference {forbidden!r}")
        info = json.loads(run([str(built), "--build-info"]).stdout)
        version_line = run([str(built), "--version"]).stdout.decode().strip()
        expected = {"component": name, "debug_assertions": False, "schema": "ag.build-info/v1",
                    "source_commit": facts["commit"], "version": VERSION}
        if info != expected:
            raise Refusal(f"{name} --build-info differs: {info}")
        if version_line != f"{name} {VERSION} ({facts['commit']})":
            raise Refusal(f"{name} --version differs: {version_line!r}")
        executables[name] = {"path": f"bin/{name}", "cargo_package": package, "bytes": len(data),
                             "sha256": sha256_bytes(data), "maximum_glibc": glibc_ceiling(target),
                             "build_info": info, "version_line": version_line}
    scripts: dict[str, Any] = {}
    for member, relative in SCRIPTS.items():
        data = (source / relative).read_bytes()
        blob = run(["git", "-C", str(source), "rev-parse", f"HEAD:{relative}"]).stdout.decode().strip()
        (stage / member).write_bytes(data)
        scripts[member] = {"source_path": relative, "git_blob": blob, "bytes": len(data),
                           "sha256": sha256_bytes(data), "answers_build_info": False,
                           "identity": "BUILD-INFO.json entry and SHA256SUMS",
                           "interpreter": "/usr/bin/python3.11 -I -S", "imports": "standard library only"}
    listing, third_party_text = third_party((case / "cargo-tree.txt").read_text(), vendor)
    shutil.copyfile(source / "LICENSE", stage / "LICENSE")
    (stage / "THIRD-PARTY-CRATES.txt").write_text(third_party_text, encoding="utf-8")
    (stage / "README.md").write_text(readme(facts["commit"]), encoding="utf-8")
    build_info = {
        "schema": BUILD_INFO_SCHEMA, "component": COMPONENT, "version": VERSION,
        "source_repository": SOURCE_REPOSITORY, "source_commit": facts["commit"], "source_tree": facts["tree"],
        "toolchain": f"rustc {TOOLCHAIN}", "profile": "release", "builder_image": IMAGE_REPO_DIGEST,
        "source_date_epoch": SOURCE_DATE_EPOCH, "executables": executables, "scripts": scripts,
        "issuance_schema_minted": "ag.governed-loop.issuance/v2",
        "classic_reach": "none: no agent_gov, agent_governor, ag_shell_client or classic RPC",
        "third_party_crates": len(listing), "limitations": LIMITATIONS,
    }
    (stage / "BUILD-INFO.json").write_bytes(json.dumps(build_info, indent=2, sort_keys=True).encode() + b"\n")
    members = sorted(p.relative_to(stage).as_posix() for p in stage.rglob("*") if p.is_file())
    (stage / "SHA256SUMS").write_text("".join(f"{sha256_file(stage / m)}  {m}\n" for m in members), encoding="utf-8")
    tar_bytes = io.BytesIO()
    with tarfile.open(fileobj=tar_bytes, mode="w", format=tarfile.PAX_FORMAT) as archive:
        entries = [stage] + sorted(stage.rglob("*"), key=lambda p: p.relative_to(stage).as_posix())
        for path in entries:
            name = TOP if path == stage else f"{TOP}/{path.relative_to(stage).as_posix()}"
            info = tarfile.TarInfo(name)
            info.uid = info.gid = 0
            info.uname = info.gname = "root"
            info.mtime = SOURCE_DATE_EPOCH
            if path.is_dir():
                info.type, info.mode = tarfile.DIRTYPE, 0o755
                archive.addfile(info)
            else:
                data = path.read_bytes()
                info.size = len(data)
                info.mode = 0o755 if path.parent.name == "bin" else 0o644
                archive.addfile(info, io.BytesIO(data))
    compressed = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=compressed, compresslevel=9, mtime=0) as gz:
        gz.write(tar_bytes.getvalue())
    (case / TARBALL).write_bytes(compressed.getvalue())
    return {"executables": executables, "scripts": scripts, "build_info": build_info,
            "third_party": listing, "tarball_sha256": sha256_bytes(compressed.getvalue()),
            "tarball_bytes": len(compressed.getvalue()),
            "build_info_sha256": sha256_file(stage / "BUILD-INFO.json"),
            "member_sums_sha256": sha256_file(stage / "SHA256SUMS")}


def packaging_facts() -> dict[str, Any]:
    here = pathlib.Path(__file__).resolve()
    root = here.parents[2]
    def git(*arguments: str) -> str | None:
        done = subprocess.run(["git", "-C", str(root), *arguments], capture_output=True, text=True)
        return done.stdout.strip() if done.returncode == 0 else None
    return {"commit": git("rev-parse", "HEAD"),
            "dirty": bool(git("status", "--porcelain", "--", *PACKAGING_FILES)),
            "files": {name: sha256_file(root / name) for name in PACKAGING_FILES if (root / name).exists()}}


def build(args: argparse.Namespace) -> None:
    if f"{os.getuid()}:{os.getgid()}" != BUILD_USER:
        raise Refusal(f"builder requires host uid:gid {BUILD_USER}")
    if not re.fullmatch(r"[0-9a-f]{40}", args.commit):
        raise Refusal("--commit must be a full 40-hex commit")
    output: pathlib.Path = args.out
    if output.exists():
        raise Refusal("output directory already exists")
    vendor = args.vendor.resolve(strict=True)
    vendor_sha, vendor_files = tree_digest(vendor)
    image = image_facts()
    scratch = pathlib.Path(tempfile.mkdtemp(prefix="ag-release-build.", dir=args.scratch))
    try:
        cases: dict[str, Any] = {}
        for label in ("a", "b"):
            case = scratch / label
            case.mkdir()
            source = case / "src"
            facts = clone(args.remote, args.commit, source, args.require_branch)
            tracked = {name: sha256_file(source / name) for name in TRACKED_INPUTS}
            log = inside_build(source, vendor, case, args.commit)
            (case / "build.log").write_bytes(log)
            assembled = assemble(source, case, facts, vendor)
            cases[label] = {"source": facts, "tracked": tracked, **assembled}
            print(json.dumps({"case": label, "tarball_sha256": assembled["tarball_sha256"]}), flush=True)
        a, b = cases["a"], cases["b"]
        if a["source"] != b["source"] or a["tracked"] != b["tracked"]:
            raise Refusal("independent clones differ")
        binaries_equal = all(a["executables"][n]["sha256"] == b["executables"][n]["sha256"] for n in EXECUTABLES)
        tar_equal = (scratch / "a" / TARBALL).read_bytes() == (scratch / "b" / TARBALL).read_bytes()
        if not (binaries_equal and tar_equal):
            raise Refusal("independent builds are not byte-equal")
        output.mkdir(parents=True, mode=0o755)
        shutil.copyfile(scratch / "a" / TARBALL, output / TARBALL)
        for label in ("a", "b"):
            shutil.copyfile(scratch / label / "build.log", output / f"build-{label}.log")
        receipt = {
            "schema": RECEIPT_SCHEMA,
            "component": COMPONENT, "version": VERSION,
            "source": {"repository": SOURCE_REPOSITORY, "remote": args.remote, **a["source"],
                       "tracked_inputs_sha256": a["tracked"]},
            "packaging": packaging_facts(),
            "vendor": {"tree_sha256": vendor_sha, "regular_files": vendor_files, "container_path": "/vendor",
                       "produced_by": f"cargo +{TOOLCHAIN} vendor --locked --versioned-dirs"},
            "builder": image,
            "build": {"environment": {k: (args.commit if v == "<SOURCE_COMMIT>" else v) for k, v in BUILD_ENV.items()},
                      "cargo_arguments": CARGO_ARGUMENTS, "tree_arguments": TREE_ARGUMENTS,
                      "cargo_config_sha256": sha256_bytes(CARGO_CONFIG.encode()),
                      "normalized_docker_argv": normalized_docker_argv(CARGO_ARGUMENTS),
                      "tar": "PAX, root:root, mtime SOURCE_DATE_EPOCH, gzip mtime 0 level 9"},
            "executables": a["executables"], "scripts": a["scripts"],
            "artifacts": {TARBALL: {"bytes": a["tarball_bytes"], "sha256": a["tarball_sha256"]}},
            "tarball_members": {"BUILD-INFO.json": a["build_info_sha256"], "SHA256SUMS": a["member_sums_sha256"]},
            "reproduction": {"clean_builds": 2, "independent_clones": 2, "byte_equal": True,
                             "build_a_tarball_sha256": a["tarball_sha256"], "build_b_tarball_sha256": b["tarball_sha256"],
                             "executables_a": {n: a["executables"][n]["sha256"] for n in EXECUTABLES},
                             "executables_b": {n: b["executables"][n]["sha256"] for n in EXECUTABLES}},
            "logs": {f"build-{label}.log": sha256_file(output / f"build-{label}.log") for label in ("a", "b")},
            "classic_reach": {"forbidden_crates_absent": list(FORBIDDEN_CRATES),
                              "forbidden_strings_absent": [s.decode() for s in FORBIDDEN_STRINGS]},
            "limitations": LIMITATIONS,
        }
        (output / RECEIPT).write_bytes(json.dumps(receipt, indent=2, sort_keys=True).encode() + b"\n")
        (output / "SHA256SUMS").write_text("".join(f"{sha256_file(output / name)}  {name}\n"
                                                   for name in (TARBALL, RECEIPT)), encoding="utf-8")
        print(json.dumps({"result": "REPRODUCIBLE_AG_RELEASE", "tarball_sha256": a["tarball_sha256"]}))
    finally:
        if not args.keep_scratch:
            subprocess.run(["chmod", "-R", "u+w", str(scratch)], check=False)
            shutil.rmtree(scratch, ignore_errors=True)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    root.add_argument("--commit", required=True, help="full 40-hex source commit to build")
    root.add_argument("--remote", default=DEFAULT_REMOTE)
    root.add_argument("--require-branch", default=None,
                      help="refuse unless the commit is reachable from origin/<branch>")
    root.add_argument("--vendor", type=pathlib.Path, required=True,
                      help="output of `cargo vendor --locked --versioned-dirs` for Cargo.lock at the commit")
    root.add_argument("--out", type=pathlib.Path, required=True)
    root.add_argument("--scratch", type=pathlib.Path, required=True, help="root-filesystem scratch parent")
    root.add_argument("--keep-scratch", action="store_true")
    return root


def main() -> int:
    try:
        build(parser().parse_args())
        return 0
    except (OSError, ValueError, Refusal) as error:
        print(f"REFUSED: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
