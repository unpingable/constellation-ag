#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Clean Debian 12 VM gate for the AG governed-loop release tarball.

This follows the style of NQ's release-closure harness and Maude's lane-C
gate. It boots one disposable Debian 12 guest from the verified read-only base
image with a qcow2 overlay and a cloud-init seed, KVM, user networking with
restrict=on and one SSH hostfwd on 127.0.0.1, and qemu -sandbox on.

The guest receives only:
- the AG release artifacts and build receipt (installed from the tarball only);
- a Docket build (``docket`` and ``docket-local-standing-resolver``) as a
  read-only compatibility input for the cross-process spend;
- the guest case script ``guest/ag_gate_guest.py`` (standard library only).

No source tree, share or host PATH is exposed. Every functional case runs as
the ``constellation`` system account with ``/usr/bin/python3.11 -I -S`` and
synthetic identities, keys and inputs made in the guest. Each case ends as
PASS, FAIL or NOT_EXERCISED.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import shlex
import shutil
import socket
import subprocess
import sys
import time
import traceback
from typing import Any

HERE = pathlib.Path(__file__).resolve().parent
HARNESS_FILES = ("run_vm_gate.py", "guest/ag_gate_guest.py")
HOST_TOOLS = ("qemu-img", "qemu-system-x86_64", "xorriso", "ssh", "scp", "ssh-keygen")
IMAGE = pathlib.Path(
    "/data/git/.campaign-artifacts/constellation-operator-beta-composed-m2-run-002/input/"
    "debian-12-genericcloud-amd64-20260903-2590.qcow2"
)
USER = "agacceptor"
HOME = f"/home/{USER}"
PY = "/usr/bin/python3.11"
VERSION = "0.1.0"
TOP = f"ag-{VERSION}"
TARBALL = f"{TOP}-linux-amd64.tar.gz"
RECEIPT = "build-receipt.v1.json"
COHORT = "/opt/constellation/cohorts/gate"
PREFIX = f"{COHORT}/ag/{TOP}"
DOCKET_BIN = f"{COHORT}/docket/docket-gate-input/bin"
STATE = "/var/lib/constellation/cohorts/gate"
GUEST_SCRIPT = "/usr/local/lib/ag-gate/ag_gate_guest.py"
EXECUTABLES = ("ag-loopctl", "ag-standing-resolver", "ag-operator-ui")
SEALER = "share/seal-standing-resolver-launcher.py"

CASES = [
    ("I-01", "guest: Debian 12; Debian's /usr/bin/python3.11 and /usr/bin/openssl; no source tree"),
    ("I-02", "artifact: sha256sum --check SHA256SUMS in the guest"),
    ("I-03", "install: from the tarball only as root:root; tar members are plain; member sums verify; bytes equal the receipt"),
    ("I-04", "identity: --version and --build-info carry component, 0.1.0 and the 40-hex source commit; sealer covered by BUILD-INFO"),
    ("I-05", "environment: no /data, no agent_gov/ag_shell_client on disk or in the executables; no egress"),
    ("I-06", "docs: packaged README and BUILD-INFO state classic absence, v2 issuance and the sealer interpreter"),
    ("S-01", "ports: sealer under python3.11 -I -S writes the -IS standing launcher; Docket launcher, issuer key and trust"),
    ("S-02", "python: sealer and launcher load only standard-library modules under -I -S"),
    ("S-03", "profile: V1 runtime profile seal and verify with synthetic inputs; create-once"),
    ("S-04", "profile: V2 runtime profile seal, verify and init-v2 over synthetic stand-in ports"),
    ("L-01", "spend: record-proposal, decide, authorize (v2 issuance with not_after) and dispatch to real Docket; executor once; settled"),
    ("L-02", "docket: Docket's own record and local standing snapshot for the AG issuance"),
    ("L-03", "issuance: minted body recomputes under the v2 identity law with not_after committed"),
    ("L-04", "inspect: occurrence, issuance, spend and settlement digests present and joined to Docket's record"),
    ("R-01", "refusal: tampered profile (rewritten, non-canonical, pinned catalog changed) refused"),
    ("R-02", "refusal: tampered launcher refused by verify/init; tampered resolver refused by the sealed launcher"),
    ("R-03", "refusal: wrong interpreter hash (and wrong resolver hash) refused by the sealer; nothing written"),
    ("R-04", "refusal: issuance past not-after never presented by AG; Docket refuses it directly as governed-issuance-expired"),
    ("U-01", "operator-ui: release ag-operator-ui serves the settled campaign on loopback only, read-only"),
    ("P-01", "packaging: a corrupted tarball fails its checksum"),
]
GUEST_CASES = {
    "S-01": "ports", "S-02": "python-origin", "S-03": "profile", "S-04": "v2-profile", "L-01": "spend",
    "L-02": "docket-view", "L-03": "issuance-law", "L-04": "join", "R-01": "refuse-profile",
    "R-02": "refuse-launcher", "R-03": "refuse-interpreter", "R-04": "expired", "U-01": "operator-ui",
}


class Refusal(Exception):
    pass


class CaseFail(Exception):
    pass


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def sha(path: pathlib.Path, algorithm: str = "sha256") -> str:
    digest = hashlib.new(algorithm)
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(command: list[str], *, check: bool = True, timeout: float = 600) -> subprocess.CompletedProcess[bytes]:
    completed = subprocess.run(command, capture_output=True, timeout=timeout, check=False)
    if check and completed.returncode != 0:
        raise Refusal(f"command failed ({completed.returncode}): {shlex.join(command)}\n"
                      f"{completed.stderr.decode(errors='replace')[-2000:]}")
    return completed


def text(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise CaseFail(message)


class Gate:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.out: pathlib.Path = args.output
        self.state: pathlib.Path = args.state_dir
        self.results = {cid: {"id": cid, "title": title, "outcome": "NOT_EXERCISED", "reason": "not reached"}
                        for cid, title in CASES}
        self.current: str | None = None
        self.process: subprocess.Popen[bytes] | None = None
        self.command: list[str] = []
        self.key = self.state / "id_ed25519"
        self.facts: dict[str, Any] = {}

    # ------------------------------------------------------------ plumbing
    def log(self, message: str) -> None:
        line = f"[{utc_now()}] {message}"
        print(line, flush=True)
        with (self.out / "host.log").open("a") as handle:
            handle.write(line + "\n")

    def ssh_base(self) -> list[str]:
        return ["ssh", "-i", str(self.key), "-p", str(self.args.ssh_port), "-o", "IdentitiesOnly=yes",
                "-o", "StrictHostKeyChecking=accept-new", "-o", f"UserKnownHostsFile={self.state / 'known_hosts'}",
                "-o", "ConnectTimeout=5", "-o", "LogLevel=ERROR", f"{USER}@127.0.0.1"]

    def scp(self, sources: list[pathlib.Path], destination: str) -> None:
        run(["scp", "-q", "-i", str(self.key), "-P", str(self.args.ssh_port), "-o", "IdentitiesOnly=yes",
             "-o", "StrictHostKeyChecking=accept-new", "-o", f"UserKnownHostsFile={self.state / 'known_hosts'}",
             "-o", "LogLevel=ERROR", *[str(s) for s in sources], f"{USER}@127.0.0.1:{destination}"])

    def sh(self, command: str, *, timeout: float = 300, check: bool = False) -> subprocess.CompletedProcess[bytes]:
        started = time.monotonic()
        try:
            completed = run(self.ssh_base() + [command], check=False, timeout=timeout)
        except subprocess.TimeoutExpired:
            completed = subprocess.CompletedProcess(command, 124, b"", b"[timeout]")
        if self.current:
            with (self.out / "cases" / f"{self.current}.log").open("a") as handle:
                handle.write(f"\n$ {command}\n# exit {completed.returncode} in {time.monotonic() - started:.1f}s\n"
                             + (f"--- stdout\n{text(completed.stdout)}\n" if completed.stdout else "")
                             + (f"--- stderr\n{text(completed.stderr)}\n" if completed.stderr else ""))
        if check and completed.returncode != 0:
            raise CaseFail(f"exit {completed.returncode}: {command}: {text(completed.stderr)[-800:]}")
        return completed

    def case(self, cid: str, function, *args: Any) -> None:
        self.current = cid
        (self.out / "cases" / f"{cid}.log").write_text(f"# {cid}: {dict(CASES)[cid]}\n")
        try:
            observed = function(*args) or {}
            self.results[cid] = {"id": cid, "title": dict(CASES)[cid], "outcome": "PASS", "observed": observed}
        except CaseFail as error:
            self.results[cid] = {"id": cid, "title": dict(CASES)[cid], "outcome": "FAIL", "error": str(error)}
        except Exception as error:  # noqa: BLE001
            self.results[cid] = {"id": cid, "title": dict(CASES)[cid], "outcome": "FAIL",
                                 "error": f"{type(error).__name__}: {error}", "trace": traceback.format_exc()[-2000:]}
        self.log(f"{cid} {self.results[cid]['outcome']}")
        self.current = None
        self.write()

    def write(self) -> None:
        summary = {o: sum(1 for r in self.results.values() if r["outcome"] == o) for o in ("PASS", "FAIL", "NOT_EXERCISED")}
        (self.out / "GATE-RESULT.json").write_text(json.dumps({
            "schema": "constellation.ag-release-vm-gate/v1", "facts": self.facts, "summary": summary,
            "qemu_command": self.command, "cases": list(self.results.values())}, indent=2, sort_keys=True) + "\n")

    # ------------------------------------------------------------ preflight
    def harness_identity(self) -> dict[str, Any]:
        def git(*arguments: str) -> str | None:
            done = subprocess.run(["git", "-C", str(HERE), *arguments], capture_output=True, text=True)
            return done.stdout.strip() if done.returncode == 0 else None
        return {"commit": git("rev-parse", "HEAD"), "branch": git("rev-parse", "--abbrev-ref", "HEAD"),
                "dirty_paths": (git("status", "--porcelain", "--", ".") or "").splitlines(),
                "files": {name: sha(HERE / name) for name in HARNESS_FILES}}

    def preflight(self) -> None:
        for tool in HOST_TOOLS:
            if shutil.which(tool) is None:
                raise Refusal(f"required tool absent: {tool}")
        if not os.access("/dev/kvm", os.R_OK | os.W_OK):
            raise Refusal("/dev/kvm is not accessible")
        with socket.socket() as probe:
            try:
                probe.bind(("127.0.0.1", self.args.ssh_port))
            except OSError as error:
                raise Refusal(f"port {self.args.ssh_port} is busy") from error
        if self.out.exists():
            raise Refusal(f"output exists: {self.out}")
        if self.state.exists():
            raise Refusal(f"state directory exists: {self.state}")
        candidate: pathlib.Path = self.args.candidate_dir
        checked = subprocess.run(["sha256sum", "--check", "--strict", "SHA256SUMS"], cwd=candidate, capture_output=True)
        if checked.returncode != 0:
            raise Refusal("candidate SHA256SUMS does not verify on the host")
        receipt = json.loads((candidate / RECEIPT).read_text())
        if not receipt.get("reproduction", {}).get("byte_equal"):
            raise Refusal("receipt does not record a byte-equal reproduction")
        expected = None
        for line in (IMAGE.parent / "SHA512SUMS").read_text().splitlines():
            digest, _, name = line.strip().partition("  ")
            if name == IMAGE.name:
                expected = digest
        actual = sha(IMAGE, "sha512")
        if expected != actual:
            raise Refusal("base image SHA-512 differs from SHA512SUMS")
        if os.access(IMAGE, os.W_OK):
            raise Refusal("base image must not be writable")
        docket_dir: pathlib.Path = self.args.docket_dir
        for name in ("docket", "docket-local-standing-resolver"):
            if not (docket_dir / name).is_file():
                raise Refusal(f"Docket input lacks {name}")
        (self.out / "cases").mkdir(parents=True)
        self.state.mkdir(parents=True, mode=0o700)
        self.receipt = receipt
        self.facts = {
            "started": utc_now(),
            "harness": self.harness_identity(),
            "candidate": {"directory": str(candidate), "receipt_sha256": sha(candidate / RECEIPT),
                          "artifacts": receipt["artifacts"], "source_commit": receipt["source"]["commit"],
                          "source_tree": receipt["source"]["tree"]},
            "docket_input": {"origin": self.args.docket_origin,
                             **{name: sha(docket_dir / name) for name in ("docket", "docket-local-standing-resolver")}},
            "image": {"path": str(IMAGE), "sha512": actual},
            "ssh_port": self.args.ssh_port,
        }
        self.write()

    # ------------------------------------------------------------ guest
    def boot(self) -> None:
        run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "ag-vm-gate", "-f", str(self.key)])
        public = self.key.with_suffix(".pub").read_text().strip()
        (self.state / "meta-data").write_text("instance-id: ag-vm-gate\nlocal-hostname: ag-gate\n")
        (self.state / "user-data").write_text(f"""#cloud-config
disable_root: true
hostname: ag-gate
package_update: false
package_upgrade: false
ssh_pwauth: false
users:
  - name: {USER}
    groups: [sudo]
    lock_passwd: true
    shell: /bin/bash
    sudo: ["ALL=(ALL) NOPASSWD:ALL"]
    ssh_authorized_keys:
      - "{public}"
""")
        run(["xorriso", "-as", "mkisofs", "-quiet", "-output", str(self.state / "seed.iso"), "-volid", "cidata",
             "-joliet", "-rock", str(self.state / "user-data"), str(self.state / "meta-data")])
        run(["qemu-img", "create", "-q", "-f", "qcow2", "-b", str(IMAGE), "-F", "qcow2", str(self.state / "overlay.qcow2")])
        self.command = [
            "qemu-system-x86_64", "-name", "ag-vm-gate,process=ag-vm-gate", "-no-user-config", "-nodefaults",
            "-accel", "kvm", "-machine", "q35", "-cpu", "host", "-smp", "2", "-m", "2048",
            "-display", "none", "-monitor", "none", "-serial", f"file:{self.state / 'serial.log'}",
            "-drive", f"if=virtio,file={self.state / 'overlay.qcow2'},format=qcow2,cache=none,aio=threads",
            "-drive", f"if=virtio,file={self.state / 'seed.iso'},format=raw,readonly=on",
            "-netdev", f"user,id=mgmt,restrict=on,hostfwd=tcp:127.0.0.1:{self.args.ssh_port}-:22",
            "-device", "virtio-net-pci,netdev=mgmt,mac=52:54:00:9c:04:31",
            "-sandbox", "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny",
        ]
        self.process = subprocess.Popen(self.command, stdout=(self.state / "qemu.stdout.log").open("wb"),
                                        stderr=(self.state / "qemu.stderr.log").open("wb"), start_new_session=True)
        self.log(f"started guest pid {self.process.pid} on 127.0.0.1:{self.args.ssh_port}")
        deadline = time.monotonic() + 900
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise Refusal("guest exited: " + (self.state / "qemu.stderr.log").read_text()[-800:])
            try:
                if run(self.ssh_base() + ["true"], check=False, timeout=30).returncode == 0:
                    break
            except subprocess.TimeoutExpired:
                pass
            time.sleep(3)
        else:
            raise Refusal("guest SSH not reachable")
        run(self.ssh_base() + ["cloud-init status --wait >/dev/null; cloud-init status"], check=False, timeout=900)
        run(self.ssh_base() + [f"mkdir -p {HOME}/candidate {HOME}/inputs/docket {HOME}/harness"])
        candidate: pathlib.Path = self.args.candidate_dir
        self.scp([candidate / name for name in (*self.receipt["artifacts"], RECEIPT, "SHA256SUMS")], f"{HOME}/candidate/")
        self.scp([self.args.docket_dir / "docket", self.args.docket_dir / "docket-local-standing-resolver"], f"{HOME}/inputs/docket/")
        self.scp([HERE / "guest" / "ag_gate_guest.py"], f"{HOME}/harness/")
        self.log("guest ready")

    def destroy(self) -> None:
        if self.process is not None and self.process.poll() is None:
            try:
                run(self.ssh_base() + ["sudo systemctl poweroff"], check=False, timeout=20)
            except subprocess.TimeoutExpired:
                pass
            deadline = time.monotonic() + 60
            while self.process.poll() is None and time.monotonic() < deadline:
                time.sleep(1)
            if self.process.poll() is None:
                self.process.kill()
                self.process.wait(timeout=30)
        for name in ("serial.log", "qemu.stdout.log", "qemu.stderr.log"):
            if (self.state / name).exists():
                shutil.copy2(self.state / name, self.out / f"guest-{name}")
        shutil.rmtree(self.state, ignore_errors=True)
        self.log("guest destroyed")

    def json_out(self, completed: subprocess.CompletedProcess[bytes]) -> Any:
        try:
            return json.loads(completed.stdout)
        except json.JSONDecodeError as error:
            raise CaseFail(f"stdout is not JSON: {text(completed.stdout)[:400]!r}") from error

    # ------------------------------------------------------------ cases
    def i01(self) -> dict:
        osr = text(self.sh('. /etc/os-release; printf "%s:%s" "$ID" "$VERSION_ID"', check=True).stdout)
        expect(osr == "debian:12", f"not Debian 12: {osr}")
        version = text(self.sh(f"{PY} -V", check=True).stdout).strip()
        owner = text(self.sh(f"dpkg -S {PY}", check=True).stdout).strip()
        digest = text(self.sh(f"sha256sum {PY}", check=True).stdout).split()[0]
        expect(version.startswith("Python 3.11") and owner.startswith("python3.11-minimal"), f"{version} {owner}")
        expect(self.sh("test ! -e /usr/bin/python3.12").returncode == 0, "python3.12 present")
        openssl = text(self.sh("openssl version; dpkg -S /usr/bin/openssl; sha256sum /usr/bin/openssl", check=True).stdout).strip()
        sources = text(self.sh("ls -d /data /home/*/src /opt 2>/dev/null; find / -xdev -name Cargo.toml -not -path '/proc/*' 2>/dev/null | head -3; true").stdout).strip()
        expect("Cargo.toml" not in sources and "/data" not in sources.split(), f"source tree present: {sources}")
        self.facts["guest_interpreter"] = {"path": PY, "version": version, "package": owner, "sha256": digest}
        return {"os": osr, "python": version, "package": owner, "sha256": digest, "openssl": openssl, "ls": sources}

    def i02(self) -> dict:
        done = self.sh(f"cd {HOME}/candidate && sha256sum --check --strict SHA256SUMS", check=True)
        return {"check": text(done.stdout).strip().splitlines()}

    def i03(self) -> dict:
        listing = text(self.sh(f"tar -tvzf {HOME}/candidate/{TARBALL}", check=True).stdout).splitlines()
        for line in listing:
            fields = line.split()
            kind, owner, name = fields[0][0], fields[1], fields[-1]
            expect(kind in "d-" and owner == "root/root", f"tar member not plain root-owned: {line}")
            expect(name.startswith(f"{TOP}/") or name == f"{TOP}/" or name == TOP, f"member outside top dir: {name}")
            expect(".." not in name.split("/") and not name.startswith("/"), f"unsafe member {name}")
            expect(not any(c in fields[0] for c in "sStT") and fields[0][5] != "w" and fields[0][8] != "w",
                   f"special or group/world-writable mode: {line}")
        self.sh(f"sudo install -d -m 0755 -o root -g root /opt/constellation /opt/constellation/cohorts {COHORT} {COHORT}/ag && "
                f"sudo tar -xzf {HOME}/candidate/{TARBALL} -C {COHORT}/ag --no-same-permissions --same-owner", check=True)
        members = self.sh(f"cd {PREFIX} && sha256sum --check --strict SHA256SUMS", check=True)
        modes = text(self.sh(f"stat -c '%a %U:%G %n' {PREFIX} {PREFIX}/bin/* {PREFIX}/share/* {PREFIX}/BUILD-INFO.json", check=True).stdout)
        installed = {}
        for name in EXECUTABLES:
            digest = text(self.sh(f"sha256sum {PREFIX}/bin/{name}", check=True).stdout).split()[0]
            expect(digest == self.receipt["executables"][name]["sha256"], f"installed {name} differs from the receipt")
            installed[name] = digest
        sealer = text(self.sh(f"sha256sum {PREFIX}/{SEALER}", check=True).stdout).split()[0]
        expect(sealer == self.receipt["scripts"][SEALER]["sha256"], "installed sealer differs from the receipt")
        for line in modes.strip().splitlines():
            expect(" root:root " in line, f"not root-owned: {line}")
        # Docket compatibility input (not part of the AG artifact).
        self.sh(f"sudo install -d -m 0755 -o root -g root {COHORT}/docket {COHORT}/docket/docket-gate-input {DOCKET_BIN} && "
                f"sudo install -m 0755 -o root -g root {HOME}/inputs/docket/docket {HOME}/inputs/docket/docket-local-standing-resolver {DOCKET_BIN}/",
                check=True)
        # The cohort account and root-owned state ancestors (driver layout).
        self.sh("sudo useradd --system --home-dir /var/lib/constellation --no-create-home --shell /usr/sbin/nologin constellation && "
                "sudo install -d -m 0711 -o root -g root /var/lib/constellation /var/lib/constellation/cohorts && "
                f"sudo install -d -m 0700 -o constellation -g constellation {STATE} && "
                f"sudo install -d -m 0755 -o root -g root /usr/local/lib/ag-gate && "
                f"sudo install -m 0644 -o root -g root {HOME}/harness/ag_gate_guest.py {GUEST_SCRIPT}", check=True)
        self.facts["installed"] = {**installed, SEALER: sealer}
        return {"members": len(listing), "member_check": text(members.stdout).strip().splitlines(),
                "modes": modes.strip().splitlines(), "installed_sha256": self.facts["installed"]}

    def i04(self) -> dict:
        commit = self.receipt["source"]["commit"]
        expect(len(commit) == 40, "receipt commit is not 40-hex")
        observed = {}
        for name in EXECUTABLES:
            version = text(self.sh(f"{PREFIX}/bin/{name} --version", check=True).stdout).strip()
            expect(version == f"{name} {VERSION} ({commit})", f"{name} --version: {version!r}")
            info = self.json_out(self.sh(f"{PREFIX}/bin/{name} --build-info", check=True))
            expect(info == {"component": name, "debug_assertions": False, "schema": "ag.build-info/v1",
                            "source_commit": commit, "version": VERSION}, f"{name} build-info {info}")
            observed[name] = {"version": version, "build_info": info}
        build_info = self.json_out(self.sh(f"cat {PREFIX}/BUILD-INFO.json", check=True))
        expect(build_info["source_commit"] == commit and build_info["source_tree"] == self.receipt["source"]["tree"],
               "BUILD-INFO source identity")
        entry = build_info["scripts"][SEALER]
        expect(entry["sha256"] == self.facts["installed"][SEALER] and entry["answers_build_info"] is False,
               "BUILD-INFO sealer entry")
        for name in EXECUTABLES:
            expect(build_info["executables"][name]["sha256"] == self.facts["installed"][name], f"BUILD-INFO {name}")
        help_text = self.sh(f"{PY} -I -S {PREFIX}/{SEALER} --build-info")
        observed["sealer"] = {"entry": entry, "own_build_info_flag": "absent (argparse refusal)" if help_text.returncode != 0 else "present"}
        return observed

    def i05(self) -> dict:
        disk = text(self.sh("sudo find / -xdev \\( -name 'agent_gov*' -o -name 'ag_shell_client*' -o -name 'agent_governor*' \\) "
                            "-not -path '/proc/*' 2>/dev/null | head; true").stdout).strip()
        expect(not disk, f"classic files on disk: {disk}")
        strings = self.sh(f"grep -c -a -E 'agent_gov|ag_shell_client|agent_governor' {PREFIX}/bin/* {PREFIX}/{SEALER}; true")
        counts = {line.rsplit(":", 1)[0]: int(line.rsplit(":", 1)[1]) for line in text(strings.stdout).split()}
        expect(all(v == 0 for v in counts.values()), f"classic strings present: {counts}")
        linked = text(self.sh(f"for f in {PREFIX}/bin/*; do echo \"== $f\"; ldd $f; done", check=True).stdout)
        expect("not found" not in linked, "missing shared library")
        egress = self.sh(f"{PY} -I -S -c \"import socket; s=socket.create_connection(('1.1.1.1', 443), timeout=5)\"")
        expect(egress.returncode != 0, "guest has egress")
        data = self.sh("test ! -e /data").returncode == 0
        expect(data, "/data exists in the guest")
        return {"classic_on_disk": "none", "classic_strings": counts, "ldd": linked.strip().splitlines(),
                "egress": "blocked", "data_path": "absent"}

    def i06(self) -> dict:
        readme = text(self.sh(f"cat {PREFIX}/README.md", check=True).stdout)
        expect("agent_gov" in readme and "no agent_gov" in readme.replace("\n", " "), "README lacks the classic statement")
        expect("ag.governed-loop.issuance/v2" in readme and "/usr/bin/python3.11 -I -S" in readme, "README lacks v2 or interpreter")
        build_info = self.json_out(self.sh(f"cat {PREFIX}/BUILD-INFO.json", check=True))
        expect(build_info["classic_reach"].startswith("none") and build_info["issuance_schema_minted"] == "ag.governed-loop.issuance/v2",
               "BUILD-INFO statements")
        return {"classic_reach": build_info["classic_reach"], "limitations": build_info["limitations"]}

    def guest_case(self, name: str) -> dict:
        done = self.sh(f"cd / && sudo -u constellation {PY} -I -S {GUEST_SCRIPT} --case {name} --ag-prefix {PREFIX} "
                       f"--docket-bin {DOCKET_BIN} --root {STATE} --python {PY} --openssl /usr/bin/openssl", timeout=600)
        lines = text(done.stdout).strip().splitlines()
        expect(bool(lines), f"no output (exit {done.returncode}): {text(done.stderr)[-800:]}")
        result = json.loads(lines[-1])
        expect(done.returncode == 0 and result.get("result") == "PASS", result.get("error") or text(done.stderr)[-800:])
        return result["observed"]

    def p01(self) -> dict:
        done = self.sh(f"cp -r {HOME}/candidate {HOME}/corrupt && cd {HOME}/corrupt && "
                       f"printf 'X' | dd of={TARBALL} bs=1 seek=4096 conv=notrunc status=none && "
                       f"sha256sum --check --strict SHA256SUMS")
        expect(done.returncode != 0 and f"{TARBALL}: FAILED".encode() in done.stdout, "corruption not detected")
        return {"exit": done.returncode, "stdout": text(done.stdout).strip().splitlines()}

    # ------------------------------------------------------------ main
    def main(self) -> int:
        try:
            self.preflight()
        except Refusal as error:
            print(f"refused: {error}", file=sys.stderr)
            return 2
        status = 0
        try:
            self.boot()
            for cid, fn in (("I-01", self.i01), ("I-02", self.i02), ("I-03", self.i03)):
                self.case(cid, fn)
            if self.results["I-03"]["outcome"] != "PASS":
                raise Refusal("install failed; later cases not exercised")
            for cid, fn in (("I-04", self.i04), ("I-05", self.i05), ("I-06", self.i06)):
                self.case(cid, fn)
            order = ["S-01", "S-02", "S-03", "S-04", "L-01", "L-02", "L-03", "L-04",
                     "R-01", "R-02", "R-03", "R-04", "U-01"]
            for cid in order:
                if cid != "S-01" and self.results["S-01"]["outcome"] != "PASS":
                    break
                if cid in ("L-02", "L-03", "L-04", "U-01") and self.results["L-01"]["outcome"] != "PASS":
                    continue
                self.case(cid, self.guest_case, GUEST_CASES[cid])
            self.case("P-01", self.p01)
        except Exception as error:  # noqa: BLE001
            self.log(f"aborted: {error}")
            for entry in self.results.values():
                if entry["outcome"] == "NOT_EXERCISED":
                    entry["reason"] = f"aborted: {error}"[:400]
            status = 1
        finally:
            self.destroy()
            self.facts["finished"] = utc_now()
            self.write()
        summary = {o: sum(1 for r in self.results.values() if r["outcome"] == o) for o in ("PASS", "FAIL", "NOT_EXERCISED")}
        self.log(f"done: {summary}")
        return 0 if status == 0 and summary["FAIL"] == 0 and summary["NOT_EXERCISED"] == 0 else 1


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--candidate-dir", type=pathlib.Path, required=True)
    p.add_argument("--docket-dir", type=pathlib.Path, required=True,
                   help="directory with docket and docket-local-standing-resolver (compatibility input)")
    p.add_argument("--docket-origin", required=True, help="free-text provenance of the Docket input, recorded in facts")
    p.add_argument("--output", type=pathlib.Path, required=True)
    p.add_argument("--state-dir", type=pathlib.Path, required=True)
    p.add_argument("--ssh-port", type=int, default=23431)
    return p


if __name__ == "__main__":
    sys.exit(Gate(parser().parse_args()).main())
