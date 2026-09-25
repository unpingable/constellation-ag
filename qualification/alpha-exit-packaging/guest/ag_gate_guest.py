# SPDX-License-Identifier: Apache-2.0
"""Guest side of the AG release VM gate (standard library only).

Run as ``/usr/bin/python3.11 -I -S ag_gate_guest.py --case <name> ...`` by the
cohort account. Every case prints one JSON document of observed facts on
success and exits 0; a failed expectation prints the reason and exits 1.

All identities, keys and inputs are synthetic and generated here. The
observation resolver and the executor are small synthetic stand-ins written by
this script: the gate qualifies AG's own role (profile sealing, the standing
resolver behind its sealed launcher, the spend, the signed v2 issuance and its
presentation to a real Docket), not Nightshift or Maude.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import time
import uuid

BASIS = {
    "atoms": ["condition.clean", "delivery.not_required"],
    "rule": {"digest": "sha256:5f8bd1a497e034633d6fd465a6834a2ca8e9a4b20158322fd0a4bc36095f8e67",
             "id": "nightshift.posture-normalization", "version": "1"},
    "schema": "nightshift.decision-basis.v1",
}
BASIS_DIGEST = "sha256:d67f86277b1604cad1916d01bcd5e01fc3a9002d4630cb8fdf5b749febf4b2c7"
WORK_SCHEMA = "gate.synthetic-write/v1"
OBSERVATION_ID = "cohort-gate-observation/v1"
STANDING_ID = "cohort-gate-ag-standing/v1"
ISSUER = "cohort-gate-ag-issuer"
ISSUER_KEY_ID = "cohort-gate-ag-issuer-k1"
OPERATOR = "cohort-gate-operator"
MAX_STANDING_TTL_MS = 300000


class Fail(Exception):
    pass


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise Fail(message)


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def label_digest(label: str) -> str:
    return sha(b"cohort-gate\0" + label.encode())


def ag_domain_digest(domain: str, payload: bytes) -> str:
    """AG's Digest::hash_domain law, reimplemented independently."""
    h = hashlib.sha256(b"ag-ng\0digest\0v1\0")
    h.update(len(domain).to_bytes(16, "big") + domain.encode())
    h.update(len(payload).to_bytes(16, "big") + payload)
    return "sha256:" + h.hexdigest()


def now_ms() -> int:
    return time.time_ns() // 1_000_000


class Ctx:
    def __init__(self, args: argparse.Namespace) -> None:
        self.prefix = pathlib.Path(args.ag_prefix)
        self.loopctl = self.prefix / "bin/ag-loopctl"
        self.resolver = self.prefix / "bin/ag-standing-resolver"
        self.sealer = self.prefix / "share/seal-standing-resolver-launcher.py"
        self.docket = pathlib.Path(args.docket_bin) / "docket"
        self.docket_resolver = pathlib.Path(args.docket_bin) / "docket-local-standing-resolver"
        self.python = pathlib.Path(args.python)
        self.openssl = pathlib.Path(args.openssl)
        self.root = pathlib.Path(args.root)
        self.ports = self.root / "ports"
        self.owner = self.root / "owner"
        self.work = self.root / "work"

    # ------------------------------------------------------------ processes
    def call(self, argv, *, stdin: bytes | None = None, timeout: float = 120):
        done = subprocess.run([str(a) for a in argv], input=stdin, capture_output=True, timeout=timeout)
        return done.returncode, done.stdout, done.stderr

    def ok(self, argv, *, stdin: bytes | None = None):
        code, out, err = self.call(argv, stdin=stdin)
        if code != 0:
            raise Fail(f"exit {code}: {' '.join(map(str, argv))}: {err.decode(errors='replace')[-1500:]}")
        return out

    def ok_json(self, argv, *, stdin: bytes | None = None):
        return json.loads(self.ok(argv, stdin=stdin))

    def loop(self, *argv):
        return self.ok_json([self.loopctl, *argv])

    def write(self, path: pathlib.Path, data: bytes, mode: int = 0o600) -> None:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)

    # ------------------------------------------------------------ fixtures
    def observation_program(self) -> bytes:
        window = self.ports / "observation-window-ms"
        return f'''#!{self.python} -IS
import hashlib, json, sys
BASIS = {BASIS!r}
request = json.loads(sys.stdin.buffer.read())
if request.get("schema") != "ag.governed-loop.observation-request/v1":
    raise SystemExit("unexpected observation request schema")
with open({str(window)!r}) as handle:
    window = int(handle.read().strip())
now = request["now_unix_ms"]
out = {{"schema": "ag.governed-loop.observation-resolution/v2", "key": request["key"],
       "observation": request["observation"],
       "currentness": "sha256:" + hashlib.sha256(("gate-currentness:" + request["observation"]).encode()).hexdigest(),
       "normalized_preconditions": {BASIS_DIGEST!r}, "basis": BASIS, "resolver_id": {OBSERVATION_ID!r},
       "subject": request["subject"], "status": "current", "resolved_at_unix_ms": now,
       "fresh_until_unix_ms": now + window}}
sys.stdout.write(json.dumps(out, sort_keys=True, separators=(",", ":")) + "\\n")
'''.encode()

    def executor_program(self) -> bytes:
        return f'''#!{self.python} -IS
import hashlib, json, os, sys
def canonical(v): return json.dumps(v, sort_keys=True, separators=(",", ":")).encode()
def digest(b): return "sha256:" + hashlib.sha256(b).hexdigest()
if len(sys.argv) != 3 or sys.argv[1] not in ("plan-id", "execute", "reconcile"):
    raise SystemExit("usage: executor plan-id|execute|reconcile CONFIG")
op, config_path = sys.argv[1], sys.argv[2]
raw = open(config_path, "rb").read()
config = json.loads(raw)
if canonical(config) != raw.rstrip(b"\\n"):
    raise SystemExit("executor config is not canonical")
work = digest(canonical(config))
if op == "plan-id":
    print(work); raise SystemExit(0)
dispatch = json.loads(sys.stdin.buffer.read())
if set(dispatch) != {{"attempt", "marker", "work_schema", "work", "subject", "scope"}}:
    raise SystemExit("dispatch is not closed")
if (dispatch["work"], dispatch["work_schema"], dispatch["subject"], dispatch["scope"]) != (work, config["work_schema"], config["subject"], config["scope"]):
    raise SystemExit("dispatch differs from the sealed plan")
journal = os.path.join(config["journal"], dispatch["attempt"].split(":")[1] + ".json")
def emit(outcome, receipt):
    sys.stdout.write(canonical({{"attempt": dispatch["attempt"], "marker": dispatch["marker"], "outcome": outcome, "receipt": receipt}}).decode() + "\\n")
if os.path.exists(journal):
    record = json.load(open(journal))
    if record["marker"] != dispatch["marker"] or record["work"] != work:
        raise SystemExit("conflicting replay refused")
    if "outcome" in record:
        emit(record["outcome"], record["receipt"]); raise SystemExit(0)
    target_ok = os.path.exists(config["target"]) and open(config["target"], "rb").read() == config["content"].encode()
    emit("success" if target_ok else "indeterminate", digest(canonical({{"attempt": dispatch["attempt"], "recovered": target_ok}})))
    raise SystemExit(0)
if op == "reconcile":
    raise SystemExit("attempt evidence is absent")
fd = os.open(journal, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
os.write(fd, canonical({{"marker": dispatch["marker"], "work": work}})); os.fsync(fd); os.close(fd)
fd = os.open(config["target"], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
os.write(fd, config["content"].encode()); os.fsync(fd); os.close(fd)
receipt = digest(canonical({{"attempt": dispatch["attempt"], "target": config["target"], "content": digest(config["content"].encode())}}))
tmp = journal + ".new"
with open(tmp, "wb") as handle:
    handle.write(canonical({{"marker": dispatch["marker"], "work": work, "outcome": "success", "receipt": receipt}}))
os.replace(tmp, journal)
emit("success", receipt)
'''.encode()

    def ag_standing_enrollment(self, resolver: pathlib.Path, store: pathlib.Path, python_sha: str) -> bytes:
        return canonical({
            "schema": "ag.governed-loop.standing-launcher-enrollment/v1",
            "resolver_program": str(resolver), "resolver_sha256": sha(resolver.read_bytes()),
            "mandate_store": str(store), "resolver_id": STANDING_ID, "answer_ttl_ms": MAX_STANDING_TTL_MS,
            "python_interpreter": str(self.python), "python_sha256": python_sha,
        })

    def mandate_store(self, subject: str, scope: str, status: str = "active") -> bytes:
        return canonical({"schema": "ag.governed-loop.standing-mandate-store/v1", "mandates": [
            {"subject": subject, "scope": scope, "generation": 1, "status": status,
             "valid_until_unix_ms": now_ms() + 24 * 3600 * 1000}]})

    def sealer_argv(self, *rest):
        return [self.python, "-I", "-S", self.sealer, *rest]


# ---------------------------------------------------------------- cases
def case_ports(ctx: Ctx) -> dict:
    """Fresh ports: Docket standing launcher, AG sealed standing launcher, issuer key and trust."""
    # The driver creates the cohort state root (owned by the cohort account,
    # 0700, under root-owned ancestors); this case requires it empty.
    expect(ctx.root.is_dir() and not any(ctx.root.iterdir()), "state root must exist and be empty")
    expect(os.stat(ctx.root).st_uid == os.getuid() and os.stat(ctx.root).st_mode & 0o077 == 0, "state root ownership/mode")
    for directory in (ctx.ports, ctx.owner, ctx.work):
        directory.mkdir(mode=0o700)
    python_sha = sha(ctx.python.read_bytes())
    (ctx.ports / "docket-state").mkdir(mode=0o700)
    ctx.write(ctx.ports / "docket-standing-config.json", canonical({
        "schema": "docket.governed-loop.local-standing-resolver-config/v1",
        "state_database": str(ctx.ports / "docket-state/state.sqlite"), "operator": OPERATOR}))
    ctx.ok([ctx.docket, "governed-loop", "standing-write-launcher", "--resolver", ctx.docket_resolver,
            "--config", ctx.ports / "docket-standing-config.json", "--python-interpreter", ctx.python,
            "--output", ctx.ports / "docket-standing-launcher"])
    subject, scope = label_digest("subject"), label_digest("scope")
    ctx.write(ctx.ports / "ag-mandates.json", ctx.mandate_store(subject, scope))
    ctx.write(ctx.ports / "ag-standing-enrollment.json",
              ctx.ag_standing_enrollment(ctx.resolver, ctx.ports / "ag-mandates.json", python_sha))
    sealer = ctx.call(ctx.sealer_argv("--enrollment", ctx.ports / "ag-standing-enrollment.json",
                                      "--launcher", ctx.ports / "ag-standing-launcher",
                                      "--manifest", ctx.ports / "ag-standing-manifest.json"))
    expect(sealer[0] == 0, f"sealer failed: {sealer[2].decode()}")
    launcher = (ctx.ports / "ag-standing-launcher").read_bytes()
    manifest = json.loads((ctx.ports / "ag-standing-manifest.json").read_bytes())
    expect(launcher.startswith(f"#!{ctx.python} -IS\n".encode()), f"launcher shebang {launcher[:40]!r}")
    expect(manifest["launcher_sha256"] == sha(launcher) and manifest["python_sha256"] == python_sha
           and manifest["resolver_sha256"] == sha(ctx.resolver.read_bytes()), "launcher manifest differs")
    expect(oct(os.stat(ctx.ports / "ag-standing-launcher").st_mode & 0o777) == "0o500", "launcher mode")
    # Issuer key: fresh Ed25519 via OpenSSL, as the kit's prepare_local_ports does.
    ctx.ok([ctx.openssl, "genpkey", "-algorithm", "Ed25519", "-outform", "DER", "-out", ctx.ports / "issuer-seed.pk8"])
    os.chmod(ctx.ports / "issuer-seed.pk8", 0o600)
    public = ctx.ok([ctx.openssl, "pkey", "-inform", "DER", "-in", ctx.ports / "issuer-seed.pk8", "-pubout", "-outform", "DER"])
    seed = (ctx.ports / "issuer-seed.pk8").read_bytes()
    expect(len(seed) == 48 and len(public) == 44, "unexpected OpenSSL Ed25519 encoding")
    ctx.write(ctx.ports / "issuer.pk8", bytes.fromhex("3051020101300506032b657004220420") + seed[16:]
              + bytes.fromhex("812100") + public[12:])
    ctx.write(ctx.ports / "docket-trust.json", canonical({"issuers": [{"issuer_principal": ISSUER, "key_id": ISSUER_KEY_ID,
              "public_key": base64.urlsafe_b64encode(public[12:]).rstrip(b"=").decode()}]}))
    ctx.write(ctx.ports / "observation-resolver", ctx.observation_program(), 0o500)
    ctx.write(ctx.ports / "observation-window-ms", b"120000\n", 0o600)
    ctx.write(ctx.ports / "executor", ctx.executor_program(), 0o500)
    ctx.write(ctx.owner / "catalog.json", canonical({"schema": "ag.governed-loop.exact-work-catalog/v1", "entries": {
        WORK_SCHEMA: {"work_schema": WORK_SCHEMA, "subject": subject, "scope": scope,
                      "precondition": {"required": ["condition.clean"], "forbidden": []}}}}), 0o600)
    enrollment = {
        "schema": "ag.governed-loop.runtime-profile-enrollment/v1",
        "profile_label": "cohort-gate-ag-release",
        "observation_resolver": str(ctx.ports / "observation-resolver"),
        "observation_resolver_id": OBSERVATION_ID,
        "standing_resolver": str(ctx.ports / "ag-standing-launcher"),
        "standing_resolver_id": STANDING_ID,
        "max_standing_ttl_ms": MAX_STANDING_TTL_MS,
        "exact_work_catalog": str(ctx.owner / "catalog.json"),
        "controlling_review": None,
        "docket": {"schema": "ag.governed-loop.docket-root-enrollment/v1", "docket_program": str(ctx.docket),
                   "state_directory": str(ctx.ports / "docket-state"), "trust_config": str(ctx.ports / "docket-trust.json"),
                   "standing_resolver": str(ctx.ports / "docket-standing-launcher"),
                   "executor_adapter": str(ctx.ports / "executor"), "issuer_principal": ISSUER,
                   "issuer_key_id": ISSUER_KEY_ID, "issuer_key": str(ctx.ports / "issuer.pk8")},
        "human_verifier": None,
    }
    ctx.write(ctx.owner / "runtime-profile-enrollment.json", canonical(enrollment))
    return {"python_sha256": python_sha, "ag_standing_launcher_sha256": sha(launcher),
            "ag_standing_manifest": manifest, "docket_standing_launcher_sha256": sha((ctx.ports / "docket-standing-launcher").read_bytes()),
            "issuer_key_bytes": len((ctx.ports / "issuer.pk8").read_bytes()), "subject": subject, "scope": scope}


def case_profile(ctx: Ctx) -> dict:
    """Seal and verify the V1 runtime profile used by the spend chain."""
    profile = ctx.owner / "runtime-profile.json"
    seal = ctx.loop("seal-runtime-profile", "--enrollment", ctx.owner / "runtime-profile-enrollment.json", "--output", profile)
    verify = ctx.loop("verify-runtime-profile", "--runtime-profile", profile)
    expect(seal == verify, "verify receipt differs from seal receipt")
    expect(seal["profile_schema"] == "ag.governed-loop.runtime-profile/v1", "profile schema")
    expect(oct(os.stat(profile).st_mode & 0o777) == "0o600", "profile mode")
    body = profile.read_bytes()
    expect(b"PRIVATE" not in body and (ctx.ports / "issuer.pk8").read_bytes().hex() not in body.hex(), "profile carries key bytes")
    again = ctx.call([ctx.loopctl, "seal-runtime-profile", "--enrollment", ctx.owner / "runtime-profile-enrollment.json", "--output", profile])
    expect(again[0] != 0 and profile.read_bytes() == body, "sealing is not create-once")
    return {"seal_receipt": seal, "profile_sha256": sha(body), "reseal_refused": again[2].decode().strip()[-200:]}


def write_occurrence(ctx: Ctx, name: str) -> dict:
    """One synthetic occurrence: executor config, genesis and proposal."""
    directory = ctx.work / name
    directory.mkdir(mode=0o700)
    (directory / "journal").mkdir(mode=0o700)
    (directory / "target").mkdir(mode=0o700)
    subject, scope = label_digest("subject"), label_digest("scope")
    config = {"schema": "gate.synthetic-executor-config/v1", "work_schema": WORK_SCHEMA, "subject": subject,
              "scope": scope, "target": str(directory / "target/result.txt"),
              "content": f"synthetic gate effect {name}\n", "journal": str(directory / "journal")}
    ctx.write(directory / "executor-config.json", canonical(config))
    work = sha(canonical(config))
    campaign, program = label_digest(f"campaign-{name}"), label_digest(f"program-{name}")
    occurrence = str(uuid.uuid4())
    ctx.write(directory / "genesis.json", canonical({
        "campaign": campaign, "occurrence": occurrence, "program": program, "expected_ag_work": work,
        "residuals": [], "budget": {"retry_limit": 1, "retries_used": 0, "probe_limit": 1, "probes_used": 0,
                                    "escalation_limit": 1, "escalations_used": 0}}))
    ctx.write(directory / "proposal.json", canonical({
        "observation": label_digest(f"observation-{name}"),
        "proposal": {"schema": "ag.governed-loop.exact-work-proposal/v1", "campaign": campaign, "subject": subject,
                     "scope": scope, "work_schema": WORK_SCHEMA, "work": work, "repair": None},
        "class": "initial"}))
    return {"dir": directory, "work": work, "campaign": campaign, "program": program, "occurrence": occurrence,
            "subject": subject, "scope": scope, "db": directory / "ag.sqlite"}


def gate_args(ctx: Ctx) -> list:
    return ["--catalog", ctx.owner / "catalog.json", "--observation-resolver", ctx.ports / "observation-resolver",
            "--expected-observation-resolver-id", OBSERVATION_ID, "--standing-resolver", ctx.ports / "ag-standing-launcher",
            "--expected-standing-resolver-id", STANDING_ID, "--max-standing-ttl-ms", str(MAX_STANDING_TTL_MS)]


def docket_args(ctx: Ctx, occ: dict) -> list:
    return ["--docket", ctx.docket, "--docket-state", ctx.ports / "docket-state", "--docket-trust", ctx.ports / "docket-trust.json",
            "--docket-standing-resolver", ctx.ports / "docket-standing-launcher", "--executor", ctx.ports / "executor",
            "--executor-config", occ["dir"] / "executor-config.json", "--issuer-principal", ISSUER,
            "--issuer-key-id", ISSUER_KEY_ID, "--issuer-key", ctx.ports / "issuer.pk8"]


def grant(ctx: Ctx, occ: dict) -> str:
    issued = now_ms()
    out = ctx.ok([ctx.docket, "governed-loop", "standing-grant", "--state", ctx.ports / "docket-state",
                  "--operator", OPERATOR, "--campaign", occ["campaign"], "--occurrence", occ["occurrence"],
                  "--program", occ["program"], "--work-schema", WORK_SCHEMA, "--work", occ["work"],
                  "--subject", occ["subject"], "--scope", occ["scope"],
                  "--issued-at-unix-ms", str(issued), "--expires-at-unix-ms", str(issued + 300000)]).decode()
    return out.strip().split()[-1]


def spend(ctx: Ctx, occ: dict) -> dict:
    profile = ctx.owner / "runtime-profile.json"
    ctx.loop("init", "--database", occ["db"], "--genesis", occ["dir"] / "genesis.json", "--runtime-profile", profile)
    ctx.loop("record-proposal", "--database", occ["db"], "--input", occ["dir"] / "proposal.json",
             "--observation-resolver", ctx.ports / "observation-resolver", "--expected-observation-resolver-id", OBSERVATION_ID)
    ctx.loop("require-standing", "--database", occ["db"])
    ctx.loop("decide", "--database", occ["db"], *gate_args(ctx))
    before = now_ms()
    authorized = ctx.loop("authorize", "--database", occ["db"], *gate_args(ctx))
    return {"authorized": authorized, "authorized_after_ms": before}


def find_issuance(value):
    """Find the one AG issuance body in a JSON projection."""
    found = []
    def walk(node):
        if isinstance(node, dict):
            if node.get("schema") in ("ag.governed-loop.issuance/v1", "ag.governed-loop.issuance/v2"):
                found.append(node)
            for child in node.values():
                walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)
    walk(value)
    return found


def case_spend(ctx: Ctx) -> dict:
    """Cross-process spend -> Docket custody -> executor once -> settlement, all real binaries."""
    occ = write_occurrence(ctx, "main")
    standing = grant(ctx, occ)
    spent = spend(ctx, occ)
    issuances = find_issuance(spent["authorized"])
    expect(len(issuances) >= 1, "authorize did not expose the issuance")
    issuance = issuances[0]
    expect(issuance["schema"] == "ag.governed-loop.issuance/v2", f"minted {issuance['schema']}")
    expect(isinstance(issuance.get("not_after_unix_ms"), int), "no integer not_after_unix_ms")
    expect(issuance["not_after_unix_ms"] > spent["authorized_after_ms"], "not_after is not after the spend")
    expect(issuance["not_after_unix_ms"] <= now_ms() + MAX_STANDING_TTL_MS, "not_after exceeds the profile cap")
    dispatched = ctx.loop("dispatch", "--database", occ["db"], *docket_args(ctx, occ))
    target = occ["dir"] / "target/result.txt"
    expect(target.read_bytes() == f"synthetic gate effect main\n".encode(), "effect bytes differ")
    polled = ctx.loop("poll", "--database", occ["db"], *docket_args(ctx, occ))
    inspect = ctx.loop("inspect", "--database", occ["db"])
    history = ctx.loop("history", "--database", occ["db"])
    replay = ctx.loop("replay", "--database", occ["db"])
    (occ["dir"] / "inspect.json").write_bytes(canonical(inspect))
    (occ["dir"] / "history.json").write_bytes(canonical(history))
    return {"occurrence": occ["occurrence"], "work": occ["work"], "docket_standing": standing,
            "issuance": issuance, "dispatch": dispatched, "poll": polled, "replay": replay,
            "inspect": inspect, "history_kinds": [t.get("kind") for t in history.get("transitions", [])],
            "journal_files": sorted(p.name for p in (occ["dir"] / "journal").iterdir())}


def docket_record(ctx: Ctx, issuance: str):
    view = ctx.ok_json([ctx.docket, "governed-loop", "inspect", "--state", ctx.ports / "docket-state", "--issuance", issuance])
    expect(view.get("schema") == "docket.governed-loop.inspection/v1", f"unexpected Docket inspection {view}")
    return view.get("record")


def case_docket_view(ctx: Ctx) -> dict:
    """Docket's own record of the AG issuance (read-only inspect and standing snapshot)."""
    inspect = json.loads((ctx.work / "main/inspect.json").read_bytes())
    body = find_issuance(inspect)[0]
    record = docket_record(ctx, body["issuance"])
    expect(record is not None, "Docket has no record of the AG issuance")
    text = json.dumps(record)
    expect(body["spend"] in text or body["issuance"] in text, "Docket record does not name the AG issuance or spend")
    snapshot = ctx.ok_json([ctx.docket, "governed-loop", "standing-snapshot", "--state", ctx.ports / "docket-state",
                            "--issuance", body["issuance"]])
    expect(snapshot is not None, "no local standing snapshot retained with custody")
    return {"issuance": body["issuance"], "docket_record": record, "standing_snapshot": snapshot}


def case_issuance_law(ctx: Ctx) -> dict:
    """The minted v2 body recomputes under the v2 identity law (independent Python)."""
    history = json.loads((ctx.work / "main/history.json").read_bytes())
    inspect = json.loads((ctx.work / "main/inspect.json").read_bytes())
    bodies = find_issuance(history) + find_issuance(inspect)
    expect(bodies, "no issuance body in history or inspect")
    body = bodies[0]
    expect(body["schema"] == "ag.governed-loop.issuance/v2", "not v2")
    text = json.dumps(history) + json.dumps(inspect)
    basis = {k: v for k, v in body.items() if k not in ("schema", "issuance")}
    recomputed = ag_domain_digest("ag.governed-loop.issuance/v2", canonical(basis))
    expect(recomputed == body["issuance"], f"v2 identity law differs: {recomputed} != {body['issuance']}")
    expect("not_after_unix_ms" in basis, "identity basis lacks not_after")
    without = {k: v for k, v in basis.items() if k != "not_after_unix_ms"}
    expect(ag_domain_digest("ag.governed-loop.issuance/v2", canonical(without)) != recomputed, "not_after not committed")
    return {"issuance_body": body, "recomputed_identity": recomputed, "not_after_committed": True}


def case_expired(ctx: Ctx) -> dict:
    """An issuance past its not-after is never presented; Docket holds nothing for it."""
    (ctx.ports / "observation-window-ms").unlink()
    ctx.write(ctx.ports / "observation-window-ms", b"2500\n")
    try:
        occ = write_occurrence(ctx, "expired")
        grant(ctx, occ)
        spent = spend(ctx, occ)
    finally:
        (ctx.ports / "observation-window-ms").unlink()
        ctx.write(ctx.ports / "observation-window-ms", b"120000\n")
    issuance = find_issuance(spent["authorized"])[0]
    expect(issuance["schema"] == "ag.governed-loop.issuance/v2", "not v2")
    wait = issuance["not_after_unix_ms"] - now_ms()
    expect(wait < 3000, f"not_after is not the short observation window: {wait} ms left")
    time.sleep(max(0, wait) / 1000 + 0.5)
    code, out, err = ctx.call([ctx.loopctl, "dispatch", "--database", occ["db"], *docket_args(ctx, occ)])
    after = ctx.loop("inspect", "--database", occ["db"])
    expect(not (occ["dir"] / "target/result.txt").exists(), "an expired issuance produced an effect")
    expect(not any((occ["dir"] / "journal").iterdir()), "the executor was invoked")
    expect(docket_record(ctx, issuance["issuance"]) is None, "Docket holds custody for the expired issuance")
    text = (out + err).decode(errors="replace")
    # Present the AG-minted expired issuance to Docket directly, signed with the
    # enrolled issuer key (Ed25519 over prefix || JCS body, via OpenSSL).
    body_bytes = canonical(issuance)
    message = ctx.work / "expired/signed-message.bin"
    ctx.write(message, b"ag-ng\0governed-loop-issuance-signature\0v1\0" + body_bytes)
    signature = ctx.ok([ctx.openssl, "pkeyutl", "-sign", "-rawin", "-inkey", ctx.ports / "issuer-seed.pk8",
                        "-keyform", "DER", "-in", message])
    trust = json.loads((ctx.ports / "docket-trust.json").read_bytes())["issuers"][0]
    envelope = canonical({"schema": "ag.governed-loop.signed-issuance/v1",
                          "body_b64": base64.urlsafe_b64encode(body_bytes).rstrip(b"=").decode(),
                          "authentication": {"issuer_principal": ISSUER, "signer_key_id": ISSUER_KEY_ID,
                                             "signer_public_key": trust["public_key"],
                                             "signature": base64.urlsafe_b64encode(signature).rstrip(b"=").decode()}})
    direct = ctx.call([ctx.docket, "governed-loop", "accept", "--state", ctx.ports / "docket-state",
                       "--trust", ctx.ports / "docket-trust.json", "--standing-resolver", ctx.ports / "docket-standing-launcher",
                       "--executor", ctx.ports / "executor", "--executor-config", occ["dir"] / "executor-config.json"], stdin=envelope)
    direct_text = (direct[1] + direct[2]).decode(errors="replace")
    expect(direct[0] != 0 and "governed-issuance-expired" in direct_text, f"Docket did not refuse as expired: {direct_text[-400:]}")
    expect(docket_record(ctx, issuance["issuance"]) is None, "Docket persisted custody for a refused expired issuance")
    expect(not (occ["dir"] / "target/result.txt").exists(), "direct presentation produced an effect")
    expect("issuance_not_current" in text.lower() or "not current" in text.lower() or "not_after" in text.lower()
           or "expired" in text.lower(), f"dispatch did not report a typed expiry: exit {code}: {text[-600:]}")
    return {"not_after_unix_ms": issuance["not_after_unix_ms"], "dispatch_exit": code,
            "dispatch_output": text[-800:], "docket_direct_refusal": direct_text.strip()[-300:], "program_counter_after": after["current"].get("program_counter")
            if isinstance(after.get("current"), dict) else None, "docket_custody": "absent", "executor_invoked": False}


def case_refuse_profile(ctx: Ctx) -> dict:
    """A tampered profile and a tampered pinned component are refused."""
    profile = ctx.owner / "runtime-profile.json"
    sealed = ctx.loop("verify-runtime-profile", "--runtime-profile", profile)["profile_digest"]
    observed = {}
    # Rewritten content is a different profile identity; enrollment by digest catches it.
    body = json.loads(profile.read_bytes())
    body["max_standing_ttl_ms"] = body["max_standing_ttl_ms"] + 1
    ctx.write(ctx.work / "profile-widened.json", canonical(body))
    widened = ctx.call([ctx.loopctl, "verify-runtime-profile", "--runtime-profile", ctx.work / "profile-widened.json"])
    widened_digest = json.loads(widened[1])["profile_digest"] if widened[0] == 0 else None
    expect(widened_digest != sealed, "a rewritten profile kept the sealed identity")
    observed["rewritten_profile_digest_differs"] = {"sealed": sealed, "rewritten": widened_digest}
    # Non-canonical bytes are refused outright.
    raw = profile.read_bytes()
    index = raw.index(b'"observation_resolver_id"')
    ctx.write(ctx.work / "profile-noncanonical.json", raw[:index] + b" " + raw[index:])
    code, _, err = ctx.call([ctx.loopctl, "verify-runtime-profile", "--runtime-profile", ctx.work / "profile-noncanonical.json"])
    expect(code != 0, "non-canonical profile bytes accepted")
    observed["noncanonical_profile"] = err.decode().strip()[-300:]
    code, _, err = ctx.call([ctx.loopctl, "init", "--database", ctx.work / "noncanonical.sqlite",
                             "--genesis", ctx.work / "main/genesis.json", "--runtime-profile", ctx.work / "profile-noncanonical.json"])
    expect(code != 0 and not (ctx.work / "noncanonical.sqlite").exists(), "init accepted non-canonical profile")
    # A pinned component changed after sealing: verify refuses and so does init.
    catalog = ctx.owner / "catalog.json"
    original = catalog.read_bytes()
    catalog.write_bytes(original.replace(b'"required":["condition.clean"]', b'"required":[]'))
    try:
        code, _, err = ctx.call([ctx.loopctl, "verify-runtime-profile", "--runtime-profile", profile])
        expect(code != 0 and b"identity changed" in err, f"tampered catalog accepted: {err[-300:]!r}")
        observed["tampered_catalog_verify"] = err.decode().strip()[-300:]
        occ = write_occurrence(ctx, "tampered-catalog")
        code, _, err = ctx.call([ctx.loopctl, "init", "--database", occ["db"], "--genesis", occ["dir"] / "genesis.json",
                                 "--runtime-profile", profile])
        expect(code != 0 and not occ["db"].exists(), "init accepted a profile whose catalog changed")
        observed["tampered_catalog_init"] = err.decode().strip()[-300:]
    finally:
        catalog.write_bytes(original)
    expect(ctx.call([ctx.loopctl, "verify-runtime-profile", "--runtime-profile", profile])[0] == 0,
           "restored profile does not verify")
    return observed


def case_refuse_launcher(ctx: Ctx) -> dict:
    """A tampered standing launcher, and a tampered resolver behind a sealed launcher, are refused."""
    observed = {}
    launcher = ctx.ports / "ag-standing-launcher"
    original = launcher.read_bytes()
    os.chmod(launcher, 0o700)
    launcher.write_bytes(original + b"# tampered\n")
    os.chmod(launcher, 0o500)
    try:
        code, _, err = ctx.call([ctx.loopctl, "verify-runtime-profile", "--runtime-profile", ctx.owner / "runtime-profile.json"])
        expect(code != 0 and b"identity changed" in err, f"tampered launcher accepted by verify: {err[-300:]!r}")
        observed["verify"] = err.decode().strip()[-300:]
        occ = write_occurrence(ctx, "tampered-launcher")
        profile = ctx.owner / "runtime-profile.json"
        code, _, err = ctx.call([ctx.loopctl, "init", "--database", occ["db"], "--genesis", occ["dir"] / "genesis.json",
                                 "--runtime-profile", profile])
        expect(code != 0 and not occ["db"].exists(), "init accepted a profile with a tampered launcher")
        observed["init"] = err.decode().strip()[-300:]
    finally:
        os.chmod(launcher, 0o700)
        launcher.write_bytes(original)
        os.chmod(launcher, 0o500)
    # A launcher sealed over a resolver copy refuses once that copy changes.
    side = ctx.work / "resolver-copy"
    side.mkdir(mode=0o700)
    copy = side / "ag-standing-resolver"
    shutil.copyfile(ctx.resolver, copy)
    os.chmod(copy, 0o700)
    store = side / "mandates.json"
    ctx.write(store, ctx.mandate_store(label_digest("subject"), label_digest("scope")))
    ctx.write(side / "enrollment.json", ctx.ag_standing_enrollment(copy, store, sha(ctx.python.read_bytes())))
    ctx.ok(ctx.sealer_argv("--enrollment", side / "enrollment.json", "--launcher", side / "launcher", "--manifest", side / "manifest.json"))
    request = canonical({"schema": "ag.governed-loop.standing-request/v1",
                         "key": {"campaign": label_digest("c"), "occurrence": str(uuid.uuid4())},
                         "observation": label_digest("o"), "proposal": label_digest("p"),
                         "subject": label_digest("subject"), "scope": label_digest("scope"), "now_unix_ms": now_ms()})
    answer = ctx.ok_json([side / "launcher"], stdin=request)
    expect(answer.get("status") == "current", f"sealed launcher did not answer current: {answer}")
    observed["sealed_answer_status"] = answer["status"]
    with copy.open("ab") as handle:
        handle.write(b"\0")
    code, _, err = ctx.call([side / "launcher"], stdin=request)
    expect(code != 0 and b"digest mismatch" in err, f"tampered resolver ran: {code} {err[-300:]!r}")
    observed["tampered_resolver"] = err.decode().strip()[-200:]
    code, _, err = ctx.call([side / "launcher", "--mandate-store", "/etc/passwd"], stdin=request)
    expect(code != 0 and b"accepts no arguments" in err, "launcher accepted arguments")
    observed["arguments_refused"] = err.decode().strip()[-200:]
    return observed


def case_refuse_interpreter(ctx: Ctx) -> dict:
    """A wrong interpreter hash (and a wrong resolver hash) make the sealer refuse and write nothing."""
    side = ctx.work / "wrong-interpreter"
    side.mkdir(mode=0o700)
    good = json.loads(ctx.ag_standing_enrollment(ctx.resolver, side / "mandates.json", sha(ctx.python.read_bytes())))
    observed = {}
    for name, field, value in (("python", "python_sha256", "sha256:" + "0" * 64),
                               ("resolver", "resolver_sha256", "sha256:" + "1" * 64)):
        bad = dict(good, **{field: value})
        ctx.write(side / f"{name}.json", canonical(bad))
        code, _, err = ctx.call(ctx.sealer_argv("--enrollment", side / f"{name}.json", "--launcher", side / f"{name}-launcher",
                                                "--manifest", side / f"{name}-manifest.json"))
        expect(code != 0 and b"digest mismatch" in err, f"{name}: wrong hash accepted: {err[-300:]!r}")
        expect(not (side / f"{name}-launcher").exists() and not (side / f"{name}-manifest.json").exists(), f"{name}: output written")
        observed[name] = err.decode().strip().splitlines()[-1]
    other = dict(good, python_interpreter="/usr/bin/python3")
    ctx.write(side / "symlink.json", canonical(other))
    code, _, err = ctx.call(ctx.sealer_argv("--enrollment", side / "symlink.json", "--launcher", side / "s-launcher",
                                            "--manifest", side / "s-manifest.json"))
    expect(code != 0, "symlinked interpreter path accepted")
    observed["symlinked_interpreter"] = err.decode().strip().splitlines()[-1]
    return observed


def case_v2_profile(ctx: Ctx) -> dict:
    """V2 profile seal, verify and init-v2 over synthetic stand-in ports (the cohort's schema)."""
    v2 = ctx.root / "v2"
    v2.mkdir(mode=0o700)
    stand_in = f"#!{ctx.python} -IS\nraise SystemExit('synthetic stand-in; not invoked by this case')\n".encode()
    for name in ("nightshift", "plan-validator", "review-verifier", "nq"):
        ctx.write(v2 / name, stand_in.replace(b"stand-in", f"stand-in {name}".encode()), 0o500)
    ctx.write(v2 / "nq-config.toml", b"# synthetic\n")
    ctx.write(v2 / "validator-config.json", canonical({"schema": "gate.synthetic-validator-config/v1"}))
    ctx.write(v2 / "review-verifier-config.json", canonical({"schema": "gate.synthetic-review-route/v1", "reviewer": "fixture"}))
    route = sha((v2 / "review-verifier-config.json").read_bytes())
    ctx.write(v2 / "review-requirement.json", canonical({"schema": "ag.governed-loop.review-requirement/v1",
              "reviewer_id": "cohort-gate-independent-reviewer", "route_enrollment_digest": route,
              "compiler_contract": "gate.synthetic-compiler/v1", "max_age_ms": 600000}))
    requirement = sha((v2 / "review-requirement.json").read_bytes())
    def pin(path):
        return {"path": str(path), "sha256": sha(path.read_bytes())}
    ctx.write(v2 / "nightshift-config.json", canonical({
        "schema": "nightshift.ag_cycle_config.v1", "store": str(v2 / "nightshift.sqlite"),
        "present_evidence_resolver": pin(v2 / "nightshift"), "nq_program": pin(v2 / "nq"),
        "nq_config": pin(v2 / "nq-config.toml"), "nq_source_id": "host:cohort-gate-host",
        "ag_loopctl": pin(ctx.loopctl), "ag_database": str(v2 / "ag.sqlite"),
        "ag_observation_resolver": pin(ctx.ports / "observation-resolver"), "ag_observation_resolver_id": OBSERVATION_ID,
        "ag_runtime_profile": str(v2 / "runtime-profile.json"), "shared_admission_requirement_digest": requirement,
        "recover_observed_at": "2026-09-25T00:00:00Z"}))
    base = json.loads((ctx.owner / "runtime-profile-enrollment.json").read_bytes())
    enrollment = dict(base, schema="ag.governed-loop.runtime-profile-enrollment/v2",
                      nightshift_cycle={"schema": "ag.governed-loop.nightshift-cycle-port/v1", "program": str(v2 / "nightshift"),
                                        "config": str(v2 / "nightshift-config.json")},
                      shared_admission={"schema": "ag.governed-loop.shared-admission/v1",
                                        "plan_binding_schema": "maude.governed-plan-binding/v1",
                                        "compiler_contract": "gate.synthetic-compiler/v1",
                                        "plan_validator": str(v2 / "plan-validator"),
                                        "plan_validator_config": str(v2 / "validator-config.json"),
                                        "review_verifier": str(v2 / "review-verifier"),
                                        "review_verifier_config": str(v2 / "review-verifier-config.json"),
                                        "review_requirement": str(v2 / "review-requirement.json")})
    ctx.write(v2 / "enrollment-v2.json", canonical(enrollment))
    profile = v2 / "runtime-profile.json"
    seal = ctx.loop("seal-runtime-profile-v2", "--enrollment", v2 / "enrollment-v2.json", "--output", profile)
    verify = ctx.loop("verify-runtime-profile-v2", "--runtime-profile", profile)
    expect(seal == verify, "v2 verify differs from seal")
    code, _, err = ctx.call([ctx.loopctl, "verify-runtime-profile", "--runtime-profile", profile])
    expect(code != 0, "a V2 profile verified as V1")
    occ = write_occurrence(ctx, "v2")
    ctx.loop("init-v2", "--database", v2 / "ag.sqlite", "--genesis", occ["dir"] / "genesis.json", "--runtime-profile", profile)
    inspect = ctx.loop("inspect", "--database", v2 / "ag.sqlite")
    expect(inspect["runtime_profile"]["schema"] == "ag.governed-loop.runtime-profile/v2"
           and inspect["runtime_profile"]["digest"] == seal["profile_digest"], "v2 store binding differs")
    # Tampered requirement: v2 verification refuses.
    requirement_path = v2 / "review-requirement.json"
    original = requirement_path.read_bytes()
    requirement_path.write_bytes(original.replace(b"600000", b"600001"))
    code, _, err = ctx.call([ctx.loopctl, "verify-runtime-profile-v2", "--runtime-profile", profile])
    requirement_path.write_bytes(original)
    expect(code != 0 and b"identity changed" in err, f"tampered v2 requirement accepted: {err[-300:]!r}")
    return {"seal_receipt": seal, "v1_verify_of_v2_refused": True, "inspect_runtime_profile": inspect["runtime_profile"],
            "tampered_requirement": err.decode().strip()[-200:]}


def settled_view(inspect: dict) -> dict:
    """The evidence-join fields of a settled occurrence in `ag-loopctl inspect`."""
    state = inspect["current"]["state"]
    expect(len(state) == 1, "state is not one tagged variant")
    (variant, body), = state.items()
    dispatch = body["dispatch"]
    return {
        "variant": variant,
        "campaign": dispatch["authorized"]["spend"]["key"]["campaign"],
        "occurrence": dispatch["authorized"]["spend"]["key"]["occurrence"],
        "issuance": dispatch["authorized"]["issuance"]["issuance"],
        "issuance_schema": dispatch["authorized"]["issuance"]["schema"],
        "not_after_unix_ms": dispatch["authorized"]["issuance"]["not_after_unix_ms"],
        "spend": dispatch["authorized"]["spend"]["spend"],
        "custody_attempt": dispatch["custody"]["attempt"],
        "settlement": body["settlement"]["settlement"],
        "settlement_outcome": body["settlement"]["outcome"],
        "state_digest": inspect["current"]["state_digest"],
        "runtime_profile_digest": inspect["runtime_profile"]["digest"],
    }


def case_join(ctx: Ctx) -> dict:
    """`inspect` exposes occurrence, issuance, spend and settlement digests that join to Docket's record."""
    inspect = json.loads((ctx.work / "main/inspect.json").read_bytes())
    view = settled_view(inspect)
    expect(view["variant"] == "settled_observation_required", f"unexpected settled variant {view['variant']}")
    expect(view["settlement_outcome"] == "success", "settlement is not success")
    body = find_issuance(inspect)[0]
    expect(body["spend"] == view["spend"] and body["key"]["occurrence"] == view["occurrence"], "issuance does not bind the spend/occurrence")
    record = docket_record(ctx, view["issuance"])
    expect(record is not None and record.get("status") == "settled", f"Docket record not settled: {record}")
    text = json.dumps(record)
    for field in ("issuance", "spend", "custody_attempt", "settlement"):
        expect(view[field] in text, f"Docket record does not carry AG {field} {view[field]}")
    replay = inspect["replay"]
    expect(replay["current_state_digest"] == view["state_digest"] and replay["ag_spends"] == 1
           and replay["docket_attempts"] == 1 and replay["settlements"] == 1, f"replay counts {replay}")
    return {"join": view, "docket_status": record.get("status"),
            "paths": {"occurrence": "current.state.<variant>.dispatch.authorized.spend.key.occurrence",
                      "issuance": "current.state.<variant>.dispatch.authorized.issuance.issuance",
                      "spend": "current.state.<variant>.dispatch.authorized.spend.spend",
                      "settlement": "current.state.<variant>.settlement.settlement"}}


def case_python_origin(ctx: Ctx) -> dict:
    """Sealer and launcher modules load only from the interpreter's standard library under -I -S."""
    probe = (
        "import atexit, json, runpy, sys\n"
        "def dump():\n"
        "    files = sorted({getattr(m, '__file__', None) or '<builtin>' for m in list(sys.modules.values())})\n"
        "    sys.__stdout__.write(json.dumps({'path': sys.path, 'files': files, 'flags': [sys.flags.isolated, sys.flags.no_site]}) + '\\n')\n"
        "atexit.register(dump)\n"
        "sys.argv = [sys.argv[1], '--help']\n"
        "import io, contextlib\n"
        "with contextlib.redirect_stdout(io.StringIO()):\n"
        "    try:\n"
        "        runpy.run_path(sys.argv[0], run_name='__main__')\n"
        "    except SystemExit:\n"
        "        pass\n"
    )
    out = json.loads(ctx.ok([ctx.python, "-I", "-S", "-c", probe, ctx.sealer]).decode().strip().splitlines()[-1])
    stdlib = str(pathlib.Path(ctx.python).resolve().parent.parent / "lib" / pathlib.Path(ctx.python).resolve().name)
    outside = [f for f in out["files"] if f != "<builtin>" and not f.startswith(stdlib + "/") and f != str(ctx.sealer)]
    expect(not outside, f"sealer loaded modules outside the standard library: {outside}")
    expect(out["flags"] == [1, 1], f"flags {out['flags']}")
    expect(not any("packages" in p for p in out["path"]), f"site directory on sys.path: {out['path']}")
    launcher_imports = "import fcntl, hashlib, os, stat, sys, json; print(json.dumps(sorted({getattr(m, '__file__', None) or '<builtin>' for m in sys.modules.values()})))"
    first = (ctx.ports / "ag-standing-launcher").read_bytes().splitlines()[0].decode()
    flags = first.split()[1:]
    files = json.loads(ctx.ok([ctx.python, *flags, "-c", launcher_imports]))
    outside_l = [f for f in files if f != "<builtin>" and not f.startswith(stdlib + "/")]
    expect(not outside_l, f"launcher modules outside the standard library: {outside_l}")
    return {"stdlib": stdlib, "sealer_modules": len(out["files"]), "sealer_sys_path": out["path"],
            "launcher_shebang": first, "launcher_modules": files}


def case_operator_ui(ctx: Ctx) -> dict:
    """The optional release ag-operator-ui serves the settled campaign read-only on loopback only."""
    ui = ctx.prefix / "bin/ag-operator-ui"
    refused = ctx.call([ui, "--campaign-root", ctx.work / "main", "--ag-loopctl", ctx.loopctl, "--bind", "0.0.0.0:18417"])
    expect(refused[0] != 0 and b"loopback" in refused[2], "non-loopback bind accepted")
    import urllib.request, urllib.error
    process = subprocess.Popen([str(ui), "--campaign-root", str(ctx.work / "main"), "--ag-loopctl", str(ctx.loopctl),
                                "--docket-bin", str(ctx.docket), "--docket-state", str(ctx.ports / "docket-state"),
                                "--bind", "127.0.0.1:18417"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        body = None
        for _ in range(50):
            try:
                with urllib.request.urlopen("http://127.0.0.1:18417/api/v1/campaigns", timeout=2) as response:
                    body = json.loads(response.read())
                break
            except (urllib.error.URLError, ConnectionError):
                time.sleep(0.2)
        expect(body is not None, "operator UI did not answer")
        inspect = json.loads((ctx.work / "main/inspect.json").read_bytes())
        campaign = settled_view(inspect)["campaign"]
        expect(campaign in json.dumps(body), "campaign index lacks the settled campaign")
        request = urllib.request.Request("http://127.0.0.1:18417/api/v1/campaigns", data=b"{}", method="POST")
        try:
            urllib.request.urlopen(request, timeout=2)
            posted = "accepted"
        except urllib.error.HTTPError as error:
            posted = error.code
        expect(posted != "accepted", "POST accepted")
    finally:
        process.terminate()
        process.wait(timeout=10)
    return {"non_loopback": refused[2].decode().strip()[-120:], "index": body, "post_status": posted}


READ_ONLY_COMMANDS = ("inspect", "replay", "history", "status", "refusals")


def read_only_outputs(ctx: Ctx, database: pathlib.Path) -> dict:
    return {command: ctx.call([ctx.loopctl, command, "--database", database]) for command in READ_ONLY_COMMANDS}


def case_keyless_inspect(ctx: Ctx) -> dict:
    """G3 D-1: read-only commands verify V1 and V2 campaigns without the issuer private key."""
    key = ctx.ports / "issuer.pk8"
    aside = ctx.root / "issuer.pk8.withheld"
    v2 = ctx.root / "v2"
    databases = {"v1-settled": ctx.work / "main/ag.sqlite", "v2": v2 / "ag.sqlite"}
    baseline = {}
    for label, database in databases.items():
        outputs = read_only_outputs(ctx, database)
        for command, (code, out, err) in outputs.items():
            expect(code == 0 and out and not err, f"{label} {command} with the key: exit {code}: {err[-300:]!r}")
        baseline[label] = {command: out for command, (_, out, _) in outputs.items()}
    digests = {label: json.loads(out["inspect"])["current"]["state_digest"] for label, out in baseline.items()}
    observed: dict = {"state_digest": digests}
    os.rename(key, aside)
    try:
        expect(not key.exists(), "issuer key still present")
        for label, database in databases.items():
            for command, (code, out, err) in read_only_outputs(ctx, database).items():
                expect(code == 0 and out == baseline[label][command] and not err,
                       f"keyless {label} {command}: exit {code}: {err[-300:]!r}")
        observed["keyless_reads"] = {label: list(READ_ONLY_COMMANDS) for label in databases}
        # Mutating and live-verification paths still require the key.
        refusals = {}
        for name, argv in (("require-standing", ["require-standing", "--database", databases["v2"]]),
                           ("verify-runtime-profile-v2", ["verify-runtime-profile-v2", "--runtime-profile",
                                                          v2 / "runtime-profile.json"])):
            code, _, err = ctx.call([ctx.loopctl, *argv])
            expect(code != 0 and b"No such file" in err, f"{name} without the key: exit {code}: {err[-300:]!r}")
            refusals[name] = err.decode().strip()[-160:]
        observed["mutating_refused_without_key"] = refusals
        # Tampered public issuer material refuses as a mismatch.
        trust = ctx.ports / "docket-trust.json"
        original = trust.read_bytes()
        tampered = json.loads(original)
        tampered["issuers"][0]["public_key"] = base64.urlsafe_b64encode(bytes(32)).rstrip(b"=").decode()
        trust.write_bytes(canonical(tampered))
        try:
            for command, (code, out, err) in read_only_outputs(ctx, databases["v2"]).items():
                expect(code == 1 and not out and b"pinned file identity changed" in err,
                       f"tampered trust {command}: exit {code}: {err[-300:]!r}")
        finally:
            trust.write_bytes(original)
        observed["tampered_trust"] = "refused (exit 1, pinned file identity changed)"
        # Tampered state refuses.
        copy = v2 / "tampered.sqlite"
        body = databases["v2"].read_bytes()
        program = label_digest("program-v2").encode()
        expect(program in body, "program digest not found in the V2 store")
        copy.write_bytes(body.replace(program, label_digest("program-tampered").encode()))
        for command, (code, out, err) in read_only_outputs(ctx, copy).items():
            expect(code == 1 and not out, f"tampered state {command}: exit {code}: {err[-300:]!r}")
        observed["tampered_state"] = err.decode().strip()[-160:]
        # An absent enrolled file is reported typed; the read still verifies the rest.
        validator = v2 / "plan-validator"
        withheld = v2 / "plan-validator.withheld"
        os.rename(validator, withheld)
        try:
            for command, (code, out, err) in read_only_outputs(ctx, databases["v2"]).items():
                expect(code == 3 and out == baseline["v2"][command], f"unavailable {command}: exit {code}: {err[-300:]!r}")
                prefix = b"enrolled file unavailable: "
                expect(err.startswith(prefix), f"untyped diagnostic: {err[-300:]!r}")
                report = json.loads(err[len(prefix):])
                expect(report["schema"] == "ag.governed-loop.read-only-verification/v1"
                       and report["status"] == "enrolled-file-unavailable"
                       and [entry["path"] for entry in report["unavailable"]] == [str(validator)],
                       f"unavailable report {report}")
        finally:
            os.rename(withheld, validator)
        observed["unavailable_report"] = report
    finally:
        os.rename(aside, key)
    return observed


CASES = {
    "ports": case_ports, "profile": case_profile, "spend": case_spend, "docket-view": case_docket_view,
    "issuance-law": case_issuance_law, "expired": case_expired, "refuse-profile": case_refuse_profile,
    "refuse-launcher": case_refuse_launcher, "refuse-interpreter": case_refuse_interpreter, "v2-profile": case_v2_profile, "join": case_join,
    "python-origin": case_python_origin, "operator-ui": case_operator_ui, "keyless-inspect": case_keyless_inspect,
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--case", required=True, choices=sorted(CASES))
    parser.add_argument("--ag-prefix", required=True)
    parser.add_argument("--docket-bin", required=True)
    parser.add_argument("--root", required=True)
    parser.add_argument("--python", default="/usr/bin/python3.11")
    parser.add_argument("--openssl", default="/usr/bin/openssl")
    args = parser.parse_args()
    try:
        observed = CASES[args.case](Ctx(args))
    except Fail as error:
        print(json.dumps({"result": "FAIL", "case": args.case, "error": str(error)}))
        return 1
    print(json.dumps({"result": "PASS", "case": args.case, "observed": observed}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
