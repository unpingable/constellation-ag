#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compose the public saved-check example with Maude and Phosphor read views."""
import argparse
import hashlib
import json
import os
import selectors
import signal
import socket
import stat
import subprocess
import threading
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

MAX_STREAM = 1_048_576
MAX_HTTP = 2_097_152
MAX_ROOT = 67_108_864

def save(path, value):
    with path.open("x", encoding="ascii") as stream:
        json.dump(value, stream, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        stream.write("\n")


def sha(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            result.update(block)
    return "sha256:" + result.hexdigest()


def parse_json(raw):
    return json.loads(raw.decode("ascii"))


class RefuseRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


HTTP_OPENER = urllib.request.build_opener(
    urllib.request.ProxyHandler({}),
    RefuseRedirect(),
)

def invoke(log, label, argv, timeout=30):
    with log.open("a",encoding="ascii") as f:
        f.write(json.dumps({"event":"planned","label":label,
                            "argv":[str(x) for x in argv],"timeout_seconds":timeout},sort_keys=True)+"\n")
    p=subprocess.Popen([str(x) for x in argv],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,env={"PATH":"/usr/bin:/bin","LANG":"C.UTF-8"})
    with log.open("a",encoding="ascii") as f:
        f.write(json.dumps({"event":"started","label":label,"pid":p.pid,
                            "argv":[str(x) for x in argv]},sort_keys=True)+"\n")
    data = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + timeout
    error = None
    try:
        with selectors.DefaultSelector() as s:
            s.register(p.stdout, selectors.EVENT_READ, "stdout")
            s.register(p.stderr, selectors.EVENT_READ, "stderr")
            while s.get_map():
                if time.monotonic() >= deadline:
                    raise RuntimeError(label + ": timeout; inspect retained root")
                for key,_ in s.select(.1):
                    b=os.read(key.fileobj.fileno(),8192)
                    if not b:
                        s.unregister(key.fileobj)
                    elif sum(map(len, data.values())) + len(b) > MAX_STREAM:
                        raise RuntimeError(label + ": output limit")
                    else:
                        data[key.data].extend(b)
        p.wait(timeout=max(.01,deadline-time.monotonic()))
        if p.returncode:
            raise RuntimeError(f"{label}: exit {p.returncode}")
    except BaseException as caught:
        error = caught
    finally:
        try: os.killpg(p.pid,signal.SIGKILL)
        except ProcessLookupError:
            pass
        p.wait()
        p.stdout.close()
        p.stderr.close()
        with log.open("a",encoding="ascii") as f:
            f.write(json.dumps({"event":"terminal","label":label,"pid":p.pid,
                                "exit_code":p.returncode,"error":None if error is None else str(error),
                                "stdout":data["stdout"].decode("ascii",errors="replace"),
                                "stderr":data["stderr"].decode("ascii",errors="replace")},sort_keys=True)+"\n")
    if error:
        raise error
    return parse_json(bytes(data["stdout"])) if data["stdout"] else None

def root_bytes(root):
    return sum(path.stat().st_size for path in root.rglob("*") if path.is_file())

def executable(path, basename):
    if not path.is_absolute() or path.name != basename:
        raise ValueError(f"{basename} must be an absolute path with the exact basename")
    info=path.stat()
    if not stat.S_ISREG(info.st_mode) or not info.st_mode & 0o111:
        raise ValueError(f"{basename} must be a regular executable")

def validate_views(fresh, stale, objective, evaluation_id):
    for view in (fresh, stale):
        if view.get("schema") != "phosphor-ng.objective-detail/v2":
            raise RuntimeError("wrong objective schema")
        authored = view.get("objective", {})
        available = authored.get("availability") == "available"
        if authored.get("schema") != "maude.objective-source/v1" or not available:
            raise RuntimeError("authored source unavailable")
        if authored.get("plan_digest") != objective["plan_digest"]:
            raise RuntimeError("plan mismatch")
        if view.get("occurrences") != []:
            raise RuntimeError("unexpected occurrence")
        if len(view.get("conditions", [])) != 2:
            raise RuntimeError("condition count mismatch")
        expected_ids = [item["condition_id"] for item in objective["acceptance_criteria"]]
        actual_ids = [item.get("condition_id") for item in view["conditions"]]
        if actual_ids != expected_ids:
            raise RuntimeError("condition identity mismatch")
        if view["conditions"][1].get("disposition") != "unknown":
            raise RuntimeError("unmapped criterion changed")
        declared = view.get("prerequisites", {}).get("owner_declared", {})
        if declared.get("coverage") != "owner_asserted_complete":
            raise RuntimeError("prerequisite mismatch")
        if len(declared.get("items", [])) != 1:
            raise RuntimeError("prerequisite mismatch")
    first = fresh["conditions"][0]
    second = stale["conditions"][0]
    if first.get("disposition") != "not_satisfied":
        raise RuntimeError("fresh assessment mismatch")
    if second.get("disposition") != "indeterminate":
        raise RuntimeError("stale assessment mismatch")
    fresh_evidence = first.get("evidence", [])
    stale_evidence = second.get("evidence", [])
    if len(fresh_evidence) != 1 or len(stale_evidence) != 1:
        raise RuntimeError("evidence count mismatch")
    if fresh_evidence[0].get("owner_outcome") != "failed":
        raise RuntimeError("owner outcome changed")
    if stale_evidence[0].get("owner_outcome") != "failed":
        raise RuntimeError("owner outcome changed")
    if fresh_evidence[0].get("source_currentness") != "fresh":
        raise RuntimeError("fresh currentness mismatch")
    if stale_evidence[0].get("source_currentness") != "stale":
        raise RuntimeError("stale currentness mismatch")
    if fresh_evidence[0].get("maintenance_annotation") != "covered":
        raise RuntimeError("fresh maintenance mismatch")
    if stale_evidence[0].get("maintenance_annotation") != "overrun":
        raise RuntimeError("stale maintenance mismatch")
    if first.get("owner_record_ref") != evaluation_id:
        raise RuntimeError("fresh evaluation identity mismatch")
    if second.get("owner_record_ref") != evaluation_id:
        raise RuntimeError("stale evaluation identity mismatch")


def validate_missing(view, objective):
    if view.get("schema") != "phosphor-ng.objective-detail/v2":
        raise RuntimeError("wrong missing-evaluation objective schema")
    authored = view.get("objective", {})
    if authored.get("schema") != "maude.objective-source/v1" or authored.get("availability") != "available":
        raise RuntimeError("missing-evaluation authored source unavailable")
    if authored.get("plan_digest") != objective["plan_digest"]:
        raise RuntimeError("missing-evaluation plan mismatch")
    if view.get("occurrences") != []:
        raise RuntimeError("unexpected missing-evaluation occurrence")
    conditions = view.get("conditions", [])
    if len(conditions) != 2:
        raise RuntimeError("missing-evaluation condition count mismatch")
    first, second = conditions
    if [item.get("condition_id") for item in conditions] != [item["condition_id"] for item in objective["acceptance_criteria"]]:
        raise RuntimeError("missing-evaluation condition identity mismatch")
    if first.get("disposition") != "unavailable":
        raise RuntimeError("missing evaluation was not unavailable")
    # The shared schema omits empty evidence vectors on the wire.
    if first.get("owner_record_ref") is not None or first.get("evidence", []) != []:
        raise RuntimeError("missing evaluation fabricated owner evidence")
    if second.get("disposition") != "unknown":
        raise RuntimeError("missing evaluation changed unmapped criterion")
    if view.get("prerequisites") != "unavailable":
        raise RuntimeError("missing evaluation fabricated prerequisite coverage")

def reader_config(root,state,objective,nq,reader_revision):
    bundle = parse_json((state / "attention-bundle.json").read_bytes())
    condition = bundle["evaluation"]["condition"]
    definition = condition["definition_identity"]
    config = {
        "schema": "phosphor-ng.objective-owner-reader-config/v1",
        "plan_digest": objective["plan_digest"],
        "owner_id": "application.saved-check-owner",
        "owner_capability": "nq.saved-check-condition/v1",
        "owner_source_revision": reader_revision,
        "nq_program": str(nq),
        "nq_program_sha256": sha(nq),
        "nq_config": str(state / "nq.toml"),
        "nq_config_sha256": sha(state / "nq.toml"),
        "criterion": {
            "condition_id": objective["acceptance_criteria"][0]["condition_id"],
            "definition_id": definition["id"],
            "definition_reference": definition["reference"],
            "definition_digest": definition["digest"],
            "evaluation_id": condition["evaluation_id"],
            "source_identity": condition["source_assertion"]["identity"],
            "required_outcome": "passed",
            "component": "disposable-queue",
            "kind": "saved-check",
            "subject": "queue",
        },
        "definition_prerequisite": {
            "prerequisite_id": "application.saved-check-definition-installed",
            "relation": "requires_definition",
            "owner_record_ref": (
                "application:nq-definition:"
                + definition["id"] + ":" + definition["reference"]
            ),
            "owner_record_digest": definition["digest"],
        },
    }
    return config, condition

def capture_http(root,label,port,ui,loopctl,maude,plan,objective,reader,config,revision):
    digest = objective["plan_digest"]
    argv = [
        ui, "--campaign-root", root / "campaigns", "--ag-loopctl", loopctl,
        "--bind", f"127.0.0.1:{port}", "--maude-objective-bin", maude,
        "--maude-objective-plan", plan, "--maude-objective-expected-plan-digest", digest,
        "--objective-owner-bin", reader, "--objective-owner-config", config,
        "--objective-owner-id", "application.saved-check-owner",
        "--objective-owner-capability", "nq.saved-check-condition/v1",
        "--objective-owner-source-revision", revision,
        "--objective-owner-expected-plan-digest", digest,
    ]
    save(root/f"{label}-server-planned.json",{"argv":[str(x) for x in argv]})
    streams = {}
    stop_diagnostics = threading.Event()
    def drain(name, stream, path):
        written = 0
        truncated = False
        complete = False
        error = None
        try:
            os.set_blocking(stream.fileno(), False)
            with path.open("xb", buffering=0) as output:
                while not stop_diagnostics.is_set():
                    try:
                        block = os.read(stream.fileno(), 8192)
                    except BlockingIOError:
                        stop_diagnostics.wait(.02)
                        continue
                    if not block:
                        complete = True
                        break
                    take = min(len(block), max(0, MAX_STREAM - written))
                    if take:
                        output.write(block[:take])
                        written += take
                    # Keep draining after truncation so diagnostics cannot block
                    # the server. Retained bytes are a prefix, not a full log.
                    truncated |= take != len(block)
        except Exception as caught:
            error = str(caught)
        finally:
            stream.close()
            streams[name] = {"path": path.name, "bytes": written,
                             "truncated": truncated, "complete": complete,
                             "error": error}
    p=subprocess.Popen([str(x) for x in argv],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
    readers = [threading.Thread(target=drain,args=(name,stream,root/f"{label}-server-{name}.log"),daemon=True) for name,stream in (("stdout",p.stdout),("stderr",p.stderr))]
    for thread in readers: thread.start()
    try:
        save(root/f"{label}-server.json",{"pid":p.pid,"argv":[str(x) for x in argv]})
        url=f"http://127.0.0.1:{port}/api/v1/objectives/{digest[7:]}"
        deadline=time.monotonic()+5
        while time.monotonic()<deadline:
            if p.poll() is not None:
                raise RuntimeError("Phosphor exited before read")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=.2):
                    pass
                break
            except ConnectionRefusedError:
                time.sleep(.1)
        else:
            raise RuntimeError("Phosphor loopback unavailable")
        with HTTP_OPENER.open(url, timeout=12) as response:
            raw = response.read(MAX_HTTP + 1)
        if len(raw) > MAX_HTTP:
            raise RuntimeError("Phosphor response limit")
        value = parse_json(raw)
        save(root / f"{label}-objective.json", value)
        return value
    finally:
        try: os.killpg(p.pid,signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        # Reap the same process group even if the initial server already exited;
        # a remaining child could otherwise hold diagnostic pipes open.
        try: os.killpg(p.pid,signal.SIGKILL)
        except ProcessLookupError:
            pass
        p.wait()
        for thread in readers: thread.join(timeout=1)
        stop_diagnostics.set()
        for thread in readers: thread.join(timeout=1)
        save(root/f"{label}-server-terminal.json",{"pid":p.pid,"returncode":p.returncode,"diagnostics":dict(streams)})
        if (any(thread.is_alive() for thread in readers) or len(streams) != 2
                or any(item["error"] is not None or not item["complete"] for item in streams.values())):
            raise RuntimeError("Phosphor diagnostic capture incomplete; inspect retained records")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    path_arguments = (
        "maude", "nq", "nightshift", "monitor", "saved-check-example",
        "project-example", "reader", "operator-ui", "ag-loopctl",
    )
    for name in path_arguments:
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--reader-revision", required=True)
    parser.add_argument("--port", type=int, default=28456)
    ns = parser.parse_args()
    if not 1 <= ns.port <= 65535:
        parser.error("--port must be 1..65535")
    valid_root = (
        ns.root.is_absolute()
        and not ns.root.exists()
        and ns.root.name.startswith("objective-owner-composed-")
    )
    if not valid_root:
        parser.error("--root must be an absent absolute objective-owner-composed-* path")
    try:
        programs = (
            (ns.maude, "maude-plan"),
            (ns.nq, "nq"),
            (ns.nightshift, "nightshift"),
            (ns.monitor, "monitor-concerns"),
            (ns.reader, "phosphor-objective-owner-reader"),
            (ns.operator_ui, "ag-operator-ui"),
            (ns.ag_loopctl, "ag-loopctl"),
        )
        for path, basename in programs:
            executable(path, basename)
        for path in (ns.saved_check_example,ns.project_example):
            regular = path.is_absolute() and stat.S_ISREG(path.stat().st_mode)
            if not regular:
                raise ValueError("example path must be an absolute regular file")
    except (OSError, ValueError) as error:
        parser.error(str(error))

    ns.root.mkdir(mode=0o700)
    log = ns.root / "commands.jsonl"
    state = ns.root / "nightshift-saved-check-run-objective"
    maude = [ns.maude, "--store", ns.root / "plans.sqlite"]
    draft = invoke(log, "maude-new", maude + [
        "new", "--goal", "Read whether the disposable queue meets its declared saved check",
        "--workspace", ns.root, "--author", "public-example-caller",
        "--submitter-kind", "synthetic_agent", "--origin", "agent_generated",
    ])
    document = draft["document"]
    document["acceptance_criteria"] = [
        "The exact enrolled saved check has a current passed result",
        "The application has assessed any other required criterion",
    ]
    plan = ns.root / "plan.json"
    save(plan, document)
    revised = invoke(log, "maude-save", maude + [
        "save", draft["draft_id"], plan, "--expected-revision",
        draft["revision_id"], "--origin", "agent",
    ])
    invoke(log, "maude-lock", maude + ["lock", draft["draft_id"]])
    objective = invoke(log, "maude-objective-read", [
        ns.maude, "objective-read", "--plan", plan,
        "--expected-plan-digest", revised["plan_digest"],
    ])
    save(ns.root / "maude-objective.json", objective)
    if objective.get("availability") != "available":
        raise RuntimeError("Maude objective unavailable")
    (ns.root/"campaigns").mkdir()
    invoke(log,"saved-check-attention",["/usr/bin/python3",ns.saved_check_example,"--attention-inbox","--nightshift",ns.nightshift,"--monitor",ns.monitor,"--nq",ns.nq,"--project-example",ns.project_example,"--root",state],timeout=180)
    config, condition = reader_config(
        ns.root, state, objective, ns.nq, ns.reader_revision
    )
    fresh_config = ns.root / "fresh-reader.json"
    save(fresh_config, config)
    nq_before = sha(state / "nq.db")
    fresh = capture_http(
        ns.root, "fresh", ns.port, ns.operator_ui, ns.ag_loopctl, ns.maude,
        plan, objective, ns.reader, fresh_config, ns.reader_revision,
    )
    observed_text = condition["source_assertion"]["observed_at"]
    observed = datetime.fromisoformat(observed_text.replace("Z", "+00:00"))
    expiry = (
        observed.timestamp()
        + condition["source_assertion"]["currentness_seconds"]
        + 1
    )
    delay = max(0, expiry - datetime.now(timezone.utc).timestamp())
    if delay > 121:
        raise RuntimeError("unexpected currentness delay")
    if delay:
        time.sleep(delay)
    stale_config = ns.root / "stale-reader.json"
    save(stale_config, config)
    stale = capture_http(
        ns.root, "stale", ns.port, ns.operator_ui, ns.ag_loopctl, ns.maude,
        plan, objective, ns.reader, stale_config, ns.reader_revision,
    )
    missing_id = "sha256:" + "0" * 64
    if missing_id == condition["evaluation_id"]:
        raise RuntimeError("missing-evaluation control collided with actual identity")
    missing_config_value = json.loads(json.dumps(config))
    missing_config_value["criterion"]["evaluation_id"] = missing_id
    missing_config = ns.root / "missing-evaluation-reader.json"
    save(missing_config, missing_config_value)
    missing = capture_http(
        ns.root, "missing-evaluation", ns.port, ns.operator_ui, ns.ag_loopctl,
        ns.maude, plan, objective, ns.reader, missing_config, ns.reader_revision,
    )
    if sha(state / "nq.db") != nq_before:
        raise RuntimeError("read path changed NQ database")
    validate_views(fresh, stale, objective, condition["evaluation_id"])
    validate_missing(missing, objective)
    if root_bytes(ns.root) > MAX_ROOT:
        raise RuntimeError("retained root exceeds 64 MiB")
    save(ns.root / "result.json", {
        "schema": "constellation.objective-owner-composed-example/v1",
        "result": "completed",
        "plan_digest": objective["plan_digest"],
        "fresh": "not_satisfied",
        "stale": "indeterminate",
        "missing_evaluation": "unavailable",
        "other_criterion": "unknown",
        "authority": "none",
        "objective_completion": "not_determined",
        "nq_database_before_after_sha256": nq_before,
        "measured_retained_bytes": root_bytes(ns.root),
        "evidence_scope": "example assertions only; profile evidence is separate",
    })

if __name__ == "__main__":
    main()
