#!/usr/bin/python3
"""Process qualification for a launcher bound to the actual AG resolver."""

import argparse
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import threading
import time


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def d(character):
    return "sha256:" + character * 64


def request(now):
    return {
        "schema": "ag.governed-loop.standing-request/v1",
        "key": {"campaign": d("1"), "occurrence": "00000000-0000-0000-0000-000000000001"},
        "observation": d("2"), "proposal": d("3"),
        "subject": d("4"), "scope": d("5"), "now_unix_ms": now,
    }


def mandate(status, valid_until, generation=1):
    return {"subject": d("4"), "scope": d("5"), "generation": generation,
            "status": status, "valid_until_unix_ms": valid_until}


def write(path, value):
    temporary = path.with_suffix(".new")
    temporary.write_bytes(canonical(value))
    os.replace(temporary, path)


def invoke(launcher, store, mandates, now):
    write(store, {"schema": "ag.governed-loop.standing-mandate-store/v1", "mandates": mandates})
    result = subprocess.run([launcher], input=canonical(request(now)), capture_output=True,
                            timeout=5, check=True)
    return json.loads(result.stdout)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--resolver", required=True, type=pathlib.Path)
    args = parser.parse_args()
    resolver = args.resolver.resolve(strict=True)
    generator = pathlib.Path(__file__).resolve().parents[2] / "tools/seal-standing-resolver-launcher.py"
    python = pathlib.Path("/usr/bin/python3").resolve(strict=True)
    with tempfile.TemporaryDirectory() as temporary:
        root = pathlib.Path(temporary)
        bound_resolver = root / "ag-standing-resolver"
        shutil.copyfile(resolver, bound_resolver)
        bound_resolver.chmod(0o500)
        store = root / "mandates.json"
        enrollment = root / "enrollment.json"
        launcher = root / "standing-launcher"
        manifest = root / "manifest.json"
        enrollment.write_bytes(canonical({
            "schema": "ag.governed-loop.standing-launcher-enrollment/v1",
            "resolver_program": str(bound_resolver),
            "resolver_sha256": sha(bound_resolver.read_bytes()),
            "mandate_store": str(store),
            "resolver_id": "ag-standing:launcher-qualification-v1",
            "answer_ttl_ms": 1000,
            "python_interpreter": str(python),
            "python_sha256": sha(python.read_bytes()),
        }))
        subprocess.run([python, generator, "--enrollment", enrollment, "--launcher", launcher,
                        "--manifest", manifest], check=True, timeout=5)
        assert invoke(launcher, store, [], 1000)["status"] == "absent"
        assert invoke(launcher, store, [mandate("active", 3000)], 1000)["status"] == "current"
        assert invoke(launcher, store, [mandate("revoked", 3000)], 1000)["status"] == "revoked"
        assert invoke(launcher, store, [mandate("active", 1000)], 1000)["status"] == "expired"
        # The same launcher rereads the owner-controlled mutable store.
        assert invoke(launcher, store, [mandate("active", 3000)], 1000)["status"] == "current"
        assert invoke(launcher, store, [mandate("active", 3000), mandate("revoked", 3000, 2)], 1000)["status"] == "revoked"
        bound_resolver.chmod(0o700)
        with bound_resolver.open("ab") as changed:
            changed.write(b"\n")
        refused = subprocess.run([launcher], input=canonical(request(1000)), capture_output=True,
                                 timeout=5)
        assert refused.returncode != 0
        assert b"digest mismatch" in refused.stderr

        # A writer racing the pathname cannot alter an image after it has been
        # copied and sealed. Each attempt must either refuse a mixed/changed
        # capture or return the authentic resolver's complete answer.
        original = resolver.read_bytes()
        concurrent = root / "concurrent-resolver"
        concurrent.write_bytes(original)
        concurrent.chmod(0o700)
        value = json.loads(enrollment.read_bytes())
        value["resolver_program"] = str(concurrent)
        value["resolver_sha256"] = sha(original)
        racing_enrollment = root / "racing-enrollment.json"
        racing_launcher = root / "racing-launcher"
        racing_manifest = root / "racing-manifest.json"
        racing_enrollment.write_bytes(canonical(value))
        subprocess.run([python, generator, "--enrollment", racing_enrollment,
                        "--launcher", racing_launcher, "--manifest", racing_manifest],
                       check=True, timeout=5)
        write(store, {"schema": "ag.governed-loop.standing-mandate-store/v1",
                      "mandates": [mandate("active", 3000)]})
        stop = threading.Event()
        def mutate():
            changed = original + b"x"
            while not stop.is_set():
                concurrent.write_bytes(changed)
                concurrent.write_bytes(original)
                time.sleep(0.002)
        writer = threading.Thread(target=mutate)
        writer.start()
        successes = 0
        refusals = 0
        try:
            for _ in range(20):
                outcome = subprocess.run([racing_launcher], input=canonical(request(1000)),
                                         capture_output=True, timeout=5)
                if outcome.returncode == 0:
                    assert json.loads(outcome.stdout)["status"] == "current"
                    successes += 1
                else:
                    assert b"digest mismatch" in outcome.stderr
                    refusals += 1
        finally:
            stop.set()
            writer.join(timeout=5)
        assert not writer.is_alive()
        assert successes + refusals == 20
        # Contention is no longer present: restore the admitted bytes and
        # require one deterministic successful capture and execution.
        concurrent.write_bytes(original)
        settled = subprocess.run([racing_launcher], input=canonical(request(1000)),
                                 capture_output=True, timeout=5, check=True)
        assert json.loads(settled.stdout)["status"] == "current"
    print(canonical({"schema": "ag.standing-launcher-qualification/v1", "result": "passed",
                     "concurrent_capture": {"attempts": 20, "authentic_successes": successes,
                                            "fail_closed_refusals": refusals,
                                            "settled_success": True},
                     "cases": ["absent", "current", "revoked", "expired",
                               "mutable_store_reread", "resolver_content_mutation_refused",
                               "concurrent_content_capture"]}).decode())


if __name__ == "__main__":
    main()
