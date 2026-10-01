#!/usr/bin/python3
"""Seal a zero-argument launcher for AG's configured standing resolver."""

import argparse
import hashlib
import json
import os
import pathlib
import stat

SCHEMA = "ag.governed-loop.standing-launcher-enrollment/v1"
MANIFEST_SCHEMA = "ag.governed-loop.standing-launcher-manifest/v1"
MAX_CONFIG = 64 * 1024
MAX_RESOLVER = 512 * 1024 * 1024
MAX_INTERPRETER = 128 * 1024 * 1024


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def regular(path, executable, maximum):
    if not path.is_absolute():
        raise ValueError("configured paths must be absolute")
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        meta = os.fstat(fd)
        if not stat.S_ISREG(meta.st_mode):
            raise ValueError(f"not a regular file: {path}")
        if executable and meta.st_mode & 0o111 == 0:
            raise ValueError(f"not executable: {path}")
        chunks = []
        total = 0
        while True:
            chunk = os.read(fd, min(65536, maximum + 1 - total))
            if not chunk:
                return b"".join(chunks)
            total += len(chunk)
            if total > maximum:
                raise ValueError(f"regular file exceeds {maximum} bytes: {path}")
            chunks.append(chunk)
    finally:
        os.close(fd)


def load(path):
    raw = regular(path, False, MAX_CONFIG)
    if not raw:
        raise ValueError("enrollment must be between 1 byte and 64 KiB")
    value = json.loads(raw)
    if canonical(value) != raw:
        raise ValueError("enrollment must be exact canonical JSON")
    required = {
        "schema", "resolver_program", "resolver_sha256", "mandate_store",
        "resolver_id", "answer_ttl_ms", "python_interpreter", "python_sha256"
    }
    if not isinstance(value, dict) or set(value) != required or value["schema"] != SCHEMA:
        raise ValueError("unsupported or non-closed enrollment")
    if (not isinstance(value["answer_ttl_ms"], int) or isinstance(value["answer_ttl_ms"], bool)
            or value["answer_ttl_ms"] <= 0 or value["answer_ttl_ms"] > 2**64 - 1):
        raise ValueError("answer_ttl_ms must be positive")
    if not isinstance(value["resolver_id"], str) or not value["resolver_id"].strip():
        raise ValueError("resolver_id must be nonempty")
    for name in ("resolver_program", "mandate_store", "python_interpreter"):
        if not isinstance(value[name], str) or not value[name]:
            raise ValueError(f"{name} must be a nonempty string")
        value[name] = str(pathlib.Path(value[name]))
        if not pathlib.Path(value[name]).is_absolute():
            raise ValueError(f"{name} must be absolute")
    if any(character.isspace() for character in value["python_interpreter"]):
        raise ValueError("Python interpreter path is not valid in a shebang")
    resolver = regular(pathlib.Path(value["resolver_program"]), True, MAX_RESOLVER)
    python = regular(pathlib.Path(value["python_interpreter"]), True, MAX_INTERPRETER)
    if digest(resolver) != value["resolver_sha256"]:
        raise ValueError("resolver digest mismatch")
    if digest(python) != value["python_sha256"]:
        raise ValueError("Python interpreter digest mismatch")
    return value


def launcher_bytes(value):
    embedded = repr({key: value[key] for key in sorted(value)})
    source = f'''#!{value["python_interpreter"]} -I
import fcntl,hashlib,os,stat,sys
C={embedded}
if len(sys.argv)!=1:
    raise SystemExit("standing launcher accepts no arguments")
flags=os.O_RDONLY|os.O_CLOEXEC|getattr(os,"O_NOFOLLOW",0)
fd=os.open(C["resolver_program"],flags)
meta=os.fstat(fd)
if not stat.S_ISREG(meta.st_mode) or meta.st_mode & 0o111 == 0:
    raise SystemExit("configured standing resolver is not an executable regular file")
h=hashlib.sha256(); image=os.memfd_create("ag-standing-resolver",os.MFD_ALLOW_SEALING)
total=0
while True:
    block=os.read(fd,65536)
    if not block: break
    total+=len(block)
    if total>{MAX_RESOLVER}:
        raise SystemExit("configured standing resolver exceeds bounded size")
    h.update(block)
    view=memoryview(block)
    while view:
        written=os.write(image,view)
        if written<=0: raise SystemExit("standing resolver image write was incomplete")
        view=view[written:]
if "sha256:"+h.hexdigest()!=C["resolver_sha256"]:
    raise SystemExit("configured standing resolver digest mismatch")
os.close(fd)
os.fchmod(image,0o500)
fcntl.fcntl(image,fcntl.F_ADD_SEALS,fcntl.F_SEAL_WRITE|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SEAL)
os.lseek(image,0,os.SEEK_SET); os.set_inheritable(image,True)
program="/proc/self/fd/"+str(image)
argv=[program,"--mandate-store",C["mandate_store"],"--resolver-id",C["resolver_id"],"--answer-ttl-ms",str(C["answer_ttl_ms"])]
os.execve(program,argv,{{}})
'''
    return source.encode()


def exclusive(path, data, mode):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("exclusive output write was incomplete")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--enrollment", required=True, type=pathlib.Path)
    parser.add_argument("--launcher", required=True, type=pathlib.Path)
    parser.add_argument("--manifest", required=True, type=pathlib.Path)
    args = parser.parse_args()
    value = load(args.enrollment)
    launcher = launcher_bytes(value)
    exclusive(args.launcher, launcher, 0o500)
    manifest = canonical({
        "schema": MANIFEST_SCHEMA,
        "launcher": str(args.launcher),
        "launcher_sha256": digest(launcher),
        "resolver_program": value["resolver_program"],
        "resolver_sha256": value["resolver_sha256"],
        "mandate_store": value["mandate_store"],
        "resolver_id": value["resolver_id"],
        "answer_ttl_ms": value["answer_ttl_ms"],
        "python_interpreter": value["python_interpreter"],
        "python_sha256": value["python_sha256"],
    })
    exclusive(args.manifest, manifest, 0o400)


if __name__ == "__main__":
    main()
