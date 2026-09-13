#!/usr/bin/python3
import hashlib
import importlib.util
import json
import os
import pathlib
import stat
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("seal", HERE / "seal-standing-resolver-launcher.py")
SEAL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SEAL)


class LauncherTests(unittest.TestCase):
    def fixture(self):
        root = pathlib.Path(tempfile.mkdtemp())
        resolver = root / "ag-standing-resolver"
        resolver.write_bytes(b"#!/bin/sh\nexit 0\n")
        resolver.chmod(0o500)
        python = pathlib.Path("/usr/bin/python3").resolve()
        enrollment = {
            "schema": SEAL.SCHEMA,
            "resolver_program": str(resolver),
            "resolver_sha256": SEAL.digest(resolver.read_bytes()),
            "mandate_store": str(root / "mandates.json"),
            "resolver_id": "ag-standing:qualification-v1",
            "answer_ttl_ms": 30000,
            "python_interpreter": str(python),
            "python_sha256": SEAL.digest(python.read_bytes()),
        }
        config = root / "enrollment.json"
        config.write_bytes(SEAL.canonical(enrollment))
        return root, resolver, config

    def test_generated_launcher_is_closed_and_zero_argument(self):
        root, _, config = self.fixture()
        value = SEAL.load(config)
        output = SEAL.launcher_bytes(value)
        self.assertIn(b"len(sys.argv)!=1", output)
        self.assertIn(b"--mandate-store", output)
        self.assertNotIn(b"os.environ", output)

    def test_changed_resolver_is_refused_before_seal(self):
        _, resolver, config = self.fixture()
        resolver.chmod(0o700)
        resolver.write_bytes(b"#!/bin/sh\nexit 1\n")
        with self.assertRaisesRegex(ValueError, "resolver digest mismatch"):
            SEAL.load(config)

    def test_unknown_config_field_is_refused(self):
        _, _, config = self.fixture()
        value = json.loads(config.read_bytes())
        value["command"] = "/bin/true"
        config.write_bytes(SEAL.canonical(value))
        with self.assertRaisesRegex(ValueError, "non-closed"):
            SEAL.load(config)


if __name__ == "__main__":
    unittest.main()
