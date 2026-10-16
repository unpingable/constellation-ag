"""Exercise the package identity contract with local executable fixtures."""

import hashlib
import io
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import subprocess
import tarfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "identity", Path(__file__).with_name("record-build-identity.py"))
identity = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(identity)
COMMIT = "0123456789abcdef0123456789abcdef01234567"


class PackageIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        env = patch.dict(os.environ, {"AG_SOURCE_COMMIT": COMMIT,
                                     "AG_BUILD_IDENTITY": "jammy-001"})
        env.start()
        self.addCleanup(env.stop)
        self.info = {}
        for name in identity.BINARIES:
            self.info[name] = {
                "schema": "ag.build_info.v1", "component": name, "version": "0.1.0",
                "source_commit": COMMIT, "build_id": "jammy-001",
                "rustc": "rustc 1.95.0 (fixture)", "target": "x86_64-unknown-linux-gnu",
                "debug_assertions": False, "systemd_dbus": True,
            }
            self.write_fixture(name)

    def write_fixture(self, name, mutate=False):
        # Each executable is a local fixture; it reads no state or enrollment.
        program = "#!/usr/bin/env python3\nimport sys\n"
        program += "assert sys.argv[1:] == ['--build-info']\n"
        program += "print(" + repr(json.dumps(self.info[name])) + ")\n"
        if mutate:
            program += "from pathlib import Path\np=Path(__file__)\np.write_text(p.read_text()+'#changed\\n')\n"
        path = self.root / identity.BINARIES[name]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(program)
        path.chmod(0o755)
        flat = self.root / name
        flat.write_text(program)
        flat.chmod(0o755)

    def receipt(self, arch="amd64"):
        return identity.record(self.root, "0.1.0+test.1", arch)

    def test_records_exact_staged_bytes_and_complete_cohort(self):
        receipt = self.receipt()
        self.assertEqual(receipt["source_commit"], COMMIT)
        self.assertEqual(receipt["build_id"], "jammy-001")
        self.assertEqual(set(receipt["executables"]), set(identity.BINARIES))
        for name, item in receipt["executables"].items():
            self.assertEqual(item["sha256"], hashlib.sha256((self.root/identity.BINARIES[name]).read_bytes()).hexdigest())

    def test_missing_or_mismatched_executable_identity_is_refused(self):
        name = "ag-effectd"
        for field, value in [("source_commit", None), ("source_commit", "f"*40),
                             ("build_id", None), ("build_id", "different-build"),
                             ("component", "another-binary"), ("schema", "other.v1"),
                             ("version", "0.9.0"), ("rustc", None),
                             ("target", "aarch64-unknown-linux-gnu"),
                             ("debug_assertions", "false")]:
            with self.subTest(field=field, value=value):
                original = self.info[name][field]
                self.info[name][field] = value
                self.write_fixture(name)
                with self.assertRaises(ValueError):
                    self.receipt()
                self.info[name][field] = original

    def test_mixed_build_profile_and_toolchain_are_refused(self):
        name = "ag-effectd"
        for field, value in [("rustc", "rustc other"), ("debug_assertions", True)]:
            with self.subTest(field=field):
                original = self.info[name][field]
                self.info[name][field] = value
                self.write_fixture(name)
                with self.assertRaisesRegex(ValueError, "inconsistent"):
                    self.receipt()
                self.info[name][field] = original

    def test_assembly_requires_explicit_expected_identity(self):
        for variable, value in [("AG_SOURCE_COMMIT", ""), ("AG_SOURCE_COMMIT", "HEAD"),
                                ("AG_BUILD_IDENTITY", ""), ("AG_BUILD_IDENTITY", "line\nbreak")]:
            with self.subTest(variable=variable, value=value), patch.dict(os.environ, {variable: value}):
                with self.assertRaises(ValueError):
                    self.receipt()

    def test_staged_content_mutation_during_probe_is_refused(self):
        self.write_fixture("ag-effectd", mutate=True)
        with self.assertRaisesRegex(ValueError, "changed"):
            self.receipt()

    def test_package_architecture_mismatch_is_refused(self):
        with self.assertRaisesRegex(ValueError, "architecture"):
            self.receipt("arm64")

    def test_package_receipt_matches_the_actual_staged_payload(self):
        output_dir = self.root / "output"
        builder = Path(__file__).with_name("build-operator-tools-deb.sh")
        result = subprocess.run(["bash", str(builder), "0.1.0+test.1", "amd64",
                                 str(self.root), str(output_dir)],
                                cwd="/", capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        complete = set()
        for package_name in ["agent-governor-ng-operator-tools", "agent-governor-ng-systemd-executor"]:
            stem = output_dir / (package_name + "_0.1.0+test.1_amd64")
            receipt = json.loads(Path(str(stem) + ".build-identity.json").read_text())
            package = Path(str(stem) + ".deb")
            tar = subprocess.run(["dpkg-deb", "--fsys-tarfile", str(package)],
                                 capture_output=True, check=True).stdout
            with tarfile.open(fileobj=io.BytesIO(tar)) as payload:
                embedded = json.load(payload.extractfile(
                    "./usr/share/doc/" + package_name + "/build-identity.json"))
                self.assertEqual(embedded, receipt)
                for name, relative in identity.BINARIES.items():
                    if not relative.startswith(package_name + "/"):
                        continue
                    executable = payload.extractfile("./" + relative.split("/", 1)[1]).read()
                    self.assertEqual(hashlib.sha256(executable).hexdigest(),
                                     receipt["executables"][name]["sha256"])
                    complete.add(name)
            expected = hashlib.sha256(package.read_bytes()).hexdigest()
            self.assertEqual(Path(str(package) + ".sha256").read_text().split()[0], expected)
        self.assertEqual(complete, set(identity.BINARIES))

    def test_executor_feature_is_required_before_either_package_is_emitted(self):
        self.info["ag-effectd"]["systemd_dbus"] = False
        self.write_fixture("ag-effectd")
        with self.assertRaisesRegex(ValueError, "systemd-dbus"):
            self.receipt()
        output_dir = self.root / "feature-refused-output"
        result = subprocess.run(["bash", str(Path(__file__).with_name("build-operator-tools-deb.sh")),
                                 "0.1.0+test.1", "amd64", str(self.root), str(output_dir)],
                                capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(list(output_dir.glob("*.deb")))
        self.assertFalse(list(output_dir.glob(".stage.*")))

    def test_package_assembly_refuses_an_unknown_build_without_emitting_a_package(self):
        output_dir = self.root / "refused-output"
        builder = Path(__file__).with_name("build-operator-tools-deb.sh")
        with patch.dict(os.environ, {"AG_SOURCE_COMMIT": ""}):
            result = subprocess.run(["bash", str(builder), "0.1.0+test.1", "amd64",
                                     str(self.root), str(output_dir)], capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(list(output_dir.glob("*.deb")))
        self.assertFalse(list(output_dir.glob(".stage.*")))


if __name__ == "__main__":
    unittest.main()
