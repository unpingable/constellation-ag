# SPDX-License-Identifier: Apache-2.0
import importlib.util
import json
import tempfile
import unittest
from importlib.machinery import SourceFileLoader
from pathlib import Path

HERE = Path(__file__).parent
SPEC = importlib.util.spec_from_loader(
    "occurrence_check",
    SourceFileLoader("occurrence_check", str(HERE / "phosphor-objective-occurrence-check")),
)
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


def source(value=None, *, unavailable=False):
    if unavailable:
        return {
            "availability": "unavailable",
            "source": "fixture",
            "command": "ag_status",
            "captured_at_unix_ms": 1,
            "error_kind": "command_refused",
            "detail": "fixture refusal",
            "exit_status": 2,
        }
    return {
        "availability": "available",
        "source": "fixture",
        "command": "ag_status",
        "captured_at_unix_ms": 1,
        "value": value or {},
        "raw": value or {},
    }


class OccurrenceCheckTests(unittest.TestCase):
    def expected(self):
        return {
            "input_sha256": "sha256:" + "f" * 64,
            "plan_digest": "sha256:" + "a" * 64,
            "maude_plan_ref": "sha256:" + "a" * 64,
            "campaign_id": "sha256:" + "b" * 64,
            "occurrence_id": "00000000-0000-0000-0000-000000000001",
            "proposal_id": "sha256:" + "c" * 64,
            "exact_work_id": "sha256:" + "d" * 64,
            "issuance_id": "sha256:" + "e" * 64,
        }

    def view(self):
        expected = self.expected()
        detail = {
            "schema": "ag.operator-ui.campaign-detail/v1",
            "locator_token": "opaque",
            "locator": "campaign.sqlite",
            "inspect": source(),
            "status": source(),
            "replay": source(),
            "history": source(),
            "refusals": source(unavailable=True),
            "projection": {"correspondence": "partial", "findings": ["refusals unavailable"]},
            "nightshift": [],
            "authoring_contexts": [],
            "authoring_custody": [],
            "external_observations": [],
            "observation_acquisitions": [],
            "docket": [{
                "identity": expected["issuance_id"],
                "result": source({
                    "schema": "docket.governed-loop.inspection/v1",
                    "requested_issuance": expected["issuance_id"],
                    "record": {"status": "indeterminate"},
                }),
            }],
        }
        return {
            "schema": "phosphor-ng.objective-detail/v2",
            "objective": {
                "schema": "maude.objective-source/v1",
                "availability": "available",
                "plan_digest": expected["plan_digest"],
            },
            "conditions": [{
                "condition_id": "sha256:" + "1" * 64,
                "disposition": "indeterminate",
                "evidence": [{"source_currentness": "stale"}],
            }],
            "occurrences": [{
                "campaign_id": expected["campaign_id"],
                "occurrence_id": expected["occurrence_id"],
                "proposal_id": expected["proposal_id"],
                "exact_work_id": expected["exact_work_id"],
                "maude_plan_ref": expected["plan_digest"],
                "detail_locator_token": "opaque",
                "detail": detail,
            }],
            "causal_unavailable": [{"locator_token": "other", "detail": "source missing"}],
            "prerequisites": "unavailable",
            "owner_projection": source(unavailable=True),
        }

    def test_accepts_exact_link_without_promoting_execution(self):
        result = CHECK.check(self.view(), self.expected())
        self.assertEqual(result["docket_record_status"], "indeterminate")
        self.assertEqual(result["objective_completion"], "not_determined")
        self.assertEqual(result["current_health"], "not_derived_from_execution")
        self.assertEqual(result["authority_for_another_action"], "none")
        self.assertEqual(result["causal_unavailable_count"], 1)

    def test_refuses_timestamp_like_or_changed_relationship(self):
        view = self.view()
        view["occurrences"][0]["proposal_id"] = "sha256:" + "9" * 64
        with self.assertRaisesRegex(ValueError, "exactly one owner-minted"):
            CHECK.check(view, self.expected())

    def test_refuses_missing_docket_record_and_unsupported_condition(self):
        view = self.view()
        view["occurrences"][0]["detail"]["docket"] = []
        with self.assertRaisesRegex(ValueError, "Docket issuance"):
            CHECK.check(view, self.expected())
        view = self.view()
        view["occurrences"][0]["detail"]["docket"][0]["result"]["value"]["record"] = None
        with self.assertRaisesRegex(ValueError, "custody state"):
            CHECK.check(view, self.expected())
        view = self.view()
        view["conditions"][0]["disposition"] = "completed"
        with self.assertRaisesRegex(ValueError, "unsupported disposition"):
            CHECK.check(view, self.expected())

    def test_accepts_explicit_owner_declared_prerequisites(self):
        view = self.view()
        view["prerequisites"] = {
            "owner_declared": {
                "coverage": "owner_asserted_complete",
                "items": [],
            }
        }
        CHECK.check(view, self.expected())

    def test_loader_refuses_symlink_and_duplicate_members(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            actual = root / "objective.json"
            actual.write_text("{\"schema\":\"x\",\"schema\":\"y\"}", encoding="ascii")
            with self.assertRaisesRegex(ValueError, "duplicate JSON member"):
                CHECK.load_regular(actual)
            link = root / "link.json"
            link.symlink_to(actual)
            with self.assertRaisesRegex(ValueError, "final-non-symlink"):
                CHECK.load_regular(link)


if __name__ == "__main__":
    unittest.main()
