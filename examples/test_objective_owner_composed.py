# SPDX-License-Identifier: Apache-2.0
import importlib.util, json, tempfile, unittest
from pathlib import Path

HERE=Path(__file__).parent
spec=importlib.util.spec_from_file_location("composed",HERE/"objective-owner-composed.py")
mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)

class ComposedTests(unittest.TestCase):
    def test_save_is_create_only_and_ascii(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/"v.json"; mod.save(p,{"schema":"test/v1"})
            self.assertEqual(json.loads(p.read_text()),{"schema":"test/v1"})
            with self.assertRaises(FileExistsError): mod.save(p,{})
    def test_hash_is_exact_bytes(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/"x"; p.write_bytes(b"x")
            self.assertEqual(mod.sha(p),"sha256:2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881")
    def test_root_accounting_counts_retained_files(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td); (p/"a").write_bytes(b"123"); (p/"d").mkdir(); (p/"d"/"b").write_bytes(b"45")
            self.assertEqual(mod.root_bytes(p),5)

    def test_actual_objective_shapes_and_same_evaluation(self):
        plan="sha256:"+"a"*64; evaluation="sha256:"+"b"*64
        objective={"plan_digest":plan,"acceptance_criteria":[{"condition_id":"sha256:"+"c"*64},{"condition_id":"sha256:"+"d"*64}]}
        def view(disposition,currentness,maintenance):
            evidence={"owner_schema":"nq.saved-check-condition/v1","owner_record_id":evaluation,
                      "owner_record_digest":"sha256:"+"e"*64,"source_observed_at":"2026-09-14T00:00:00Z",
                      "read_attempted_at":"2026-09-14T00:00:01Z","projected_at":"2026-09-14T00:00:02Z",
                      "source_currentness":currentness,"owner_outcome":"failed","maintenance_annotation":maintenance}
            return {"schema":"phosphor-ng.objective-detail/v2","objective":{"schema":"maude.objective-source/v1","availability":"available","plan_digest":plan},"occurrences":[],
                    "conditions":[{"condition_id":objective["acceptance_criteria"][0]["condition_id"],
                                   "disposition":disposition,"owner_record_ref":evaluation,"evidence":[evidence]},
                                  {"condition_id":objective["acceptance_criteria"][1]["condition_id"],
                                   "disposition":"unknown","owner_record_ref":None}],
                    "prerequisites":{"owner_declared":{"coverage":"owner_asserted_complete","items":[{"prerequisite_id":"definition"}]}}}
        mod.validate_views(view("not_satisfied","fresh","covered"),
                           view("indeterminate","stale","overrun"),objective,evaluation)

    def test_validation_refuses_unknown_disposition_and_changed_identity(self):
        objective={"plan_digest":"sha256:"+"a"*64,"acceptance_criteria":[
            {"condition_id":"sha256:"+"c"*64},{"condition_id":"sha256:"+"d"*64}]}
        bad={"schema":"phosphor-ng.objective-detail/v2","objective":{"schema":"maude.objective-source/v1","availability":"available","plan_digest":objective["plan_digest"]},
             "occurrences":[],"conditions":[{"condition_id":"sha256:"+"c"*64,"disposition":"completed","owner_record_ref":"sha256:"+"b"*64,"evidence":[]},{"condition_id":"sha256:"+"d"*64,"disposition":"unknown"}],
             "prerequisites":{"owner_declared":{"coverage":"owner_asserted_complete","items":[{}]}}}
        with self.assertRaises(RuntimeError): mod.validate_views(bad,bad,objective,"sha256:"+"b"*64)

    def test_missing_evaluation_is_closed_unavailable(self):
        plan = "sha256:" + "a" * 64
        first_id, second_id = "sha256:" + "b" * 64, "sha256:" + "c" * 64
        objective = {"plan_digest": plan, "acceptance_criteria": [{"condition_id": first_id}, {"condition_id": second_id}]}
        view = {
            "schema": "phosphor-ng.objective-detail/v2",
            "objective": {"schema": "maude.objective-source/v1", "availability": "available", "plan_digest": plan},
            "occurrences": [],
            "conditions": [
                {"condition_id": first_id, "disposition": "unavailable", "owner_record_ref": None},
                {"condition_id": second_id, "disposition": "unknown", "owner_record_ref": None},
            ],
            "prerequisites": "unavailable",
        }
        mod.validate_missing(view, objective)
        view["conditions"][0]["evidence"] = [{"owner_outcome": "failed"}]
        with self.assertRaises(RuntimeError):
            mod.validate_missing(view, objective)

if __name__=="__main__": unittest.main()
