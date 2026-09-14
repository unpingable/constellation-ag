# SPDX-License-Identifier: Apache-2.0
import hashlib, json, os, subprocess, tempfile, time, unittest
from pathlib import Path

HERE=Path(__file__).resolve().parent
READER=HERE/"phosphor-objective-owner-reader"
PLAN="sha256:"+"1"*64
DEF="sha256:"+"2"*64
EVAL="sha256:"+"3"*64

def sha(b): return "sha256:"+hashlib.sha256(b).hexdigest()

class ReaderTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.root=Path(self.tmp.name)
        self.nqcfg=self.root/"nq.json"; self.nqcfg.write_text("{}",encoding="ascii")
        self.marker=self.root/"launched"
    def tearDown(self): self.tmp.cleanup()
    def owner(self, *, state="available", outcome="failed", current="fresh", read_state="recorded", read_at="2026-09-14T00:00:01Z", mismatch=None, oversized=False, claimed=False, refusal=False):
        script=self.root/"nq"
        if oversized:
            body="import sys; print('x'*1048577)"
        else:
            body=f'''import json,sys
open({str(self.marker)!r},"a").write("1")
a=sys.argv; at=a[a.index("--at")+1]
assert a[a.index("--config")+1].startswith("/proc/self/fd/")
observed=at if {current!r}=="fresh" else ("2020-01-01T00:00:00Z" if {current!r}=="stale" else "2099-01-01T00:00:00Z")
binding={{"definition_digest":{DEF!r},"target_reference":"component-only","source_identity":"source-1","source_observed_at_assertion":observed,"currentness_seconds":300}}
detail={{"binding":binding}} if {claimed!r} else {{"binding":binding,"read_attempted_at":{read_at!r},"refusal_reason":None}}
v={{"schema":"nq.saved-check-condition/v1","projection_state":{state!r},"evaluation_id":{EVAL!r},"definition_identity":{{"id":"definition-1","reference":"check.ref","digest":{DEF!r},"installed_at":"2026-09-13T00:00:00Z"}},"original_result":{{"state":("indeterminate" if {claimed!r} else {outcome!r}),"outcome":{outcome!r},"detail":detail}},"source_assertion":{{"identity":"source-1","observed_at":observed,"currentness_seconds":300,"state":{current!r}}},"read_attempt":{{"state":{read_state!r},"at":{read_at!r},"scope":"retained_local_read_evidence"}},"maintenance":{{"state":"covered","maintenance_id":"maintenance-1","declaration_digest":"sha256:"+"5"*64,"declared_at":"2026-09-13T00:00:00Z"}},"caller_mapping":{{"component":"queue","kind":"saved-check","subject":"local","at":at,"mapping_owner":"caller"}},"authority":"none","automatic_nightshift_integration":False,"limitations":[]}}
if {refusal!r}: v={{"schema":"nq.saved-check-condition/v1","projection_state":"refused","refusal_reason":"evaluation_missing","evaluation_id":{EVAL!r},"caller_mapping":{{"component":"queue","kind":"saved-check","subject":"local","at":at,"mapping_owner":"caller"}},"maintenance":{{"state":"unavailable","reason":"retained_result_unavailable"}},"authority":"none","automatic_nightshift_integration":False}}
if {mismatch!r}: v[{mismatch!r}]="wrong"
raw=json.dumps(v,sort_keys=True,separators=(",",":"))+"\\n"
open({str(self.root / 'captured-owner.json')!r},"w").write(raw)
print(raw,end="")'''
        script.write_text("#!/usr/bin/python3\n"+body+"\n",encoding="ascii"); script.chmod(0o700)
        return script
    def config(self, program, *, prereq=True, alter=None):
        pre={"prerequisite_id":"installed-definition","relation":"requires","owner_record_ref":"application:nq-definition:definition-1:check.ref","owner_record_digest":DEF} if prereq else None
        c={"schema":"phosphor-ng.objective-owner-reader-config/v1","plan_digest":PLAN,"owner_id":"application","owner_capability":"nq.saved-check-condition/v1","owner_source_revision":"public-example-1","nq_program":str(program),"nq_program_sha256":sha(program.read_bytes()),"nq_config":str(self.nqcfg),"nq_config_sha256":sha(self.nqcfg.read_bytes()),"criterion":{"condition_id":"sha256:"+"4"*64,"definition_id":"definition-1","definition_reference":"check.ref","definition_digest":DEF,"evaluation_id":EVAL,"source_identity":"source-1","required_outcome":"passed","component":"queue","kind":"saved-check","subject":"local"},"definition_prerequisite":pre}
        if alter: alter(c)
        path=self.root/"config.json"; path.write_text(json.dumps(c,separators=(",",":")),encoding="ascii"); return path
    def run_reader(self,cfg,*extra):
        return subprocess.run([str(READER),"--config",str(cfg),"objective-projection","--plan-digest",PLAN,*extra],text=True,capture_output=True)
    def test_exact_mapping_preserves_failed_covered(self):
        p=self.run_reader(self.config(self.owner())); self.assertEqual(p.returncode,0,p.stderr)
        v=json.loads(p.stdout); c=v["conditions"][0]; e=c["evidence"][0]
        self.assertEqual(c["assessment"],"not_satisfied"); self.assertIsNone(c["reason"])
        self.assertEqual((e["owner_outcome"],e["maintenance_annotation"]),("failed","covered"))
        self.assertEqual(c["owner_record_ref"],EVAL)
        self.assertEqual(c["owner_record_ref"],e["owner_record_id"])
        captured=(self.root/"captured-owner.json").read_bytes()
        self.assertTrue(captured.endswith(b"\n"))
        self.assertEqual(c["owner_record_digest"],sha(captured))
        self.assertNotEqual(c["owner_record_digest"],sha(captured.rstrip(b"\n")))
        self.assertEqual(v["prerequisites"]["coverage"],"owner_asserted_complete"); self.assertEqual(v["authority"],"none")
        check=dict(v); check["projection_id"]=""; self.assertEqual(v["projection_id"],sha(json.dumps(check,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode("ascii")))
    def test_matching_outcome_is_satisfied(self):
        cfg=self.config(self.owner(outcome="passed"),alter=lambda x:x["criterion"].update(required_outcome="passed"))
        self.assertEqual(json.loads(self.run_reader(cfg).stdout)["conditions"][0]["assessment"],"satisfied")
    def test_stale_is_indeterminate_and_retains_facts(self):
        c=json.loads(self.run_reader(self.config(self.owner(current="stale"))).stdout)["conditions"][0]
        self.assertEqual(c["assessment"],"indeterminate"); self.assertTrue(c["evidence"]); self.assertTrue(c["reason"])
    def test_claimed_is_indeterminate_and_retains_labels(self):
        c=json.loads(self.run_reader(self.config(self.owner(state="indeterminate",outcome="claimed",current="fresh",read_state="indeterminate",read_at=None,claimed=True))).stdout)["conditions"][0]
        self.assertEqual(c["assessment"],"indeterminate"); self.assertIsNone(c["evidence"][0]["read_attempted_at"])
        self.assertEqual((c["evidence"][0]["owner_outcome"],c["evidence"][0]["maintenance_annotation"]),("claimed","covered"))
    def test_prerequisites_default_unavailable(self):
        v=json.loads(self.run_reader(self.config(self.owner(),prereq=False)).stdout)
        self.assertEqual(v["prerequisites"],{"availability":"unavailable","coverage":None,"items":[],"reason":"caller_did_not_declare_complete_prerequisites"})
    def test_refusal_is_unavailable(self):
        c=json.loads(self.run_reader(self.config(self.owner(refusal=True))).stdout)["conditions"][0]
        self.assertEqual(c["assessment"],"unavailable"); self.assertEqual(c["evidence"],[])
    def test_binding_mismatch_is_unavailable(self):
        program=self.owner(); text=program.read_text().replace('"source-1"','"different-source"'); program.write_text(text); program.chmod(0o700)
        c=json.loads(self.run_reader(self.config(program)).stdout)["conditions"][0]; self.assertEqual(c["assessment"],"unavailable")
    def test_unknown_member_is_unavailable(self):
        c=json.loads(self.run_reader(self.config(self.owner(mismatch="unexpected"))).stdout)["conditions"][0]
        self.assertEqual(c["assessment"],"unavailable")
    def test_contradictory_currentness_is_unavailable(self):
        program=self.owner(current="fresh"); body=program.read_text().replace('"currentness_seconds":300,"state":\'fresh\'','"currentness_seconds":300,"state":\'stale\'')
        program.write_text(body); program.chmod(0o700)
        c=json.loads(self.run_reader(self.config(program)).stdout)["conditions"][0]; self.assertEqual(c["assessment"],"unavailable")
    def test_timeout_reaps_the_exact_read_child(self):
        program=self.root/"nq"
        child_pid=self.root/"read-pid"
        program.write_text("#!/usr/bin/python3\nimport os,time\n"
                           + f"open({str(child_pid)!r},'w').write(str(os.getpid()))\n"
                           + "time.sleep(30)\n")
        program.chmod(0o700)
        start=time.monotonic()
        result=self.run_reader(self.config(program))
        self.assertNotEqual(result.returncode,0)
        self.assertLess(time.monotonic()-start,5)
        with self.assertRaises(ProcessLookupError):
            os.kill(int(child_pid.read_text()),0)

    def test_output_limit_refusal_does_not_accept_an_owner_record(self):
        p=self.run_reader(self.config(self.owner(oversized=True))); self.assertNotEqual(p.returncode,0); self.assertNotIn(str(self.root),p.stderr)
    def test_plan_mismatch_does_not_launch(self):
        program=self.owner(); cfg=self.config(program)
        p=subprocess.run([str(READER),"--config",str(cfg),"objective-projection","--plan-digest","sha256:"+"9"*64],text=True,capture_output=True)
        self.assertNotEqual(p.returncode,0); self.assertFalse(self.marker.exists())
    def test_nonrecorded_read_is_unavailable(self):
        c=json.loads(self.run_reader(self.config(self.owner(read_state="indeterminate"))).stdout)["conditions"][0]
        self.assertEqual(c["assessment"],"unavailable"); self.assertEqual(c["evidence"],[])
    def test_naive_timestamp_is_unavailable(self):
        c=json.loads(self.run_reader(self.config(self.owner(read_at="2026-09-14T00:00:01"))).stdout)["conditions"][0]
        self.assertEqual(c["assessment"],"unavailable")
    def test_oversized_config_does_not_launch(self):
        program=self.owner(); cfg=self.config(program); cfg.write_bytes(b"{"+b" "*32768+b"}")
        p=self.run_reader(cfg); self.assertNotEqual(p.returncode,0); self.assertFalse(self.marker.exists())
    def test_fifo_config_refuses_without_blocking(self):
        fifo=self.root/"config.fifo"; os.mkfifo(fifo)
        p=subprocess.run([str(READER),"--config",str(fifo),"objective-projection","--plan-digest",PLAN],text=True,capture_output=True,timeout=2)
        self.assertNotEqual(p.returncode,0); self.assertFalse(self.marker.exists())
    def test_help_malformed_and_missing_do_not_launch(self):
        program=self.owner(); cfg=self.config(program)
        help_run=subprocess.run([str(READER),"--help"],capture_output=True,text=True); self.assertEqual(help_run.returncode,0)
        bad=subprocess.run([str(READER),"--config",str(cfg),"objective-projection"],capture_output=True,text=True); self.assertNotEqual(bad.returncode,0)
        missing=subprocess.run([str(READER),"--config",str(self.root/"missing"),"objective-projection","--plan-digest",PLAN],capture_output=True,text=True); self.assertNotEqual(missing.returncode,0)
        self.assertFalse(self.marker.exists())
    def test_invalid_config_does_not_launch(self):
        program=self.owner(); cfg=self.config(program,alter=lambda x:x.update(extra="no")); p=self.run_reader(cfg)
        self.assertNotEqual(p.returncode,0); self.assertFalse(self.marker.exists()); self.assertNotIn(str(self.root),p.stderr)

if __name__=="__main__": unittest.main()
