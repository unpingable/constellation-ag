//! V1 byte identity and historical reconciliation remain readable; bare V1
//! execution is no longer a current authenticated C1 CLI path.

use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::Path;
use std::process::{Command, Stdio};

use ag_app::effect_executor_adapter::{
    execute_effect_attempt, EffectAuthorizationInputsV2, EffectExecutorDispatchV1,
    EffectExecutorPlanV1, EFFECT_EXECUTOR_PLAN_SCHEMA_V1, EFFECT_EXECUTOR_PLAN_SCHEMA_V2,
    EFFECT_EXECUTOR_WORK_SCHEMA_V1,
};
use ag_primitives::{Digest, JcsDocument};

fn plan(root: &Path) -> EffectExecutorPlanV1 {
    serde_json::from_value(serde_json::json!({
        "schema": EFFECT_EXECUTOR_PLAN_SCHEMA_V1,
        "attempt_store": root.join("attempts.sqlite"),
        "subject": format!("sha256:{}", "62".repeat(32)),
        "scope": format!("sha256:{}", "31".repeat(32)),
        "effect_index": 0,
        "effect": {
            "kind": "managed_file_put", "target": "v1-history-fixture",
            "path": root.join("target"), "expected_content": null,
            "content": Digest::hash_bytes(b"historical-fixture\n"),
            "mode": 384,
            "uid": nix::unistd::Uid::current().as_raw(),
            "gid": nix::unistd::Gid::current().as_raw()
        },
        "artifacts": [{
            "digest": Digest::hash_bytes(b"historical-fixture\n"),
            "path": root.join("artifact")
        }],
        "file_policy": {
            "max_content_bytes": 1024,
            "trusted_ancestor_uid": std::fs::metadata("/").unwrap().uid(),
            "trusted_parent_uid": nix::unistd::Uid::current().as_raw(),
            "require_private_parent_writes": true
        },
        "preparation_checkpoint": null
    }))
    .unwrap()
}

fn dispatch(plan: &EffectExecutorPlanV1) -> EffectExecutorDispatchV1 {
    EffectExecutorDispatchV1 {
        attempt: Digest::hash_bytes(b"historical-attempt"),
        marker: Digest::hash_bytes(b"historical-marker"),
        work_schema: EFFECT_EXECUTOR_WORK_SCHEMA_V1.to_owned(),
        work: plan.identity().unwrap(),
        subject: plan.subject.clone(),
        scope: plan.scope.clone(),
    }
}

fn cli(
    operation: &str,
    plan_path: &Path,
    input: Option<&EffectExecutorDispatchV1>,
) -> std::process::Output {
    if input.is_none() {
        return Command::new(env!("CARGO_BIN_EXE_ag-effectd"))
            .arg(operation)
            .arg(plan_path)
            .output()
            .unwrap();
    }
    // `output` closes stdin immediately; use `spawn` for the dispatch case.
    let mut process = Command::new(env!("CARGO_BIN_EXE_ag-effectd"))
        .arg(operation)
        .arg(plan_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    process
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(input.unwrap()).unwrap())
        .unwrap();
    process.wait_with_output().unwrap()
}

#[test]
fn v1_plan_identity_is_unchanged_and_execute_refuses_before_any_effect() {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let plan = plan(root.path());
    std::fs::write(root.path().join("artifact"), b"historical-fixture\n").unwrap();
    let plan_path = root.path().join("plan.json");
    std::fs::write(
        &plan_path,
        JcsDocument::canonicalize(&plan).unwrap().as_bytes(),
    )
    .unwrap();
    let id = cli("plan-id", &plan_path, None);
    assert!(id.status.success());
    assert_eq!(
        String::from_utf8(id.stdout).unwrap().trim(),
        plan.identity().unwrap().as_str()
    );
    assert!(!std::fs::read_to_string(&plan_path)
        .unwrap()
        .contains("authorization"));

    let refused = cli("execute", &plan_path, Some(&dispatch(&plan)));
    assert!(!refused.status.success());
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("effect-executor-v1-execute-not-current")
    );
    assert!(!root.path().join("target").exists());
    assert!(!root.path().join("attempts.sqlite").exists());
}

#[test]
fn historical_v1_reconcile_reads_same_attempt_without_mechanics() {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let plan = plan(root.path());
    let dispatch = dispatch(&plan);
    std::fs::write(root.path().join("artifact"), b"historical-fixture\n").unwrap();
    let prior = execute_effect_attempt(&plan, &dispatch).unwrap();
    let plan_path = root.path().join("plan.json");
    std::fs::write(
        &plan_path,
        JcsDocument::canonicalize(&plan).unwrap().as_bytes(),
    )
    .unwrap();
    // A later target mutation is not a reason to repeat historical mechanics.
    std::fs::write(root.path().join("target"), b"later-local-state\n").unwrap();
    let result = cli("reconcile", &plan_path, Some(&dispatch));
    assert!(result.status.success());
    let replay: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(replay["receipt"], prior.receipt.as_str());
    assert_eq!(
        std::fs::read(root.path().join("target")).unwrap(),
        b"later-local-state\n"
    );
}

#[test]
fn v2_plan_id_refuses_unenrolled_profile_before_docket_custody() {
    let root = tempfile::tempdir().unwrap();
    let mut plan = plan(root.path());
    plan.schema = EFFECT_EXECUTOR_PLAN_SCHEMA_V2.to_owned();
    plan.authorization = Some(EffectAuthorizationInputsV2 {
        expected_runtime_profile: Digest::hash_bytes(b"uninstalled-fixture-profile"),
    });
    let plan_path = root.path().join("plan.json");
    std::fs::write(
        &plan_path,
        JcsDocument::canonicalize(&plan).unwrap().as_bytes(),
    )
    .unwrap();
    let result = cli("plan-id", &plan_path, None);
    assert!(!result.status.success());
    assert!(!root.path().join("attempts.sqlite").exists());
    assert!(!root.path().join("target").exists());
}
