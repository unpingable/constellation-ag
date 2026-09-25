//! Read-only evidence commands over a V2 campaign verify genesis against
//! public material only. They never open the issuer signing key, they refuse
//! drifted public material or state, and they report absent enrolled files as
//! unavailable rather than passing. Mutating commands keep the live check.

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::{Command, Output};

use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

const ISSUER_PKCS8_HEX: &str = "3051020101300506032b657004220420c226c22f628685cd349518c28eff015fd216a106bb49534286dceed3202b1c0e81210028d8b71d122a31cfd39f26313275119934a021918f5d37d100ad2f27acbaf776";
const ISSUER_PUBLIC_B64URL: &str = "KNi3HRIqMc_TnyYxMnURmTSgIZGPXTfRAK0vJ6y693Y";
const READ_ONLY: [&str; 5] = ["inspect", "replay", "history", "status", "refusals"];

fn digest(byte: char) -> String {
    format!("sha256:{}", byte.to_string().repeat(64))
}

fn sha256(path: &Path) -> String {
    format!(
        "sha256:{}",
        hex::encode(Sha256::digest(fs::read(path).unwrap()))
    )
}

fn write_jcs(path: &Path, value: &Value) {
    fs::write(path, serde_jcs::to_vec(value).unwrap()).unwrap();
}

fn write_executable(path: &Path, body: &str) {
    fs::write(path, format!("#!/bin/sh\n# {body}\nexit 0\n")).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

fn invoke(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ag-loopctl"))
        .args(arguments)
        .output()
        .unwrap()
}

fn value(output: &Output) -> Value {
    assert!(
        output.status.success(),
        "ag-loopctl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn read_all(database: &str) -> Vec<Output> {
    READ_ONLY
        .iter()
        .map(|command| invoke(&[command, "--database", database]))
        .collect()
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one V2 deployment trace keeps keyless reads, drift, absence, and live refusals adjacent"
)]
fn read_only_commands_need_no_signing_key_and_report_unavailable_files() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let config = root.join("config");
    let state = root.join("state");
    let secrets = root.join("secrets");
    for path in [&config, &state, &secrets] {
        fs::create_dir(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let program = |name: &str| {
        let path = config.join(name);
        write_executable(&path, name);
        path
    };
    let command = program("boundary-command");
    let nightshift = program("nightshift");
    let nq = program("nq");
    let plan_validator = program("plan-validator");
    let review_verifier = program("review-verifier");
    let loopctl = program("ag-loopctl-pinned");

    let catalog = config.join("catalog.json");
    write_jcs(
        &catalog,
        &json!({
            "schema": "ag.governed-loop.exact-work-catalog/v1",
            "entries": {
                "fixture.work/v1": {
                    "work_schema": "fixture.work/v1",
                    "subject": digest('d'),
                    "scope": digest('e'),
                    "precondition": {"required": [], "forbidden": []}
                }
            }
        }),
    );
    let trust = config.join("docket-trust.json");
    write_jcs(
        &trust,
        &json!({"issuers": [{
            "issuer_principal": "fixture-ag",
            "key_id": "fixture-key-1",
            "public_key": ISSUER_PUBLIC_B64URL
        }]}),
    );
    let issuer_key = secrets.join("issuer.pk8");
    fs::write(&issuer_key, hex::decode(ISSUER_PKCS8_HEX).unwrap()).unwrap();
    fs::set_permissions(&issuer_key, fs::Permissions::from_mode(0o600)).unwrap();

    let nq_config = config.join("nq-config.toml");
    fs::write(&nq_config, b"# synthetic\n").unwrap();
    let validator_config = config.join("validator-config.json");
    write_jcs(
        &validator_config,
        &json!({"schema": "fixture.validator/v1"}),
    );
    let route_config = config.join("review-verifier-config.json");
    write_jcs(&route_config, &json!({"schema": "fixture.route/v1"}));
    let requirement = config.join("review-requirement.json");
    write_jcs(
        &requirement,
        &json!({
            "schema": "ag.governed-loop.review-requirement/v1",
            "reviewer_id": "fixture-reviewer",
            "route_enrollment_digest": sha256(&route_config),
            "compiler_contract": "fixture.compiler/v1",
            "max_age_ms": 600_000
        }),
    );
    let database = state.join("campaign.sqlite");
    let profile = config.join("runtime-profile.json");
    let pin = |path: &Path| json!({"path": path, "sha256": sha256(path)});
    let nightshift_config = config.join("nightshift-config.json");
    write_jcs(
        &nightshift_config,
        &json!({
            "schema": "nightshift.ag_cycle_config.v1",
            "store": state.join("nightshift.sqlite"),
            "present_evidence_resolver": pin(&command),
            "nq_program": pin(&nq),
            "nq_config": pin(&nq_config),
            "nq_source_id": "host:fixture",
            "ag_loopctl": pin(&loopctl),
            "ag_database": database,
            "ag_observation_resolver": pin(&command),
            "ag_observation_resolver_id": "fixture-observation/v1",
            "ag_runtime_profile": profile,
            "shared_admission_requirement_digest": sha256(&requirement),
            "recover_observed_at": "2026-09-25T00:00:00Z"
        }),
    );
    let enrollment = config.join("runtime-profile-enrollment-v2.json");
    write_jcs(
        &enrollment,
        &json!({
            "schema": "ag.governed-loop.runtime-profile-enrollment/v2",
            "profile_label": "read-only-qualification",
            "observation_resolver": command,
            "observation_resolver_id": "fixture-observation/v1",
            "standing_resolver": command,
            "standing_resolver_id": "fixture-standing/v1",
            "max_standing_ttl_ms": 60000,
            "exact_work_catalog": catalog,
            "controlling_review": null,
            "docket": {
                "schema": "ag.governed-loop.docket-root-enrollment/v1",
                "docket_program": command,
                "state_directory": state.join("docket"),
                "trust_config": trust,
                "standing_resolver": command,
                "executor_adapter": command,
                "issuer_principal": "fixture-ag",
                "issuer_key_id": "fixture-key-1",
                "issuer_key": issuer_key
            },
            "human_verifier": null,
            "nightshift_cycle": {
                "schema": "ag.governed-loop.nightshift-cycle-port/v1",
                "program": nightshift,
                "config": nightshift_config
            },
            "shared_admission": {
                "schema": "ag.governed-loop.shared-admission/v1",
                "plan_binding_schema": "maude.governed-plan-binding/v1",
                "compiler_contract": "fixture.compiler/v1",
                "plan_validator": plan_validator,
                "plan_validator_config": validator_config,
                "review_verifier": review_verifier,
                "review_verifier_config": route_config,
                "review_requirement": requirement
            }
        }),
    );
    let profile_arg = profile.display().to_string();
    let seal = value(&invoke(&[
        "seal-runtime-profile-v2",
        "--enrollment",
        &enrollment.display().to_string(),
        "--output",
        &profile_arg,
    ]));
    let genesis = config.join("genesis.json");
    write_jcs(
        &genesis,
        &json!({
            "campaign": digest('a'),
            "occurrence": "00000000-0000-4000-8000-000000000001",
            "program": digest('b'),
            "expected_ag_work": digest('f'),
            "residuals": [],
            "budget": {
                "retry_limit": 1, "retries_used": 0,
                "probe_limit": 1, "probes_used": 0,
                "escalation_limit": 1, "escalations_used": 0
            }
        }),
    );
    let db = database.display().to_string();
    let _ = value(&invoke(&[
        "init-v2",
        "--database",
        &db,
        "--genesis",
        &genesis.display().to_string(),
        "--runtime-profile",
        &profile_arg,
    ]));

    let baseline: Vec<Value> = read_all(&db).iter().map(value).collect();
    let inspected = &baseline[0];
    assert_eq!(
        inspected["runtime_profile"]["digest"],
        seal["profile_digest"]
    );
    let state_digest = inspected["current"]["state_digest"].clone();
    assert_eq!(baseline[1]["current_state_digest"], state_digest);
    assert_eq!(baseline[2]["current_state_digest"], state_digest);

    // With the signing key absent every read succeeds with identical output.
    let key_bytes = fs::read(&issuer_key).unwrap();
    fs::remove_file(&issuer_key).unwrap();
    for (output, expected) in read_all(&db).iter().zip(&baseline) {
        assert_eq!(&value(output), expected);
        assert!(output.stderr.is_empty(), "{}", stderr(output));
    }
    // Reads never open the key: unparseable bytes at its path change nothing.
    fs::write(&issuer_key, b"not a key").unwrap();
    for (output, expected) in read_all(&db).iter().zip(&baseline) {
        assert_eq!(&value(output), expected);
    }

    // Mutating and live-verification paths still require the signing key.
    fs::remove_file(&issuer_key).unwrap();
    for arguments in [
        vec!["require-standing", "--database", db.as_str()],
        vec![
            "verify-runtime-profile-v2",
            "--runtime-profile",
            profile_arg.as_str(),
        ],
    ] {
        let output = invoke(&arguments);
        assert!(
            !output.status.success(),
            "{arguments:?} accepted without the key"
        );
        assert!(
            stderr(&output).contains("No such file"),
            "{arguments:?}: {}",
            stderr(&output)
        );
    }
    fs::write(&issuer_key, &key_bytes).unwrap();
    fs::set_permissions(&issuer_key, fs::Permissions::from_mode(0o600)).unwrap();
    let _ = value(&invoke(&[
        "verify-runtime-profile-v2",
        "--runtime-profile",
        &profile_arg,
    ]));
    fs::remove_file(&issuer_key).unwrap();

    // Tampered public issuer material refuses; it is a mismatch, not absence.
    let trust_bytes = fs::read(&trust).unwrap();
    write_jcs(
        &trust,
        &json!({"issuers": [{
            "issuer_principal": "fixture-ag",
            "key_id": "fixture-key-1",
            "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        }]}),
    );
    for output in read_all(&db) {
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert!(stderr(&output).contains("pinned file identity changed"));
        assert!(!stderr(&output).contains("unavailable"));
    }
    fs::write(&trust, &trust_bytes).unwrap();

    // An absent enrolled file is reported typed, with everything else still
    // verified, and never exits as success.
    let validator_bytes = fs::read(&plan_validator).unwrap();
    fs::remove_file(&plan_validator).unwrap();
    for (output, expected) in read_all(&db).iter().zip(&baseline) {
        assert_eq!(output.status.code(), Some(3), "{}", stderr(output));
        assert_eq!(
            &serde_json::from_slice::<Value>(&output.stdout).unwrap(),
            expected
        );
        let diagnostic = stderr(output);
        let report: Value = serde_json::from_str(
            diagnostic
                .trim()
                .strip_prefix("enrolled file unavailable: ")
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            report["schema"],
            "ag.governed-loop.read-only-verification/v1"
        );
        assert_eq!(report["status"], "enrolled-file-unavailable");
        assert_eq!(
            report["unavailable"],
            json!([{
                "role": "shared_admission.plan_validator",
                "path": plan_validator,
                "identity": sha256_bytes(&validator_bytes)
            }])
        );
    }
    // Absence does not mask drift in a file that is present.
    fs::write(&catalog, b"{}").unwrap();
    let output = invoke(&["inspect", "--database", &db]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("pinned file identity changed"));
    fs::write(&plan_validator, &validator_bytes).unwrap();
    fs::set_permissions(&plan_validator, fs::Permissions::from_mode(0o700)).unwrap();
    write_jcs(
        &catalog,
        &json!({
            "schema": "ag.governed-loop.exact-work-catalog/v1",
            "entries": {
                "fixture.work/v1": {
                    "work_schema": "fixture.work/v1",
                    "subject": digest('d'),
                    "scope": digest('e'),
                    "precondition": {"required": [], "forbidden": []}
                }
            }
        }),
    );
    assert_eq!(value(&invoke(&["inspect", "--database", &db])), baseline[0]);

    // Tampered state refuses in every read.
    let tampered = state.join("tampered.sqlite");
    fs::copy(&database, &tampered).unwrap();
    {
        let connection = rusqlite::Connection::open(&tampered).unwrap();
        let changed = connection
            .execute(
                "UPDATE occurrences SET snapshot_jcs = CAST(replace(CAST(snapshot_jcs AS TEXT), ?1, ?2) AS BLOB)",
                [digest('b'), digest('c')],
            )
            .unwrap();
        assert_eq!(changed, 1);
    }
    for output in read_all(&tampered.display().to_string()) {
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert!(
            stderr(&output).contains("corrupt campaign store"),
            "{}",
            stderr(&output)
        );
    }
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}
