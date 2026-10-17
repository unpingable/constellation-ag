//! RC2 shim-conformance: deployment authorization through the real enforcement path
//! (cartography #94 "Shim conformance"; #90 provider-neutral deployment shim).
//!
//! A signed, ordinary-shaped proposal intent — the exact ingress an authorized agent caller
//! uses — that violates an existing catalog/authority constraint must be refused by the real
//! `EffectBrokerV1::handle_proposal` path before any effect occurs. The broker is constructed
//! with a recording effect runner: any bypass of validation would surface as a runner
//! invocation and be detected here. The positive control shows a conforming request proceeds
//! to canonicalization; the ratification control carries a conforming request through human
//! ratification and observes exactly one runner invocation, which is what makes the empty log
//! in the refusal cases a real signal. The negative control shows only that the recording double
//! records a direct call. No systemd, pointer, filesystem (outside tempdirs), or network effects.
//!
//! What the refusal cases establish is the typed response (`Refused` / `Indeterminate` rather
//! than `Canonicalized`): proposal ingress never invokes the runner for any request, valid or not,
//! so an empty log during ingress alone would hold even if validation were bypassed.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use ag_app::api::{
    AgdRequestV1, ApiResultV1, ArtifactTransferV1, EffectAdminRequestV1, EffectAdminResponseV1,
    EffectProposalRequestV1, EffectProposalResponseV1, GovernedProposalIngressV1,
    ProposalIngressProofV1,
};
use ag_app::config::{EffectTargetConfigV1, EffectdConfigV1};
use ag_app::effectd::{BrokerEffectRunnerV1, EffectBrokerV1, configured_catalog_identity};
use ag_app::peer::signed_principal_chain;
use ag_app::rpc_auth::{RpcKeyIdV1, RpcReplayGuardV1, RpcSignerV1, VerifiedRpcPrincipalV1};
use ag_effect::executor::{
    EXECUTION_RECEIPT_SCHEMA_V1, ExecutionIndeterminateCodeV1, ExecutionIndeterminateV1,
    ExecutionOutcomeV1, ExecutionPhaseV1, ExecutionReceiptV1,
};
use ag_effect::{
    CanonicalEffectV1, EFFECT_SCHEMA_V1, EffectIntentV1, ProposalIntentV1, SystemdUnitActionV1,
    TargetId,
};
use ag_primitives::{AuthorityDomain, Digest, Epoch, PrincipalChainV1};
use ag_protocol::{RequestEnvelopeV1, RequestId};
use ag_store::{Store, StoreIdentityV1, WriterIdentityV1};
use base64::Engine as _;
use nix::unistd::{getegid, geteuid};
use tempfile::TempDir;

fn now_unix_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("wall clock")
            .as_millis(),
    )
    .expect("wall clock fits u64")
}

/// Recorded runner invocations: (proposal, attempt, effect index, exact canonical effect).
type InvocationLog = Arc<Mutex<Vec<(Digest, Digest, u32, CanonicalEffectV1)>>>;

/// Test-double effect runner: records every invocation and performs no effect. Any bypass of
/// proposal validation that reached the effect boundary would be observed in this log.
#[derive(Clone, Default)]
struct RecordingEffectRunner {
    invocations: InvocationLog,
}

impl BrokerEffectRunnerV1 for RecordingEffectRunner {
    fn execute_once(
        &mut self,
        _store: &Store,
        proposal: &Digest,
        authorization: &Digest,
        attempt: &Digest,
        effect_index: u32,
        effect: &CanonicalEffectV1,
    ) -> ExecutionReceiptV1 {
        self.invocations.lock().expect("invocation log").push((
            proposal.clone(),
            attempt.clone(),
            effect_index,
            effect.clone(),
        ));
        ExecutionReceiptV1 {
            schema: EXECUTION_RECEIPT_SCHEMA_V1.to_owned(),
            proposal: proposal.clone(),
            authorization: authorization.clone(),
            attempt: attempt.clone(),
            effect_index,
            effect: effect.clone(),
            outcome: ExecutionOutcomeV1::Indeterminate {
                envelope: ExecutionIndeterminateV1 {
                    code: ExecutionIndeterminateCodeV1::BackendOutcomeUnknown,
                    phase: ExecutionPhaseV1::PrestateCheck,
                    detail: "recording test runner: no effect performed".to_owned(),
                    source_code: Some("recording_runner".to_owned()),
                    evidence: None,
                },
            },
        }
    }
}

struct Fixture {
    _dir: TempDir,
    target_path: PathBuf,
    broker: EffectBrokerV1<RecordingEffectRunner>,
    runner_log: InvocationLog,
    governor: RpcSignerV1,
    proposer: RpcSignerV1,
    governor_peer: VerifiedRpcPrincipalV1,
    admin_peer: VerifiedRpcPrincipalV1,
    proposer_chain: PrincipalChainV1,
    authority_domain: AuthorityDomain,
    epoch: Epoch,
}

fn fixture() -> Fixture {
    fixture_with_profile(None)
}

/// `security_profile` overrides the example config's "production" profile. Only the
/// ratification control uses "development": that profile waives the live authority-activation
/// receipt that a production effectd obtains at startup, and nothing else on this path.
fn fixture_with_profile(security_profile: Option<&str>) -> Fixture {
    let directory = TempDir::new().expect("temporary directory");
    let mut config: EffectdConfigV1 = toml::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../config/effectd.example.toml"
    )))
    .expect("effectd example config");
    if let Some(profile) = security_profile {
        profile.clone_into(&mut config.security_profile);
    }
    config.store.database = directory.path().join("effectd.db");
    config.store.object_store = directory.path().join("objects");
    let target_path = directory.path().join("managed.conf");
    config.targets = vec![EffectTargetConfigV1::ManagedFile {
        id: "managed-config".to_owned(),
        path: target_path.clone(),
        mode: 0o600,
        uid: geteuid().as_raw(),
        gid: getegid().as_raw(),
    }];

    let signer = |label: &str| {
        RpcSignerV1::generate_ephemeral_candidate_ingress(
            Digest::hash_domain("ag-rc2-shim-conformance-20261017", label.as_bytes()),
            RpcKeyIdV1::new(format!("{label}.v1")).expect("key ID"),
        )
        .expect("ephemeral signer")
        .0
    };
    let governor = signer("governor");
    let proposer = signer("proposer");
    let admin = signer("admin");
    config.agd_peer.rpc_key = governor
        .enrollment(30_000)
        .expect("governor enrollment")
        .key;
    config.proposer_peer.rpc_key = proposer
        .enrollment(30_000)
        .expect("proposer enrollment")
        .key;
    config.admin_peer.rpc_key = admin.enrollment(30_000).expect("admin enrollment").key;

    let governor_peer = VerifiedRpcPrincipalV1 {
        principal: config.agd_peer.rpc_key.principal.clone(),
        key_id: config.agd_peer.rpc_key.key_id.clone(),
    };
    let proposer_peer = VerifiedRpcPrincipalV1 {
        principal: config.proposer_peer.rpc_key.principal.clone(),
        key_id: config.proposer_peer.rpc_key.key_id.clone(),
    };
    let admin_peer = VerifiedRpcPrincipalV1 {
        principal: config.admin_peer.rpc_key.principal.clone(),
        key_id: config.admin_peer.rpc_key.key_id.clone(),
    };
    let authority_domain =
        AuthorityDomain::parse(&config.authority_domain).expect("authority domain");
    let epoch = Epoch::parse(&config.epoch).expect("epoch");
    let proposer_chain = signed_principal_chain(
        &proposer_peer,
        &config.proposer_peer,
        authority_domain.clone(),
        epoch,
    )
    .expect("proposer chain");

    let store = Store::open(
        &config.store.database,
        &config.store.object_store,
        StoreIdentityV1::current(0x4147_5232, "ag-rc2-shim-conformance-test")
            .expect("store identity"),
        &WriterIdentityV1 {
            writer_id: "ag-rc2-shim-conformance-writer".to_owned(),
            principal_digest: Digest::hash_bytes(b"ag-rc2-shim-conformance-writer"),
            process_nonce: "ag-rc2-shim-conformance-nonce".to_owned(),
            claimed_at_unix_ms: 1,
        },
    )
    .expect("store");
    let catalog_identity = configured_catalog_identity(&config.targets).expect("catalog identity");
    let runner = RecordingEffectRunner::default();
    let runner_log = Arc::clone(&runner.invocations);
    let broker = EffectBrokerV1::new(
        &config,
        &catalog_identity,
        store,
        runner,
        Arc::new(RpcReplayGuardV1::new(32).expect("replay guard")),
    )
    .expect("broker");

    Fixture {
        _dir: directory,
        target_path,
        broker,
        runner_log,
        governor,
        proposer,
        governor_peer,
        admin_peer,
        proposer_chain,
        authority_domain,
        epoch,
    }
}

impl Fixture {
    fn intent(
        &self,
        intent_id: &str,
        effect: EffectIntentV1,
        admitted: &[Digest],
    ) -> ProposalIntentV1 {
        ProposalIntentV1 {
            schema: EFFECT_SCHEMA_V1.to_owned(),
            intent_id: intent_id.to_owned(),
            authority_domain: self.authority_domain.clone(),
            epoch: self.epoch,
            proposer: self.proposer_chain.clone(),
            judgment: Digest::hash_bytes(b"admitted-judgment"),
            admitted_artifacts: admitted.iter().cloned().collect::<BTreeSet<_>>(),
            effects: vec![effect],
        }
    }

    /// Submits an intent exactly as an authorized agent caller does: a fresh governor challenge
    /// and a proposer-signed request envelope through `handle_proposal`.
    fn submit_signed(
        &mut self,
        intent: ProposalIntentV1,
        artifacts: Vec<ArtifactTransferV1>,
        request_id: &str,
    ) -> ApiResultV1<EffectProposalResponseV1> {
        let now = now_unix_ms();
        let enrollment = self
            .proposer
            .enrollment(30_000)
            .expect("proposer enrollment");
        let challenge = self
            .governor
            .issue_challenge(&enrollment, now)
            .expect("server challenge");
        let request = RequestEnvelopeV1::new(
            RequestId::new(request_id).expect("request ID"),
            AgdRequestV1::SubmitProposal {
                intent: Box::new(intent),
            },
        )
        .expect("request envelope");
        let proof = ProposalIngressProofV1 {
            server_challenge: challenge.clone(),
            signed_request: Box::new(
                self.proposer
                    .sign_request(request, &challenge, now)
                    .expect("signed request"),
            ),
        };
        self.broker.handle_proposal(
            EffectProposalRequestV1::SubmitAuthenticatedIntent {
                ingress: Box::new(GovernedProposalIngressV1::ExternalSigned {
                    proof: Box::new(proof),
                }),
                artifacts,
            },
            &self.governor_peer,
        )
    }
}

fn artifact(content: &[u8]) -> (Digest, ArtifactTransferV1) {
    let digest = Digest::hash_bytes(content);
    (
        digest.clone(),
        ArtifactTransferV1 {
            digest,
            byte_length: content.len() as u64,
            content_base64: base64::engine::general_purpose::STANDARD.encode(content),
        },
    )
}

fn no_effects_observed(fx: &Fixture) {
    assert!(
        fx.runner_log.lock().expect("invocation log").is_empty(),
        "the effect runner must never be invoked by proposal ingress"
    );
    assert!(
        !fx.target_path.exists(),
        "no target-path effect may occur: {}",
        fx.target_path.display()
    );
}

/// Positive control: a conforming signed request is processed by the same path — canonicalized
/// and parked for ratification — proving the refusals below are discriminating, not a path that
/// rejects everything. Even here the runner is not invoked: effects require ratification.
#[test]
fn positive_control_conforming_signed_request_canonicalizes_without_effect() {
    let mut fx = fixture();
    let (digest, transfer) = artifact(b"managed = true\n");
    let intent = fx.intent(
        "stable-intent-conforming-1",
        EffectIntentV1::ManagedFilePut {
            target: TargetId::parse("managed-config").expect("target"),
            content: digest.clone(),
        },
        &[digest],
    );
    let first = fx.submit_signed(
        intent.clone(),
        vec![transfer.clone()],
        "submission-conforming-1",
    );
    let ApiResultV1::Ok {
        response: EffectProposalResponseV1::Canonicalized { .. },
    } = &first
    else {
        panic!("conforming request must canonicalize: {first:?}");
    };
    // The exact same signed proof replays the durable record; a fresh proof of the same intent
    // returns the same response: persistence is deterministic, not recomputed per caller.
    let replay = fx.submit_signed(intent, vec![transfer], "submission-conforming-2");
    assert_eq!(&first, &replay);
    no_effects_observed(&fx);
}

/// Ratification control: the same conforming request, inspected and ratified by the enrolled
/// operator, reaches the effect runner exactly once with the catalog-bound canonical effect.
/// This proves the recording runner sits on the real execution path, so its empty log in the
/// refusal cases is evidence rather than a property of ingress. The recording runner performs
/// no effect and reports Indeterminate, so the target file still does not exist.
#[test]
fn ratification_control_reaches_the_runner_exactly_once() {
    let mut fx = fixture_with_profile(Some("development"));
    let (digest, transfer) = artifact(b"managed = ratified\n");
    let intent = fx.intent(
        "stable-intent-ratified-1",
        EffectIntentV1::ManagedFilePut {
            target: TargetId::parse("managed-config").expect("target"),
            content: digest.clone(),
        },
        std::slice::from_ref(&digest),
    );
    let submitted = fx.submit_signed(intent, vec![transfer], "submission-ratified-1");
    let ApiResultV1::Ok {
        response:
            EffectProposalResponseV1::Canonicalized {
                proposal_digest, ..
            },
    } = submitted
    else {
        panic!("conforming request must canonicalize: {submitted:?}");
    };
    assert!(
        fx.runner_log.lock().expect("invocation log").is_empty(),
        "canonicalization alone must not invoke the runner"
    );

    let inspected = fx.broker.handle_admin(
        EffectAdminRequestV1::InspectProposal {
            proposal: proposal_digest.clone(),
        },
        &fx.admin_peer,
        &Digest::hash_domain("ag-rc2-shim-conformance/inspection", b"ratified-1"),
    );
    let ApiResultV1::Ok {
        response: EffectAdminResponseV1::Proposal { challenge, .. },
    } = inspected
    else {
        panic!("operator inspection must return a ratification challenge: {inspected:?}");
    };
    let ratified = fx.broker.handle_admin(
        EffectAdminRequestV1::Ratify {
            proposal: proposal_digest.clone(),
            challenge,
        },
        &fx.admin_peer,
        &Digest::hash_domain("ag-rc2-shim-conformance/ratification", b"ratified-1"),
    );
    assert!(
        matches!(
            &ratified,
            ApiResultV1::Ok {
                response: EffectAdminResponseV1::ExecutionReceipt { .. }
            }
        ),
        "ratification must execute through the runner: {ratified:?}"
    );

    let invocations = fx.runner_log.lock().expect("invocation log");
    assert_eq!(invocations.len(), 1, "exactly one runner invocation");
    let (proposal, _attempt, effect_index, effect) = &invocations[0];
    assert_eq!(proposal, &proposal_digest);
    assert_eq!(*effect_index, 0);
    let CanonicalEffectV1::ManagedFilePut {
        target,
        path,
        content,
        ..
    } = effect
    else {
        panic!("runner received another effect family: {effect:?}");
    };
    assert_eq!(target.as_str(), "managed-config");
    assert_eq!(
        PathBuf::from(path),
        fx.target_path,
        "the path comes from the catalog"
    );
    assert_eq!(content, &digest);
    drop(invocations);
    assert!(
        !fx.target_path.exists(),
        "the recording runner performs no effect"
    );
}

/// Boundary case 1: an ordinary-shaped signed deployment request naming a target the root-owned
/// catalog does not admit. The request passes signature and lineage verification and is rejected
/// before any effect. Note the exact stage: catalog membership is enforced at the broker's
/// observation step (typed `Indeterminate`, phase `TargetObservation`; effectd.rs
/// `prepare_intent` "target not catalogued"), with the compiler's semantic `UnknownTarget`
/// refusal as defense in depth behind it.
#[test]
fn request_to_uncatalogued_target_is_rejected_before_any_effect() {
    let mut fx = fixture();
    let (digest, transfer) = artifact(b"nothing \xce\xa9\n");
    let intent = fx.intent(
        "stable-intent-uncatalogued-1",
        EffectIntentV1::ManagedFilePut {
            target: TargetId::parse("managed-config-backup").expect("target"),
            content: digest.clone(),
        },
        &[digest],
    );
    let first = fx.submit_signed(
        intent.clone(),
        vec![transfer.clone()],
        "submission-uncatalogued-1",
    );
    let ApiResultV1::Ok {
        response: EffectProposalResponseV1::Indeterminate { .. },
    } = &first
    else {
        panic!("uncatalogued target must be rejected at observation: {first:?}");
    };
    let replay = fx.submit_signed(intent, vec![transfer], "submission-uncatalogued-2");
    assert_eq!(
        &first, &replay,
        "the rejected outcome is the durable record, not a fresh decision"
    );
    no_effects_observed(&fx);
}

/// Boundary case 2: an ordinary-shaped signed request that exceeds the catalogued target's
/// authority — it asks to restart "managed-config" as a systemd unit, but the catalog admits
/// that ID only as a managed file. The real path refuses with typed semantic evidence at
/// compilation (`TargetKindMismatch`), before any effect.
#[test]
fn request_exceeding_catalogued_target_authority_is_refused_before_any_effect() {
    let mut fx = fixture();
    let intent = fx.intent(
        "stable-intent-overreach-1",
        EffectIntentV1::SystemdUnit {
            target: TargetId::parse("managed-config").expect("target"),
            action: SystemdUnitActionV1::Restart,
        },
        &[],
    );
    let first = fx.submit_signed(intent.clone(), vec![], "submission-overreach-1");
    let ApiResultV1::Ok {
        response: EffectProposalResponseV1::Refused { .. },
    } = &first
    else {
        panic!("authority overreach must be semantically refused: {first:?}");
    };
    let replay = fx.submit_signed(intent, vec![], "submission-overreach-2");
    assert_eq!(
        &first, &replay,
        "the refusal is the durable record, not a fresh decision"
    );
    no_effects_observed(&fx);
}

/// Negative control (deliberately invalid): bypass the broker entirely and invoke the effect
/// runner directly with the canonical effect the overreach request would have needed. This
/// shows only that the recording double records a direct call; that the broker's execution
/// path reaches it is shown by the ratification control.
#[test]
fn negative_control_harness_detects_an_actual_runner_invocation() {
    let directory = TempDir::new().expect("temporary directory");
    let store = Store::open(
        directory.path().join("scratch.db"),
        directory.path().join("objects"),
        StoreIdentityV1::current(0x4147_5232, "ag-rc2-shim-conformance-control")
            .expect("store identity"),
        &WriterIdentityV1 {
            writer_id: "ag-rc2-shim-conformance-control-writer".to_owned(),
            principal_digest: Digest::hash_bytes(b"ag-rc2-shim-conformance-control-writer"),
            process_nonce: "ag-rc2-shim-conformance-control-nonce".to_owned(),
            claimed_at_unix_ms: 1,
        },
    )
    .expect("scratch store");
    let mut runner = RecordingEffectRunner::default();
    let log = Arc::clone(&runner.invocations);
    assert!(log.lock().expect("log").is_empty());

    let effect = CanonicalEffectV1::ManagedFilePut {
        target: TargetId::parse("managed-config").expect("target"),
        path: "/tmp/ag-rc2-negative-control-never-written.conf".to_owned(),
        expected_content: None,
        content: Digest::hash_bytes(b"bypassed-validation content"),
        mode: 0o600,
        uid: geteuid().as_raw(),
        gid: getegid().as_raw(),
    };
    let receipt = runner.execute_once(
        &store,
        &Digest::hash_bytes(b"proposal-never-canonicalized"),
        &Digest::hash_bytes(b"authorization-never-burned"),
        &Digest::hash_bytes(b"attempt-never-journaled"),
        0,
        &effect,
    );
    let invocations = log.lock().expect("log");
    assert_eq!(
        invocations.len(),
        1,
        "the harness must observe the direct invocation"
    );
    let (proposal, _attempt, effect_index, recorded) = &invocations[0];
    assert_eq!(
        proposal,
        &Digest::hash_bytes(b"proposal-never-canonicalized")
    );
    assert_eq!(*effect_index, 0);
    assert_eq!(
        recorded, &effect,
        "the recorded effect is exactly the requested one"
    );
    drop(invocations);
    assert!(
        matches!(receipt.outcome, ExecutionOutcomeV1::Indeterminate { .. }),
        "the recording runner performs no effect and says so"
    );
    assert!(
        !PathBuf::from("/tmp/ag-rc2-negative-control-never-written.conf").exists(),
        "no filesystem effect occurred even in the bypass control"
    );
}
