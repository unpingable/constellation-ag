#![allow(
    clippy::wildcard_imports,
    reason = "the record-driven CLI exposes the governed kernel's complete typed input vocabulary"
)]
#![allow(
    clippy::too_many_lines,
    reason = "the closed command dispatch remains one explicit auditable match"
)]

//! Exact, record-driven production CLI for the canonical AG governed loop.
//!
//! This CLI is deliberately not a planner.  It accepts only typed exact
//! records and invokes external currentness/authority owners at each live
//! boundary.  The `SQLite` campaign store is the sole program-counter owner.

use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use ag_app::governed_loop::{
    CampaignEngineErrorV1, CampaignEngineV1, CampaignRecoveryV1, VersionedExactWorkCatalogV1,
};
use ag_app::governed_ports::{
    AgIssuanceSignerV1, CommandDocketCustodyPortV1, CommandDocketReconciliationPortV1,
    CommandGovernedInterventionVerifierV1, CommandHumanDispositionVerifierV1,
    CommandObservationResolverV1, CommandStandingResolverV1, GOVERNED_RUNTIME_PROFILE_SCHEMA_V1,
    GOVERNED_RUNTIME_PROFILE_SCHEMA_V2, GovernedRuntimeProfileEnrollmentV1,
    GovernedRuntimeProfileEnrollmentV2, GovernedRuntimeProfileV1, GovernedRuntimeProfileV2,
};
use ag_app::intervention_ingress::*;
use ag_app::shared_admission::RecordReviewInputV1;
use ag_campaign::CampaignId;
use ag_campaign::governed::*;
use ag_primitives::{Digest, JcsDocument};
use ag_protocol::strict_json_from_slice;
use ag_store::campaign::{CampaignReplayReportV1, CampaignTransitionEvidenceV1};
use anyhow::{Context as _, bail};
use base64::Engine as _;
use clap::{Args, Parser, Subcommand};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};

#[derive(Debug, Parser)]
#[command(
    name = "ag-loopctl",
    version,
    about = "Canonical AG exact-occurrence governed-loop controller"
)]
struct Arguments {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Measure deployment inputs and create one immutable runtime profile.
    SealRuntimeProfile {
        #[arg(long)]
        enrollment: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Measure deployment inputs into an explicit protected V2 profile.
    SealRuntimeProfileV2 {
        #[arg(long)]
        enrollment: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Remeasure and validate one sealed runtime profile without creating authority.
    VerifyRuntimeProfile {
        #[arg(long)]
        runtime_profile: PathBuf,
    },
    /// Remeasure and validate an explicit protected V2 profile.
    VerifyRuntimeProfileV2 {
        #[arg(long)]
        runtime_profile: PathBuf,
    },
    /// Construct canonical intervention-request bytes from one exact typed draft.
    PrepareInterventionRequest {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Inspect the exact canonical intervention-request bytes without mutation.
    InspectInterventionRequest {
        #[arg(long)]
        request: PathBuf,
    },
    /// Sign/package exact request bytes for one genesis-bound AG runtime.
    PackageInterventionSubmission {
        #[arg(long)]
        runtime_profile: PathBuf,
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        submitter_principal: String,
        #[arg(long)]
        submitter_key_id: String,
        #[arg(long)]
        submitter_key: PathBuf,
        #[arg(long)]
        created_at_unix_ms: u64,
        #[arg(long)]
        expires_at_unix_ms: u64,
        #[arg(long)]
        output: PathBuf,
    },
    /// Create one authority-empty campaign occurrence.
    Init {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        genesis: PathBuf,
        /// Deployment-owned policy and Docket boundary, pinned at genesis.
        #[arg(long)]
        runtime_profile: PathBuf,
    },
    /// Create a fresh campaign bound to a protected V2 runtime profile.
    InitV2 {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        genesis: PathBuf,
        #[arg(long)]
        runtime_profile: PathBuf,
    },
    /// Print the exact authoritative current occurrence.
    Status {
        #[arg(long)]
        database: PathBuf,
    },
    /// Deterministically replay and verify the authoritative store.
    Replay {
        #[arg(long)]
        database: PathBuf,
    },
    /// Emit the verified canonical transition journal in durable order.
    History {
        #[arg(long)]
        database: PathBuf,
    },
    /// Emit verified durable non-authorizing refusal facts.
    Refusals {
        #[arg(long)]
        database: PathBuf,
    },
    /// Authenticate and append occurrence-bound independent review evidence.
    RecordReview {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        input: PathBuf,
    },
    /// Evaluate protected permission without granting or spending authority.
    PermissionPreflight {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        input: PathBuf,
    },
    /// Advance one existing campaign through a finite, sealed foreground run.
    Run {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        run_input: PathBuf,
    },
    /// Emit one machine-readable state/replay/profile projection for operators.
    Inspect {
        #[arg(long)]
        database: PathBuf,
    },
    /// Resolve a fresh observation and record one exact proposal.
    RecordProposal {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        observation_resolver: PathBuf,
        #[arg(long)]
        expected_observation_resolver_id: String,
        /// Required exact Maude binding for a protected V2 campaign.
        #[arg(long)]
        plan_binding: Option<PathBuf>,
    },
    /// Enter the explicit current-standing-required state.
    RequireStanding {
        #[arg(long)]
        database: PathBuf,
    },
    /// Resolve current premises and record a positive AG decision only.
    Decide {
        #[arg(long)]
        database: PathBuf,
        #[command(flatten)]
        gate: GateArguments,
    },
    /// Re-resolve current premises and durably spend the one AG authorization.
    Authorize {
        #[arg(long)]
        database: PathBuf,
        #[command(flatten)]
        gate: GateArguments,
    },
    /// Submit the already-durable exact issuance to Docket custody.
    Dispatch {
        #[arg(long)]
        database: PathBuf,
        #[command(flatten)]
        docket: DocketArguments,
    },
    /// Read-only reconcile/poll the exact Docket attempt.
    Poll {
        #[arg(long)]
        database: PathBuf,
        #[command(flatten)]
        docket: DocketArguments,
    },
    /// Apply the PC-specific restart law without reconstructing authority.
    Recover {
        #[arg(long)]
        database: PathBuf,
        #[command(flatten)]
        docket: DocketArguments,
    },
    /// Open a distinct authority-empty occurrence after settlement.
    Continue {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        input: PathBuf,
    },
    /// Persist one read-only probe-count fact.
    NoteProbe {
        #[arg(long)]
        database: PathBuf,
    },
    /// Halt from an authority-safe boundary.
    Halt {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        input: PathBuf,
    },
    /// Consume one escalation budget fact and halt.
    Escalate {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        input: PathBuf,
    },
    /// Apply one exact externally verified human disposition.
    ApplyDisposition {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        observation_resolver: PathBuf,
        #[arg(long)]
        expected_observation_resolver_id: String,
        #[arg(long)]
        human_verifier: PathBuf,
    },
    /// Authenticate and submit one already-typed exact intervention envelope.
    SubmitIntervention {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        submission: PathBuf,
        /// Exact Docket executor plan; required only for `reconcile_attempt`.
        #[arg(long)]
        executor_config: Option<PathBuf>,
    },
    /// Read-only lookup of one exact immutable submission receipt chain.
    InterventionReceipt {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        submission: String,
    },
    /// Read-only projection of every immutable submission receipt.
    InterventionSubmissions {
        #[arg(long)]
        database: PathBuf,
    },
    /// Complete only from a fresh observation boundary with no residuals.
    Complete {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        observation_resolver: PathBuf,
        #[arg(long)]
        expected_observation_resolver_id: String,
    },
    /// Record a typed non-authorizing refusal without advancing the PC.
    Refuse {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        input: PathBuf,
    },
}

#[derive(Debug, Args)]
struct GateArguments {
    #[arg(long)]
    catalog: PathBuf,
    #[arg(long)]
    observation_resolver: PathBuf,
    #[arg(long)]
    expected_observation_resolver_id: String,
    #[arg(long)]
    standing_resolver: PathBuf,
    #[arg(long)]
    expected_standing_resolver_id: String,
    /// Maximum accepted standing-answer lifetime in milliseconds.
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    max_standing_ttl_ms: u64,
    #[arg(long)]
    controlling_review: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct DocketArguments {
    #[arg(long)]
    docket: PathBuf,
    #[arg(long)]
    docket_state: PathBuf,
    #[arg(long)]
    docket_trust: PathBuf,
    #[arg(long)]
    docket_standing_resolver: PathBuf,
    #[arg(long)]
    executor: PathBuf,
    #[arg(long)]
    executor_config: PathBuf,
    #[arg(long)]
    issuer_principal: String,
    #[arg(long)]
    issuer_key_id: String,
    #[arg(long)]
    issuer_key: PathBuf,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GenesisInputV1 {
    campaign: CampaignId,
    occurrence: OccurrenceId,
    program: ProgramBasisRefV1,
    /// The exact executable-work identity this occurrence is opened to
    /// govern, taken from the Nightshift-prepared binding.
    expected_ag_work: Digest,
    residuals: ResidualSetV1,
    budget: LoopBudgetV1,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProposalInputV1 {
    observation: ObservationRefV1,
    proposal: ExactWorkProposalV1,
    class: ProposalClassV1,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ContinuationInputV1 {
    occurrence: OccurrenceId,
    /// The exact executable-work identity the continuation occurrence is
    /// opened to govern.
    expected_ag_work: Digest,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HaltInputV1 {
    reason: HaltReasonRefV1,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HumanDispositionInputV1 {
    artifact: HumanDispositionV1,
    expected_principal: HumanPrincipalRefV1,
    expected_mandate: MandateRefV1,
    new_occurrence: Option<OccurrenceId>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CompletionInputV1 {
    observation: ObservationRefV1,
    subject: Digest,
    terminal_witness: TerminalWitnessRefV1,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RefusalInputV1 {
    code: RefusalCodeV1,
    evidence: Option<Digest>,
}

const RUNTIME_PROFILE_SEAL_RECEIPT_SCHEMA_V1: &str =
    "ag.governed-loop.runtime-profile-seal-receipt/v1";
const OPERATIONAL_SNAPSHOT_SCHEMA_V1: &str = "ag.governed-loop.operational-snapshot/v1";

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RuntimeProfileSealReceiptV1 {
    schema: &'static str,
    profile_schema: &'static str,
    profile_digest: Digest,
    observation_resolver_id: String,
    standing_resolver_id: String,
    issuer_principal: String,
    issuer_key_id: String,
    intervention_submitter_principal: Option<String>,
    intervention_submitter_key_id: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct RuntimeProfileBindingV1 {
    schema: String,
    digest: Digest,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct OperationalSnapshotV1 {
    schema: &'static str,
    current: OccurrenceSnapshotV1,
    replay: CampaignReplayReportV1,
    runtime_profile: RuntimeProfileBindingV1,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PermissionPreflightInputV1 {
    schema: String,
    binding_id: Digest,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RunInputV1 {
    schema: String,
    campaign: CampaignId,
    runtime_profile_digest: Digest,
    plan_binding: PathBuf,
    review_input: PathBuf,
    nightshift_cycle_request: PathBuf,
    executor_config: PathBuf,
    continuation_input: Option<PathBuf>,
    max_steps: u64,
    max_polls: u64,
    deadline_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RunOccurrenceMaterialV1 {
    occurrence: Option<OccurrenceId>,
    plan_binding: PathBuf,
    plan_binding_sha256: Option<String>,
    review_input: PathBuf,
    nightshift_cycle_request: PathBuf,
    nightshift_cycle_request_sha256: Option<String>,
    executor_config: PathBuf,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RunInitialMaterialV1 {
    occurrence: OccurrenceId,
    plan_binding: PathBuf,
    plan_binding_sha256: String,
    review_input: PathBuf,
    nightshift_cycle_request: PathBuf,
    nightshift_cycle_request_sha256: String,
    executor_config: PathBuf,
}

impl RunInitialMaterialV1 {
    fn material(self) -> RunOccurrenceMaterialV1 {
        RunOccurrenceMaterialV1 {
            occurrence: Some(self.occurrence),
            plan_binding: self.plan_binding,
            plan_binding_sha256: Some(self.plan_binding_sha256),
            review_input: self.review_input,
            nightshift_cycle_request: self.nightshift_cycle_request,
            nightshift_cycle_request_sha256: Some(self.nightshift_cycle_request_sha256),
            executor_config: self.executor_config,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RunInputV2 {
    schema: String,
    campaign: CampaignId,
    runtime_profile_digest: Digest,
    initial: RunInitialMaterialV1,
    continuations: Vec<PathBuf>,
    max_steps: u64,
    max_polls: u64,
    deadline_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RunContinuationV1 {
    schema: String,
    campaign: CampaignId,
    predecessor_occurrence: OccurrenceId,
    predecessor_expected_ag_work: Digest,
    occurrence: OccurrenceId,
    expected_ag_work: Digest,
    plan_binding: PathBuf,
    plan_binding_sha256: String,
    review_input: PathBuf,
    nightshift_cycle_request: PathBuf,
    nightshift_cycle_request_sha256: String,
    executor_config: PathBuf,
}

struct NormalizedRunInput {
    campaign: CampaignId,
    profile_digest: Digest,
    initial: RunOccurrenceMaterialV1,
    v1_continuation: Option<PathBuf>,
    v2_continuations: Vec<PathBuf>,
    max_steps: u64,
    max_polls: u64,
    deadline_unix_ms: u64,
    is_v2: bool,
}

impl RunContinuationV1 {
    fn material(&self) -> RunOccurrenceMaterialV1 {
        RunOccurrenceMaterialV1 {
            occurrence: Some(self.occurrence),
            plan_binding: self.plan_binding.clone(),
            plan_binding_sha256: Some(self.plan_binding_sha256.clone()),
            review_input: self.review_input.clone(),
            nightshift_cycle_request: self.nightshift_cycle_request.clone(),
            nightshift_cycle_request_sha256: Some(self.nightshift_cycle_request_sha256.clone()),
            executor_config: self.executor_config.clone(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RunStatusV1 {
    schema: String,
    run_id: Digest,
    status: String,
    reason: String,
    program_counter: ProgramCounterV1,
    steps: u64,
    polls: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum V2StartupDisposition {
    ReplayTerminal,
    ValidateInitial,
    ResumeActive,
}

fn v2_startup_disposition(
    prior_status: Option<&str>,
    declared_initial: Option<OccurrenceId>,
    current: OccurrenceId,
) -> anyhow::Result<V2StartupDisposition> {
    match prior_status {
        Some("terminal") => Ok(V2StartupDisposition::ReplayTerminal),
        Some("active" | "waiting") => Ok(V2StartupDisposition::ResumeActive),
        None if declared_initial == Some(current) => Ok(V2StartupDisposition::ValidateInitial),
        None => bail!("new V2 run initial occurrence differs from the current campaign occurrence"),
        Some(_) => bail!("V2 run has an unsupported durable lifecycle status"),
    }
}

fn main() -> anyhow::Result<()> {
    let arguments = Arguments::parse();
    let now = now_unix_ms;
    match arguments.command {
        Command::SealRuntimeProfile { enrollment, output } => {
            let enrollment: GovernedRuntimeProfileEnrollmentV1 = read_exact_record(&enrollment)?;
            let profile = enrollment.seal()?;
            let canonical = JcsDocument::canonicalize(&profile)?;
            write_exact_file(&output, canonical.as_bytes())?;
            write_exact(&runtime_profile_receipt(&profile, canonical.as_bytes()))
        }
        Command::SealRuntimeProfileV2 { enrollment, output } => {
            let enrollment: GovernedRuntimeProfileEnrollmentV2 = read_exact_record(&enrollment)?;
            let profile = enrollment.seal()?;
            let canonical = JcsDocument::canonicalize(&profile)?;
            write_exact_file(&output, canonical.as_bytes())?;
            write_exact(&runtime_profile_receipt_v2(&profile, canonical.as_bytes()))
        }
        Command::VerifyRuntimeProfile { runtime_profile } => {
            let profile: GovernedRuntimeProfileV1 = read_exact_record(&runtime_profile)?;
            profile.verify_genesis()?;
            let canonical = JcsDocument::canonicalize(&profile)?;
            write_exact(&runtime_profile_receipt(&profile, canonical.as_bytes()))
        }
        Command::VerifyRuntimeProfileV2 { runtime_profile } => {
            let profile: GovernedRuntimeProfileV2 = read_exact_record(&runtime_profile)?;
            profile.verify_genesis()?;
            let canonical = JcsDocument::canonicalize(&profile)?;
            write_exact(&runtime_profile_receipt_v2(&profile, canonical.as_bytes()))
        }
        Command::PrepareInterventionRequest { input, output } => {
            let draft: GovernedInterventionRequestDraftV1 = read_exact_record(&input)?;
            let request = draft.construct()?;
            let canonical = JcsDocument::canonicalize(&request)?;
            write_exact_file(&output, canonical.as_bytes())?;
            write_exact(&inspect_request_bytes(canonical.as_bytes())?)
        }
        Command::InspectInterventionRequest { request } => {
            let bytes = read_exact_input(&request, max_request_bytes())?;
            write_exact(&inspect_request_bytes(&bytes)?)
        }
        Command::PackageInterventionSubmission {
            runtime_profile,
            request,
            submitter_principal,
            submitter_key_id,
            submitter_key,
            created_at_unix_ms,
            expires_at_unix_ms,
            output,
        } => {
            let profile: GovernedRuntimeProfileV1 = read_exact_record(&runtime_profile)?;
            let ingress = profile
                .intervention_ingress
                .as_ref()
                .context("runtime profile has no intervention ingress")?;
            if ingress.submitter_principal != submitter_principal
                || ingress.submitter_key_id != submitter_key_id
            {
                bail!("packager identity differs from the runtime-profile ingress");
            }
            let signer = GovernedInterventionSubmissionSignerV1::from_protected_file(
                submitter_principal,
                submitter_key_id,
                &submitter_key,
            )?;
            if signer.public_key_b64() != ingress.submitter_public_key {
                bail!("packager key differs from the runtime-profile ingress key");
            }
            let request_bytes = read_exact_input(&request, max_request_bytes())?;
            let profile_jcs = JcsDocument::canonicalize(&profile)?;
            let submission = signer.package(
                &request_bytes,
                runtime_profile_digest(profile_jcs.as_bytes()),
                created_at_unix_ms,
                expires_at_unix_ms,
            )?;
            let canonical = JcsDocument::canonicalize(&submission)?;
            write_exact_file(&output, canonical.as_bytes())?;
            write_exact(&submission)
        }
        Command::Init {
            database,
            genesis,
            runtime_profile,
        } => {
            let input: GenesisInputV1 = read_exact_record(&genesis)?;
            let profile: GovernedRuntimeProfileV1 = read_exact_record(&runtime_profile)?;
            profile.verify_genesis()?;
            let profile_jcs = JcsDocument::canonicalize(&profile)?;
            let engine = CampaignEngineV1::create_with_runtime_profile(
                &database,
                input.campaign,
                input.occurrence,
                input.program,
                input.expected_ag_work,
                input.residuals,
                input.budget,
                GOVERNED_RUNTIME_PROFILE_SCHEMA_V1,
                profile_jcs.as_bytes(),
                now()?,
            )?;
            write_exact(&engine.current()?)
        }
        Command::InitV2 {
            database,
            genesis,
            runtime_profile,
        } => {
            let input: GenesisInputV1 = read_exact_record(&genesis)?;
            let profile: GovernedRuntimeProfileV2 = read_exact_record(&runtime_profile)?;
            profile.verify_genesis()?;
            let profile_jcs = JcsDocument::canonicalize(&profile)?;
            let engine = CampaignEngineV1::create_with_runtime_profile(
                &database,
                input.campaign,
                input.occurrence,
                input.program,
                input.expected_ag_work,
                input.residuals,
                input.budget,
                GOVERNED_RUNTIME_PROFILE_SCHEMA_V2,
                profile_jcs.as_bytes(),
                now()?,
            )?;
            write_exact(&engine.current()?)
        }
        Command::Status { database } => {
            let (engine, _) = open_bound(&database)?;
            write_exact(&engine.current()?)
        }
        Command::RecordReview { database, input } => {
            let input: RecordReviewInputV1 = read_exact_record(&input)?;
            let mut engine = CampaignEngineV1::open(&database)?;
            write_exact(&engine.record_review(&input, now()?)?)
        }
        Command::PermissionPreflight { database, input } => {
            let input: PermissionPreflightInputV1 = read_exact_record(&input)?;
            if input.schema != "ag.governed-loop.permission-preflight-input/v1" {
                bail!("unsupported permission-preflight input schema");
            }
            let (engine, profile) = open_bound(&database)?;
            let catalog: VersionedExactWorkCatalogV1 =
                read_exact_record(&profile.exact_work_catalog.path)?;
            let review = profile
                .controlling_review
                .as_ref()
                .map(|pinned| read_exact_record(&pinned.path))
                .transpose()?;
            let mut observation =
                CommandObservationResolverV1::new(profile.observation_resolver.path.clone());
            let mut standing =
                CommandStandingResolverV1::new(profile.standing_resolver.path.clone());
            write_exact(&engine.permission_preflight_versioned(
                input.binding_id,
                &mut observation,
                &mut standing,
                &catalog,
                review.as_ref(),
                &profile.observation_resolver_id,
                &profile.standing_resolver_id,
                profile.max_standing_ttl_ms,
                now()?,
            )?)
        }
        Command::Run {
            database,
            run_input,
        } => run_finite(&database, &run_input, now),
        Command::Replay { database } => {
            let (engine, _) = open_bound(&database)?;
            write_exact(&engine.replay()?)
        }
        Command::History { database } => {
            let (engine, _) = open_bound(&database)?;
            write_exact(&engine.history()?)
        }
        Command::Refusals { database } => {
            let (engine, _) = open_bound(&database)?;
            write_exact(&engine.refusal_history()?)
        }
        Command::Inspect { database } => {
            let (engine, _) = open_bound(&database)?;
            let stored = engine
                .runtime_profile()?
                .context("campaign has no genesis-bound runtime profile")?;
            let current = engine.current()?;
            let replay = engine.replay()?;
            if replay.current_state_digest != *current.state_digest() {
                bail!("operational snapshot state differs from deterministic replay");
            }
            write_exact(&OperationalSnapshotV1 {
                schema: OPERATIONAL_SNAPSHOT_SCHEMA_V1,
                current,
                replay,
                runtime_profile: RuntimeProfileBindingV1 {
                    schema: stored.schema,
                    digest: stored.digest,
                },
            })
        }
        Command::RecordProposal {
            database,
            input,
            observation_resolver,
            expected_observation_resolver_id,
            plan_binding,
        } => {
            let input: ProposalInputV1 = read_exact_record(&input)?;
            let (mut engine, profile) = open_bound(&database)?;
            let _ = profile
                .observation_resolver
                .verify_presented(&observation_resolver, true)?;
            if expected_observation_resolver_id != profile.observation_resolver_id {
                bail!("caller substituted the genesis-pinned observation resolver identity");
            }
            let mut observation =
                CommandObservationResolverV1::new(profile.observation_resolver.path.clone());
            let protected = engine
                .runtime_profile()?
                .is_some_and(|stored| stored.schema == GOVERNED_RUNTIME_PROFILE_SCHEMA_V2);
            let state = if protected {
                let binding = read_exact_input(
                    plan_binding
                        .as_deref()
                        .context("protected campaign requires --plan-binding")?,
                    16 * 1024 * 1024,
                )?;
                engine.record_proposal_with_shared_admission(
                    input.observation,
                    input.proposal,
                    input.class,
                    &mut observation,
                    &profile.observation_resolver_id,
                    &binding,
                    now()?,
                )?
            } else {
                if plan_binding.is_some() {
                    bail!("V1 campaign does not accept shared plan binding");
                }
                engine.record_proposal(
                    input.observation,
                    input.proposal,
                    input.class,
                    &mut observation,
                    &profile.observation_resolver_id,
                    now()?,
                )?
            };
            write_exact(&state)
        }
        Command::RequireStanding { database } => {
            let (mut engine, _) = open_bound(&database)?;
            write_exact(&engine.require_standing(now()?)?)
        }
        Command::Decide { database, gate } => {
            let (mut engine, profile) = open_bound(&database)?;
            let (mut observation, mut standing, catalog, review) =
                gate_components(&profile, &gate)?;
            write_exact(&engine.decide_versioned(
                &mut observation,
                &mut standing,
                &catalog,
                review.as_ref(),
                &profile.observation_resolver_id,
                &profile.standing_resolver_id,
                profile.max_standing_ttl_ms,
                now()?,
            )?)
        }
        Command::Authorize { database, gate } => {
            let (mut engine, profile) = open_bound(&database)?;
            let (mut observation, mut standing, catalog, review) =
                gate_components(&profile, &gate)?;
            write_exact(&engine.authorize_versioned(
                &mut observation,
                &mut standing,
                &catalog,
                review.as_ref(),
                &profile.observation_resolver_id,
                &profile.standing_resolver_id,
                profile.max_standing_ttl_ms,
                now()?,
            )?)
        }
        Command::Dispatch { database, docket } => {
            let (mut engine, profile) = open_bound(&database)?;
            let mut docket = docket_port(&profile, &docket)?;
            write_exact(&engine.dispatch(&mut docket, now()?)?)
        }
        Command::Poll { database, docket } => {
            let (mut engine, profile) = open_bound(&database)?;
            let mut docket = docket_port(&profile, &docket)?;
            let _ = engine.poll_docket(&mut docket, now()?)?;
            write_exact(&engine.current()?)
        }
        Command::Recover { database, docket } => {
            let (mut engine, profile) = open_bound(&database)?;
            let mut docket = docket_port(&profile, &docket)?;
            write_exact(&engine.recover(&mut docket, now()?)?)
        }
        Command::Continue { database, input } => {
            let input: ContinuationInputV1 = read_exact_record(&input)?;
            let (mut engine, _) = open_bound(&database)?;
            write_exact(&engine.open_continuation(
                input.occurrence,
                input.expected_ag_work,
                now()?,
            )?)
        }
        Command::NoteProbe { database } => {
            let (mut engine, _) = open_bound(&database)?;
            write_exact(&engine.note_probe(now()?)?)
        }
        Command::Halt { database, input } => {
            let input: HaltInputV1 = read_exact_record(&input)?;
            let (mut engine, _) = open_bound(&database)?;
            write_exact(&engine.halt(input.reason, now()?)?)
        }
        Command::Escalate { database, input } => {
            let input: HaltInputV1 = read_exact_record(&input)?;
            let (mut engine, _) = open_bound(&database)?;
            write_exact(&engine.escalate(input.reason, now()?)?)
        }
        Command::ApplyDisposition {
            database,
            input,
            observation_resolver,
            expected_observation_resolver_id,
            human_verifier,
        } => {
            let input: HumanDispositionInputV1 = read_exact_record(&input)?;
            let (mut engine, profile) = open_bound(&database)?;
            let _ = profile
                .observation_resolver
                .verify_presented(&observation_resolver, true)?;
            if expected_observation_resolver_id != profile.observation_resolver_id {
                bail!("caller substituted the genesis-pinned observation resolver identity");
            }
            let pinned_verifier = profile
                .human_verifier
                .as_ref()
                .context("campaign has no genesis-pinned human verifier")?;
            let _ = pinned_verifier.verify_presented(&human_verifier, true)?;
            let mut observation =
                CommandObservationResolverV1::new(profile.observation_resolver.path.clone());
            let mut verifier = CommandHumanDispositionVerifierV1::new(pinned_verifier.path.clone());
            let scope = HumanAuthorityScopeV1 {
                principal: input.expected_principal,
                mandate: input.expected_mandate,
            };
            let _ = engine.apply_human_disposition(
                input.artifact,
                &scope,
                input.new_occurrence,
                &mut observation,
                &profile.observation_resolver_id,
                &mut verifier,
                now()?,
            )?;
            write_exact(&engine.current()?)
        }
        Command::SubmitIntervention {
            database,
            submission,
            executor_config,
        } => submit_intervention(&database, &submission, executor_config.as_deref(), now()?),
        Command::InterventionReceipt {
            database,
            submission,
        } => {
            let (_, profile, profile_digest) = open_bound_with_digest(&database)?;
            profile
                .intervention_ingress
                .as_ref()
                .context("runtime profile has no intervention ingress")?;
            let submission = Digest::parse(&submission)?;
            let ledger_path = InterventionSubmissionLedgerV1::path_for_campaign(&database);
            if !ledger_path.exists() {
                return write_exact(&InterventionSubmissionHistoryV1 {
                    schema: INTERVENTION_SUBMISSION_HISTORY_SCHEMA_V1.to_owned(),
                    target_runtime_profile: profile_digest,
                    submission: Some(submission),
                    receipts: Vec::new(),
                });
            }
            let ledger = InterventionSubmissionLedgerV1::open_reader(&ledger_path, profile_digest)?;
            write_exact(&ledger.history(Some(&submission))?)
        }
        Command::InterventionSubmissions { database } => {
            let (_, profile, profile_digest) = open_bound_with_digest(&database)?;
            profile
                .intervention_ingress
                .as_ref()
                .context("runtime profile has no intervention ingress")?;
            let ledger_path = InterventionSubmissionLedgerV1::path_for_campaign(&database);
            if !ledger_path.exists() {
                return write_exact(&InterventionSubmissionHistoryV1 {
                    schema: INTERVENTION_SUBMISSION_HISTORY_SCHEMA_V1.to_owned(),
                    target_runtime_profile: profile_digest,
                    submission: None,
                    receipts: Vec::new(),
                });
            }
            let ledger = InterventionSubmissionLedgerV1::open_reader(&ledger_path, profile_digest)?;
            write_exact(&ledger.history(None)?)
        }
        Command::Complete {
            database,
            input,
            observation_resolver,
            expected_observation_resolver_id,
        } => {
            let input: CompletionInputV1 = read_exact_record(&input)?;
            let (mut engine, profile) = open_bound(&database)?;
            let _ = profile
                .observation_resolver
                .verify_presented(&observation_resolver, true)?;
            if expected_observation_resolver_id != profile.observation_resolver_id {
                bail!("caller substituted the genesis-pinned observation resolver identity");
            }
            let mut observation =
                CommandObservationResolverV1::new(profile.observation_resolver.path.clone());
            write_exact(&engine.complete(
                input.observation,
                &input.subject,
                input.terminal_witness,
                &mut observation,
                &profile.observation_resolver_id,
                now()?,
            )?)
        }
        Command::Refuse { database, input } => {
            let input: RefusalInputV1 = read_exact_record(&input)?;
            let (mut engine, _) = open_bound(&database)?;
            let refusal = engine.record_refusal(input.code, input.evidence, now()?)?;
            write_exact(&refusal)
        }
    }
}

fn run_finite(
    database: &Path,
    run_input_path: &Path,
    clock: fn() -> anyhow::Result<u64>,
) -> anyhow::Result<()> {
    let input_bytes = read_exact_input(run_input_path, 1024 * 1024)?;
    let value: serde_json::Value = strict_json_from_slice(&input_bytes)?;
    let schema = value.get("schema").and_then(|value| value.as_str());
    let NormalizedRunInput {
        campaign,
        profile_digest: profile_input_digest,
        initial,
        v1_continuation,
        v2_continuations,
        max_steps,
        max_polls,
        deadline_unix_ms,
        is_v2,
    } = match schema {
        Some("ag.governed-loop.run-input/v1") => {
            let input: RunInputV1 = strict_json_from_slice(&input_bytes)?;
            let material = RunOccurrenceMaterialV1 {
                occurrence: None,
                plan_binding: input.plan_binding,
                plan_binding_sha256: None,
                review_input: input.review_input,
                nightshift_cycle_request: input.nightshift_cycle_request,
                nightshift_cycle_request_sha256: None,
                executor_config: input.executor_config,
            };
            NormalizedRunInput {
                campaign: input.campaign,
                profile_digest: input.runtime_profile_digest,
                initial: material,
                v1_continuation: input.continuation_input,
                v2_continuations: Vec::new(),
                max_steps: input.max_steps,
                max_polls: input.max_polls,
                deadline_unix_ms: input.deadline_unix_ms,
                is_v2: false,
            }
        }
        Some("ag.governed-loop.run-input/v2") => {
            let input: RunInputV2 = strict_json_from_slice(&input_bytes)?;
            if input.continuations.len() > 8
                || u64::try_from(input.continuations.len())? > input.max_steps
            {
                bail!("too many continuation envelopes");
            }
            NormalizedRunInput {
                campaign: input.campaign,
                profile_digest: input.runtime_profile_digest,
                initial: input.initial.material(),
                v1_continuation: None,
                v2_continuations: input.continuations,
                max_steps: input.max_steps,
                max_polls: input.max_polls,
                deadline_unix_ms: input.deadline_unix_ms,
                is_v2: true,
            }
        }
        _ => bail!("unsupported finite run input schema"),
    };
    let canonical = JcsDocument::from_canonical_bytes(&input_bytes)?;
    let absolute = [
        &initial.plan_binding,
        &initial.review_input,
        &initial.nightshift_cycle_request,
        &initial.executor_config,
    ]
    .into_iter()
    .all(|path| path.is_absolute())
        && v1_continuation
            .as_ref()
            .is_none_or(|path| path.is_absolute())
        && v2_continuations.iter().all(|path| path.is_absolute());
    if max_steps == 0 || max_polls == 0 || !absolute {
        bail!("invalid finite run input");
    }
    let (mut engine, profile, profile_digest) = open_bound_with_digest(database)?;
    engine.set_process_deadline(deadline_unix_ms);
    let first_current = engine.current()?;
    if first_current.key().campaign != campaign
        || profile_digest != profile_input_digest
        || engine
            .runtime_profile()?
            .is_none_or(|stored| stored.schema != GOVERNED_RUNTIME_PROFILE_SCHEMA_V2)
    {
        bail!("run input differs from protected campaign genesis");
    }
    let prospective_run_id = Digest::hash_domain(
        if is_v2 {
            "ag.governed-loop.run-input/v2"
        } else {
            "ag.governed-loop.run-input/v1"
        },
        canonical.as_bytes(),
    );
    let prior_status = if is_v2 {
        engine.run_status(&prospective_run_id)?
    } else {
        None
    };
    let startup = is_v2
        .then(|| {
            v2_startup_disposition(
                prior_status.as_deref(),
                initial.occurrence,
                first_current.key().occurrence,
            )
        })
        .transpose()?;
    if startup == Some(V2StartupDisposition::ReplayTerminal) {
        let status = engine
            .terminal_run_observation(&prospective_run_id)?
            .context("terminal V2 run lacks its retained terminal observation")?;
        let status: RunStatusV1 = strict_json_from_slice(&status)?;
        if status.run_id != prospective_run_id || status.status != "terminal" {
            bail!("retained terminal observation differs from its V2 run identity");
        }
        return write_exact(&status);
    }
    if startup == Some(V2StartupDisposition::ValidateInitial) {
        validate_material_binding(
            &initial,
            &campaign,
            first_current.key().occurrence,
            first_current.state().meta().expected_work(),
        )?;
    }
    let run_id = if is_v2 {
        engine.begin_run_v2(canonical.as_bytes(), clock()?)?
    } else {
        engine.begin_run(canonical.as_bytes(), clock()?)?
    };
    let catalog: VersionedExactWorkCatalogV1 = read_exact_record(&profile.exact_work_catalog.path)?;
    let controlling_review = profile
        .controlling_review
        .as_ref()
        .map(|pinned| read_exact_record(&pinned.path))
        .transpose()?;
    let mut observation =
        CommandObservationResolverV1::new(profile.observation_resolver.path.clone())
            .with_deadline(deadline_unix_ms);
    let mut standing = CommandStandingResolverV1::new(profile.standing_resolver.path.clone())
        .with_deadline(deadline_unix_ms);
    let mut steps = 0_u64;
    let mut polls = 0_u64;
    loop {
        let now_unix_ms = clock()?;
        let current = engine.current()?;
        let material = if !is_v2 || Some(current.key().occurrence) == initial.occurrence {
            initial.clone()
        } else {
            let (_, retained) = engine
                .retained_run_continuation(&run_id, &current.key().occurrence)?
                .context("current V2 occurrence lacks a retained continuation")?;
            let continuation: RunContinuationV1 = strict_json_from_slice(&retained)?;
            continuation.material()
        };
        let captured_cycle_request = if is_v2 {
            Some(validate_material_binding(
                &material,
                &campaign,
                current.key().occurrence,
                current.state().meta().expected_work(),
            )?)
        } else {
            None
        };
        let terminal = |status: &str, reason: &str, steps, polls| RunStatusV1 {
            schema: "ag.governed-loop.run-status/v1".to_owned(),
            run_id: run_id.clone(),
            status: status.to_owned(),
            reason: reason.to_owned(),
            program_counter: current.program_counter(),
            steps,
            polls,
        };
        if now_unix_ms >= deadline_unix_ms {
            let status = terminal("waiting", "deadline_exhausted", steps, polls);
            engine.record_run_observation(&run_id, &status, "waiting", now_unix_ms)?;
            return write_exact(&status);
        }
        if steps >= max_steps {
            let status = terminal("waiting", "step_bound_exhausted", steps, polls);
            engine.record_run_observation(&run_id, &status, "waiting", now_unix_ms)?;
            return write_exact(&status);
        }
        match current.program_counter() {
            ProgramCounterV1::ObservationRequired => {
                let cycle_request = match captured_cycle_request {
                    Some(bytes) => bytes,
                    None => read_exact_input(&material.nightshift_cycle_request, 16 * 1024 * 1024)?,
                };
                let cycle_request_digest = Digest::hash_domain(
                    "ag.governed-loop.nightshift-cycle-request/v1",
                    &cycle_request,
                );
                let recover_cycle = engine.mark_cycle_inflight(&run_id, &cycle_request_digest)?;
                if !recover_cycle {
                    let started = terminal("active", "cycle_request_started", steps, polls);
                    engine.record_run_observation(&run_id, &started, "active", now_unix_ms)?;
                }
                let stored: GovernedRuntimeProfileV2 = {
                    let stored = engine
                        .runtime_profile()?
                        .context("protected profile missing")?;
                    strict_json_from_slice(&stored.canonical_bytes)?
                };
                let captured_request = if is_v2 {
                    Some(capture_cycle_request(database, &cycle_request)?)
                } else {
                    None
                };
                let cycle_request_path = captured_request.as_ref().map_or_else(
                    || material.nightshift_cycle_request.as_path(),
                    tempfile::NamedTempFile::path,
                );
                let response = stored.nightshift_cycle.run_cycle(
                    cycle_request_path,
                    recover_cycle,
                    deadline_unix_ms,
                );
                let Ok(response) = response else {
                    let status = terminal(
                        "waiting",
                        "independent_observation_unavailable",
                        steps,
                        polls,
                    );
                    engine.record_run_observation(&run_id, &status, "waiting", now_unix_ms)?;
                    return write_exact(&status);
                };
                engine.record_run_observation(&run_id, &response, "active", now_unix_ms)?;
                engine.clear_cycle_inflight(&run_id, &cycle_request_digest)?;
                if engine.current()?.program_counter() == ProgramCounterV1::ObservationRequired {
                    let status = terminal(
                        "waiting",
                        "independent_observation_unavailable",
                        steps,
                        polls,
                    );
                    engine.record_run_observation(&run_id, &status, "waiting", now_unix_ms)?;
                    return write_exact(&status);
                }
            }
            ProgramCounterV1::ProposalRecorded => {
                if material.review_input.try_exists()? {
                    let review: RecordReviewInputV1 = read_exact_record(&material.review_input)?;
                    let _ = engine.record_review(&review, now_unix_ms)?;
                }
                engine.require_standing(now_unix_ms)?;
            }
            ProgramCounterV1::StandingRequired => {
                if material.review_input.try_exists()? {
                    let review: RecordReviewInputV1 = read_exact_record(&material.review_input)?;
                    let _ = engine.record_review(&review, now_unix_ms)?;
                }
                match engine.decide_versioned(
                    &mut observation,
                    &mut standing,
                    &catalog,
                    controlling_review.as_ref(),
                    &profile.observation_resolver_id,
                    &profile.standing_resolver_id,
                    profile.max_standing_ttl_ms,
                    now_unix_ms,
                ) {
                    Ok(_) => {}
                    Err(CampaignEngineErrorV1::SharedAdmissionRequired) => {
                        let status = terminal("waiting", "review_missing_or_stale", steps, polls);
                        engine.record_run_observation(&run_id, &status, "waiting", now_unix_ms)?;
                        return write_exact(&status);
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            ProgramCounterV1::AdmissiblePendingAuthorization => {
                engine.authorize_versioned(
                    &mut observation,
                    &mut standing,
                    &catalog,
                    controlling_review.as_ref(),
                    &profile.observation_resolver_id,
                    &profile.standing_resolver_id,
                    profile.max_standing_ttl_ms,
                    now_unix_ms,
                )?;
            }
            ProgramCounterV1::AuthorizationConsumed => {
                let mut reconciliation =
                    docket_port_from_profile(&profile, &material.executor_config)?
                        .with_deadline(deadline_unix_ms);
                match engine.recover(&mut reconciliation, now_unix_ms) {
                    Ok(CampaignRecoveryV1::IssuanceNotAccepted(_)) => {
                        let mut docket =
                            docket_custody_from_profile(&profile, &material.executor_config)?
                                .with_deadline(deadline_unix_ms);
                        if engine.dispatch(&mut docket, now_unix_ms).is_err() {
                            let status = terminal(
                                "waiting",
                                "docket_acceptance_indeterminate",
                                steps,
                                polls,
                            );
                            engine.record_run_observation(
                                &run_id,
                                &status,
                                "waiting",
                                now_unix_ms,
                            )?;
                            return write_exact(&status);
                        }
                    }
                    Ok(CampaignRecoveryV1::Advanced(_)) => {}
                    Ok(CampaignRecoveryV1::ExternalRevalidation(_)) => {
                        let status =
                            terminal("waiting", "docket_revalidation_required", steps, polls);
                        engine.record_run_observation(&run_id, &status, "waiting", now_unix_ms)?;
                        return write_exact(&status);
                    }
                    Err(_) => {
                        let status = terminal(
                            "waiting",
                            "docket_reconciliation_indeterminate",
                            steps,
                            polls,
                        );
                        engine.record_run_observation(&run_id, &status, "waiting", now_unix_ms)?;
                        return write_exact(&status);
                    }
                }
            }
            ProgramCounterV1::Dispatched => {
                if polls >= max_polls {
                    let status = terminal("waiting", "poll_bound_exhausted", steps, polls);
                    engine.record_run_observation(&run_id, &status, "waiting", now_unix_ms)?;
                    return write_exact(&status);
                }
                let mut docket = docket_port_from_profile(&profile, &material.executor_config)?
                    .with_deadline(deadline_unix_ms);
                let _ = engine.recover(&mut docket, now_unix_ms)?;
                polls = polls.saturating_add(1);
            }
            ProgramCounterV1::ReconciliationRequired => {
                if polls >= max_polls {
                    let status = terminal("waiting", "reconciliation_indeterminate", steps, polls);
                    engine.record_run_observation(&run_id, &status, "waiting", now_unix_ms)?;
                    return write_exact(&status);
                }
                let mut docket = docket_port_from_profile(&profile, &material.executor_config)?
                    .with_deadline(deadline_unix_ms);
                let _ = engine.recover(&mut docket, now_unix_ms)?;
                polls = polls.saturating_add(1);
            }
            ProgramCounterV1::SettledObservationRequired => {
                if is_v2 {
                    let ordinal = engine.run_continuation_count(&run_id)?;
                    let Some(path) = v2_continuations.get(usize::from(ordinal)) else {
                        let status = terminal(
                            "terminal",
                            "finite_continuation_bound_complete",
                            steps,
                            polls,
                        );
                        engine.record_run_observation(&run_id, &status, "terminal", now_unix_ms)?;
                        return write_exact(&status);
                    };
                    if !path.try_exists()? {
                        let status =
                            terminal("waiting", "continuation_input_required", steps, polls);
                        engine.record_run_observation(&run_id, &status, "waiting", now_unix_ms)?;
                        return write_exact(&status);
                    }
                    let bytes = read_exact_input(path, 1024 * 1024)?;
                    let continuation = validate_run_continuation(&bytes, &campaign, &current)?;
                    engine.open_run_continuation(
                        &run_id,
                        ordinal,
                        path,
                        &bytes,
                        continuation.occurrence,
                        continuation.expected_ag_work,
                        now_unix_ms,
                    )?;
                    steps = steps.saturating_add(1);
                    continue;
                }
                let Some(path) = v1_continuation.as_ref() else {
                    let status = terminal("waiting", "continuation_input_required", steps, polls);
                    engine.record_run_observation(&run_id, &status, "waiting", now_unix_ms)?;
                    return write_exact(&status);
                };
                let continuation: ContinuationInputV1 = read_exact_record(path)?;
                engine.open_continuation(
                    continuation.occurrence,
                    continuation.expected_ag_work,
                    now_unix_ms,
                )?;
            }
            ProgramCounterV1::Halted => {
                let status = terminal("terminal", "halted", steps, polls);
                engine.record_run_observation(&run_id, &status, "terminal", now_unix_ms)?;
                return write_exact(&status);
            }
            ProgramCounterV1::Completed => {
                let status = terminal("terminal", "completed", steps, polls);
                engine.record_run_observation(&run_id, &status, "terminal", now_unix_ms)?;
                return write_exact(&status);
            }
        }
        steps = steps.saturating_add(1);
    }
}

fn validate_run_continuation(
    bytes: &[u8],
    campaign: &CampaignId,
    current: &OccurrenceSnapshotV1,
) -> anyhow::Result<RunContinuationV1> {
    JcsDocument::from_canonical_bytes(bytes)?;
    let continuation: RunContinuationV1 = strict_json_from_slice(bytes)?;
    let paths = [
        &continuation.plan_binding,
        &continuation.review_input,
        &continuation.nightshift_cycle_request,
        &continuation.executor_config,
    ];
    if continuation.schema != "ag.governed-loop.run-continuation/v1"
        || &continuation.campaign != campaign
        || continuation.predecessor_occurrence != current.key().occurrence
        || &continuation.predecessor_expected_ag_work != current.state().meta().expected_work()
        || continuation.occurrence == current.key().occurrence
        || !paths.into_iter().all(|path| path.is_absolute())
    {
        bail!("continuation envelope does not bind the current occurrence");
    }
    let binding_bytes = read_exact_input(&continuation.plan_binding, 16 * 1024 * 1024)?;
    require_sha256(&binding_bytes, &continuation.plan_binding_sha256)?;
    JcsDocument::from_canonical_bytes(&binding_bytes)?;
    let binding: serde_json::Value = strict_json_from_slice(&binding_bytes)?;
    let successor_occurrence = continuation.occurrence.to_string();
    if binding.get("schema").and_then(serde_json::Value::as_str)
        != Some("maude.governed-plan-binding/v1")
        || binding.get("campaign").and_then(serde_json::Value::as_str) != Some(campaign.as_str())
        || binding
            .get("occurrence")
            .and_then(serde_json::Value::as_str)
            != Some(successor_occurrence.as_str())
        || binding.get("work").and_then(serde_json::Value::as_str)
            != Some(continuation.expected_ag_work.as_str())
    {
        bail!("continuation plan binding differs from the successor boundary");
    }
    let request_bytes = read_exact_input(&continuation.nightshift_cycle_request, 16 * 1024 * 1024)?;
    require_sha256(
        &request_bytes,
        &continuation.nightshift_cycle_request_sha256,
    )?;
    JcsDocument::from_canonical_bytes(&request_bytes)?;
    let request: serde_json::Value = strict_json_from_slice(&request_bytes)?;
    let proposal = request
        .get("proposal")
        .context("cycle request has no proposal")?;
    if proposal
        .get("campaign_id")
        .and_then(serde_json::Value::as_str)
        != Some(campaign.as_str())
        || proposal
            .get("occurrence_id")
            .and_then(serde_json::Value::as_str)
            != Some(successor_occurrence.as_str())
    {
        bail!("continuation cycle request differs from the successor boundary");
    }
    let transport = request
        .get("reviewed_plan_binding")
        .context("cycle request has no reviewed plan binding")?;
    if transport.get("schema").and_then(serde_json::Value::as_str)
        != Some("nightshift.reviewed-plan-binding-transport/v1")
    {
        bail!("cycle request has unsupported plan-binding transport");
    }
    let encoded = transport
        .get("binding_base64")
        .and_then(serde_json::Value::as_str)
        .context("cycle request plan binding is absent")?;
    let transported = base64::engine::general_purpose::STANDARD.decode(encoded)?;
    let digest = format!("sha256:{:x}", Sha256::digest(&transported));
    if transported.is_empty()
        || transported.len() > 16 * 1024 * 1024
        || base64::engine::general_purpose::STANDARD.encode(&transported) != encoded
        || transported != binding_bytes
        || transport
            .get("binding_sha256")
            .and_then(serde_json::Value::as_str)
            != Some(digest.as_str())
    {
        bail!("cycle request substitutes the continuation plan binding");
    }
    Ok(continuation)
}

fn capture_cycle_request(
    database: &Path,
    request: &[u8],
) -> anyhow::Result<tempfile::NamedTempFile> {
    let parent = database
        .parent()
        .context("campaign database has no parent")?;
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.as_file_mut().write_all(request)?;
    file.as_file_mut().sync_all()?;
    Ok(file)
}

fn verify_material_pins(material: &RunOccurrenceMaterialV1) -> anyhow::Result<()> {
    for (path, expected) in [
        (
            &material.plan_binding,
            material.plan_binding_sha256.as_deref(),
        ),
        (
            &material.nightshift_cycle_request,
            material.nightshift_cycle_request_sha256.as_deref(),
        ),
    ] {
        let expected = expected.context("V2 run material lacks a required content pin")?;
        let bytes = read_exact_input(path, 16 * 1024 * 1024)?;
        let actual = format!("sha256:{:x}", Sha256::digest(&bytes));
        if actual != expected {
            bail!("V2 run material content differs from its retained pin");
        }
    }
    Ok(())
}

fn require_sha256(bytes: &[u8], expected: &str) -> anyhow::Result<()> {
    let actual = format!("sha256:{:x}", Sha256::digest(bytes));
    if actual != expected {
        bail!("V2 run material content differs from its retained pin");
    }
    Ok(())
}

fn validate_material_binding(
    material: &RunOccurrenceMaterialV1,
    campaign: &CampaignId,
    occurrence: OccurrenceId,
    expected_work: &Digest,
) -> anyhow::Result<Vec<u8>> {
    verify_material_pins(material)?;
    let binding_bytes = read_exact_input(&material.plan_binding, 16 * 1024 * 1024)?;
    require_sha256(
        &binding_bytes,
        material
            .plan_binding_sha256
            .as_deref()
            .context("missing binding pin")?,
    )?;
    JcsDocument::from_canonical_bytes(&binding_bytes)?;
    let binding: serde_json::Value = strict_json_from_slice(&binding_bytes)?;
    let occurrence = occurrence.to_string();
    if binding.get("schema").and_then(serde_json::Value::as_str)
        != Some("maude.governed-plan-binding/v1")
        || binding.get("campaign").and_then(serde_json::Value::as_str) != Some(campaign.as_str())
        || binding
            .get("occurrence")
            .and_then(serde_json::Value::as_str)
            != Some(occurrence.as_str())
        || binding.get("work").and_then(serde_json::Value::as_str) != Some(expected_work.as_str())
    {
        bail!("V2 run plan binding differs from its occurrence boundary");
    }
    let request_bytes = read_exact_input(&material.nightshift_cycle_request, 16 * 1024 * 1024)?;
    require_sha256(
        &request_bytes,
        material
            .nightshift_cycle_request_sha256
            .as_deref()
            .context("missing cycle-request pin")?,
    )?;
    JcsDocument::from_canonical_bytes(&request_bytes)?;
    let request: serde_json::Value = strict_json_from_slice(&request_bytes)?;
    let proposal = request
        .get("proposal")
        .context("cycle request has no proposal")?;
    let transport = request
        .get("reviewed_plan_binding")
        .context("cycle request has no reviewed plan binding")?;
    let encoded = transport
        .get("binding_base64")
        .and_then(serde_json::Value::as_str)
        .context("cycle request plan binding is absent")?;
    let transported = base64::engine::general_purpose::STANDARD.decode(encoded)?;
    let binding_digest = format!("sha256:{:x}", Sha256::digest(&transported));
    if proposal
        .get("campaign_id")
        .and_then(serde_json::Value::as_str)
        != Some(campaign.as_str())
        || proposal
            .get("occurrence_id")
            .and_then(serde_json::Value::as_str)
            != Some(occurrence.as_str())
        || transport.get("schema").and_then(serde_json::Value::as_str)
            != Some("nightshift.reviewed-plan-binding-transport/v1")
        || base64::engine::general_purpose::STANDARD.encode(&transported) != encoded
        || transported != binding_bytes
        || transport
            .get("binding_sha256")
            .and_then(serde_json::Value::as_str)
            != Some(binding_digest.as_str())
    {
        bail!("V2 cycle request differs from its plan/occurrence boundary");
    }
    Ok(request_bytes)
}

fn docket_custody_from_profile(
    profile: &GovernedRuntimeProfileV1,
    executor_config: &Path,
) -> anyhow::Result<CommandDocketCustodyPortV1> {
    let pinned = &profile.docket;
    pinned.verify_all()?;
    let signer = AgIssuanceSignerV1::from_pkcs8(
        pinned.issuer_principal.clone(),
        pinned.issuer_key_id.clone(),
        &pinned.issuer_key.verify(false)?,
    )?;
    Ok(CommandDocketCustodyPortV1::new(
        pinned.docket_program.path.clone(),
        pinned.state_directory.clone(),
        pinned.trust_config.path.clone(),
        pinned.standing_resolver.path.clone(),
        pinned.executor_adapter.path.clone(),
        executor_config.to_owned(),
        signer,
    ))
}

fn open_bound(database: &Path) -> anyhow::Result<(CampaignEngineV1, GovernedRuntimeProfileV1)> {
    let (engine, profile, _) = open_bound_with_digest(database)?;
    Ok((engine, profile))
}

fn open_bound_with_digest(
    database: &Path,
) -> anyhow::Result<(CampaignEngineV1, GovernedRuntimeProfileV1, Digest)> {
    let engine = CampaignEngineV1::open(database)?;
    let stored = engine
        .runtime_profile()?
        .context("campaign was not created through the genesis-bound production surface")?;
    let profile = match stored.schema.as_str() {
        GOVERNED_RUNTIME_PROFILE_SCHEMA_V1 => {
            let profile: GovernedRuntimeProfileV1 = strict_json_from_slice(&stored.canonical_bytes)
                .context("decode genesis-bound runtime profile v1")?;
            if profile.schema != stored.schema {
                bail!("campaign runtime profile schema binding is inconsistent");
            }
            profile
        }
        GOVERNED_RUNTIME_PROFILE_SCHEMA_V2 => {
            let profile: GovernedRuntimeProfileV2 = strict_json_from_slice(&stored.canonical_bytes)
                .context("decode genesis-bound runtime profile v2")?;
            profile.verify_genesis()?;
            profile.common_profile()
        }
        _ => bail!("campaign runtime profile schema is not supported"),
    };
    Ok((engine, profile, stored.digest))
}

fn submit_intervention(
    database: &Path,
    submission_path: &Path,
    executor_config: Option<&Path>,
    now_unix_ms: u64,
) -> anyhow::Result<()> {
    let presentation = read_exact_input(submission_path, max_submission_bytes())?;
    let (mut engine, profile, profile_digest) = open_bound_with_digest(database)?;
    let ingress = profile
        .intervention_ingress
        .as_ref()
        .context("campaign has no genesis-bound intervention ingress")?;
    let ledger_path = InterventionSubmissionLedgerV1::path_for_campaign(database);
    let mut ledger =
        InterventionSubmissionLedgerV1::open_writer(&ledger_path, profile_digest.clone())?;

    let verified =
        match verify_submission_bytes(&presentation, ingress, &profile_digest, now_unix_ms) {
            Ok(verified) => verified,
            Err(InterventionIngressErrorV1::Custody(code)) => {
                let (claimed_submission, claimed_request) =
                    claimed_submission_references(&presentation);
                let receipt = ledger.record_custody_refusal(
                    &presentation,
                    claimed_submission,
                    claimed_request,
                    code,
                    now_unix_ms,
                )?;
                return write_exact(&receipt);
            }
            Err(error) => return Err(error.into()),
        };
    let _ = ledger.record_received(&verified, now_unix_ms)?;

    if let Some(result) = canonical_submission_result(&engine, &verified.request)? {
        let receipt = ledger.record_result(&verified, result, now_unix_ms)?;
        return write_exact(&receipt);
    }

    let request = verified.request.clone();
    let scope = HumanAuthorityScopeV1 {
        principal: request.principal.clone(),
        mandate: request.mandate.clone(),
    };
    let evaluation = (|| -> anyhow::Result<()> {
        let pinned_verifier = profile
            .human_verifier
            .as_ref()
            .context("campaign has no genesis-pinned human/intervention verifier")?;
        let _ = pinned_verifier.verify(true)?;
        let mut authority_verifier =
            CommandGovernedInterventionVerifierV1::new(pinned_verifier.path.clone());

        if matches!(
            request.intervention,
            GovernedInterventionClassV1::ReconcileAttempt { .. }
        ) {
            let executor_config = executor_config.context(
                "reconcile_attempt submission requires the exact Docket executor configuration",
            )?;
            let mut docket = docket_port_from_profile(&profile, executor_config)?;
            let _ = engine.request_reconciliation(
                request,
                &scope,
                &mut authority_verifier,
                &mut docket,
                now_unix_ms,
            )?;
        } else {
            if executor_config.is_some() {
                bail!("executor configuration is accepted only for reconcile_attempt");
            }
            let _ = engine.apply_governed_intervention(
                request,
                &scope,
                &mut authority_verifier,
                now_unix_ms,
            )?;
        }
        Ok(())
    })();

    let result = if let Some(result) = canonical_submission_result(&engine, &verified.request)? {
        result
    } else {
        match evaluation {
            Ok(()) => InterventionSubmissionStatusV1::OutcomeUnknown {
                code: "governed_result_missing".to_owned(),
            },
            Err(error) => {
                if let Some(
                    CampaignEngineErrorV1::Kernel(KernelErrorV1::External(
                        ExternalBoundaryErrorV1::Refused { code, .. },
                    ))
                    | CampaignEngineErrorV1::External(ExternalBoundaryErrorV1::Refused {
                        code, ..
                    }),
                ) = error.downcast_ref::<CampaignEngineErrorV1>()
                {
                    InterventionSubmissionStatusV1::GovernedRefused {
                        refusal: None,
                        code: format!("requester_verification:{code}"),
                    }
                } else if let Some(CampaignEngineErrorV1::Kernel(_)) =
                    error.downcast_ref::<CampaignEngineErrorV1>()
                {
                    InterventionSubmissionStatusV1::GovernedRefused {
                        refusal: None,
                        code: "governed_kernel_refusal".to_owned(),
                    }
                } else {
                    InterventionSubmissionStatusV1::OutcomeUnknown {
                        code: "governed_evaluation_unavailable".to_owned(),
                    }
                }
            }
        }
    };
    let receipt = ledger.record_result(&verified, result, now_unix_ms)?;
    write_exact(&receipt)
}

fn canonical_submission_result(
    engine: &CampaignEngineV1,
    request: &GovernedInterventionRequestV1,
) -> anyhow::Result<Option<InterventionSubmissionStatusV1>> {
    let history = engine.history()?;
    for transition in history.transitions.iter().rev() {
        if let CampaignTransitionEvidenceV1::GovernedIntervention { verified } =
            &transition.evidence
            && verified.request.request == request.request
        {
            return Ok(Some(InterventionSubmissionStatusV1::GovernedAccepted {
                event: transition.event_digest.clone(),
                successor_state: transition.successor_state_digest.clone(),
                transition: serde_enum_name(&transition.kind)?,
            }));
        }
    }
    let refusals = engine.refusal_history()?;
    for refusal in refusals.refusals.iter().rev() {
        if let Some(verified) = &refusal.outcome.governed_intervention
            && verified.request.request == request.request
        {
            if refusal.outcome.code == RefusalCodeV1::InterventionOutcomeUnknown {
                return Ok(Some(InterventionSubmissionStatusV1::OutcomeUnknown {
                    code: "reconciliation_outcome_unknown".to_owned(),
                }));
            }
            return Ok(Some(InterventionSubmissionStatusV1::GovernedRefused {
                refusal: Some(refusal.refusal.clone()),
                code: serde_enum_name(&refusal.outcome.code)?,
            }));
        }
    }
    Ok(None)
}

fn serde_enum_name<T: Serialize>(value: &T) -> anyhow::Result<String> {
    serde_json::to_value(value)?
        .as_str()
        .map(ToOwned::to_owned)
        .context("canonical enum is not represented by one string")
}

fn docket_port_from_profile(
    profile: &GovernedRuntimeProfileV1,
    executor_config: &Path,
) -> anyhow::Result<CommandDocketReconciliationPortV1> {
    let pinned = &profile.docket;
    let _ = pinned.docket_program.verify(true)?;
    let _ = pinned.trust_config.verify(false)?;
    let _ = pinned.standing_resolver.verify(true)?;
    let _ = pinned.executor_adapter.verify(true)?;
    Ok(CommandDocketReconciliationPortV1::new(
        pinned.docket_program.path.clone(),
        pinned.state_directory.clone(),
        pinned.trust_config.path.clone(),
        pinned.standing_resolver.path.clone(),
        pinned.executor_adapter.path.clone(),
        executor_config.to_owned(),
    ))
}

fn gate_components(
    profile: &GovernedRuntimeProfileV1,
    arguments: &GateArguments,
) -> anyhow::Result<(
    CommandObservationResolverV1,
    CommandStandingResolverV1,
    VersionedExactWorkCatalogV1,
    Option<C1RejectedReviewBasisV1>,
)> {
    let _ = profile
        .observation_resolver
        .verify_presented(&arguments.observation_resolver, true)?;
    let _ = profile
        .standing_resolver
        .verify_presented(&arguments.standing_resolver, true)?;
    let _ = profile
        .exact_work_catalog
        .verify_presented(&arguments.catalog, false)?;
    if arguments.expected_observation_resolver_id != profile.observation_resolver_id
        || arguments.expected_standing_resolver_id != profile.standing_resolver_id
        || arguments.max_standing_ttl_ms != profile.max_standing_ttl_ms
    {
        bail!("caller substituted a genesis-pinned governance parameter");
    }
    match (&profile.controlling_review, &arguments.controlling_review) {
        (None, None) => {}
        (Some(pinned), Some(presented)) => {
            let _ = pinned.verify_presented(presented, false)?;
        }
        _ => bail!("caller substituted the genesis-pinned controlling review"),
    }
    let catalog: VersionedExactWorkCatalogV1 = read_exact_record(&profile.exact_work_catalog.path)?;
    let review = profile
        .controlling_review
        .as_ref()
        .map(|pinned| read_exact_record(&pinned.path))
        .transpose()?;
    Ok((
        CommandObservationResolverV1::new(profile.observation_resolver.path.clone()),
        CommandStandingResolverV1::new(profile.standing_resolver.path.clone()),
        catalog,
        review,
    ))
}

fn docket_port(
    profile: &GovernedRuntimeProfileV1,
    arguments: &DocketArguments,
) -> anyhow::Result<CommandDocketCustodyPortV1> {
    let pinned = &profile.docket;
    if arguments.docket != pinned.docket_program.path
        || arguments.docket_state != pinned.state_directory
        || arguments.docket_trust != pinned.trust_config.path
        || arguments.docket_standing_resolver != pinned.standing_resolver.path
        || arguments.executor != pinned.executor_adapter.path
        || arguments.issuer_principal != pinned.issuer_principal
        || arguments.issuer_key_id != pinned.issuer_key_id
        || arguments.issuer_key != pinned.issuer_key.path
    {
        bail!("caller substituted the genesis-pinned Docket boundary");
    }
    pinned.verify_all()?;
    let key = pinned.issuer_key.verify(false)?;
    let signer = AgIssuanceSignerV1::from_pkcs8(
        pinned.issuer_principal.clone(),
        pinned.issuer_key_id.clone(),
        &key,
    )?;
    // The executor plan is not a deployment selector: it is the exact work
    // for this occurrence, and Docket refuses it unless its identity equals
    // the work identity in AG's signed issuance.
    Ok(CommandDocketCustodyPortV1::new(
        pinned.docket_program.path.clone(),
        pinned.state_directory.clone(),
        pinned.trust_config.path.clone(),
        pinned.standing_resolver.path.clone(),
        pinned.executor_adapter.path.clone(),
        arguments.executor_config.clone(),
        signer,
    ))
}

fn runtime_profile_receipt(
    profile: &GovernedRuntimeProfileV1,
    canonical_bytes: &[u8],
) -> RuntimeProfileSealReceiptV1 {
    RuntimeProfileSealReceiptV1 {
        schema: RUNTIME_PROFILE_SEAL_RECEIPT_SCHEMA_V1,
        profile_schema: GOVERNED_RUNTIME_PROFILE_SCHEMA_V1,
        profile_digest: Digest::hash_domain(GOVERNED_RUNTIME_PROFILE_SCHEMA_V1, canonical_bytes),
        observation_resolver_id: profile.observation_resolver_id.clone(),
        standing_resolver_id: profile.standing_resolver_id.clone(),
        issuer_principal: profile.docket.issuer_principal.clone(),
        issuer_key_id: profile.docket.issuer_key_id.clone(),
        intervention_submitter_principal: profile
            .intervention_ingress
            .as_ref()
            .map(|ingress| ingress.submitter_principal.clone()),
        intervention_submitter_key_id: profile
            .intervention_ingress
            .as_ref()
            .map(|ingress| ingress.submitter_key_id.clone()),
    }
}

fn runtime_profile_receipt_v2(
    profile: &GovernedRuntimeProfileV2,
    canonical_bytes: &[u8],
) -> RuntimeProfileSealReceiptV1 {
    RuntimeProfileSealReceiptV1 {
        schema: RUNTIME_PROFILE_SEAL_RECEIPT_SCHEMA_V1,
        profile_schema: GOVERNED_RUNTIME_PROFILE_SCHEMA_V2,
        profile_digest: Digest::hash_domain(GOVERNED_RUNTIME_PROFILE_SCHEMA_V2, canonical_bytes),
        observation_resolver_id: profile.observation_resolver_id.clone(),
        standing_resolver_id: profile.standing_resolver_id.clone(),
        issuer_principal: profile.docket.issuer_principal.clone(),
        issuer_key_id: profile.docket.issuer_key_id.clone(),
        intervention_submitter_principal: profile
            .intervention_ingress
            .as_ref()
            .map(|ingress| ingress.submitter_principal.clone()),
        intervention_submitter_key_id: profile
            .intervention_ingress
            .as_ref()
            .map(|ingress| ingress.submitter_key_id.clone()),
    }
}

fn runtime_profile_digest(canonical_bytes: &[u8]) -> Digest {
    Digest::hash_domain(GOVERNED_RUNTIME_PROFILE_SCHEMA_V1, canonical_bytes)
}

fn write_exact_file(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    if !path.is_absolute() {
        bail!("sealed runtime-profile output path must be absolute");
    }
    let parent = path
        .parent()
        .context("sealed runtime-profile output has no parent")?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("sealed runtime-profile output has no normal filename")?;
    let temporary = parent.join(format!(".{file_name}.{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| -> anyhow::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&temporary)
            .with_context(|| format!("create sealed profile {}", temporary.display()))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::hard_link(&temporary, path).with_context(|| {
            format!(
                "publish sealed profile without replacement: {}",
                path.display()
            )
        })?;
        fs::remove_file(&temporary)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn read_exact_record<T>(path: &Path) -> anyhow::Result<T>
where
    T: DeserializeOwned + Serialize,
{
    let bytes = fs::read(path).with_context(|| format!("read exact record {}", path.display()))?;
    let value: T = strict_json_from_slice(&bytes)
        .with_context(|| format!("parse exact record {}", path.display()))?;
    let canonical = JcsDocument::canonicalize(&value)?;
    if bytes != canonical.as_bytes()
        && !(bytes.ends_with(b"\n") && &bytes[..bytes.len() - 1] == canonical.as_bytes())
    {
        bail!(
            "record is not canonical JSON (with at most one final LF): {}",
            path.display()
        );
    }
    Ok(value)
}

fn write_exact<T: Serialize + ?Sized>(value: &T) -> anyhow::Result<()> {
    let canonical = JcsDocument::canonicalize(value)?;
    println!("{}", canonical.as_str());
    Ok(())
}

fn now_unix_ms() -> anyhow::Result<u64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?;
    u64::try_from(duration.as_millis()).context("system clock exceeds u64 milliseconds")
}

#[cfg(test)]
mod finite_continuation_tests {
    use super::*;

    #[test]
    fn v2_material_pins_refuse_content_mutation() {
        let directory = tempfile::tempdir().unwrap();
        let binding = directory.path().join("binding.json");
        let request = directory.path().join("request.json");
        fs::write(&binding, b"binding-one").unwrap();
        fs::write(&request, b"request-one").unwrap();
        let material = RunOccurrenceMaterialV1 {
            occurrence: Some(OccurrenceId::allocate()),
            plan_binding: binding.clone(),
            plan_binding_sha256: Some(format!("sha256:{:x}", Sha256::digest(b"binding-one"))),
            review_input: directory.path().join("review.json"),
            nightshift_cycle_request: request,
            nightshift_cycle_request_sha256: Some(format!(
                "sha256:{:x}",
                Sha256::digest(b"request-one")
            )),
            executor_config: directory.path().join("executor.json"),
        };
        verify_material_pins(&material).unwrap();
        fs::write(binding, b"binding-two").unwrap();
        assert!(verify_material_pins(&material).is_err());
    }

    #[test]
    fn v2_material_requires_both_content_pins() {
        let directory = tempfile::tempdir().unwrap();
        let binding = directory.path().join("binding.json");
        let request = directory.path().join("request.json");
        fs::write(&binding, b"binding").unwrap();
        fs::write(&request, b"request").unwrap();
        let material = RunOccurrenceMaterialV1 {
            occurrence: Some(OccurrenceId::allocate()),
            plan_binding: binding,
            plan_binding_sha256: None,
            review_input: directory.path().join("review.json"),
            nightshift_cycle_request: request,
            nightshift_cycle_request_sha256: None,
            executor_config: directory.path().join("executor.json"),
        };
        assert!(verify_material_pins(&material).is_err());
    }

    #[test]
    fn startup_selection_refuses_new_mismatch_and_selects_existing_resume() {
        let current = OccurrenceId::allocate();
        let wrong = OccurrenceId::allocate();
        assert!(v2_startup_disposition(None, Some(wrong), current).is_err());
        assert_eq!(
            v2_startup_disposition(Some("waiting"), Some(wrong), current).unwrap(),
            V2StartupDisposition::ResumeActive
        );
    }

    #[test]
    fn owned_terminal_status_round_trips_nonzero_counters() {
        let status = RunStatusV1 {
            schema: "ag.governed-loop.run-status/v1".to_owned(),
            run_id: Digest::hash_domain("test.run/v1", b"run"),
            status: "terminal".to_owned(),
            reason: "finite_continuation_bound_complete".to_owned(),
            program_counter: ProgramCounterV1::SettledObservationRequired,
            steps: 7,
            polls: 2,
        };
        let bytes = JcsDocument::canonicalize(&status).unwrap();
        let decoded: RunStatusV1 = strict_json_from_slice(bytes.as_bytes()).unwrap();
        assert_eq!(decoded.status, "terminal");
        assert_eq!(decoded.steps, 7);
    }

    #[test]
    fn captured_cycle_request_is_independent_of_source_content_mutation() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("campaign.sqlite");
        let source = directory.path().join("cycle-request.json");
        fs::write(&source, b"first-request").unwrap();
        let bytes = fs::read(&source).unwrap();
        let captured = capture_cycle_request(&database, &bytes).unwrap();
        fs::write(source, b"replacement-request").unwrap();
        assert_eq!(fs::read(captured.path()).unwrap(), b"first-request");
    }
}
