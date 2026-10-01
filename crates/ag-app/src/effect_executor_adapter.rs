//! Authority-neutral `ag-effectd` adapter for Docket-custodied attempts.
//!
//! This module owns exact-effect mechanics and an executor-local idempotency
//! journal. V2 additionally verifies an already-spent AG issuance and exact
//! persisted Docket custody before mechanics; it does not grant standing,
//! create a campaign transition, or perform continuation.

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Read as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use ag_campaign::governed::{AgIssuanceV1, DocketCustodyV1, AG_ISSUANCE_SCHEMA_V1};
use ag_effect::executor::{
    ArtifactReadErrorV1, ArtifactSourceV1, CapabilityFailureV1, CapabilityOutcomeV1,
    DocketCustodiedExecutionPermitV1, DocketEffectExecutionReceiptV1, EffectExecutorV1,
    ExecutionOutcomeV1, ManagedFilePolicyV1, PinnedHelperIdentityV1, PinnedPointerHelperV1,
    PointerCasRequestV1, PointerCasSuccessV1, PointerPreparationRequestV1,
    PointerPreparationSuccessV1, SystemdDbusBackendV1, SystemdManagerReloadRequestV1,
    SystemdManagerReloadSuccessV1, SystemdUnitRequestV1, SystemdUnitSuccessV1,
};
use ag_effect::CanonicalEffectV1;
use ag_primitives::{Digest, JcsDocument};

mod systemd_executor_v2;

use ag_protocol::strict_json_from_slice;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ring::signature::{UnparsedPublicKey, ED25519};
use rusqlite::{params, Connection, ErrorCode, OpenFlags, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
pub use systemd_executor_v2::{
    audit_systemd_effect_store_cut, execute_systemd_effect_attempt,
    load_effect_executor_systemd_plan, reconcile_systemd_effect_attempt,
    reopen_systemd_dbus_evidence, EffectExecutorSystemdPlanV2,
    EFFECT_EXECUTOR_SYSTEMD_PLAN_SCHEMA_V2, EFFECT_EXECUTOR_SYSTEMD_WORK_SCHEMA_V2,
};
use systemd_executor_v2::{decode_effect_executor_systemd_plan, MAX_PLAN_BYTES};

use crate::governed_ports::{
    GovernedDocketRootV1, GovernedRuntimeProfileV1, SignedAgIssuanceEnvelopeV1,
    GOVERNED_DOCKET_ROOT_SCHEMA_V1, GOVERNED_RUNTIME_PROFILE_SCHEMA_V1,
};

/// Exact Docket work-schema accepted by this adapter.
pub const EFFECT_EXECUTOR_WORK_SCHEMA_V1: &str = "ag-effectd.docket-executor-work/v1";
/// Exact sealed executor-plan schema.
pub const EFFECT_EXECUTOR_PLAN_SCHEMA_V1: &str = "ag-effectd.docket-executor-plan/v1";
/// Authorization-carrying plan; V1 plan serialization and identity remain unchanged.
pub const EFFECT_EXECUTOR_PLAN_SCHEMA_V2: &str = "ag-effectd.docket-executor-plan/v2";
/// Docket's current, closed authorization-carrying executor input.
pub const DOCKET_EXECUTOR_DISPATCH_SCHEMA_V2: &str = "docket.governed-executor-dispatch/v2";
const DOCKET_INSPECTION_SCHEMA_V1: &str = "docket.governed-loop.inspection/v1";
const DOCKET_CUSTODY_SCHEMA_V1: &str = "ag.governed-loop.docket-custody/v1";
const SIGNATURE_PREFIX_V1: &[u8] = b"ag-ng\0governed-loop-issuance-signature\0v1\0";
const EFFECT_EXECUTOR_DEPLOYMENT_SCHEMA_V1: &str = "ag-effectd.deployment/v1";
const MAX_DEPLOYMENT_CONFIG_BYTES: u64 = 64 * 1024;
/// External Docket-owned transport law implemented independently by `ag-effectd`.
pub const DOCKET_EXECUTOR_TRANSPORT_SCHEMA_V1: &str = "docket.governed-executor-transport/v1";
/// External Docket-owned dispatch schema implemented by `EffectExecutorDispatchV1`.
pub const DOCKET_EXECUTOR_DISPATCH_SCHEMA_V1: &str = "docket.governed-executor-dispatch/v1";
/// External Docket-owned outcome schema implemented by `EffectExecutorOutcomeV1`.
pub const DOCKET_EXECUTOR_OUTCOME_SCHEMA_V1: &str = "docket.governed-executor-outcome/v1";
/// V1 transport document bound shared by Docket and every executor adapter.
pub const DOCKET_EXECUTOR_MAX_DOCUMENT_BYTES_V1: u64 = 1024 * 1024;

const STORE_SCHEMA: &str = r"
CREATE TABLE IF NOT EXISTS docket_effect_attempt (
  attempt TEXT PRIMARY KEY NOT NULL,
  marker TEXT UNIQUE NOT NULL,
  work TEXT NOT NULL,
  subject TEXT NOT NULL,
  scope TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('started','success','failure','indeterminate')),
  receipt TEXT,
  receipt_body BLOB,
  CHECK (
    (status='started' AND receipt IS NULL AND receipt_body IS NULL)
    OR
    (status!='started' AND receipt IS NOT NULL AND receipt_body IS NOT NULL)
  )
) STRICT;

CREATE TABLE IF NOT EXISTS systemd_dbus_evidence (
  attempt TEXT PRIMARY KEY NOT NULL,
  evidence TEXT UNIQUE NOT NULL,
  outcome_class TEXT NOT NULL
    CHECK (outcome_class IN ('success','failure','indeterminate')),
  raw_len INTEGER NOT NULL CHECK (raw_len > 0 AND raw_len <= 1048576),
  message_count INTEGER NOT NULL CHECK (message_count >= 0 AND message_count <= 16),
  maximum_message_bytes INTEGER NOT NULL
    CHECK (maximum_message_bytes >= 0 AND maximum_message_bytes <= 65536),
  cumulative_message_bytes INTEGER NOT NULL
    CHECK (cumulative_message_bytes >= 0 AND cumulative_message_bytes <= 262144),
  raw BLOB NOT NULL,
  CHECK (length(raw) = raw_len)
) STRICT;

CREATE TRIGGER IF NOT EXISTS systemd_dbus_evidence_no_update
BEFORE UPDATE ON systemd_dbus_evidence
BEGIN
  SELECT RAISE(ABORT, 'systemd D-Bus evidence is append-only');
END;

CREATE TRIGGER IF NOT EXISTS systemd_dbus_evidence_no_delete
BEFORE DELETE ON systemd_dbus_evidence
BEGIN
  SELECT RAISE(ABORT, 'systemd D-Bus evidence is append-only');
END;
";
const SYSTEMD_EVIDENCE_UPDATE_TRIGGER_SQL: &str = "CREATE TRIGGER systemd_dbus_evidence_no_update BEFORE UPDATE ON systemd_dbus_evidence BEGIN SELECT RAISE(ABORT, 'systemd D-Bus evidence is append-only'); END";
const SYSTEMD_EVIDENCE_DELETE_TRIGGER_SQL: &str = "CREATE TRIGGER systemd_dbus_evidence_no_delete BEFORE DELETE ON systemd_dbus_evidence BEGIN SELECT RAISE(ABORT, 'systemd D-Bus evidence is append-only'); END";

fn normalized_sql(sql: &str) -> String {
    sql.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn systemd_evidence_table_has_rows(connection: &Connection) -> Result<bool, String> {
    let exists = connection
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='systemd_dbus_evidence'",
            [],
            |_| Ok(()),
        )
        .optional()
        .map_err(|error| format!("systemd-evidence-schema-inspect:{error}"))?
        .is_some();
    if !exists {
        return Ok(false);
    }
    connection
        .query_row("SELECT count(*) FROM systemd_dbus_evidence", [], |row| {
            row.get::<_, i64>(0)
        })
        .map(|count| count > 0)
        .map_err(|error| format!("systemd-evidence-row-count:{error}"))
}

pub(super) fn validate_systemd_evidence_guards(connection: &Connection) -> Result<(), String> {
    for (name, expected) in [
        (
            "systemd_dbus_evidence_no_update",
            SYSTEMD_EVIDENCE_UPDATE_TRIGGER_SQL,
        ),
        (
            "systemd_dbus_evidence_no_delete",
            SYSTEMD_EVIDENCE_DELETE_TRIGGER_SQL,
        ),
    ] {
        let sql = connection
            .query_row(
                "SELECT sql FROM sqlite_master
                 WHERE type='trigger' AND name=?1 AND tbl_name='systemd_dbus_evidence'",
                [name],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| format!("systemd-evidence-guard-inspect:{error}"))?
            .ok_or_else(|| format!("systemd-evidence-guard-missing:{name}"))?;
        if normalized_sql(&sql) != expected {
            return Err(format!("systemd-evidence-guard-substitution:{name}"));
        }
    }
    Ok(())
}

/// Docket-to-executor message.  Its fields are exact references, not bearer
/// authority accepted independently by this adapter.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectExecutorDispatchV1 {
    /// Docket-owned execution attempt.
    pub attempt: Digest,
    /// Executor-local idempotency marker.
    pub marker: Digest,
    /// Exact work schema.
    pub work_schema: String,
    /// Exact sealed executor-plan identity.
    pub work: Digest,
    /// Exact standing-bound subject.
    pub subject: Digest,
    /// Exact standing-bound scope.
    pub scope: Digest,
}

/// Closed mechanics outcome returned to Docket.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectExecutorOutcomeClassV1 {
    /// Exact effect and durability boundary completed.
    Success,
    /// Exact mechanics proved no requested effect occurred.
    Failure,
    /// Mechanics cannot prove whether an effect occurred.
    Indeterminate,
}

/// Exact executor response consumed by Docket settlement logic.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectExecutorOutcomeV1 {
    /// Exact Docket attempt.
    pub attempt: Digest,
    /// Exact executor marker.
    pub marker: Digest,
    /// Exact canonical mechanics receipt identity.
    pub receipt: Digest,
    /// Closed outcome class.
    pub outcome: EffectExecutorOutcomeClassV1,
}

/// One exact artifact file bound into a sealed effect plan.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectArtifactFileV1 {
    /// Expected content identity.
    pub digest: Digest,
    /// Absolute non-symlink regular-file custody path.
    pub path: PathBuf,
}

/// Serializable managed-file trust policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectFilePolicyV1 {
    /// Maximum admitted or existing managed-file size.
    pub max_content_bytes: u64,
    /// Required owner of stable ancestors.
    pub trusted_ancestor_uid: u32,
    /// Required owner of the final parent directory.
    pub trusted_parent_uid: u32,
    /// Whether group/world writable final parents are refused.
    pub require_private_parent_writes: bool,
}

/// Occurrence-work assertion of the existing genesis profile identity. It is
/// never a selector for issuer trust, Docket program/state, or enrollment.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectAuthorizationInputsV2 {
    pub expected_runtime_profile: Digest,
}

/// Owner-installed sibling of the qualified `ag-effectd` binary. The binary
/// chooses its path from `/proc/self/exe`; no work or CLI argument selects it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EffectExecutorDeploymentV1 {
    schema: String,
    campaign_database: PathBuf,
    expected_runtime_profile: Digest,
}

struct EnrolledRuntimeV1 {
    campaign: Digest,
    profile_digest: Digest,
    profile: GovernedRuntimeProfileV1,
}

/// Docket-owned V2 input, mirrored independently by the AG executor.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizedEffectDispatchV2 {
    pub schema: String,
    pub signed_issuance: SignedAgIssuanceEnvelopeV1,
    pub custody: DocketCustodyV1,
    pub dispatch: EffectExecutorDispatchV1,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustedIssuerV1 {
    issuer_principal: String,
    key_id: String,
    public_key: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IssuerTrustV1 {
    issuers: Vec<TrustedIssuerV1>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DocketInspectionV1 {
    schema: String,
    requested_issuance: String,
    record: Option<DocketInspectionRecordV1>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DocketInspectionRecordV1 {
    issuance: AgIssuanceV1,
    authentication: crate::governed_ports::AgIssuanceAuthenticationV1,
    custody: DocketCustodyV1,
    status: String,
    settlement: Option<serde_json::Value>,
    indeterminate: Option<serde_json::Value>,
    executor_binding: String,
    executor_program_digest: String,
    executor_plan: String,
}

impl From<EffectFilePolicyV1> for ManagedFilePolicyV1 {
    fn from(value: EffectFilePolicyV1) -> Self {
        Self {
            max_content_bytes: value.max_content_bytes,
            trusted_ancestor_uid: value.trusted_ancestor_uid,
            trusted_parent_uid: value.trusted_parent_uid,
            require_private_parent_writes: value.require_private_parent_writes,
        }
    }
}

/// Sealed exact mechanics plan referenced by an AG issuance.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectExecutorPlanV1 {
    /// Plan schema.
    pub schema: String,
    /// Executor-local transactional idempotency journal.
    pub attempt_store: PathBuf,
    /// Exact Docket standing subject required by this plan.
    pub subject: Digest,
    /// Exact Docket standing scope required by this plan.
    pub scope: Digest,
    /// Effect position in the exact plan.
    pub effect_index: u32,
    /// One exact canonical effect.
    pub effect: CanonicalEffectV1,
    /// Exact artifact custody paths, normalized by digest.
    pub artifacts: Vec<EffectArtifactFileV1>,
    /// Closed direct-file mechanics policy.
    pub file_policy: EffectFilePolicyV1,
    /// Required durable reversible-preparation checkpoint for pointer commit.
    pub preparation_checkpoint: Option<Digest>,
    /// Absent in frozen V1. Present only in V2 and covered by the work identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization: Option<EffectAuthorizationInputsV2>,
}

impl EffectExecutorPlanV1 {
    /// Returns the exact immutable work identity bound into AG issuance.
    ///
    /// # Errors
    ///
    /// Returns an error when the plan is not closed and normalized.
    pub fn identity(&self) -> Result<Digest, String> {
        validate_plan(self)?;
        let bytes = JcsDocument::canonicalize(self)
            .map_err(|error| format!("effect-executor-plan-canonical:{error}"))?;
        Ok(Digest::hash_domain(&self.schema, bytes.as_bytes()))
    }
}

/// Loads an exact canonical plan (optionally followed by one LF).
///
/// # Errors
///
/// Returns an error for noncanonical bytes, invalid shape, or unsafe paths.
pub fn load_effect_executor_plan(path: &Path) -> Result<EffectExecutorPlanV1, String> {
    if !path.is_absolute() {
        return Err("effect-executor-plan-path-not-absolute".to_owned());
    }
    let bytes = std::fs::read(path)
        .map_err(|error| format!("effect-executor-plan-read:{}:{error}", path.display()))?;
    let body = bytes.strip_suffix(b"\n").unwrap_or(&bytes);
    let canonical = JcsDocument::from_canonical_bytes(body)
        .map_err(|error| format!("effect-executor-plan-not-canonical:{error}"))?;
    let plan: EffectExecutorPlanV1 = serde_json::from_slice(canonical.as_bytes())
        .map_err(|error| format!("effect-executor-plan-decode:{error}"))?;
    validate_plan(&plan)?;
    Ok(plan)
}

/// One schema-discriminated executor plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LoadedEffectExecutorPlan {
    /// Exact legacy V1 plan.
    V1(EffectExecutorPlanV1),
    /// Exact machine-bound systemd V2 plan.
    SystemdV2(EffectExecutorSystemdPlanV2),
}

#[derive(Deserialize)]
struct EffectExecutorPlanSchemaProbe {
    schema: String,
}

impl LoadedEffectExecutorPlan {
    /// Derive the exact owner work identity.
    ///
    /// # Errors
    ///
    /// Refuses a plan whose retained fields do not produce a valid owner identity.
    pub fn identity(&self) -> Result<Digest, String> {
        match self {
            Self::V1(plan) => plan.identity(),
            Self::SystemdV2(plan) => plan.identity(),
        }
    }
}

/// Discriminate the exact plan schema before typed decoding.
///
/// # Errors
///
/// Refuses an unrecognized schema, invalid canonical bytes, or an invalid plan.
pub fn load_effect_executor_plan_any(path: &Path) -> Result<LoadedEffectExecutorPlan, String> {
    if !path.is_absolute() {
        return Err("effect-executor-plan-path-not-absolute".to_owned());
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("effect-executor-plan-open:{}:{error}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("effect-executor-plan-metadata:{error}"))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_PLAN_BYTES {
        return Err("effect-executor-plan-not-bounded-regular-file".to_owned());
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAX_PLAN_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("effect-executor-plan-read:{error}"))?;
    if bytes.len() as u64 > MAX_PLAN_BYTES {
        return Err("effect-executor-plan-too-large".to_owned());
    }
    let body = bytes.strip_suffix(b"\n").unwrap_or(&bytes);
    let canonical = JcsDocument::from_canonical_bytes(body)
        .map_err(|error| format!("effect-executor-plan-not-canonical:{error}"))?;
    let probe: EffectExecutorPlanSchemaProbe = serde_json::from_slice(canonical.as_bytes())
        .map_err(|error| format!("effect-executor-plan-schema-probe:{error}"))?;
    match probe.schema.as_str() {
        EFFECT_EXECUTOR_PLAN_SCHEMA_V1 | EFFECT_EXECUTOR_PLAN_SCHEMA_V2 => {
            let plan: EffectExecutorPlanV1 = serde_json::from_slice(canonical.as_bytes())
                .map_err(|error| format!("effect-executor-plan-decode:{error}"))?;
            validate_plan(&plan)?;
            Ok(LoadedEffectExecutorPlan::V1(plan))
        }
        EFFECT_EXECUTOR_SYSTEMD_PLAN_SCHEMA_V2 => {
            decode_effect_executor_systemd_plan(&canonical).map(LoadedEffectExecutorPlan::SystemdV2)
        }
        _ => Err("effect-executor-plan-schema".to_owned()),
    }
}

/// Executes one exact Docket-custodied attempt or returns its prior outcome.
///
/// # Errors
///
/// Returns a refusal before mechanics for any binding or journal conflict.
pub fn execute_effect_attempt(
    plan: &EffectExecutorPlanV1,
    dispatch: &EffectExecutorDispatchV1,
) -> Result<EffectExecutorOutcomeV1, String> {
    validate_dispatch(plan, dispatch)?;
    let mut store = EffectAttemptStoreV1::open(&plan.attempt_store)?;
    match store.reserve(plan, dispatch)? {
        ReservationV1::Prior(outcome) => return Ok(outcome),
        ReservationV1::Ambiguous => {
            return store.mark_indeterminate(
                plan,
                dispatch,
                "restart-after-reserved-attempt",
                None,
            );
        }
        ReservationV1::Reserved => {}
    }

    let artifacts = PlanArtifactSourceV1::new(plan)?;
    let pointer = UnavailablePointerHelperV1;
    let systemd = UnavailableSystemdBackendV1;
    let executor = EffectExecutorV1::new(
        &artifacts,
        &pointer,
        &systemd,
        ManagedFilePolicyV1::from(plan.file_policy),
    );
    let permit = match &plan.preparation_checkpoint {
        Some(checkpoint) => DocketCustodiedExecutionPermitV1::from_docket_preparation(
            dispatch.work.clone(),
            dispatch.marker.clone(),
            dispatch.attempt.clone(),
            plan.effect_index,
            checkpoint.clone(),
        ),
        None => DocketCustodiedExecutionPermitV1::from_docket_custody(
            dispatch.work.clone(),
            dispatch.marker.clone(),
            dispatch.attempt.clone(),
            plan.effect_index,
        ),
    };
    let receipt = executor.execute_docket_custodied_once(permit, &plan.effect);
    receipt
        .verify_bindings(
            &dispatch.work,
            &dispatch.marker,
            &dispatch.attempt,
            plan.effect_index,
            &plan.effect,
        )
        .map_err(|error| format!("effect-executor-receipt-binding:{error}"))?;
    let outcome = match &receipt.outcome {
        ExecutionOutcomeV1::Succeeded { .. } => EffectExecutorOutcomeClassV1::Success,
        ExecutionOutcomeV1::Failed { .. } => EffectExecutorOutcomeClassV1::Failure,
        ExecutionOutcomeV1::Indeterminate { .. } => EffectExecutorOutcomeClassV1::Indeterminate,
    };
    let receipt_body = JcsDocument::canonicalize(&receipt)
        .map_err(|error| format!("effect-executor-receipt-canonical:{error}"))?;
    let receipt_id = receipt
        .digest()
        .map_err(|error| format!("effect-executor-receipt-digest:{error}"))?;
    store.finish(plan, dispatch, receipt_id, outcome, receipt_body.as_bytes())
}

/// Reads only executor-local attempt evidence; never invokes mechanics.
///
/// # Errors
///
/// Returns a refusal for a missing or substituted attempt.
pub fn reconcile_effect_attempt(
    plan: &EffectExecutorPlanV1,
    dispatch: &EffectExecutorDispatchV1,
) -> Result<EffectExecutorOutcomeV1, String> {
    validate_dispatch(plan, dispatch)?;
    let mut store = EffectAttemptStoreV1::open(&plan.attempt_store)?;
    match store.get(&dispatch.attempt)? {
        Some(record) if !record.matches(dispatch) => {
            Err("effect-executor-attempt-substitution".to_owned())
        }
        Some(record) => match record.outcome(plan)? {
            Some(outcome) => Ok(outcome),
            None => store.mark_indeterminate(
                plan,
                dispatch,
                "reconciliation-found-reserved-attempt",
                None,
            ),
        },
        None => Err("effect-executor-attempt-not-found".to_owned()),
    }
}

fn validate_plan(plan: &EffectExecutorPlanV1) -> Result<(), String> {
    if !matches!(
        (plan.schema.as_str(), plan.authorization.is_some()),
        (EFFECT_EXECUTOR_PLAN_SCHEMA_V1, false) | (EFFECT_EXECUTOR_PLAN_SCHEMA_V2, true)
    ) {
        return Err("effect-executor-plan-schema".to_owned());
    }
    if !plan.attempt_store.is_absolute() || plan.file_policy.max_content_bytes == 0 {
        return Err("effect-executor-plan-store-or-limit".to_owned());
    }
    let is_promotion = matches!(
        &plan.effect,
        CanonicalEffectV1::ManagedPointerPromotion { .. }
    );
    if is_promotion != plan.preparation_checkpoint.is_some() {
        return Err("effect-executor-plan-preparation-checkpoint".to_owned());
    }
    let mut previous: Option<&Digest> = None;
    for artifact in &plan.artifacts {
        if !artifact.path.is_absolute() {
            return Err("effect-executor-artifact-path-not-absolute".to_owned());
        }
        if previous.is_some_and(|prior| prior >= &artifact.digest) {
            return Err("effect-executor-artifacts-not-unique-sorted".to_owned());
        }
        previous = Some(&artifact.digest);
    }
    Ok(())
}

fn validate_dispatch(
    plan: &EffectExecutorPlanV1,
    dispatch: &EffectExecutorDispatchV1,
) -> Result<(), String> {
    validate_plan(plan)?;
    if dispatch.work_schema != EFFECT_EXECUTOR_WORK_SCHEMA_V1
        || dispatch.work != plan.identity()?
        || dispatch.subject != plan.subject
        || dispatch.scope != plan.scope
    {
        return Err("effect-executor-dispatch-plan-binding".to_owned());
    }
    Ok(())
}

fn decode_base64_exact(value: &str, label: &str) -> Result<Vec<u8>, String> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| format!("effect-executor-{label}-base64"))?;
    if URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(format!("effect-executor-{label}-noncanonical"));
    }
    Ok(bytes)
}

fn installed_deployment_path() -> Result<PathBuf, String> {
    let executable = std::fs::read_link("/proc/self/exe")
        .map_err(|error| format!("effect-executor-installed-exe:{error}"))?;
    let parent = executable
        .parent()
        .ok_or_else(|| "effect-executor-installed-parent-absent".to_owned())?;
    Ok(parent.join("ag-effectd.deployment.json"))
}

fn load_enrolled_runtime(path: &Path) -> Result<EnrolledRuntimeV1, String> {
    // This fixed sibling is an owner-installed deployment input, not a
    // plan-selected authority. Same-UID replacement is outside this host's
    // stated isolation claim; source-free installation must retain its custody.
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("effect-executor-deployment-open:{error}"))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("effect-executor-deployment-metadata:{error}"))?;
    if !metadata.is_file() || metadata.len() > MAX_DEPLOYMENT_CONFIG_BYTES {
        return Err("effect-executor-deployment-shape".to_owned());
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|error| format!("effect-executor-deployment-read:{error}"))?;
    if bytes.len() as u64 > MAX_DEPLOYMENT_CONFIG_BYTES {
        return Err("effect-executor-deployment-size".to_owned());
    }
    let document = JcsDocument::from_canonical_bytes(&bytes)
        .map_err(|error| format!("effect-executor-deployment-canonical:{error}"))?;
    let deployment: EffectExecutorDeploymentV1 = strict_json_from_slice(document.as_bytes())
        .map_err(|error| format!("effect-executor-deployment-json:{error}"))?;
    if deployment.schema != EFFECT_EXECUTOR_DEPLOYMENT_SCHEMA_V1
        || !deployment.campaign_database.is_absolute()
    {
        return Err("effect-executor-deployment-schema-or-path".to_owned());
    }
    let connection = Connection::open_with_flags(
        &deployment.campaign_database,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|error| format!("effect-executor-campaign-open:{error}"))?;
    connection
        .busy_timeout(Duration::from_secs(5))
        .map_err(|error| format!("effect-executor-campaign-timeout:{error}"))?;
    let campaign_text: String = connection
        .query_row("SELECT campaign_id FROM campaigns", [], |row| row.get(0))
        .map_err(|error| format!("effect-executor-campaign-id:{error}"))?;
    let campaign = Digest::parse(&campaign_text)
        .map_err(|error| format!("effect-executor-campaign-identity:{error}"))?;
    let (schema, digest_text, profile_bytes): (String, String, Vec<u8>) = connection
        .query_row(
            "SELECT schema,profile_digest,profile_jcs FROM runtime_profile WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|error| format!("effect-executor-genesis-profile:{error}"))?;
    if schema != GOVERNED_RUNTIME_PROFILE_SCHEMA_V1 {
        return Err("effect-executor-genesis-profile-schema".to_owned());
    }
    let profile_digest = Digest::parse(&digest_text)
        .map_err(|error| format!("effect-executor-genesis-profile-identity:{error}"))?;
    let canonical = JcsDocument::from_canonical_bytes(&profile_bytes)
        .map_err(|error| format!("effect-executor-genesis-profile-canonical:{error}"))?;
    if profile_digest != Digest::hash_domain(&schema, canonical.as_bytes())
        || profile_digest != deployment.expected_runtime_profile
    {
        return Err("effect-executor-genesis-profile-binding".to_owned());
    }
    let profile: GovernedRuntimeProfileV1 = strict_json_from_slice(canonical.as_bytes())
        .map_err(|error| format!("effect-executor-genesis-profile-json:{error}"))?;
    if profile.schema != schema {
        return Err("effect-executor-genesis-profile-substitution".to_owned());
    }
    Ok(EnrolledRuntimeV1 {
        campaign,
        profile_digest,
        profile,
    })
}

fn bind_enrolled_docket<'a>(
    plan: &EffectExecutorPlanV1,
    enrolled: &'a EnrolledRuntimeV1,
    executable_path: &Path,
    executable_bytes: &[u8],
) -> Result<(&'a GovernedDocketRootV1, Vec<u8>), String> {
    let expected = plan
        .authorization
        .as_ref()
        .ok_or_else(|| "effect-executor-v2-plan-required".to_owned())?;
    if expected.expected_runtime_profile != enrolled.profile_digest {
        return Err("effect-executor-plan-profile-substitution".to_owned());
    }
    let docket = &enrolled.profile.docket;
    if docket.schema != GOVERNED_DOCKET_ROOT_SCHEMA_V1
        || !docket.state_directory.is_absolute()
        || docket.issuer_principal.is_empty()
        || docket.issuer_key_id.is_empty()
        || docket.executor_adapter.path != executable_path
        || docket.executor_adapter.identity != Digest::hash_bytes(executable_bytes)
    {
        return Err("effect-executor-installed-docket-root-substitution".to_owned());
    }
    docket
        .executor_adapter
        .verify(true)
        .map_err(|error| format!("effect-executor-installed-binary:{error}"))?;
    docket
        .docket_program
        .verify(true)
        .map_err(|error| format!("effect-executor-installed-docket:{error}"))?;
    docket
        .standing_resolver
        .verify(true)
        .map_err(|error| format!("effect-executor-installed-standing-resolver:{error}"))?;
    let trust = docket
        .trust_config
        .verify(false)
        .map_err(|error| format!("effect-executor-installed-trust:{error}"))?;
    Ok((docket, trust))
}

/// Checks the installed V2 executor root before Docket accepts custody. The
/// caller cannot present an alternate deployment path; V1 identities remain
/// readable without this V2-only installation premise.
pub fn verify_plan_deployment_v2(plan: &EffectExecutorPlanV1) -> Result<(), String> {
    validate_plan(plan)?;
    if plan.authorization.is_none() {
        return Ok(());
    }
    let enrolled = load_enrolled_runtime(&installed_deployment_path()?)?;
    let executable_path = std::fs::read_link("/proc/self/exe")
        .map_err(|error| format!("effect-executor-self-path:{error}"))?;
    let executable_bytes = std::fs::read("/proc/self/exe")
        .map_err(|error| format!("effect-executor-self-identity:{error}"))?;
    let _ = bind_enrolled_docket(plan, &enrolled, &executable_path, &executable_bytes)?;
    Ok(())
}

/// Verifies V2 against the independently owner-installed C1 genesis profile
/// and read-only persisted Docket custody. The work plan asserts only the
/// expected profile identity; it cannot select the trust, inspector or state.
pub fn verify_authorized_dispatch_v2(
    plan: &EffectExecutorPlanV1,
    input: &AuthorizedEffectDispatchV2,
    operation: &str,
) -> Result<EffectExecutorDispatchV1, String> {
    validate_plan(plan)?;
    let deployment_path = installed_deployment_path()?;
    let enrolled = load_enrolled_runtime(&deployment_path)?;
    let executable_path = std::fs::read_link("/proc/self/exe")
        .map_err(|error| format!("effect-executor-self-path:{error}"))?;
    let self_bytes = std::fs::read("/proc/self/exe")
        .map_err(|error| format!("effect-executor-self-identity:{error}"))?;
    let (authority, trust_bytes) =
        bind_enrolled_docket(plan, &enrolled, &executable_path, &self_bytes)?;
    if input.schema != DOCKET_EXECUTOR_DISPATCH_SCHEMA_V2 {
        return Err("effect-executor-dispatch-schema".to_owned());
    }
    validate_dispatch(plan, &input.dispatch)?;

    let trust: IssuerTrustV1 = strict_json_from_slice(&trust_bytes)
        .map_err(|error| format!("effect-executor-issuer-trust-json:{error}"))?;
    let authentication = &input.signed_issuance.authentication;
    if input.signed_issuance.schema != "ag.governed-loop.signed-issuance/v1"
        || authentication.issuer_principal != authority.issuer_principal
        || authentication.signer_key_id != authority.issuer_key_id
    {
        return Err("effect-executor-untrusted-issuer".to_owned());
    }
    let trusted = trust
        .issuers
        .iter()
        .filter(|issuer| {
            issuer.issuer_principal == authority.issuer_principal
                && issuer.key_id == authority.issuer_key_id
        })
        .collect::<Vec<_>>();
    if trusted.len() != 1 || trusted[0].public_key != authentication.signer_public_key {
        return Err("effect-executor-issuer-key-substitution".to_owned());
    }
    let body = decode_base64_exact(&input.signed_issuance.body_b64, "issuance-body")?;
    let key = decode_base64_exact(&trusted[0].public_key, "issuer-key")?;
    let signature = decode_base64_exact(&authentication.signature, "issuance-signature")?;
    if key.len() != 32 || signature.len() != 64 {
        return Err("effect-executor-issuer-signature-shape".to_owned());
    }
    let mut signed = Vec::with_capacity(SIGNATURE_PREFIX_V1.len() + body.len());
    signed.extend_from_slice(SIGNATURE_PREFIX_V1);
    signed.extend_from_slice(&body);
    UnparsedPublicKey::new(&ED25519, &key)
        .verify(&signed, &signature)
        .map_err(|_| "effect-executor-issuance-signature".to_owned())?;
    let canonical_body = JcsDocument::from_canonical_bytes(&body)
        .map_err(|error| format!("effect-executor-issuance-canonical:{error}"))?;
    let issuance: AgIssuanceV1 = strict_json_from_slice(canonical_body.as_bytes())
        .map_err(|error| format!("effect-executor-issuance-json:{error}"))?;
    if issuance.schema != AG_ISSUANCE_SCHEMA_V1 {
        return Err("effect-executor-issuance-schema".to_owned());
    }
    if issuance.key.campaign.as_digest() != &enrolled.campaign {
        return Err("effect-executor-campaign-substitution".to_owned());
    }
    let basis = serde_json::json!({
        "key": issuance.key,
        "program": issuance.program,
        "proposal": issuance.proposal,
        "work_schema": issuance.work_schema,
        "work": issuance.work,
        "subject": issuance.subject,
        "scope": issuance.scope,
        "observation": issuance.observation,
        "standing_resolution": issuance.standing_resolution,
        "mandate": issuance.mandate,
        "spend": issuance.spend,
    });
    let basis = JcsDocument::canonicalize(&basis)
        .map_err(|error| format!("effect-executor-issuance-basis:{error}"))?;
    if Digest::hash_domain(AG_ISSUANCE_SCHEMA_V1, basis.as_bytes()).as_str()
        != issuance.issuance.as_str()
    {
        return Err("effect-executor-issuance-identity".to_owned());
    }
    let custody = &input.custody;
    if custody.schema != DOCKET_CUSTODY_SCHEMA_V1
        || custody.issuance != issuance.issuance
        || custody.ag_spend != issuance.spend
        || input.dispatch.work != issuance.work
        || input.dispatch.work_schema != issuance.work_schema
        || input.dispatch.subject != issuance.subject
        || input.dispatch.scope != issuance.scope
        || input.dispatch.attempt.as_str() != custody.attempt.as_str()
        || input.dispatch.marker.as_str() != custody.executor_marker.as_str()
    {
        return Err("effect-executor-issuance-custody-dispatch-binding".to_owned());
    }
    let attempt_basis = serde_json::to_vec(issuance.issuance.as_str())
        .map_err(|error| format!("effect-executor-attempt-basis:{error}"))?;
    let expected_attempt =
        Digest::hash_domain("ag.governed-loop.docket-attempt/v1", &attempt_basis);
    let expected_marker = Digest::hash_domain(
        "docket.governed-loop.executor-marker/v1",
        expected_attempt.as_str().as_bytes(),
    );
    if custody.attempt.as_str() != expected_attempt.as_str()
        || custody.executor_marker.as_str() != expected_marker.as_str()
    {
        return Err("effect-executor-attempt-marker-binding".to_owned());
    }

    // The Docket accept transaction commits custody before executor delivery.
    // The same read-only inspection is valid on historical reconciliation;
    // neither branch asks for current standing or a new issuance window.
    let mut inspector = Command::new(&authority.docket_program.path)
        .args(["governed-loop", "inspect", "--state"])
        .arg(&authority.state_directory)
        .arg("--issuance")
        .arg(issuance.issuance.as_str())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("effect-executor-docket-inspect:{error}"))?;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match inspector.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {}
            Err(error) => {
                let _ = inspector.kill();
                let _ = inspector.wait();
                return Err(format!("effect-executor-docket-inspect-wait:{error}"));
            }
        }
        if Instant::now() >= deadline {
            let _ = inspector.kill();
            let _ = inspector.wait_with_output();
            return Err("effect-executor-docket-inspect-timeout".to_owned());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = inspector
        .wait_with_output()
        .map_err(|error| format!("effect-executor-docket-inspect-output:{error}"))?;
    if !output.status.success() || output.stdout.len() as u64 > DOCKET_EXECUTOR_MAX_DOCUMENT_BYTES_V1 {
        return Err("effect-executor-docket-inspect-refused".to_owned());
    }
    let inspected: DocketInspectionV1 = strict_json_from_slice(&output.stdout)
        .map_err(|error| format!("effect-executor-docket-inspection-json:{error}"))?;
    let record = inspected
        .record
        .ok_or_else(|| "effect-executor-docket-custody-absent".to_owned())?;
    if inspected.schema != DOCKET_INSPECTION_SCHEMA_V1
        || inspected.requested_issuance != issuance.issuance.as_str()
        || record.issuance != issuance
        || record.authentication != *authentication
        || record.custody != *custody
        || record.executor_plan != plan.identity()?.as_str()
    {
        return Err("effect-executor-docket-inspection-substitution".to_owned());
    }
    let program_digest =
        Digest::hash_domain("docket.governed-loop.executor-program/v1", &self_bytes);
    let binding = serde_json::json!({
        "plan": record.executor_plan,
        "program_digest": program_digest.as_str(),
    });
    let binding = JcsDocument::canonicalize(&binding)
        .map_err(|error| format!("effect-executor-docket-binding:{error}"))?;
    if record.executor_program_digest != program_digest.as_str()
        || record.executor_binding
            != Digest::hash_domain(
                "docket.governed-loop.executor-binding/v1",
                binding.as_bytes(),
            )
            .as_str()
    {
        return Err("effect-executor-docket-executor-substitution".to_owned());
    }
    match operation {
        "execute"
            if record.status == "accepted"
                && record.settlement.is_none()
                && record.indeterminate.is_none() => {}
        "reconcile"
            if matches!(
                record.status.as_str(),
                "accepted" | "indeterminate" | "settled"
            ) => {}
        _ => return Err("effect-executor-docket-status-not-admitting".to_owned()),
    }
    Ok(input.dispatch.clone())
}

struct PlanArtifactSourceV1 {
    paths: BTreeMap<Digest, PathBuf>,
    maximum: u64,
}

impl PlanArtifactSourceV1 {
    fn new(plan: &EffectExecutorPlanV1) -> Result<Self, String> {
        let paths = plan
            .artifacts
            .iter()
            .map(|artifact| (artifact.digest.clone(), artifact.path.clone()))
            .collect::<BTreeMap<_, _>>();
        if paths.len() != plan.artifacts.len() {
            return Err("effect-executor-artifact-duplicate".to_owned());
        }
        Ok(Self {
            paths,
            maximum: plan.file_policy.max_content_bytes,
        })
    }
}

impl ArtifactSourceV1 for PlanArtifactSourceV1 {
    fn load(&self, digest: &Digest) -> Result<Vec<u8>, ArtifactReadErrorV1> {
        let path = self.paths.get(digest).ok_or_else(|| {
            ArtifactReadErrorV1::new("artifact_not_bound", "effect plan does not bind artifact")
        })?;
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
            .map_err(|error| ArtifactReadErrorV1::new("artifact_open", error.to_string()))?;
        let metadata = file
            .metadata()
            .map_err(|error| ArtifactReadErrorV1::new("artifact_metadata", error.to_string()))?;
        if !metadata.is_file() || metadata.len() > self.maximum {
            return Err(ArtifactReadErrorV1::new(
                "artifact_shape",
                "artifact is not a bounded regular file",
            ));
        }
        let mut bytes = Vec::new();
        file.by_ref()
            .take(self.maximum + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| ArtifactReadErrorV1::new("artifact_read", error.to_string()))?;
        if bytes.len() as u64 > self.maximum || Digest::hash_bytes(&bytes) != *digest {
            return Err(ArtifactReadErrorV1::new(
                "artifact_identity",
                "artifact bytes differ from exact plan identity",
            ));
        }
        Ok(bytes)
    }
}

struct UnavailablePointerHelperV1;

impl PinnedPointerHelperV1 for UnavailablePointerHelperV1 {
    fn identity(&self) -> CapabilityOutcomeV1<PinnedHelperIdentityV1> {
        CapabilityOutcomeV1::Failed(unavailable("pointer_helper_unavailable"))
    }

    fn prepare(
        &self,
        _request: &PointerPreparationRequestV1,
        _artifact: &[u8],
    ) -> CapabilityOutcomeV1<PointerPreparationSuccessV1> {
        CapabilityOutcomeV1::Failed(unavailable("pointer_helper_unavailable"))
    }

    fn compare_and_swap(
        &self,
        _request: &PointerCasRequestV1,
    ) -> CapabilityOutcomeV1<PointerCasSuccessV1> {
        CapabilityOutcomeV1::Failed(unavailable("pointer_helper_unavailable"))
    }
}

struct UnavailableSystemdBackendV1;

impl SystemdDbusBackendV1 for UnavailableSystemdBackendV1 {
    fn unit_action(
        &self,
        _request: &SystemdUnitRequestV1,
    ) -> CapabilityOutcomeV1<SystemdUnitSuccessV1> {
        CapabilityOutcomeV1::Failed(unavailable("systemd_backend_unavailable"))
    }

    fn reload_manager(
        &self,
        _request: &SystemdManagerReloadRequestV1,
    ) -> CapabilityOutcomeV1<SystemdManagerReloadSuccessV1> {
        CapabilityOutcomeV1::Failed(unavailable("systemd_backend_unavailable"))
    }
}

fn unavailable(code: &str) -> CapabilityFailureV1 {
    CapabilityFailureV1 {
        code: code.to_owned(),
        detail: "capability is not installed in this authority-neutral adapter".to_owned(),
        evidence: None,
    }
}

#[derive(Clone)]
struct AttemptRecordV1 {
    attempt: Digest,
    marker: Digest,
    work: Digest,
    subject: Digest,
    scope: Digest,
    status: String,
    receipt: Option<Digest>,
    receipt_body: Option<Vec<u8>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredIndeterminateReceiptV1 {
    schema: String,
    attempt: Digest,
    marker: Digest,
    reason: String,
    evidence: Option<Vec<u8>>,
}

impl AttemptRecordV1 {
    fn matches(&self, dispatch: &EffectExecutorDispatchV1) -> bool {
        self.attempt == dispatch.attempt
            && self.marker == dispatch.marker
            && self.work == dispatch.work
            && self.subject == dispatch.subject
            && self.scope == dispatch.scope
    }

    fn outcome(
        &self,
        plan: &EffectExecutorPlanV1,
    ) -> Result<Option<EffectExecutorOutcomeV1>, String> {
        let Some(receipt) = &self.receipt else {
            return if self.status == "started" && self.receipt_body.is_none() {
                Ok(None)
            } else {
                Err("effect-executor-attempt-corrupt".to_owned())
            };
        };
        let body = self
            .receipt_body
            .as_deref()
            .ok_or_else(|| "effect-executor-receipt-body-missing".to_owned())?;
        let canonical = JcsDocument::from_canonical_bytes(body)
            .map_err(|error| format!("effect-executor-receipt-body-invalid:{error}"))?;
        if Digest::from_serializable(
            &serde_json::from_slice::<serde_json::Value>(canonical.as_bytes())
                .map_err(|error| format!("effect-executor-receipt-json:{error}"))?,
        )
        .map_err(|error| format!("effect-executor-receipt-redigest:{error}"))?
            != *receipt
        {
            return Err("effect-executor-receipt-identity-mismatch".to_owned());
        }
        let outcome = match self.status.as_str() {
            "success" => {
                self.verify_effect_receipt(canonical.as_bytes(), plan, false)?;
                EffectExecutorOutcomeClassV1::Success
            }
            "failure" => {
                self.verify_effect_receipt(canonical.as_bytes(), plan, false)?;
                EffectExecutorOutcomeClassV1::Failure
            }
            "indeterminate" => {
                if self
                    .verify_effect_receipt(canonical.as_bytes(), plan, true)
                    .is_err()
                {
                    let record: StoredIndeterminateReceiptV1 =
                        serde_json::from_slice(canonical.as_bytes()).map_err(|error| {
                            format!("effect-executor-indeterminate-body:{error}")
                        })?;
                    if record.schema != "ag-effectd.executor-indeterminate/v1"
                        || record.attempt != self.attempt
                        || record.marker != self.marker
                        || record.reason.is_empty()
                    {
                        return Err("effect-executor-indeterminate-binding".to_owned());
                    }
                    let _ = record.evidence;
                }
                EffectExecutorOutcomeClassV1::Indeterminate
            }
            _ => return Err("effect-executor-attempt-status".to_owned()),
        };
        Ok(Some(EffectExecutorOutcomeV1 {
            attempt: self.attempt.clone(),
            marker: self.marker.clone(),
            receipt: receipt.clone(),
            outcome,
        }))
    }

    fn verify_effect_receipt(
        &self,
        body: &[u8],
        plan: &EffectExecutorPlanV1,
        expect_indeterminate: bool,
    ) -> Result<(), String> {
        let receipt: DocketEffectExecutionReceiptV1 = serde_json::from_slice(body)
            .map_err(|error| format!("effect-executor-typed-receipt:{error}"))?;
        receipt
            .verify_bindings(
                &self.work,
                &self.marker,
                &self.attempt,
                plan.effect_index,
                &plan.effect,
            )
            .map_err(|_| "effect-executor-typed-receipt-binding".to_owned())?;
        let is_indeterminate = matches!(receipt.outcome, ExecutionOutcomeV1::Indeterminate { .. });
        let is_success = matches!(receipt.outcome, ExecutionOutcomeV1::Succeeded { .. });
        if is_indeterminate != expect_indeterminate
            || (self.status == "success" && !is_success)
            || (self.status == "failure" && (is_success || is_indeterminate))
        {
            return Err("effect-executor-typed-receipt-outcome".to_owned());
        }
        Ok(())
    }
}

#[derive(Debug)]
enum ReservationV1 {
    Reserved,
    Prior(EffectExecutorOutcomeV1),
    Ambiguous,
}

struct EffectAttemptStoreV1 {
    connection: Connection,
}

impl EffectAttemptStoreV1 {
    fn open(path: &Path) -> Result<Self, String> {
        if !path.is_absolute() {
            return Err("effect-executor-store-path-not-absolute".to_owned());
        }
        if !path.exists() {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|error| format!("effect-executor-store-parent:{error}"))?;
            }
            match OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(path)
            {
                Ok(file) => drop(file),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(format!("effect-executor-store-create:{error}")),
            }
        }
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|error| format!("effect-executor-store-lstat:{error}"))?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Err("effect-executor-store-not-regular".to_owned());
        }
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|error| format!("effect-executor-store-open:{error}"))?;
        connection
            .busy_timeout(Duration::from_secs(5))
            .map_err(|error| format!("effect-executor-store-busy:{error}"))?;
        if systemd_evidence_table_has_rows(&connection)? {
            validate_systemd_evidence_guards(&connection)?;
        }
        // Two first deliveries can discover the newly created database at the
        // same time. `busy_timeout` covers SQLITE_BUSY, but SQLite can report
        // SQLITE_LOCKED while the other connection changes journal mode or
        // installs the schema.  Initialization is authority-neutral and
        // idempotent, so retry only these two lock classifications within the
        // same bounded five-second window used for write contention.
        execute_batch_with_lock_retry(
            &connection,
            "effect-executor-store-pragmas",
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA trusted_schema=OFF;",
        )?;
        execute_batch_with_lock_retry(&connection, "effect-executor-store-schema", STORE_SCHEMA)?;
        validate_systemd_evidence_guards(&connection)?;
        Ok(Self { connection })
    }

    fn reserve(
        &mut self,
        plan: &EffectExecutorPlanV1,
        dispatch: &EffectExecutorDispatchV1,
    ) -> Result<ReservationV1, String> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| format!("effect-executor-reserve-begin:{error}"))?;
        let existing = read_attempt(&transaction, &dispatch.attempt)?;
        let result = match existing {
            Some(record) if !record.matches(dispatch) => {
                return Err("effect-executor-attempt-substitution".to_owned());
            }
            Some(record) => match record.outcome(plan)? {
                Some(outcome) => ReservationV1::Prior(outcome),
                None => ReservationV1::Ambiguous,
            },
            None => {
                transaction
                    .execute(
                        "INSERT INTO docket_effect_attempt
                         (attempt,marker,work,subject,scope,status)
                         VALUES (?1,?2,?3,?4,?5,'started')",
                        params![
                            dispatch.attempt.as_str(),
                            dispatch.marker.as_str(),
                            dispatch.work.as_str(),
                            dispatch.subject.as_str(),
                            dispatch.scope.as_str()
                        ],
                    )
                    .map_err(|error| format!("effect-executor-reserve-insert:{error}"))?;
                ReservationV1::Reserved
            }
        };
        transaction
            .commit()
            .map_err(|error| format!("effect-executor-reserve-commit:{error}"))?;
        checkpoint(&self.connection)?;
        Ok(result)
    }

    fn get(&mut self, attempt: &Digest) -> Result<Option<AttemptRecordV1>, String> {
        read_attempt(&self.connection, attempt)
    }

    fn finish(
        &mut self,
        plan: &EffectExecutorPlanV1,
        dispatch: &EffectExecutorDispatchV1,
        receipt: Digest,
        outcome: EffectExecutorOutcomeClassV1,
        body: &[u8],
    ) -> Result<EffectExecutorOutcomeV1, String> {
        let status = match outcome {
            EffectExecutorOutcomeClassV1::Success => "success",
            EffectExecutorOutcomeClassV1::Failure => "failure",
            EffectExecutorOutcomeClassV1::Indeterminate => "indeterminate",
        };
        let changed = self
            .connection
            .execute(
                "UPDATE docket_effect_attempt
                 SET status=?1,receipt=?2,receipt_body=?3
                 WHERE attempt=?4 AND marker=?5 AND status='started'",
                params![
                    status,
                    receipt.as_str(),
                    body,
                    dispatch.attempt.as_str(),
                    dispatch.marker.as_str()
                ],
            )
            .map_err(|error| format!("effect-executor-finish:{error}"))?;
        if changed != 1 {
            return self
                .get(&dispatch.attempt)?
                .ok_or_else(|| "effect-executor-finish-attempt-missing".to_owned())?
                .outcome(plan)?
                .ok_or_else(|| "effect-executor-finish-conflict".to_owned());
        }
        checkpoint(&self.connection)?;
        Ok(EffectExecutorOutcomeV1 {
            attempt: dispatch.attempt.clone(),
            marker: dispatch.marker.clone(),
            receipt,
            outcome,
        })
    }

    fn mark_indeterminate(
        &mut self,
        plan: &EffectExecutorPlanV1,
        dispatch: &EffectExecutorDispatchV1,
        reason: &str,
        evidence: Option<&[u8]>,
    ) -> Result<EffectExecutorOutcomeV1, String> {
        #[derive(Serialize)]
        struct Indeterminate<'a> {
            schema: &'static str,
            attempt: &'a Digest,
            marker: &'a Digest,
            reason: &'a str,
            evidence: Option<&'a [u8]>,
        }
        let record = Indeterminate {
            schema: "ag-effectd.executor-indeterminate/v1",
            attempt: &dispatch.attempt,
            marker: &dispatch.marker,
            reason,
            evidence,
        };
        let body = JcsDocument::canonicalize(&record)
            .map_err(|error| format!("effect-executor-indeterminate-canonical:{error}"))?;
        let receipt = Digest::from_serializable(&record)
            .map_err(|error| format!("effect-executor-indeterminate-digest:{error}"))?;
        self.finish(
            plan,
            dispatch,
            receipt,
            EffectExecutorOutcomeClassV1::Indeterminate,
            body.as_bytes(),
        )
    }
}

fn execute_batch_with_lock_retry(
    connection: &Connection,
    context: &str,
    sql: &str,
) -> Result<(), String> {
    const RETRY_COUNT: usize = 1_000;
    const RETRY_DELAY: Duration = Duration::from_millis(5);

    for attempt in 0..=RETRY_COUNT {
        match connection.execute_batch(sql) {
            Ok(()) => return Ok(()),
            Err(error)
                if attempt < RETRY_COUNT
                    && matches!(
                        error.sqlite_error_code(),
                        Some(ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked)
                    ) =>
            {
                std::thread::sleep(RETRY_DELAY);
            }
            Err(error) => return Err(format!("{context}:{error}")),
        }
    }
    unreachable!("bounded SQLite initialization retry returns from every branch")
}

fn read_attempt(
    connection: &Connection,
    attempt: &Digest,
) -> Result<Option<AttemptRecordV1>, String> {
    connection
        .query_row(
            "SELECT attempt,marker,work,subject,scope,status,receipt,receipt_body
             FROM docket_effect_attempt WHERE attempt=?1",
            [attempt.as_str()],
            |row| {
                let attempt: String = row.get(0)?;
                let marker: String = row.get(1)?;
                let work: String = row.get(2)?;
                let subject: String = row.get(3)?;
                let scope: String = row.get(4)?;
                let receipt: Option<String> = row.get(6)?;
                Ok((
                    attempt,
                    marker,
                    work,
                    subject,
                    scope,
                    row.get(5)?,
                    receipt,
                    row.get(7)?,
                ))
            },
        )
        .optional()
        .map_err(|error| format!("effect-executor-attempt-read:{error}"))?
        .map(
            |(attempt, marker, work, subject, scope, status, receipt, receipt_body)| {
                Ok(AttemptRecordV1 {
                    attempt: Digest::parse(&attempt)
                        .map_err(|error| format!("effect-executor-attempt-digest:{error}"))?,
                    marker: Digest::parse(&marker)
                        .map_err(|error| format!("effect-executor-marker-digest:{error}"))?,
                    work: Digest::parse(&work)
                        .map_err(|error| format!("effect-executor-work-digest:{error}"))?,
                    subject: Digest::parse(&subject)
                        .map_err(|error| format!("effect-executor-subject-digest:{error}"))?,
                    scope: Digest::parse(&scope)
                        .map_err(|error| format!("effect-executor-scope-digest:{error}"))?,
                    status,
                    receipt: receipt
                        .map(|value| {
                            Digest::parse(&value)
                                .map_err(|error| format!("effect-executor-receipt-digest:{error}"))
                        })
                        .transpose()?,
                    receipt_body,
                })
            },
        )
        .transpose()
}

fn checkpoint(connection: &Connection) -> Result<(), String> {
    connection
        .execute_batch("PRAGMA wal_checkpoint(PASSIVE);")
        .map_err(|error| format!("effect-executor-store-checkpoint:{error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governed_ports::PinnedDeploymentFileV1;
    use ag_effect::{SystemdUnitActionV1, TargetId};
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    fn fixture() -> (
        tempfile::TempDir,
        EffectExecutorPlanV1,
        EffectExecutorDispatchV1,
    ) {
        let directory = tempfile::tempdir().expect("temporary effect executor root");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let artifact_path = directory.path().join("artifact");
        std::fs::write(&artifact_path, b"governed-loop-effect\n").unwrap();
        let content = Digest::hash_bytes(b"governed-loop-effect\n");
        let subject = Digest::hash_bytes(b"effect-subject");
        let scope = Digest::hash_bytes(b"effect-scope");
        let plan = EffectExecutorPlanV1 {
            schema: EFFECT_EXECUTOR_PLAN_SCHEMA_V1.to_owned(),
            attempt_store: directory.path().join("attempt.sqlite3"),
            subject: subject.clone(),
            scope: scope.clone(),
            effect_index: 0,
            effect: CanonicalEffectV1::ManagedFilePut {
                target: TargetId::parse("governed-loop-test").unwrap(),
                path: directory.path().join("target").display().to_string(),
                expected_content: None,
                content: content.clone(),
                mode: 0o600,
                uid: nix::unistd::Uid::current().as_raw(),
                gid: nix::unistd::Gid::current().as_raw(),
            },
            artifacts: vec![EffectArtifactFileV1 {
                digest: content,
                path: artifact_path,
            }],
            file_policy: EffectFilePolicyV1 {
                max_content_bytes: 1024,
                trusted_ancestor_uid: std::fs::metadata("/").unwrap().uid(),
                trusted_parent_uid: nix::unistd::Uid::current().as_raw(),
                require_private_parent_writes: true,
            },
            preparation_checkpoint: None,
            authorization: None,
        };
        let dispatch = EffectExecutorDispatchV1 {
            attempt: Digest::hash_bytes(b"effect-attempt"),
            marker: Digest::hash_bytes(b"effect-marker"),
            work_schema: EFFECT_EXECUTOR_WORK_SCHEMA_V1.to_owned(),
            work: plan.identity().unwrap(),
            subject,
            scope,
        };
        (directory, plan, dispatch)
    }

    #[test]
    fn v2_work_cannot_select_an_alternate_trust_inspector_or_state() {
        let (directory, mut plan, _) = fixture();
        plan.schema = EFFECT_EXECUTOR_PLAN_SCHEMA_V2.to_owned();
        plan.authorization = Some(EffectAuthorizationInputsV2 {
            expected_runtime_profile: Digest::hash_bytes(b"enrolled-profile"),
        });
        let mut authored = serde_json::to_value(&plan).unwrap();
        let authorization = authored["authorization"].as_object_mut().unwrap();
        authorization.insert(
            "issuer_trust".to_owned(),
            serde_json::json!({"path":"/tmp/alternate-trust"}),
        );
        authorization.insert(
            "docket_program".to_owned(),
            serde_json::json!({"path":"/tmp/alternate-inspector"}),
        );
        authorization.insert(
            "docket_state".to_owned(),
            serde_json::json!("/tmp/alternate-state"),
        );
        assert!(serde_json::from_value::<EffectExecutorPlanV1>(authored).is_err());
        assert!(!directory.path().join("attempt.sqlite3").exists());
        assert!(!directory.path().join("target").exists());
    }

    #[test]
    fn fixed_fixture_enrollment_matches_genesis_and_refuses_byte_substitution() {
        let (directory, mut plan, _) = fixture();
        let root = directory.path();
        let test_program = root.join("installed-effectd-fixture");
        let docket_program = root.join("installed-docket-fixture");
        let resolver = root.join("installed-standing-fixture");
        for path in [&test_program, &docket_program, &resolver] {
            std::fs::write(path, b"non-deployable-fixture-executable").unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let trust_path = root.join("fixture-trust.json");
        std::fs::write(&trust_path, b"{\"issuers\":[]}").unwrap();
        let key_path = root.join("unused-fixture-key-locator");
        // Published all-01 seed in PKCS#8 v2 with its public key: test-only, never enroll.
        let fixture_key = hex::decode("3051020101300506032b65700422042001010101010101010101010101010101010101010101010101010101010101018121008a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c").unwrap();
        std::fs::write(&key_path, fixture_key).unwrap();
        let catalog = root.join("unused-fixture-catalog");
        let catalog_document = serde_json::json!({
            "schema": "ag.governed-loop.exact-work-catalog/v2",
            "entries": {
                (EFFECT_EXECUTOR_WORK_SCHEMA_V1): {
                    "work_schema": EFFECT_EXECUTOR_WORK_SCHEMA_V1,
                    "subject": plan.subject.clone(),
                    "scope": plan.scope.clone(),
                    "observation_basis": {
                        "kind": "typed_basis",
                        "requirement": {
                            "schema": "ag.governed-loop.typed-observation-basis/v1",
                            "basis_type": "fixture.source-only/v1",
                            "basis_identity": Digest::hash_bytes(b"fixture-basis")
                        }
                    }
                }
            }
        });
        std::fs::write(
            &catalog,
            JcsDocument::canonicalize(&catalog_document)
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        let profile: GovernedRuntimeProfileV1 = serde_json::from_value(serde_json::json!({
            "schema": GOVERNED_RUNTIME_PROFILE_SCHEMA_V1,
            "profile_label": "fixture-only",
            "observation_resolver": PinnedDeploymentFileV1::measure(&resolver, true).unwrap(),
            "observation_resolver_id": "fixture-observation",
            "standing_resolver": PinnedDeploymentFileV1::measure(&resolver, true).unwrap(),
            "standing_resolver_id": "fixture-standing",
            "max_standing_ttl_ms": 1000,
            "exact_work_catalog": PinnedDeploymentFileV1::measure(&catalog, false).unwrap(),
            "controlling_review": null,
            "docket": {
                "schema": GOVERNED_DOCKET_ROOT_SCHEMA_V1,
                "docket_program": PinnedDeploymentFileV1::measure(&docket_program, true).unwrap(),
                "state_directory": root.join("docket-state"),
                "trust_config": PinnedDeploymentFileV1::measure(&trust_path, false).unwrap(),
                "standing_resolver": PinnedDeploymentFileV1::measure(&resolver, true).unwrap(),
                "executor_adapter": PinnedDeploymentFileV1::measure(&test_program, true).unwrap(),
                "issuer_principal": "fixture-principal-never-enroll",
                "issuer_key_id": "fixture-key-never-enroll",
                "issuer_key": PinnedDeploymentFileV1::measure(&key_path, false).unwrap()
            },
            "human_verifier": null,
            "intervention_ingress": null
        }))
        .unwrap();
        profile.verify_genesis().unwrap();
        let profile_bytes = JcsDocument::canonicalize(&profile).unwrap();
        let profile_digest =
            Digest::hash_domain(GOVERNED_RUNTIME_PROFILE_SCHEMA_V1, profile_bytes.as_bytes());
        let campaign = Digest::hash_bytes(b"fixture-campaign");
        let campaign_db = root.join("campaign.sqlite");
        let db = Connection::open(&campaign_db).unwrap();
        db.execute_batch("CREATE TABLE campaigns(campaign_id TEXT NOT NULL); CREATE TABLE runtime_profile(singleton INTEGER PRIMARY KEY,schema TEXT NOT NULL,profile_digest TEXT NOT NULL,profile_jcs BLOB NOT NULL);").unwrap();
        db.execute(
            "INSERT INTO campaigns(campaign_id) VALUES(?1)",
            [campaign.as_str()],
        )
        .unwrap();
        db.execute("INSERT INTO runtime_profile(singleton,schema,profile_digest,profile_jcs) VALUES(1,?1,?2,?3)", params![GOVERNED_RUNTIME_PROFILE_SCHEMA_V1, profile_digest.as_str(), profile_bytes.as_bytes()]).unwrap();
        drop(db);
        let deployment_path = root.join("ag-effectd.deployment.json");
        let deployment = EffectExecutorDeploymentV1 {
            schema: EFFECT_EXECUTOR_DEPLOYMENT_SCHEMA_V1.to_owned(),
            campaign_database: campaign_db,
            expected_runtime_profile: profile_digest.clone(),
        };
        std::fs::write(
            &deployment_path,
            JcsDocument::canonicalize(&deployment).unwrap().as_bytes(),
        )
        .unwrap();
        let enrolled = load_enrolled_runtime(&deployment_path).unwrap();
        assert_eq!(enrolled.campaign, campaign);
        plan.schema = EFFECT_EXECUTOR_PLAN_SCHEMA_V2.to_owned();
        plan.authorization = Some(EffectAuthorizationInputsV2 {
            expected_runtime_profile: profile_digest,
        });
        let work = plan.identity().unwrap();
        assert_eq!(work, plan.identity().unwrap());
        assert!(!catalog_document.to_string().contains(work.as_str()));
        assert!(bind_enrolled_docket(
            &plan,
            &enrolled,
            &test_program,
            b"non-deployable-fixture-executable"
        )
        .is_ok());
        let mut wrong_plan = plan.clone();
        wrong_plan.authorization = Some(EffectAuthorizationInputsV2 {
            expected_runtime_profile: Digest::hash_bytes(b"alternate-profile"),
        });
        assert!(bind_enrolled_docket(
            &wrong_plan,
            &enrolled,
            &test_program,
            b"non-deployable-fixture-executable"
        )
        .is_err());
        std::fs::write(&trust_path, b"{\"issuers\":[{}]}").unwrap();
        assert!(bind_enrolled_docket(
            &plan,
            &enrolled,
            &test_program,
            b"non-deployable-fixture-executable"
        )
        .is_err());
        assert!(!root.join("attempt.sqlite3").exists());
        assert!(!root.join("target").exists());
    }

    #[test]
    fn exact_docket_attempt_executes_once_and_replays_receipt() {
        let (_directory, plan, dispatch) = fixture();
        let first = execute_effect_attempt(&plan, &dispatch).unwrap();
        assert_eq!(
            first.outcome,
            EffectExecutorOutcomeClassV1::Success,
            "{first:?}"
        );
        let CanonicalEffectV1::ManagedFilePut { path, .. } = &plan.effect else {
            unreachable!()
        };
        std::fs::write(path, b"hostile-after-first\n").unwrap();
        let replay = execute_effect_attempt(&plan, &dispatch).unwrap();
        assert_eq!(replay, first);
        assert_eq!(std::fs::read(path).unwrap(), b"hostile-after-first\n");
        assert_eq!(reconcile_effect_attempt(&plan, &dispatch).unwrap(), first);
    }

    #[test]
    fn marker_and_work_substitution_refuse_before_effect() {
        let (_directory, plan, dispatch) = fixture();
        let mut wrong_marker = dispatch.clone();
        wrong_marker.marker = Digest::hash_bytes(b"wrong-marker");
        execute_effect_attempt(&plan, &wrong_marker).unwrap();
        assert_eq!(
            execute_effect_attempt(&plan, &dispatch).unwrap_err(),
            "effect-executor-attempt-substitution"
        );

        let mut wrong_work = dispatch.clone();
        wrong_work.attempt = Digest::hash_bytes(b"another-attempt");
        wrong_work.work = Digest::hash_bytes(b"wrong-work");
        assert_eq!(
            execute_effect_attempt(&plan, &wrong_work).unwrap_err(),
            "effect-executor-dispatch-plan-binding"
        );
    }

    #[test]
    fn reserved_crash_cut_becomes_indeterminate_and_never_executes() {
        let (_directory, plan, dispatch) = fixture();
        let mut store = EffectAttemptStoreV1::open(&plan.attempt_store).unwrap();
        assert!(matches!(
            store.reserve(&plan, &dispatch).unwrap(),
            ReservationV1::Reserved
        ));
        drop(store);
        let outcome = execute_effect_attempt(&plan, &dispatch).unwrap();
        assert_eq!(outcome.outcome, EffectExecutorOutcomeClassV1::Indeterminate);
        let CanonicalEffectV1::ManagedFilePut { path, .. } = &plan.effect else {
            unreachable!()
        };
        assert!(!Path::new(path).exists());
    }

    #[test]
    fn concurrent_delivery_reserves_exactly_one_mechanics_attempt() {
        let (_directory, plan, dispatch) = fixture();
        let (left, right) = std::thread::scope(|scope| {
            let left_plan = plan.clone();
            let left_dispatch = dispatch.clone();
            let left = scope.spawn(move || {
                let mut store = EffectAttemptStoreV1::open(&left_plan.attempt_store).unwrap();
                store.reserve(&left_plan, &left_dispatch).unwrap()
            });
            let right_plan = plan.clone();
            let right_dispatch = dispatch.clone();
            let right = scope.spawn(move || {
                let mut store = EffectAttemptStoreV1::open(&right_plan.attempt_store).unwrap();
                store.reserve(&right_plan, &right_dispatch).unwrap()
            });
            (left.join().unwrap(), right.join().unwrap())
        });
        let reserved = usize::from(matches!(left, ReservationV1::Reserved))
            + usize::from(matches!(right, ReservationV1::Reserved));
        let ambiguous = usize::from(matches!(left, ReservationV1::Ambiguous))
            + usize::from(matches!(right, ReservationV1::Ambiguous));
        assert_eq!((reserved, ambiguous), (1, 1));
    }

    #[test]
    fn restart_refuses_recomputed_receipt_for_substituted_effect() {
        let (_directory, plan, dispatch) = fixture();
        execute_effect_attempt(&plan, &dispatch).unwrap();

        let connection = Connection::open(&plan.attempt_store).unwrap();
        let body: Vec<u8> = connection
            .query_row(
                "SELECT receipt_body FROM docket_effect_attempt WHERE attempt=?1",
                [dispatch.attempt.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        let mut receipt: DocketEffectExecutionReceiptV1 = serde_json::from_slice(&body).unwrap();
        receipt.effect_index += 1;
        let hostile_body = JcsDocument::canonicalize(&receipt).unwrap();
        let hostile_digest = receipt.digest().unwrap();
        connection
            .execute(
                "UPDATE docket_effect_attempt SET receipt=?1,receipt_body=?2 WHERE attempt=?3",
                params![
                    hostile_digest.as_str(),
                    hostile_body.as_bytes(),
                    dispatch.attempt.as_str()
                ],
            )
            .unwrap();
        drop(connection);

        assert_eq!(
            reconcile_effect_attempt(&plan, &dispatch).unwrap_err(),
            "effect-executor-typed-receipt-binding"
        );
    }

    #[test]
    fn machine_less_v1_systemd_failure_and_terminal_replay_remain_exact() {
        let (_directory, mut plan, mut dispatch) = fixture();
        plan.effect = CanonicalEffectV1::SystemdUnit {
            target: TargetId::parse("legacy-systemd").unwrap(),
            unit: "legacy.service".to_owned(),
            action: SystemdUnitActionV1::Start,
            expected_active_state: "inactive".to_owned(),
            expected_unit_file_state: "disabled".to_owned(),
        };
        plan.artifacts.clear();
        dispatch.work = plan.identity().unwrap();

        let first = execute_effect_attempt(&plan, &dispatch).unwrap();
        assert_eq!(first.outcome, EffectExecutorOutcomeClassV1::Failure);
        let replay = execute_effect_attempt(&plan, &dispatch).unwrap();
        assert_eq!(replay, first);
        assert_eq!(reconcile_effect_attempt(&plan, &dispatch).unwrap(), first);

        let connection = Connection::open(&plan.attempt_store).unwrap();
        let body: Vec<u8> = connection
            .query_row(
                "SELECT receipt_body FROM docket_effect_attempt",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let receipt: DocketEffectExecutionReceiptV1 = serde_json::from_slice(&body).unwrap();
        let ExecutionOutcomeV1::Failed { failure } = receipt.outcome else {
            panic!("legacy machine-less systemd must remain a definite failure");
        };
        assert_eq!(
            failure.source_code.as_deref(),
            Some("systemd_backend_unavailable")
        );
    }
    #[test]
    fn plan_identity_matches_the_pinned_cross_repo_vector() {
        // The identical plan document and expected digest are pinned in
        // nightshift against its independent mirror of the AG digest
        // construction: both repositories derive the same executable-work
        // identity from the same semantic plan.
        let document = serde_json::json!({
            "schema": "ag-effectd.docket-executor-plan/v1",
            "attempt_store": "/tmp/wo9-1-vector/effect-attempts.sqlite",
            "subject": format!("sha256:{}", "62".repeat(32)),
            "scope": format!("sha256:{}", "31".repeat(32)),
            "effect_index": 0,
            "effect": {
                "kind": "managed_file_put",
                "target": "wo9-1-vector",
                "path": "/tmp/wo9-1-vector/target",
                "expected_content": null,
                "content": format!("sha256:{}", "35".repeat(32)),
                "mode": 384,
                "uid": 1000,
                "gid": 1000
            },
            "artifacts": [{
                "digest": format!("sha256:{}", "35".repeat(32)),
                "path": "/tmp/wo9-1-vector/artifact"
            }],
            "file_policy": {
                "max_content_bytes": 1024,
                "trusted_ancestor_uid": 0,
                "trusted_parent_uid": 1000,
                "require_private_parent_writes": true
            },
            "preparation_checkpoint": null
        });
        let plan: EffectExecutorPlanV1 = serde_json::from_value(document).unwrap();
        assert_eq!(
            plan.identity().unwrap().as_str(),
            "sha256:c938048c15ac6ebe40053d6137924cd60e75c649e4239b318901a5be77517ca6"
        );
    }
}
