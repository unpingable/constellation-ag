//! Closed records and process checks for shared plan/review admission.
//!
//! These judgments are evidence only. They never resolve standing, spend an
//! authorization, claim Docket custody, or invoke executor mechanics.

use ag_campaign::CampaignId;
use ag_campaign::governed::OccurrenceKeyV1;
use ag_primitives::{Digest, JcsDocument};
use serde::{Deserialize, Serialize};
use base64::{Engine as _, engine::general_purpose::STANDARD};

use crate::governed_ports::{
    GovernedPortErrorV1, GovernedSharedAdmissionV1, run_json_program,
};

pub const REVIEW_REQUIREMENT_SCHEMA_V1: &str =
    "ag.governed-loop.review-requirement/v1";
pub const PLAN_REVIEW_SCHEMA_V1: &str = "maude.governed-plan-review/v1";
pub const REVIEW_RECORD_INPUT_SCHEMA_V1: &str =
    "ag.governed-loop.review-record-input/v1";
pub const PLAN_VALIDATION_REQUEST_SCHEMA_V1: &str =
    "ag.governed-loop.plan-validation-request/v1";
pub const REVIEW_VERIFICATION_REQUEST_SCHEMA_V1: &str =
    "ag.governed-loop.review-verification-request/v1";
pub const OWNER_VERIFICATION_RESPONSE_SCHEMA_V1: &str =
    "ag.governed-loop.owner-verification-response/v1";
pub const MAUDE_PLAN_VALIDATION_SCHEMA_V1: &str = "maude.governed-plan-validation/v1";
pub const PERMISSION_PREFLIGHT_SCHEMA_V1: &str =
    "ag.governed-loop.permission-preflight/v1";

pub fn canonical_file_identity(bytes: &[u8]) -> Result<Digest, GovernedPortErrorV1> {
    let canonical = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    JcsDocument::from_canonical_bytes(canonical)
        .map_err(|error| GovernedPortErrorV1::Canonical(error.to_string()))?;
    Ok(Digest::hash_bytes(canonical))
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewRequirementV1 {
    pub schema: String,
    pub reviewer_id: String,
    pub route_enrollment_digest: Digest,
    pub compiler_contract: String,
    pub max_age_ms: u64,
}

impl ReviewRequirementV1 {
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, GovernedPortErrorV1> {
        let bytes = bytes.strip_suffix(b"\n").unwrap_or(bytes);
        let document = JcsDocument::from_canonical_bytes(bytes)
            .map_err(|error| GovernedPortErrorV1::Canonical(error.to_string()))?;
        let value: Self = document
            .decode()
            .map_err(|error| GovernedPortErrorV1::Canonical(error.to_string()))?;
        if value.schema != REVIEW_REQUIREMENT_SCHEMA_V1
            || value.reviewer_id.is_empty()
            || value.compiler_contract.is_empty()
            || value.max_age_ms == 0
        {
            return Err(GovernedPortErrorV1::InvalidConfiguration(
                "invalid shared review requirement",
            ));
        }
        Ok(value)
    }

    pub fn identity(&self) -> Result<Digest, GovernedPortErrorV1> {
        let canonical = JcsDocument::canonicalize(self)
            .map_err(|error| GovernedPortErrorV1::Canonical(error.to_string()))?;
        Ok(Digest::hash_bytes(canonical.as_bytes()))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewVerdictV1 {
    Accepted,
    Rejected,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanReviewV1 {
    pub schema: String,
    pub binding_id: Digest,
    pub requirement_digest: Digest,
    pub dispatch_id: Digest,
    pub reviewer_id: String,
    pub verdict: ReviewVerdictV1,
    pub reviewed_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub result_digest: Digest,
    pub custody_receipt_digest: Digest,
}

impl PlanReviewV1 {
    pub fn validate(&self, requirement: &ReviewRequirementV1) -> Result<(), GovernedPortErrorV1> {
        if self.schema != PLAN_REVIEW_SCHEMA_V1
            || self.reviewer_id != requirement.reviewer_id
            || self.requirement_digest != requirement.identity()?
            || self.reviewed_at_unix_ms >= self.expires_at_unix_ms
            || self.expires_at_unix_ms - self.reviewed_at_unix_ms > requirement.max_age_ms
        {
            return Err(GovernedPortErrorV1::Refused(
                "review does not satisfy the genesis requirement".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewArtifactBundleV1 {
    pub result_bytes_base64: String,
    pub custody_receipt_bytes_base64: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordReviewInputV1 {
    pub schema: String,
    pub campaign: CampaignId,
    pub occurrence: String,
    pub binding_id: Digest,
    pub requirement_digest: Digest,
    pub review: PlanReviewV1,
    pub artifacts: ReviewArtifactBundleV1,
}

impl RecordReviewInputV1 {
    pub fn validate_artifacts(&self) -> Result<(), GovernedPortErrorV1> {
        if self.schema != REVIEW_RECORD_INPUT_SCHEMA_V1
            || self.binding_id != self.review.binding_id
            || self.requirement_digest != self.review.requirement_digest
        {
            return Err(GovernedPortErrorV1::Refused(
                "review input binding mismatch".to_owned(),
            ));
        }
        let result = STANDARD
            .decode(&self.artifacts.result_bytes_base64)
            .map_err(|_| GovernedPortErrorV1::Canonical("invalid result base64".to_owned()))?;
        let custody = STANDARD
            .decode(&self.artifacts.custody_receipt_bytes_base64)
            .map_err(|_| GovernedPortErrorV1::Canonical("invalid custody base64".to_owned()))?;
        if result.len() > 16 * 1024 * 1024 || custody.len() > 16 * 1024 * 1024
            || STANDARD.encode(&result) != self.artifacts.result_bytes_base64
            || STANDARD.encode(&custody) != self.artifacts.custody_receipt_bytes_base64
            || Digest::hash_bytes(&result) != self.review.result_digest
            || Digest::hash_bytes(&custody) != self.review.custody_receipt_digest
        {
            return Err(GovernedPortErrorV1::Refused(
                "review artifact identity mismatch".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerVerificationResponseV1 {
    pub schema: String,
    pub accepted: bool,
    pub binding_id: Digest,
    pub configuration_digest: Digest,
    pub evidence_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaudePlanValidationV1 {
    pub schema: String,
    pub result: String,
    pub binding_id: Digest,
    pub config_digest: Digest,
    pub stored_lock_id: Digest,
    pub stored_compilation_id: Digest,
}

/// Invokes the deployment-pinned Maude validator with an exact parsed binding.
pub fn validate_plan_binding(
    profile: &GovernedSharedAdmissionV1,
    binding_bytes: &[u8],
) -> Result<MaudePlanValidationV1, GovernedPortErrorV1> {
    let _ = profile.plan_validator.verify(true)?;
    let _ = profile.plan_validator_config.verify(false)?;
    let document = JcsDocument::from_canonical_bytes(binding_bytes)
        .map_err(|error| GovernedPortErrorV1::Canonical(error.to_string()))?;
    let _: serde_json::Value = document
        .decode()
        .map_err(|error| GovernedPortErrorV1::Canonical(error.to_string()))?;
    let mut binding_file = tempfile::NamedTempFile::new()
        .map_err(GovernedPortErrorV1::Io)?;
    std::io::Write::write_all(&mut binding_file, binding_bytes)
        .map_err(GovernedPortErrorV1::Io)?;
    let response: MaudePlanValidationV1 = run_json_program(
        &profile.plan_validator.path,
        &[
            "validate".to_owned(),
            "--config".to_owned(),
            profile.plan_validator_config.path.display().to_string(),
            "--binding".to_owned(),
            binding_file.path().display().to_string(),
        ],
        &serde_json::json!({}),
    )?;
    if response.schema != MAUDE_PLAN_VALIDATION_SCHEMA_V1 || response.result != "passed" {
        return Err(GovernedPortErrorV1::Refused(
            "Maude validator did not accept the exact binding".to_owned(),
        ));
    }
    Ok(response)
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ReviewVerificationRequestV1<'a> {
    schema: &'static str,
    requirement: &'a ReviewRequirementV1,
    review: &'a PlanReviewV1,
    artifacts: &'a ReviewArtifactBundleV1,
}

pub fn verify_review(
    profile: &GovernedSharedAdmissionV1,
    requirement: &ReviewRequirementV1,
    input: &RecordReviewInputV1,
) -> Result<OwnerVerificationResponseV1, GovernedPortErrorV1> {
    input.validate_artifacts()?;
    input.review.validate(requirement)?;
    let _ = profile.review_verifier.verify(true)?;
    let response: OwnerVerificationResponseV1 = run_json_program(
        &profile.review_verifier.path,
        &[],
        &ReviewVerificationRequestV1 {
            schema: REVIEW_VERIFICATION_REQUEST_SCHEMA_V1,
            requirement,
            review: &input.review,
            artifacts: &input.artifacts,
        },
    )?;
    if response.schema != OWNER_VERIFICATION_RESPONSE_SCHEMA_V1
        || !response.accepted
        || response.binding_id != input.binding_id
        || response.configuration_digest != requirement.route_enrollment_digest
    {
        return Err(GovernedPortErrorV1::Refused(
            "review verifier did not authenticate exact custody".to_owned(),
        ));
    }
    Ok(response)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionPreflightDecisionV1 {
    Allowed,
    Denied,
    Indeterminate,
}

/// Closed tri-state aggregation. Determinate refusal dominates unavailable
/// evidence; authority is allowed only when every required check is positive.
#[must_use]
pub const fn permission_decision(
    all_positive: bool,
    determinate_refusal: bool,
    unavailable: bool,
) -> PermissionPreflightDecisionV1 {
    if determinate_refusal {
        PermissionPreflightDecisionV1::Denied
    } else if all_positive && !unavailable {
        PermissionPreflightDecisionV1::Allowed
    } else {
        PermissionPreflightDecisionV1::Indeterminate
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PermissionPreflightV1 {
    pub schema: String,
    pub key: OccurrenceKeyV1,
    pub profile_digest: Digest,
    pub binding_id: Digest,
    pub review_id: Option<Digest>,
    pub sampled_state_digest: Digest,
    pub evaluated_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub decision: PermissionPreflightDecisionV1,
    pub evidence: Vec<Digest>,
    pub reasons: Vec<String>,
    pub grants_authority: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(label: &str) -> Digest {
        Digest::hash_bytes(label.as_bytes())
    }

    #[test]
    fn review_requires_exact_target_and_exclusive_bounded_expiry() {
        let requirement = ReviewRequirementV1 {
            schema: REVIEW_REQUIREMENT_SCHEMA_V1.to_owned(),
            reviewer_id: "independent-reviewer".to_owned(),
            route_enrollment_digest: digest("route"),
            compiler_contract: "maude.reviewed-local-copy/v1".to_owned(),
            max_age_ms: 100,
        };
        let review = PlanReviewV1 {
            schema: PLAN_REVIEW_SCHEMA_V1.to_owned(),
            binding_id: digest("binding"),
            requirement_digest: requirement.identity().unwrap(),
            dispatch_id: digest("dispatch"),
            reviewer_id: requirement.reviewer_id.clone(),
            verdict: ReviewVerdictV1::Accepted,
            reviewed_at_unix_ms: 10,
            expires_at_unix_ms: 110,
            result_digest: digest("result"),
            custody_receipt_digest: digest("custody"),
        };
        assert!(review.validate(&requirement).is_ok());
        let mut overlong = review;
        overlong.expires_at_unix_ms = 111;
        assert!(overlong.validate(&requirement).is_err());
    }

    #[test]
    fn artifact_substitution_is_refused_before_verifier_invocation() {
        let result = b"accepted result";
        let custody = b"custody";
        let input = RecordReviewInputV1 {
            schema: REVIEW_RECORD_INPUT_SCHEMA_V1.to_owned(),
            campaign: CampaignId::from_digest(digest("campaign")),
            occurrence: "1".to_owned(),
            binding_id: digest("binding"),
            requirement_digest: digest("requirement"),
            review: PlanReviewV1 {
                schema: PLAN_REVIEW_SCHEMA_V1.to_owned(),
                binding_id: digest("binding"),
                requirement_digest: digest("requirement"),
                dispatch_id: digest("dispatch"),
                reviewer_id: "reviewer".to_owned(),
                verdict: ReviewVerdictV1::Accepted,
                reviewed_at_unix_ms: 1,
                expires_at_unix_ms: 2,
                result_digest: Digest::hash_bytes(result),
                custody_receipt_digest: Digest::hash_bytes(custody),
            },
            artifacts: ReviewArtifactBundleV1 {
                result_bytes_base64: STANDARD.encode(b"substituted"),
                custody_receipt_bytes_base64: STANDARD.encode(custody),
            },
        };
        assert!(input.validate_artifacts().is_err());
    }

    #[test]
    fn permission_preflight_has_all_three_outcomes_and_denial_dominates_unknown() {
        assert_eq!(permission_decision(true, false, false), PermissionPreflightDecisionV1::Allowed);
        assert_eq!(permission_decision(false, true, false), PermissionPreflightDecisionV1::Denied);
        assert_eq!(permission_decision(false, false, true), PermissionPreflightDecisionV1::Indeterminate);
        assert_eq!(permission_decision(false, true, true), PermissionPreflightDecisionV1::Denied);
    }
}
