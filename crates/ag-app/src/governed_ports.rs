#![allow(
    clippy::missing_errors_doc,
    reason = "GovernedPortErrorV1 is the closed error contract for all concrete process ports"
)]
#![allow(
    clippy::wildcard_imports,
    reason = "the port module implements the governed kernel's complete external-boundary vocabulary"
)]

//! Concrete process boundaries for the canonical governed loop.
//!
//! Each invocation is a fresh request to an external owner.  Responses may be
//! retained as evidence, but this module never turns response bytes into a
//! reusable resolver, standing instrument, or campaign transition.  Docket
//! receives an authenticated exact AG issuance and remains the only process
//! permitted to invoke the configured executor adapter.

use std::fs::{self, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ag_campaign::governed::*;
use ag_primitives::{Digest, JcsDocument};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;

/// Schema for the authenticated canonical AG issuance handed to Docket.
pub const SIGNED_AG_ISSUANCE_SCHEMA_V1: &str = "ag.governed-loop.signed-issuance/v1";
/// Schema for process observation-resolution requests.
pub const OBSERVATION_REQUEST_SCHEMA_V1: &str = "ag.governed-loop.observation-request/v1";
/// Schema for process standing-resolution requests.
pub const STANDING_REQUEST_SCHEMA_V1: &str = "ag.governed-loop.standing-request/v1";
/// Schema for process human-verification requests.
pub const HUMAN_VERIFICATION_REQUEST_SCHEMA_V1: &str =
    "ag.governed-loop.human-verification-request/v1";
/// Schema for process human-verification responses.
pub const HUMAN_VERIFICATION_RESPONSE_SCHEMA_V1: &str =
    "ag.governed-loop.human-verification-response/v1";
/// Schema for process governed-intervention verification requests.
pub const INTERVENTION_VERIFICATION_REQUEST_SCHEMA_V1: &str =
    "ag.governed-loop.intervention-verification-request/v1";
/// Schema for process governed-intervention verification responses.
pub const INTERVENTION_VERIFICATION_RESPONSE_SCHEMA_V1: &str =
    "ag.governed-loop.intervention-verification-response/v1";
/// Schema for the deployment-owned campaign runtime profile.
pub const GOVERNED_RUNTIME_PROFILE_SCHEMA_V1: &str = "ag.governed-loop.runtime-profile/v1";
/// Schema for a runtime profile that requires shared plan and review admission.
pub const GOVERNED_RUNTIME_PROFILE_SCHEMA_V2: &str = "ag.governed-loop.runtime-profile/v2";
/// Schema for the deployment input used to seal a runtime profile.
pub const GOVERNED_RUNTIME_PROFILE_ENROLLMENT_SCHEMA_V1: &str =
    "ag.governed-loop.runtime-profile-enrollment/v1";
/// Deployment enrollment schema for a protected shared-admission profile.
pub const GOVERNED_RUNTIME_PROFILE_ENROLLMENT_SCHEMA_V2: &str =
    "ag.governed-loop.runtime-profile-enrollment/v2";
/// Closed shared-admission profile member.
pub const GOVERNED_SHARED_ADMISSION_SCHEMA_V1: &str = "ag.governed-loop.shared-admission/v1";
/// Exact Maude governed-plan binding schema.
pub const MAUDE_GOVERNED_PLAN_BINDING_SCHEMA_V1: &str = "maude.governed-plan-binding/v1";
/// V2 top-level canonical Nightshift cycle port.
pub const GOVERNED_NIGHTSHIFT_CYCLE_PORT_SCHEMA_V1: &str =
    "ag.governed-loop.nightshift-cycle-port/v1";
/// Closed nonsecret configuration consumed by the Nightshift cycle adapter.
pub const NIGHTSHIFT_AG_CYCLE_PORT_CONFIG_SCHEMA_V1: &str = "nightshift.ag_cycle_config.v1";
/// Schema for the deployment-owned Docket adapter root.
pub const GOVERNED_DOCKET_ROOT_SCHEMA_V1: &str = "ag.governed-loop.docket-root/v1";
/// Schema for the Docket portion of runtime-profile enrollment.
pub const GOVERNED_DOCKET_ROOT_ENROLLMENT_SCHEMA_V1: &str =
    "ag.governed-loop.docket-root-enrollment/v1";
/// Schema for the genesis-bound intervention ingress identity.
pub const GOVERNED_INTERVENTION_INGRESS_SCHEMA_V1: &str =
    "ag.governed-loop.intervention-ingress/v1";
/// Schema for intervention ingress enrollment.
pub const GOVERNED_INTERVENTION_INGRESS_ENROLLMENT_SCHEMA_V1: &str =
    "ag.governed-loop.intervention-ingress-enrollment/v1";

const SIGNATURE_PREFIX_V1: &[u8] = b"ag-ng\0governed-loop-issuance-signature\0v1\0";
const MAX_PINNED_FILE_BYTES: u64 = 512 * 1024 * 1024;

/// One immutable deployment file coordinate. The path is a locator; the
/// digest binds the exact bytes accepted at each consequence boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedDeploymentFileV1 {
    /// Absolute deployment path.
    pub path: PathBuf,
    /// SHA-256 over the exact file bytes.
    pub identity: Digest,
}

impl PinnedDeploymentFileV1 {
    fn read_bounded(path: &Path, executable: bool) -> Result<Vec<u8>, GovernedPortErrorV1> {
        if !path.is_absolute() {
            return Err(GovernedPortErrorV1::Deployment(format!(
                "pinned path is not absolute: {}",
                path.display()
            )));
        }
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
            .map_err(GovernedPortErrorV1::Io)?;
        let metadata = file.metadata().map_err(GovernedPortErrorV1::Io)?;
        if !metadata.is_file() || metadata.len() > MAX_PINNED_FILE_BYTES {
            return Err(GovernedPortErrorV1::Deployment(format!(
                "pinned path is not a bounded regular file: {}",
                path.display()
            )));
        }
        if executable && metadata.permissions().mode() & 0o111 == 0 {
            return Err(GovernedPortErrorV1::Deployment(format!(
                "pinned command is not executable: {}",
                path.display()
            )));
        }
        let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
        file.read_to_end(&mut bytes)
            .map_err(GovernedPortErrorV1::Io)?;
        Ok(bytes)
    }

    /// Measures one exact bounded regular file for deployment enrollment.
    pub fn measure(
        path: impl Into<PathBuf>,
        executable: bool,
    ) -> Result<Self, GovernedPortErrorV1> {
        let path = path.into();
        let bytes = Self::read_bounded(&path, executable)?;
        Ok(Self {
            path,
            identity: Digest::hash_bytes(&bytes),
        })
    }

    /// Measures exact regular-file bytes without following a final symlink.
    pub fn verify(&self, executable: bool) -> Result<Vec<u8>, GovernedPortErrorV1> {
        let bytes = Self::read_bounded(&self.path, executable)?;
        if Digest::hash_bytes(&bytes) != self.identity {
            return Err(GovernedPortErrorV1::Deployment(format!(
                "pinned file identity changed: {}",
                self.path.display()
            )));
        }
        Ok(bytes)
    }

    /// Requires a caller-repeated locator to be the genesis-pinned locator,
    /// then remeasures the bytes. Repetition is compatibility, not selection.
    pub fn verify_presented(
        &self,
        presented: &Path,
        executable: bool,
    ) -> Result<Vec<u8>, GovernedPortErrorV1> {
        if self.path != presented {
            return Err(GovernedPortErrorV1::Deployment(format!(
                "caller substituted pinned path: expected {}, got {}",
                self.path.display(),
                presented.display()
            )));
        }
        self.verify(executable)
    }
}

/// Deployment-owned Docket custody and execution coordinates. Docket state is
/// a mutable locator, while the authority-bearing programs, trust, resolver,
/// and signing material are byte-pinned. The executor plan is deliberately
/// occurrence-bound exact work and is checked by Docket against the issuance.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedDocketRootV1 {
    /// Exact schema.
    pub schema: String,
    /// Docket executable.
    pub docket_program: PinnedDeploymentFileV1,
    /// Mutable Docket state directory locator.
    pub state_directory: PathBuf,
    /// Docket trust configuration.
    pub trust_config: PinnedDeploymentFileV1,
    /// Docket execution-standing resolver.
    pub standing_resolver: PinnedDeploymentFileV1,
    /// Authority-neutral executor adapter.
    pub executor_adapter: PinnedDeploymentFileV1,
    /// AG issuance principal trusted by Docket.
    pub issuer_principal: String,
    /// AG issuance signing-key identity.
    pub issuer_key_id: String,
    /// AG issuance signing key bytes.
    pub issuer_key: PinnedDeploymentFileV1,
}

impl GovernedDocketRootV1 {
    fn validate(&self) -> Result<(), GovernedPortErrorV1> {
        if self.schema != GOVERNED_DOCKET_ROOT_SCHEMA_V1
            || !self.state_directory.is_absolute()
            || self.issuer_principal.is_empty()
            || self.issuer_key_id.is_empty()
        {
            return Err(GovernedPortErrorV1::InvalidConfiguration(
                "invalid governed Docket root",
            ));
        }
        Ok(())
    }

    /// Remeasures every configured Docket boundary component.
    pub fn verify_all(&self) -> Result<(), GovernedPortErrorV1> {
        self.validate()?;
        let _ = self.docket_program.verify(true)?;
        let _ = self.trust_config.verify(false)?;
        let _ = self.standing_resolver.verify(true)?;
        let _ = self.executor_adapter.verify(true)?;
        let key = self.issuer_key.verify(false)?;
        let _ = AgIssuanceSignerV1::from_pkcs8(
            self.issuer_principal.clone(),
            self.issuer_key_id.clone(),
            &key,
        )?;
        Ok(())
    }
}

/// Genesis-bound policy and execution profile for the canonical campaign
/// product. Later CLI arguments may repeat these coordinates but cannot alter
/// them, widen them, or introduce a different resolver/catalog/Docket root.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedRuntimeProfileV1 {
    /// Exact schema.
    pub schema: String,
    /// Bounded deployment label with no authority meaning.
    pub profile_label: String,
    /// Nightshift observation resolver executable.
    pub observation_resolver: PinnedDeploymentFileV1,
    /// Exact resolver identity accepted in returned records.
    pub observation_resolver_id: String,
    /// Present-tense standing resolver executable.
    pub standing_resolver: PinnedDeploymentFileV1,
    /// Exact standing resolver identity accepted in returned records.
    pub standing_resolver_id: String,
    /// Maximum accepted standing-answer lifetime.
    pub max_standing_ttl_ms: u64,
    /// Exact-work catalog bytes.
    pub exact_work_catalog: PinnedDeploymentFileV1,
    /// Optional exact controlling review evidence.
    pub controlling_review: Option<PinnedDeploymentFileV1>,
    /// Exact Docket custody/executor boundary.
    pub docket: GovernedDocketRootV1,
    /// Optional external human-disposition verifier.
    pub human_verifier: Option<PinnedDeploymentFileV1>,
    /// Optional authenticated non-browser intervention submission ingress.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intervention_ingress: Option<GovernedInterventionIngressV1>,
}

/// Genesis-pinned programs and policy for the protected shared interface.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedSharedAdmissionV1 {
    /// Exact schema.
    pub schema: String,
    /// Exact Maude binding schema accepted by the validator.
    pub plan_binding_schema: String,
    /// Exact compiler/executor contract.
    pub compiler_contract: String,
    /// Read-only Maude binding validator.
    pub plan_validator: PinnedDeploymentFileV1,
    /// Nonsecret validator configuration.
    pub plan_validator_config: PinnedDeploymentFileV1,
    /// Authenticated review-custody verifier.
    pub review_verifier: PinnedDeploymentFileV1,
    /// Closed verifier route/backend configuration.
    pub review_verifier_config: PinnedDeploymentFileV1,
    /// Nonsecret independent-review requirement.
    pub review_requirement: PinnedDeploymentFileV1,
}

impl GovernedSharedAdmissionV1 {
    /// Remeasures the complete protected boundary.
    pub fn verify_all(&self) -> Result<(), GovernedPortErrorV1> {
        if self.schema != GOVERNED_SHARED_ADMISSION_SCHEMA_V1
            || self.plan_binding_schema != MAUDE_GOVERNED_PLAN_BINDING_SCHEMA_V1
            || self.compiler_contract.is_empty()
            || self.compiler_contract.chars().any(char::is_whitespace)
        {
            return Err(GovernedPortErrorV1::InvalidConfiguration(
                "invalid governed shared admission",
            ));
        }
        let _ = self.plan_validator.verify(true)?;
        let config = self.plan_validator_config.verify(false)?;
        let _ = crate::shared_admission::canonical_file_identity(&config)?;
        let _ = self.review_verifier.verify(true)?;
        let verifier_config = self.review_verifier_config.verify(false)?;
        let verifier_config_digest =
            crate::shared_admission::canonical_file_identity(&verifier_config)?;
        let requirement = self.review_requirement.verify(false)?;
        let requirement =
            crate::shared_admission::ReviewRequirementV1::from_canonical_bytes(&requirement)?;
        if requirement.compiler_contract != self.compiler_contract
            || requirement.route_enrollment_digest != verifier_config_digest
        {
            return Err(GovernedPortErrorV1::InvalidConfiguration(
                "review requirement differs from shared admission enrollment",
            ));
        }
        Ok(())
    }
}

/// V2 runtime profile. V1 is a distinct type and is never implicitly upgraded.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedRuntimeProfileV2 {
    /// Exact V2 schema.
    pub schema: String,
    /// Deployment label without authority meaning.
    pub profile_label: String,
    /// Pinned observation resolver.
    pub observation_resolver: PinnedDeploymentFileV1,
    /// Required observation resolver identity.
    pub observation_resolver_id: String,
    /// Pinned standing resolver.
    pub standing_resolver: PinnedDeploymentFileV1,
    /// Required standing resolver identity.
    pub standing_resolver_id: String,
    /// Maximum standing lifetime.
    pub max_standing_ttl_ms: u64,
    /// Pinned exact-work catalog.
    pub exact_work_catalog: PinnedDeploymentFileV1,
    /// Optional pinned controlling review.
    pub controlling_review: Option<PinnedDeploymentFileV1>,
    /// Pinned Docket custody boundary.
    pub docket: GovernedDocketRootV1,
    /// Optional human verifier.
    pub human_verifier: Option<PinnedDeploymentFileV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Optional intervention ingress.
    pub intervention_ingress: Option<GovernedInterventionIngressV1>,
    /// Required Nightshift cycle boundary.
    pub nightshift_cycle: GovernedNightshiftCyclePortV1,
    /// Required shared-admission boundary.
    pub shared_admission: GovernedSharedAdmissionV1,
}

/// Fixed AG-to-Nightshift cycle invocation boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedNightshiftCyclePortV1 {
    /// Exact port schema.
    pub schema: String,
    /// Pinned Nightshift executable.
    pub program: PinnedDeploymentFileV1,
    /// Pinned closed cycle configuration.
    pub config: PinnedDeploymentFileV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NightshiftCyclePortConfigV1 {
    schema: String,
    store: PathBuf,
    present_evidence_resolver: NightshiftPinnedFileV1,
    nq_program: NightshiftPinnedFileV1,
    nq_config: NightshiftPinnedFileV1,
    nq_source_id: String,
    ag_loopctl: NightshiftPinnedFileV1,
    ag_database: PathBuf,
    ag_observation_resolver: NightshiftPinnedFileV1,
    ag_observation_resolver_id: String,
    ag_runtime_profile: PathBuf,
    shared_admission_requirement_digest: Digest,
    recover_observed_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NightshiftPinnedFileV1 {
    path: PathBuf,
    sha256: Digest,
}

impl NightshiftCyclePortConfigV1 {
    fn validate(&self) -> Result<(), GovernedPortErrorV1> {
        if self.schema != NIGHTSHIFT_AG_CYCLE_PORT_CONFIG_SCHEMA_V1
            || self.nq_source_id.is_empty()
            || self.ag_observation_resolver_id.is_empty()
            || self.recover_observed_at.is_empty()
            || [
                &self.store,
                &self.present_evidence_resolver.path,
                &self.nq_program.path,
                &self.nq_config.path,
                &self.ag_loopctl.path,
                &self.ag_database,
                &self.ag_observation_resolver.path,
                &self.ag_runtime_profile,
            ]
            .into_iter()
            .any(|path| !path.is_absolute())
        {
            return Err(GovernedPortErrorV1::InvalidConfiguration(
                "invalid Nightshift cycle adapter config",
            ));
        }
        for (file, executable) in [
            (&self.present_evidence_resolver, true),
            (&self.nq_program, true),
            (&self.nq_config, false),
            (&self.ag_loopctl, true),
            (&self.ag_observation_resolver, true),
        ] {
            let _ = PinnedDeploymentFileV1 {
                path: file.path.clone(),
                identity: file.sha256.clone(),
            }
            .verify(executable)?;
        }
        Ok(())
    }
}

impl GovernedNightshiftCyclePortV1 {
    /// Remeasures the complete cycle boundary.
    pub fn verify_all(&self) -> Result<(), GovernedPortErrorV1> {
        if self.schema != GOVERNED_NIGHTSHIFT_CYCLE_PORT_SCHEMA_V1 {
            return Err(GovernedPortErrorV1::InvalidConfiguration(
                "invalid Nightshift cycle port",
            ));
        }
        let _ = self.program.verify(true)?;
        let config = self.config.verify(false)?;
        let _ = crate::shared_admission::canonical_file_identity(&config)?;
        let config: NightshiftCyclePortConfigV1 =
            JcsDocument::from_canonical_bytes(config.strip_suffix(b"\n").unwrap_or(&config))
                .and_then(|document| document.decode())
                .map_err(|error| GovernedPortErrorV1::Canonical(error.to_string()))?;
        config.validate()?;
        Ok(())
    }

    /// Invokes the fixed finite cycle operation. The request is mechanism
    /// data; neither it nor the caller selects a program, config, or store.
    pub fn run_cycle(
        &self,
        request: &Path,
        recover: bool,
        deadline_unix_ms: u64,
    ) -> Result<serde_json::Value, GovernedPortErrorV1> {
        self.verify_all()?;
        if !request.is_absolute() {
            return Err(GovernedPortErrorV1::InvalidConfiguration(
                "cycle request is not absolute",
            ));
        }
        let arguments = vec![
            "cycle".to_owned(),
            if recover {
                "recover-config"
            } else {
                "run-config"
            }
            .to_owned(),
            "--config".to_owned(),
            self.config.path.display().to_string(),
            "--request".to_owned(),
            request.display().to_string(),
        ];
        run_json_program_until(
            &self.program.path,
            &arguments,
            &serde_json::json!({}),
            Some(deadline_unix_ms),
        )
    }
}

impl GovernedRuntimeProfileV2 {
    /// Validates V2 without accepting a V1 object or optional shared policy.
    pub fn verify_genesis(&self) -> Result<(), GovernedPortErrorV1> {
        if self.schema != GOVERNED_RUNTIME_PROFILE_SCHEMA_V2 {
            return Err(GovernedPortErrorV1::InvalidConfiguration(
                "invalid governed runtime profile v2",
            ));
        }
        self.common_profile().verify_genesis()?;
        self.nightshift_cycle.verify_all()?;
        self.shared_admission.verify_all()?;
        let config_bytes = self.nightshift_cycle.config.verify(false)?;
        let config: NightshiftCyclePortConfigV1 = JcsDocument::from_canonical_bytes(
            config_bytes.strip_suffix(b"\n").unwrap_or(&config_bytes),
        )
        .and_then(|document| document.decode())
        .map_err(|error| GovernedPortErrorV1::Canonical(error.to_string()))?;
        let requirement_bytes = self.shared_admission.review_requirement.verify(false)?;
        let requirement_digest =
            crate::shared_admission::canonical_file_identity(&requirement_bytes)?;
        if config.shared_admission_requirement_digest != requirement_digest {
            return Err(GovernedPortErrorV1::InvalidConfiguration(
                "Nightshift config differs from shared admission requirement",
            ));
        }
        Ok(())
    }

    /// Returns the unchanged common coordinates consumed by existing ports.
    #[must_use]
    pub fn common_profile(&self) -> GovernedRuntimeProfileV1 {
        GovernedRuntimeProfileV1 {
            schema: GOVERNED_RUNTIME_PROFILE_SCHEMA_V1.to_owned(),
            profile_label: self.profile_label.clone(),
            observation_resolver: self.observation_resolver.clone(),
            observation_resolver_id: self.observation_resolver_id.clone(),
            standing_resolver: self.standing_resolver.clone(),
            standing_resolver_id: self.standing_resolver_id.clone(),
            max_standing_ttl_ms: self.max_standing_ttl_ms,
            exact_work_catalog: self.exact_work_catalog.clone(),
            controlling_review: self.controlling_review.clone(),
            docket: self.docket.clone(),
            human_verifier: self.human_verifier.clone(),
            intervention_ingress: self.intervention_ingress.clone(),
        }
    }
}

impl GovernedRuntimeProfileV1 {
    /// Validates and measures every genesis-bound component.
    pub fn verify_genesis(&self) -> Result<(), GovernedPortErrorV1> {
        if self.schema != GOVERNED_RUNTIME_PROFILE_SCHEMA_V1
            || self.profile_label.is_empty()
            || self.profile_label.len() > 128
            || self.profile_label.chars().any(char::is_control)
            || self.observation_resolver_id.is_empty()
            || self.standing_resolver_id.is_empty()
            || self.max_standing_ttl_ms == 0
        {
            return Err(GovernedPortErrorV1::InvalidConfiguration(
                "invalid governed runtime profile",
            ));
        }
        let _ = self.observation_resolver.verify(true)?;
        let _ = self.standing_resolver.verify(true)?;
        let catalog = self.exact_work_catalog.verify(false)?;
        let document =
            JcsDocument::from_canonical_bytes(catalog.strip_suffix(b"\n").unwrap_or(&catalog))
                .map_err(|error| GovernedPortErrorV1::Canonical(error.to_string()))?;
        let catalog: crate::governed_loop::VersionedExactWorkCatalogV1 =
            serde_json::from_slice(document.as_bytes())
                .map_err(|error| GovernedPortErrorV1::Canonical(error.to_string()))?;
        catalog
            .validate()
            .map_err(|error| GovernedPortErrorV1::Deployment(error.to_string()))?;
        if let Some(review) = &self.controlling_review {
            let _ = review.verify(false)?;
        }
        if let Some(verifier) = &self.human_verifier {
            let _ = verifier.verify(true)?;
        }
        if let Some(ingress) = &self.intervention_ingress {
            ingress.validate()?;
        }
        self.docket.verify_all()
    }
}

/// Genesis-bound identity of the sole intervention submitting service.
///
/// This authenticates transport custody only. It is not a human mandate,
/// standing record, AG authorization, spend, or Docket credential.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedInterventionIngressV1 {
    /// Exact ingress schema.
    pub schema: String,
    /// Stable submitting-service principal.
    pub submitter_principal: String,
    /// Deployment key identity.
    pub submitter_key_id: String,
    /// Canonical base64url-no-pad Ed25519 public key.
    pub submitter_public_key: String,
}

impl GovernedInterventionIngressV1 {
    fn validate(&self) -> Result<(), GovernedPortErrorV1> {
        let public_key = URL_SAFE_NO_PAD
            .decode(&self.submitter_public_key)
            .map_err(|_| GovernedPortErrorV1::InvalidConfiguration("invalid ingress public key"))?;
        if self.schema != GOVERNED_INTERVENTION_INGRESS_SCHEMA_V1
            || self.submitter_principal.is_empty()
            || self.submitter_principal.len() > 256
            || self.submitter_principal.chars().any(char::is_whitespace)
            || self.submitter_key_id.is_empty()
            || self.submitter_key_id.len() > 256
            || self.submitter_key_id.chars().any(char::is_whitespace)
            || public_key.len() != 32
        {
            return Err(GovernedPortErrorV1::InvalidConfiguration(
                "invalid governed intervention ingress",
            ));
        }
        Ok(())
    }
}

/// Deployment-controlled, unhashed Docket coordinates accepted only by the
/// profile-sealing operation. This object is configuration input, not
/// authority and not a runtime fallback.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedDocketRootEnrollmentV1 {
    /// Exact enrollment schema.
    pub schema: String,
    /// Docket executable path.
    pub docket_program: PathBuf,
    /// Mutable Docket state-directory locator.
    pub state_directory: PathBuf,
    /// Docket trust configuration path.
    pub trust_config: PathBuf,
    /// Docket execution-standing resolver path.
    pub standing_resolver: PathBuf,
    /// Authority-neutral executor adapter path.
    pub executor_adapter: PathBuf,
    /// AG issuance principal trusted by Docket.
    pub issuer_principal: String,
    /// AG issuance signing-key identity.
    pub issuer_key_id: String,
    /// AG issuance signing-key path. The sealed profile contains only its
    /// locator and digest, never the key bytes.
    pub issuer_key: PathBuf,
}

/// Deployment-controlled input whose exact files are measured into one
/// immutable runtime profile. Sealing does not create a campaign or authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedRuntimeProfileEnrollmentV1 {
    /// Exact enrollment schema.
    pub schema: String,
    /// Bounded deployment label with no authority meaning.
    pub profile_label: String,
    /// Nightshift observation resolver executable path.
    pub observation_resolver: PathBuf,
    /// Exact expected observation resolver identity.
    pub observation_resolver_id: String,
    /// Present-tense standing resolver executable path.
    pub standing_resolver: PathBuf,
    /// Exact expected standing resolver identity.
    pub standing_resolver_id: String,
    /// Maximum accepted standing-answer lifetime.
    pub max_standing_ttl_ms: u64,
    /// Exact-work catalog path.
    pub exact_work_catalog: PathBuf,
    /// Optional controlling-review path.
    pub controlling_review: Option<PathBuf>,
    /// Docket custody/execution enrollment.
    pub docket: GovernedDocketRootEnrollmentV1,
    /// Optional human-verifier executable path.
    pub human_verifier: Option<PathBuf>,
    /// Optional intervention submitting-service enrollment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intervention_ingress: Option<GovernedInterventionIngressEnrollmentV1>,
}

/// Deployment paths measured into the required V2 shared-admission member.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedSharedAdmissionEnrollmentV1 {
    /// Exact shared-admission schema.
    pub schema: String,
    /// Required Maude binding schema.
    pub plan_binding_schema: String,
    /// Required compiler contract.
    pub compiler_contract: String,
    /// Validator executable path.
    pub plan_validator: PathBuf,
    /// Validator configuration path.
    pub plan_validator_config: PathBuf,
    /// Review verifier executable path.
    pub review_verifier: PathBuf,
    /// Review verifier configuration path.
    pub review_verifier_config: PathBuf,
    /// Review requirement path.
    pub review_requirement: PathBuf,
}

/// Explicit V2 enrollment. It cannot deserialize from or seal as V1.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedRuntimeProfileEnrollmentV2 {
    /// Exact V2 enrollment schema.
    pub schema: String,
    /// Deployment label.
    pub profile_label: String,
    /// Observation resolver path.
    pub observation_resolver: PathBuf,
    /// Observation resolver identity.
    pub observation_resolver_id: String,
    /// Standing resolver path.
    pub standing_resolver: PathBuf,
    /// Standing resolver identity.
    pub standing_resolver_id: String,
    /// Maximum standing lifetime.
    pub max_standing_ttl_ms: u64,
    /// Exact-work catalog path.
    pub exact_work_catalog: PathBuf,
    /// Optional controlling-review path.
    pub controlling_review: Option<PathBuf>,
    /// Docket enrollment.
    pub docket: GovernedDocketRootEnrollmentV1,
    /// Optional human-verifier path.
    pub human_verifier: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Optional intervention ingress enrollment.
    pub intervention_ingress: Option<GovernedInterventionIngressEnrollmentV1>,
    /// Nightshift cycle enrollment.
    pub nightshift_cycle: GovernedNightshiftCyclePortEnrollmentV1,
    /// Shared-admission enrollment.
    pub shared_admission: GovernedSharedAdmissionEnrollmentV1,
}

/// Deployment paths for the Nightshift cycle boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedNightshiftCyclePortEnrollmentV1 {
    /// Exact port schema.
    pub schema: String,
    /// Nightshift executable path.
    pub program: PathBuf,
    /// Closed configuration path.
    pub config: PathBuf,
}

impl GovernedRuntimeProfileEnrollmentV2 {
    /// Measures every V2 component and performs a second complete verification.
    pub fn seal(self) -> Result<GovernedRuntimeProfileV2, GovernedPortErrorV1> {
        if self.schema != GOVERNED_RUNTIME_PROFILE_ENROLLMENT_SCHEMA_V2
            || self.shared_admission.schema != GOVERNED_SHARED_ADMISSION_SCHEMA_V1
            || self.shared_admission.plan_binding_schema != MAUDE_GOVERNED_PLAN_BINDING_SCHEMA_V1
            || self.nightshift_cycle.schema != GOVERNED_NIGHTSHIFT_CYCLE_PORT_SCHEMA_V1
        {
            return Err(GovernedPortErrorV1::InvalidConfiguration(
                "invalid governed runtime profile enrollment v2",
            ));
        }
        let shared = GovernedSharedAdmissionV1 {
            schema: self.shared_admission.schema,
            plan_binding_schema: self.shared_admission.plan_binding_schema,
            compiler_contract: self.shared_admission.compiler_contract,
            plan_validator: PinnedDeploymentFileV1::measure(
                self.shared_admission.plan_validator,
                true,
            )?,
            plan_validator_config: PinnedDeploymentFileV1::measure(
                self.shared_admission.plan_validator_config,
                false,
            )?,
            review_verifier: PinnedDeploymentFileV1::measure(
                self.shared_admission.review_verifier,
                true,
            )?,
            review_verifier_config: PinnedDeploymentFileV1::measure(
                self.shared_admission.review_verifier_config,
                false,
            )?,
            review_requirement: PinnedDeploymentFileV1::measure(
                self.shared_admission.review_requirement,
                false,
            )?,
        };
        let nightshift_cycle = GovernedNightshiftCyclePortV1 {
            schema: self.nightshift_cycle.schema,
            program: PinnedDeploymentFileV1::measure(self.nightshift_cycle.program, true)?,
            config: PinnedDeploymentFileV1::measure(self.nightshift_cycle.config, false)?,
        };
        let legacy = GovernedRuntimeProfileEnrollmentV1 {
            schema: GOVERNED_RUNTIME_PROFILE_ENROLLMENT_SCHEMA_V1.to_owned(),
            profile_label: self.profile_label,
            observation_resolver: self.observation_resolver,
            observation_resolver_id: self.observation_resolver_id,
            standing_resolver: self.standing_resolver,
            standing_resolver_id: self.standing_resolver_id,
            max_standing_ttl_ms: self.max_standing_ttl_ms,
            exact_work_catalog: self.exact_work_catalog,
            controlling_review: self.controlling_review,
            docket: self.docket,
            human_verifier: self.human_verifier,
            intervention_ingress: self.intervention_ingress,
        }
        .seal()?;
        let profile = GovernedRuntimeProfileV2 {
            schema: GOVERNED_RUNTIME_PROFILE_SCHEMA_V2.to_owned(),
            profile_label: legacy.profile_label,
            observation_resolver: legacy.observation_resolver,
            observation_resolver_id: legacy.observation_resolver_id,
            standing_resolver: legacy.standing_resolver,
            standing_resolver_id: legacy.standing_resolver_id,
            max_standing_ttl_ms: legacy.max_standing_ttl_ms,
            exact_work_catalog: legacy.exact_work_catalog,
            controlling_review: legacy.controlling_review,
            docket: legacy.docket,
            human_verifier: legacy.human_verifier,
            intervention_ingress: legacy.intervention_ingress,
            nightshift_cycle,
            shared_admission: shared,
        };
        profile.verify_genesis()?;
        Ok(profile)
    }
}

/// Deployment input for one authenticated non-browser intervention submitter.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedInterventionIngressEnrollmentV1 {
    /// Exact enrollment schema.
    pub schema: String,
    /// Stable submitting-service principal.
    pub submitter_principal: String,
    /// Deployment key identity.
    pub submitter_key_id: String,
    /// File containing exactly 32 raw Ed25519 public-key bytes.
    pub submitter_public_key: PathBuf,
}

impl GovernedRuntimeProfileEnrollmentV1 {
    /// Measures and validates every configured file into a closed runtime
    /// profile. A second validation pass detects ordinary drift during seal.
    pub fn seal(self) -> Result<GovernedRuntimeProfileV1, GovernedPortErrorV1> {
        if self.schema != GOVERNED_RUNTIME_PROFILE_ENROLLMENT_SCHEMA_V1
            || self.docket.schema != GOVERNED_DOCKET_ROOT_ENROLLMENT_SCHEMA_V1
        {
            return Err(GovernedPortErrorV1::InvalidConfiguration(
                "invalid governed runtime profile enrollment",
            ));
        }
        let profile = GovernedRuntimeProfileV1 {
            schema: GOVERNED_RUNTIME_PROFILE_SCHEMA_V1.to_owned(),
            profile_label: self.profile_label,
            observation_resolver: PinnedDeploymentFileV1::measure(self.observation_resolver, true)?,
            observation_resolver_id: self.observation_resolver_id,
            standing_resolver: PinnedDeploymentFileV1::measure(self.standing_resolver, true)?,
            standing_resolver_id: self.standing_resolver_id,
            max_standing_ttl_ms: self.max_standing_ttl_ms,
            exact_work_catalog: PinnedDeploymentFileV1::measure(self.exact_work_catalog, false)?,
            controlling_review: self
                .controlling_review
                .map(|path| PinnedDeploymentFileV1::measure(path, false))
                .transpose()?,
            docket: GovernedDocketRootV1 {
                schema: GOVERNED_DOCKET_ROOT_SCHEMA_V1.to_owned(),
                docket_program: PinnedDeploymentFileV1::measure(self.docket.docket_program, true)?,
                state_directory: self.docket.state_directory,
                trust_config: PinnedDeploymentFileV1::measure(self.docket.trust_config, false)?,
                standing_resolver: PinnedDeploymentFileV1::measure(
                    self.docket.standing_resolver,
                    true,
                )?,
                executor_adapter: PinnedDeploymentFileV1::measure(
                    self.docket.executor_adapter,
                    true,
                )?,
                issuer_principal: self.docket.issuer_principal,
                issuer_key_id: self.docket.issuer_key_id,
                issuer_key: PinnedDeploymentFileV1::measure(self.docket.issuer_key, false)?,
            },
            human_verifier: self
                .human_verifier
                .map(|path| PinnedDeploymentFileV1::measure(path, true))
                .transpose()?,
            intervention_ingress: self
                .intervention_ingress
                .map(|ingress| {
                    if ingress.schema != GOVERNED_INTERVENTION_INGRESS_ENROLLMENT_SCHEMA_V1 {
                        return Err(GovernedPortErrorV1::InvalidConfiguration(
                            "invalid governed intervention ingress enrollment",
                        ));
                    }
                    let public_key =
                        PinnedDeploymentFileV1::read_bounded(&ingress.submitter_public_key, false)?;
                    if public_key.len() != 32 {
                        return Err(GovernedPortErrorV1::InvalidConfiguration(
                            "intervention ingress public key must contain exactly 32 raw bytes",
                        ));
                    }
                    Ok(GovernedInterventionIngressV1 {
                        schema: GOVERNED_INTERVENTION_INGRESS_SCHEMA_V1.to_owned(),
                        submitter_principal: ingress.submitter_principal,
                        submitter_key_id: ingress.submitter_key_id,
                        submitter_public_key: URL_SAFE_NO_PAD.encode(public_key),
                    })
                })
                .transpose()?,
        };
        profile.verify_genesis()?;
        Ok(profile)
    }
}

/// Authentication metadata for one exact canonical issuance body.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgIssuanceAuthenticationV1 {
    /// AG principal trusted by the Docket deployment.
    pub issuer_principal: String,
    /// Exact configured signing-key identity.
    pub signer_key_id: String,
    /// Canonical base64url-no-pad Ed25519 public key.
    pub signer_public_key: String,
    /// Signature over the domain prefix followed by the exact body bytes.
    pub signature: String,
}

/// Authenticated immutable envelope for one already-spent AG issuance.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAgIssuanceEnvelopeV1 {
    /// Exact envelope schema.
    pub schema: String,
    /// Canonical `AgIssuanceV1` bytes, base64url-no-pad.
    pub body_b64: String,
    /// Exact authentication over `body_b64`'s decoded bytes.
    pub authentication: AgIssuanceAuthenticationV1,
}

/// AG's configured issuance signer.  It does not create or spend authority;
/// it authenticates an issuance that already exists in the spend journal.
pub struct AgIssuanceSignerV1 {
    issuer_principal: String,
    key_id: String,
    key_pair: Ed25519KeyPair,
}

impl AgIssuanceSignerV1 {
    /// Loads one explicit PKCS#8 v2 Ed25519 credential.
    pub fn from_pkcs8_file(
        issuer_principal: impl Into<String>,
        key_id: impl Into<String>,
        path: &Path,
    ) -> Result<Self, GovernedPortErrorV1> {
        let bytes = fs::read(path).map_err(GovernedPortErrorV1::Io)?;
        Self::from_pkcs8(issuer_principal, key_id, &bytes)
    }

    /// Parses one explicit PKCS#8 v2 Ed25519 credential.
    pub fn from_pkcs8(
        issuer_principal: impl Into<String>,
        key_id: impl Into<String>,
        bytes: &[u8],
    ) -> Result<Self, GovernedPortErrorV1> {
        let issuer_principal = issuer_principal.into();
        let key_id = key_id.into();
        if issuer_principal.is_empty() || key_id.is_empty() {
            return Err(GovernedPortErrorV1::InvalidConfiguration(
                "issuer principal and key ID must be nonempty",
            ));
        }
        let key_pair = Ed25519KeyPair::from_pkcs8(bytes)
            .map_err(|_| GovernedPortErrorV1::InvalidSigningKey)?;
        Ok(Self {
            issuer_principal,
            key_id,
            key_pair,
        })
    }

    /// Authenticates an exact durable issuance without changing it.
    pub fn sign(
        &self,
        issuance: &AgIssuanceV1,
    ) -> Result<SignedAgIssuanceEnvelopeV1, GovernedPortErrorV1> {
        let body = JcsDocument::canonicalize(issuance)
            .map_err(|error| GovernedPortErrorV1::Canonical(error.to_string()))?;
        let mut signed = Vec::with_capacity(SIGNATURE_PREFIX_V1.len() + body.as_bytes().len());
        signed.extend_from_slice(SIGNATURE_PREFIX_V1);
        signed.extend_from_slice(body.as_bytes());
        let signature = self.key_pair.sign(&signed);
        Ok(SignedAgIssuanceEnvelopeV1 {
            schema: SIGNED_AG_ISSUANCE_SCHEMA_V1.to_owned(),
            body_b64: URL_SAFE_NO_PAD.encode(body.as_bytes()),
            authentication: AgIssuanceAuthenticationV1 {
                issuer_principal: self.issuer_principal.clone(),
                signer_key_id: self.key_id.clone(),
                signer_public_key: URL_SAFE_NO_PAD.encode(self.key_pair.public_key().as_ref()),
                signature: URL_SAFE_NO_PAD.encode(signature.as_ref()),
            },
        })
    }
}

/// Exact owned request sent to an observation owner on every live resolution.
#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct ObservationCommandRequestV1<'a> {
    schema: &'static str,
    key: &'a OccurrenceKeyV1,
    observation: &'a ObservationRefV1,
    subject: &'a ag_primitives::Digest,
    now_unix_ms: u64,
}

/// Exact owned request sent to Standing/Docket on every live resolution.
#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct StandingCommandRequestV1<'a> {
    schema: &'static str,
    key: &'a OccurrenceKeyV1,
    observation: &'a ObservationRefV1,
    proposal: &'a ProposalRefV1,
    subject: &'a ag_primitives::Digest,
    scope: &'a ag_primitives::Digest,
    now_unix_ms: u64,
}

/// Exact request sent to the external human-authority verifier.
#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct HumanVerificationCommandRequestV1<'a> {
    schema: &'static str,
    artifact: &'a HumanDispositionV1,
    expected_principal: &'a HumanPrincipalRefV1,
    expected_mandate: &'a MandateRefV1,
    now_unix_ms: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HumanVerificationCommandResponseV1 {
    schema: String,
    verification: HumanVerificationRefV1,
}

/// Exact request sent to the external intervention principal/mandate verifier.
#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct InterventionVerificationCommandRequestV1<'a> {
    schema: &'static str,
    request: &'a GovernedInterventionRequestV1,
    expected_principal: &'a HumanPrincipalRefV1,
    expected_mandate: &'a MandateRefV1,
    now_unix_ms: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InterventionVerificationCommandResponseV1 {
    schema: String,
    verification: GovernedInterventionVerificationRefV1,
}

/// Fresh process adapter for an external observation owner.
pub struct CommandObservationResolverV1 {
    program: PathBuf,
    deadline_unix_ms: Option<u64>,
}

impl CommandObservationResolverV1 {
    /// Configures the exact executable invoked once per resolution.
    #[must_use]
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            deadline_unix_ms: None,
        }
    }

    /// Applies an absolute deadline to resolver subprocesses.
    #[must_use]
    pub fn with_deadline(mut self, deadline_unix_ms: u64) -> Self {
        self.deadline_unix_ms = Some(deadline_unix_ms);
        self
    }
}

impl ObservationResolverV1 for CommandObservationResolverV1 {
    fn resolve_observation(
        &mut self,
        request: &ObservationResolutionRequestV1<'_>,
    ) -> Result<VersionedObservationResolutionV1, ExternalBoundaryErrorV1> {
        run_json_program_until(
            &self.program,
            &[],
            &ObservationCommandRequestV1 {
                schema: OBSERVATION_REQUEST_SCHEMA_V1,
                key: request.key,
                observation: request.observation,
                subject: request.subject,
                now_unix_ms: request.now_unix_ms,
            },
            self.deadline_unix_ms,
        )
        .map_err(external_error)
    }
}

/// Fresh process adapter for the authoritative current-standing owner.
pub struct CommandStandingResolverV1 {
    program: PathBuf,
    deadline_unix_ms: Option<u64>,
}

impl CommandStandingResolverV1 {
    /// Configures the exact executable invoked once per resolution.
    #[must_use]
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            deadline_unix_ms: None,
        }
    }

    /// Applies an absolute deadline to resolver subprocesses.
    #[must_use]
    pub fn with_deadline(mut self, deadline_unix_ms: u64) -> Self {
        self.deadline_unix_ms = Some(deadline_unix_ms);
        self
    }
}

impl StandingResolverV1 for CommandStandingResolverV1 {
    fn resolve_standing(
        &mut self,
        request: &StandingResolutionRequestV1<'_>,
    ) -> Result<CurrentStandingResolutionV2, ExternalBoundaryErrorV1> {
        run_json_program_until(
            &self.program,
            &[],
            &StandingCommandRequestV1 {
                schema: STANDING_REQUEST_SCHEMA_V1,
                key: request.key,
                observation: request.observation,
                proposal: request.proposal,
                subject: request.subject,
                scope: request.scope,
                now_unix_ms: request.now_unix_ms,
            },
            self.deadline_unix_ms,
        )
        .map_err(external_error)
    }
}

/// Fresh process adapter for external human-authority verification.
pub struct CommandHumanDispositionVerifierV1 {
    program: PathBuf,
}

impl CommandHumanDispositionVerifierV1 {
    /// Configures the exact executable invoked once per verification.
    #[must_use]
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
        }
    }
}

impl HumanDispositionVerifierV1 for CommandHumanDispositionVerifierV1 {
    fn verify_human_disposition(
        &mut self,
        request: &HumanDispositionVerificationRequestV1<'_>,
    ) -> Result<HumanVerificationRefV1, ExternalBoundaryErrorV1> {
        let response: HumanVerificationCommandResponseV1 = run_json_program(
            &self.program,
            &[],
            &HumanVerificationCommandRequestV1 {
                schema: HUMAN_VERIFICATION_REQUEST_SCHEMA_V1,
                artifact: request.artifact,
                expected_principal: &request.expected_scope.principal,
                expected_mandate: &request.expected_scope.mandate,
                now_unix_ms: request.now_unix_ms,
            },
        )
        .map_err(external_error)?;
        if response.schema != HUMAN_VERIFICATION_RESPONSE_SCHEMA_V1 {
            return Err(ExternalBoundaryErrorV1::Refused {
                code: "foreign-human-verification-schema".to_owned(),
                evidence: None,
            });
        }
        Ok(response.verification)
    }
}

/// Fresh process adapter for authenticated intervention verification.
///
/// The adapter may point at the same deployment-pinned verifier as human
/// dispositions, but the protocol/schema and returned receipt remain distinct.
pub struct CommandGovernedInterventionVerifierV1 {
    program: PathBuf,
}

impl CommandGovernedInterventionVerifierV1 {
    /// Configures the exact executable invoked once per verification.
    #[must_use]
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
        }
    }
}

impl GovernedInterventionVerifierV1 for CommandGovernedInterventionVerifierV1 {
    fn verify_governed_intervention(
        &mut self,
        request: &GovernedInterventionVerificationRequestV1<'_>,
    ) -> Result<GovernedInterventionVerificationRefV1, ExternalBoundaryErrorV1> {
        let response: InterventionVerificationCommandResponseV1 = run_json_program(
            &self.program,
            &[],
            &InterventionVerificationCommandRequestV1 {
                schema: INTERVENTION_VERIFICATION_REQUEST_SCHEMA_V1,
                request: request.request,
                expected_principal: &request.expected_scope.principal,
                expected_mandate: &request.expected_scope.mandate,
                now_unix_ms: request.now_unix_ms,
            },
        )
        .map_err(external_error)?;
        if response.schema != INTERVENTION_VERIFICATION_RESPONSE_SCHEMA_V1 {
            return Err(ExternalBoundaryErrorV1::Refused {
                code: "foreign-intervention-verification-schema".to_owned(),
                evidence: None,
            });
        }
        Ok(response.verification)
    }
}

/// Concrete authenticated subprocess seam to Docket's custody service.
pub struct CommandDocketCustodyPortV1 {
    docket_program: PathBuf,
    state_directory: PathBuf,
    trust_config: PathBuf,
    standing_resolver: PathBuf,
    executor_adapter: PathBuf,
    executor_config: PathBuf,
    signer: AgIssuanceSignerV1,
    deadline_unix_ms: Option<u64>,
}

impl CommandDocketCustodyPortV1 {
    /// Binds the exact Docket deployment and its external execution boundaries.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        docket_program: impl Into<PathBuf>,
        state_directory: impl Into<PathBuf>,
        trust_config: impl Into<PathBuf>,
        standing_resolver: impl Into<PathBuf>,
        executor_adapter: impl Into<PathBuf>,
        executor_config: impl Into<PathBuf>,
        signer: AgIssuanceSignerV1,
    ) -> Self {
        Self {
            docket_program: docket_program.into(),
            state_directory: state_directory.into(),
            trust_config: trust_config.into(),
            standing_resolver: standing_resolver.into(),
            executor_adapter: executor_adapter.into(),
            executor_config: executor_config.into(),
            signer,
            deadline_unix_ms: None,
        }
    }

    /// Applies an absolute deadline for finite-run subprocess I/O and wait.
    #[must_use]
    pub fn with_deadline(mut self, deadline_unix_ms: u64) -> Self {
        self.deadline_unix_ms = Some(deadline_unix_ms);
        self
    }

    fn arguments(&self, operation: &str) -> Vec<String> {
        vec![
            "governed-loop".to_owned(),
            operation.to_owned(),
            "--state".to_owned(),
            self.state_directory.display().to_string(),
            "--trust".to_owned(),
            self.trust_config.display().to_string(),
            "--standing-resolver".to_owned(),
            self.standing_resolver.display().to_string(),
            "--executor".to_owned(),
            self.executor_adapter.display().to_string(),
            "--executor-config".to_owned(),
            self.executor_config.display().to_string(),
        ]
    }
}

impl DocketCustodyPortV1 for CommandDocketCustodyPortV1 {
    fn accept_issuance(
        &mut self,
        issuance: &AgIssuanceV1,
    ) -> Result<DocketCustodyV1, ExternalBoundaryErrorV1> {
        let envelope = self.signer.sign(issuance).map_err(external_error)?;
        let arguments = self.arguments("accept");
        run_json_program_until(
            &self.docket_program,
            &arguments,
            &envelope,
            self.deadline_unix_ms,
        )
        .map_err(external_error)
    }

    fn reconcile_issuance(
        &mut self,
        issuance: &AgIssuanceV1,
    ) -> Result<DocketIssuanceReconciliationV1, ExternalBoundaryErrorV1> {
        #[derive(Serialize)]
        #[serde(deny_unknown_fields)]
        struct Request<'a> {
            issuance: &'a AgIssuanceRefV1,
        }
        let arguments = self.arguments("reconcile-issuance");
        run_json_program_until(
            &self.docket_program,
            &arguments,
            &Request {
                issuance: &issuance.issuance,
            },
            self.deadline_unix_ms,
        )
        .map_err(external_error)
    }

    fn reconcile_attempt(
        &mut self,
        custody: &DocketCustodyV1,
    ) -> Result<DocketIssuanceReconciliationV1, ExternalBoundaryErrorV1> {
        #[derive(Serialize)]
        #[serde(deny_unknown_fields)]
        struct Request<'a> {
            issuance: &'a AgIssuanceRefV1,
            attempt: &'a DocketAttemptRefV1,
        }
        let arguments = self.arguments("reconcile-attempt");
        run_json_program_until(
            &self.docket_program,
            &arguments,
            &Request {
                issuance: &custody.issuance,
                attempt: &custody.attempt,
            },
            self.deadline_unix_ms,
        )
        .map_err(external_error)
    }
}

/// Read-only Docket reconciliation adapter with no AG issuance signing key.
///
/// This is the only Docket port constructed by governed-intervention ingress.
/// Its `accept_issuance` implementation is a structural refusal, so operator
/// submission cannot become custody acceptance or dispatch.
pub struct CommandDocketReconciliationPortV1 {
    docket_program: PathBuf,
    state_directory: PathBuf,
    trust_config: PathBuf,
    standing_resolver: PathBuf,
    executor_adapter: PathBuf,
    executor_config: PathBuf,
    deadline_unix_ms: Option<u64>,
}

impl CommandDocketReconciliationPortV1 {
    /// Binds exact read-only Docket inspection/reconciliation coordinates.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        docket_program: impl Into<PathBuf>,
        state_directory: impl Into<PathBuf>,
        trust_config: impl Into<PathBuf>,
        standing_resolver: impl Into<PathBuf>,
        executor_adapter: impl Into<PathBuf>,
        executor_config: impl Into<PathBuf>,
    ) -> Self {
        Self {
            docket_program: docket_program.into(),
            state_directory: state_directory.into(),
            trust_config: trust_config.into(),
            standing_resolver: standing_resolver.into(),
            executor_adapter: executor_adapter.into(),
            executor_config: executor_config.into(),
            deadline_unix_ms: None,
        }
    }

    /// Applies an absolute deadline for finite-run reconciliation calls.
    #[must_use]
    pub fn with_deadline(mut self, deadline_unix_ms: u64) -> Self {
        self.deadline_unix_ms = Some(deadline_unix_ms);
        self
    }

    fn arguments(&self, operation: &str) -> Vec<String> {
        vec![
            "governed-loop".to_owned(),
            operation.to_owned(),
            "--state".to_owned(),
            self.state_directory.display().to_string(),
            "--trust".to_owned(),
            self.trust_config.display().to_string(),
            "--standing-resolver".to_owned(),
            self.standing_resolver.display().to_string(),
            "--executor".to_owned(),
            self.executor_adapter.display().to_string(),
            "--executor-config".to_owned(),
            self.executor_config.display().to_string(),
        ]
    }
}

impl DocketCustodyPortV1 for CommandDocketReconciliationPortV1 {
    fn accept_issuance(
        &mut self,
        _: &AgIssuanceV1,
    ) -> Result<DocketCustodyV1, ExternalBoundaryErrorV1> {
        Err(ExternalBoundaryErrorV1::Refused {
            code: "intervention-ingress-is-read-only".to_owned(),
            evidence: None,
        })
    }

    fn reconcile_issuance(
        &mut self,
        issuance: &AgIssuanceV1,
    ) -> Result<DocketIssuanceReconciliationV1, ExternalBoundaryErrorV1> {
        #[derive(Serialize)]
        #[serde(deny_unknown_fields)]
        struct Request<'a> {
            issuance: &'a AgIssuanceRefV1,
        }
        run_json_program_until(
            &self.docket_program,
            &self.arguments("reconcile-issuance"),
            &Request {
                issuance: &issuance.issuance,
            },
            self.deadline_unix_ms,
        )
        .map_err(external_error)
    }

    fn reconcile_attempt(
        &mut self,
        custody: &DocketCustodyV1,
    ) -> Result<DocketIssuanceReconciliationV1, ExternalBoundaryErrorV1> {
        #[derive(Serialize)]
        #[serde(deny_unknown_fields)]
        struct Request<'a> {
            issuance: &'a AgIssuanceRefV1,
            attempt: &'a DocketAttemptRefV1,
        }
        run_json_program_until(
            &self.docket_program,
            &self.arguments("reconcile-attempt"),
            &Request {
                issuance: &custody.issuance,
                attempt: &custody.attempt,
            },
            self.deadline_unix_ms,
        )
        .map_err(external_error)
    }
}

/// Concrete-process boundary failures.  They never grant authority.
#[derive(Debug, Error)]
pub enum GovernedPortErrorV1 {
    /// Explicit configuration is malformed.
    #[error("invalid governed-port configuration: {0}")]
    InvalidConfiguration(&'static str),
    /// A genesis-pinned deployment coordinate was substituted or drifted.
    #[error("governed deployment correspondence failed: {0}")]
    Deployment(String),
    /// Signing key is not an Ed25519 PKCS#8 v2 key.
    #[error("invalid governed-loop issuance signing key")]
    InvalidSigningKey,
    /// Local filesystem/process I/O failed.
    #[error("governed-port I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// Strict canonical request encoding failed.
    #[error("governed-port canonical encoding failed: {0}")]
    Canonical(String),
    /// External owner refused the request.
    #[error("external governed owner refused: {0}")]
    Refused(String),
    /// External owner returned a malformed response.
    #[error("external governed owner returned malformed output: {0}")]
    MalformedResponse(String),
    /// A finite process boundary exceeded its absolute deadline and was reaped.
    #[error("governed-port deadline exhausted")]
    DeadlineExhausted,
}

pub(crate) fn run_json_program<I, O>(
    program: &Path,
    arguments: &[String],
    input: &I,
) -> Result<O, GovernedPortErrorV1>
where
    I: Serialize + ?Sized,
    O: DeserializeOwned,
{
    run_json_program_until(program, arguments, input, None)
}

const MAX_PROCESS_OUTPUT_BYTES: u64 = 16 * 1024 * 1024;

pub(crate) fn run_json_program_until<I, O>(
    program: &Path,
    arguments: &[String],
    input: &I,
    deadline_unix_ms: Option<u64>,
) -> Result<O, GovernedPortErrorV1>
where
    I: Serialize + ?Sized,
    O: DeserializeOwned,
{
    let body = JcsDocument::canonicalize(input)
        .map_err(|error| GovernedPortErrorV1::Canonical(error.to_string()))?;
    let mut child = Command::new(program)
        .args(arguments)
        .process_group(0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(GovernedPortErrorV1::Io)?;
    let mut stdin = child.stdin.take().ok_or_else(|| {
        GovernedPortErrorV1::Io(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "child stdin unavailable",
        ))
    })?;
    let stdout = child.stdout.take().ok_or_else(|| {
        GovernedPortErrorV1::Io(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "child stdout unavailable",
        ))
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        GovernedPortErrorV1::Io(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "child stderr unavailable",
        ))
    })?;
    let input_bytes = body.as_bytes().to_vec();
    let writer = thread::spawn(move || stdin.write_all(&input_bytes));
    let output_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout
            .take(MAX_PROCESS_OUTPUT_BYTES + 1)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let error_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr
            .take(MAX_PROCESS_OUTPUT_BYTES + 1)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let status = loop {
        if let Some(status) = child.try_wait().map_err(GovernedPortErrorV1::Io)? {
            break status;
        }
        if deadline_unix_ms.is_some_and(|deadline| unix_time_ms() >= deadline) {
            if let Ok(pid) = i32::try_from(child.id()) {
                let _ = nix::sys::signal::killpg(
                    nix::unistd::Pid::from_raw(pid),
                    nix::sys::signal::Signal::SIGKILL,
                );
            }
            let _ = child.kill();
            let _ = child.wait();
            let _ = writer.join();
            let _ = output_reader.join();
            let _ = error_reader.join();
            return Err(GovernedPortErrorV1::DeadlineExhausted);
        }
        thread::sleep(Duration::from_millis(10));
    };
    // A direct child may exit while a descendant retains one of its pipes.
    // Close the whole invocation boundary before joining the pipe workers.
    if let Ok(pid) = i32::try_from(child.id()) {
        let _ = nix::sys::signal::killpg(
            nix::unistd::Pid::from_raw(pid),
            nix::sys::signal::Signal::SIGKILL,
        );
    }
    writer
        .join()
        .map_err(|_| GovernedPortErrorV1::MalformedResponse("stdin writer failed".to_owned()))?
        .map_err(GovernedPortErrorV1::Io)?;
    let stdout = output_reader
        .join()
        .map_err(|_| GovernedPortErrorV1::MalformedResponse("stdout reader failed".to_owned()))?
        .map_err(GovernedPortErrorV1::Io)?;
    let stderr = error_reader
        .join()
        .map_err(|_| GovernedPortErrorV1::MalformedResponse("stderr reader failed".to_owned()))?
        .map_err(GovernedPortErrorV1::Io)?;
    if stdout.len() > usize::try_from(MAX_PROCESS_OUTPUT_BYTES).unwrap_or(usize::MAX)
        || stderr.len() > usize::try_from(MAX_PROCESS_OUTPUT_BYTES).unwrap_or(usize::MAX)
    {
        return Err(GovernedPortErrorV1::MalformedResponse(
            "process output exceeds bound".to_owned(),
        ));
    }
    if !status.success() {
        let detail = String::from_utf8_lossy(&stderr);
        return Err(GovernedPortErrorV1::Refused(
            detail.chars().take(512).collect(),
        ));
    }
    serde_json::from_slice(&stdout)
        .map_err(|error| GovernedPortErrorV1::MalformedResponse(error.to_string()))
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .unwrap_or(u64::MAX)
}

fn external_error(error: GovernedPortErrorV1) -> ExternalBoundaryErrorV1 {
    match error {
        GovernedPortErrorV1::Refused(detail) => ExternalBoundaryErrorV1::Refused {
            code: format!("external-process:{detail}"),
            evidence: None,
        },
        other => ExternalBoundaryErrorV1::Unavailable {
            code: other.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    #[test]
    fn pinned_deployment_file_rejects_locator_substitution_and_byte_drift() {
        let directory = tempfile::tempdir().unwrap();
        let pinned_path = directory.path().join("pinned-command");
        let substituted_path = directory.path().join("substituted-command");
        fs::write(&pinned_path, b"#!/bin/sh\nexit 0\n").unwrap();
        fs::write(&substituted_path, b"#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&pinned_path, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&substituted_path, fs::Permissions::from_mode(0o700)).unwrap();
        let pinned = PinnedDeploymentFileV1 {
            path: pinned_path.clone(),
            identity: Digest::hash_bytes(&fs::read(&pinned_path).unwrap()),
        };

        assert!(pinned.verify_presented(&pinned_path, true).is_ok());
        assert!(matches!(
            pinned.verify_presented(&substituted_path, true),
            Err(GovernedPortErrorV1::Deployment(_))
        ));

        fs::write(&pinned_path, b"#!/bin/sh\nexit 1\n").unwrap();
        assert!(matches!(
            pinned.verify_presented(&pinned_path, true),
            Err(GovernedPortErrorV1::Deployment(_))
        ));
    }

    #[test]
    fn profile_versions_do_not_silently_upgrade_or_accept_missing_shared_policy() {
        let v1 = serde_json::json!({
            "schema": GOVERNED_RUNTIME_PROFILE_SCHEMA_V1,
            "profile_label": "fixture"
        });
        assert!(serde_json::from_value::<GovernedRuntimeProfileV2>(v1).is_err());
        let v2 = serde_json::json!({
            "schema": GOVERNED_RUNTIME_PROFILE_SCHEMA_V2,
            "profile_label": "fixture"
        });
        assert!(serde_json::from_value::<GovernedRuntimeProfileV1>(v2.clone()).is_err());
        assert!(serde_json::from_value::<GovernedRuntimeProfileV2>(v2).is_err());
    }

    #[test]
    fn nightshift_cycle_config_is_closed_and_requires_absolute_coordinates() {
        let value = serde_json::json!({
            "schema": NIGHTSHIFT_AG_CYCLE_PORT_CONFIG_SCHEMA_V1,
            "store": "/state", "present_evidence_resolver": {"path":"/bin/present","sha256":Digest::hash_bytes(b"p")},
            "nq_program": {"path":"/bin/nq","sha256":Digest::hash_bytes(b"nq")},
            "nq_config": {"path":"/etc/nq.json","sha256":Digest::hash_bytes(b"nqc")},
            "nq_source_id": "source", "ag_loopctl": {"path":"/bin/ag-loopctl","sha256":Digest::hash_bytes(b"ag")},
            "ag_database": "/state/ag.sqlite", "ag_observation_resolver": {"path":"/bin/observe","sha256":Digest::hash_bytes(b"obs")},
            "ag_observation_resolver_id": "observe/v1", "ag_runtime_profile": "/etc/ag-profile.json",
            "shared_admission_requirement_digest": Digest::hash_bytes(b"requirement"),
            "recover_observed_at": "2026-09-12T12:00:00Z", "substituted_program": "/tmp/other"
        });
        assert!(serde_json::from_value::<NightshiftCyclePortConfigV1>(value).is_err());
    }

    #[test]
    fn process_boundary_bounds_nonreading_nonexiting_and_pipe_flood_children() {
        for script in ["sleep 10", "yes x", "(sleep 10) & exit 0"] {
            let deadline = unix_time_ms().saturating_add(200);
            let result = run_json_program_until::<_, serde_json::Value>(
                Path::new("/bin/sh"),
                &["-c".to_owned(), script.to_owned()],
                &serde_json::json!({"input": "fixture"}),
                Some(deadline),
            );
            assert!(result.is_err(), "fixture unexpectedly succeeded: {script}");
        }
    }
}
