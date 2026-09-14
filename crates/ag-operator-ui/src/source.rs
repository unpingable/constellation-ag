//! Closed read-command adapter and campaign read-model assembly.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ag_campaign::governed::OccurrenceSnapshotV1;
use ag_store::campaign::{
    CAMPAIGN_REFUSAL_HISTORY_SCHEMA_V1, CAMPAIGN_TRANSITION_HISTORY_SCHEMA_V1,
    CampaignRefusalHistoryV1, CampaignReplayReportV1, CampaignTransitionHistoryV1,
};
use serde::{Deserialize as _, de::DeserializeOwned};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::links::GovernedRuntimeLinkV1;
use crate::model::{
    AG_INTERVENTION_SUBMISSION_HISTORY_SCHEMA_V1, AcquisitionHistoryV1, AgInspectV1,
    CAMPAIGN_DETAIL_SCHEMA_V1, CAMPAIGN_INDEX_SCHEMA_V1, CampaignDetailV1, CampaignIndexEntryV1,
    CampaignIndexV1, DEMO_CORPUS_SCHEMA_V1, DOCKET_INSPECTION_SCHEMA_V1, DemoCorpusV1,
    DocketInspectionV1, ExternalObservationExportV1, InterventionSubmissionHistoryProjectionV1,
    MAUDE_OBJECTIVE_READ_SCHEMA_V1, MaudeObjectiveAvailabilityV1, MaudeObjectiveReadV1,
    NightshiftAuthoringContextExportV1, NightshiftAuthoringContextQueryV1,
    NightshiftAuthoringCustodyExportV1, NightshiftObservationExportV1, OBJECTIVE_DETAIL_SCHEMA_V1,
    OBJECTIVE_DETAIL_SCHEMA_V2, OBJECTIVE_OWNER_PROJECTION_SCHEMA_V1, ObjectiveCausalUnavailableV1,
    ObjectiveConditionDispositionV1, ObjectiveConditionV1, ObjectiveDetailV1,
    ObjectiveEvidenceCurrentnessV1, ObjectiveOccurrenceLinkV1, ObjectiveOwnerProjectionV1,
    ObjectivePrerequisiteAvailabilityV1, ObjectivePrerequisitesV1,
    PUBLIC_OBJECTIVE_PROJECTION_SCHEMA_V1, ProjectionCheckV1, ProjectionCorrespondenceV1,
    PublicObjectiveProjectionV1, ReadCommandNameV1, RelatedSourceV1, SourceErrorKindV1,
    SourceResultV1,
};

const MAX_STDOUT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_STDERR_BYTES: u64 = 64 * 1024;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(5);
const RELATED_SOURCE_PROCESS_LIMIT: usize = 128;
const MAX_DEMO_CORPUS_BYTES: u64 = 64 * 1024 * 1024;
const MAX_DEMO_CAMPAIGNS: usize = 512;
/// Presentation-only evidence-age window passed transparently to Nightshift.
/// It is never used as canonical cycle currentness or AG authority.
const EXTERNAL_OBSERVATION_DISPLAY_TTL_MS: u64 = 5 * 60 * 1_000;

/// Optional Nightshift read-source coordinates.
#[derive(Clone, Debug)]
pub struct NightshiftReadSourceV1 {
    /// Exact canonical Nightshift CLI.
    pub program: PathBuf,
    /// Existing canonical Nightshift store.
    pub store: PathBuf,
}

/// Optional Docket read-source coordinates.
#[derive(Clone, Debug)]
pub struct DocketReadSourceV1 {
    /// Exact canonical Docket CLI.
    pub program: PathBuf,
    /// Existing Docket state directory.
    pub state: PathBuf,
}

/// Optional Maude acquisition-orchestration read source.
#[derive(Clone, Debug)]
pub struct MaudeAcquisitionReadSourceV1 {
    /// Exact closed acquisition CLI.
    pub program: PathBuf,
    /// Existing immutable trigger/request/event ledger.
    pub ledger: PathBuf,
}

/// Optional bounded Maude authored-objective read source. Maude owns bounded
/// regular-file handling; Phosphor supplies only the exact expected digest.
#[derive(Clone, Debug)]
pub struct MaudeObjectiveReadSourceV1 {
    /// Fixed canonical Maude objective-reader executable.
    pub program: PathBuf,
    /// Exact authored plan locator consumed by Maude.
    pub plan: PathBuf,
    /// Expected canonical `PlanDocument` digest.
    pub expected_plan_digest: String,
}

/// Optional fixed application-owner reader enrollment.
#[derive(Clone, Debug)]
pub struct ObjectiveOwnerProjectionSourceV1 {
    /// Fixed reader executable with the required canonical basename.
    pub program: PathBuf,
    /// Absolute deployment-selected reader configuration.
    pub config: PathBuf,
    /// Expected application-owner identity.
    pub expected_owner_id: String,
    /// Expected declared reader capability.
    pub expected_owner_capability: String,
    /// Expected application-owned source revision.
    pub expected_source_revision: String,
    /// Exact Maude plan digest shared with the objective source.
    pub expected_plan_digest: String,
}

/// Closed local operator backend configuration.
#[derive(Clone, Debug)]
pub struct OperatorSourceConfigV1 {
    /// Root whose immediate regular `.sqlite` children are campaign stores.
    pub campaign_root: PathBuf,
    /// Exact canonical AG controller.
    pub ag_loopctl: PathBuf,
    /// Optional Nightshift observation-provenance source.
    pub nightshift: Option<NightshiftReadSourceV1>,
    /// Optional Docket custody/outcome source.
    pub docket: Option<DocketReadSourceV1>,
    /// Optional Maude acquisition mechanics provenance.
    pub maude_acquisition: Option<MaudeAcquisitionReadSourceV1>,
    /// Optional Maude authored objective source.
    pub maude_objective: Option<MaudeObjectiveReadSourceV1>,
    /// Optional application-owned interpretation; never an authority source.
    pub objective_owner_projection: Option<ObjectiveOwnerProjectionSourceV1>,
    /// Optional separately approved public-safe objective artifact.
    pub public_objective_projection: Option<PathBuf>,
    /// Deployment-approved public receipt URL allowlist; HTTPS alone is not approval.
    pub public_approved_receipt_urls: BTreeSet<String>,
}

impl OperatorSourceConfigV1 {
    /// Validates locators and exact program names without invoking anything.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing campaign root or a noncanonical binary
    /// coordinate.
    pub fn validate(&self) -> Result<(), String> {
        require_program_name(&self.ag_loopctl, "ag-loopctl")?;
        if !self.campaign_root.is_dir() {
            return Err(format!(
                "campaign root is not a directory: {}",
                self.campaign_root.display()
            ));
        }
        if let Some(source) = &self.nightshift {
            require_program_name(&source.program, "nightshift")?;
        }
        if let Some(source) = &self.docket {
            require_program_name(&source.program, "docket")?;
        }
        if let Some(source) = &self.maude_acquisition {
            require_program_name(&source.program, "maude-observation-acquisition")?;
        }
        if let Some(source) = &self.maude_objective {
            require_program_name(&source.program, "maude-plan")?;
            if !is_sha256_digest(&source.expected_plan_digest) {
                return Err("Maude objective expected digest is not sha256".to_owned());
            }
        }
        if let Some(source) = &self.objective_owner_projection {
            require_program_name(&source.program, "phosphor-objective-owner-reader")?;
            if !source.config.is_absolute()
                || !is_sha256_digest(&source.expected_plan_digest)
                || source.expected_owner_id.is_empty()
                || source.expected_owner_capability.is_empty()
                || source.expected_source_revision.is_empty()
            {
                return Err("invalid objective owner projection enrollment".to_owned());
            }
            for value in [
                &source.expected_owner_id,
                &source.expected_owner_capability,
                &source.expected_source_revision,
            ] {
                if value.len() > 256 || !value.bytes().all(|byte| byte.is_ascii_graphic()) {
                    return Err(
                        "objective owner enrollment labels must be bounded visible ASCII"
                            .to_owned(),
                    );
                }
            }
        }
        if let (Some(maude), Some(owner)) =
            (&self.maude_objective, &self.objective_owner_projection)
            && maude.expected_plan_digest != owner.expected_plan_digest
        {
            return Err(
                "Maude and application-owner sources must bind the same plan digest".to_owned(),
            );
        }
        Ok(())
    }
}

/// Closed read requests. No variant accepts an arbitrary verb or argument
/// list, which makes the process boundary mechanically non-extensible without
/// changing this enum and its structural test.
#[derive(Clone, Debug)]
enum CanonicalReadRequestV1 {
    AgInspect(PathBuf),
    AgStatus(PathBuf),
    AgReplay(PathBuf),
    AgHistory(PathBuf),
    AgRefusals(PathBuf),
    AgInterventionSubmissions(PathBuf),
    NightshiftExportObservation(String),
    NightshiftExportAuthoringContext {
        campaign: String,
        occurrence: String,
    },
    NightshiftExportAuthoringCustody {
        campaign: String,
        occurrence: String,
    },
    NightshiftExportExternalObservation {
        campaign: String,
        occurrence: String,
        evaluated_at_unix_ms: i64,
        evidence_ttl_ms: u64,
    },
    MaudeExportObservationAcquisitions {
        campaign: String,
        occurrence: String,
    },
    MaudeObjectiveRead,
    ObjectiveOwnerProjection,
    DocketInspect(String),
}

impl CanonicalReadRequestV1 {
    const fn name(&self) -> ReadCommandNameV1 {
        match self {
            Self::AgInspect(_) => ReadCommandNameV1::AgInspect,
            Self::AgStatus(_) => ReadCommandNameV1::AgStatus,
            Self::AgReplay(_) => ReadCommandNameV1::AgReplay,
            Self::AgHistory(_) => ReadCommandNameV1::AgHistory,
            Self::AgRefusals(_) => ReadCommandNameV1::AgRefusals,
            Self::AgInterventionSubmissions(_) => ReadCommandNameV1::AgInterventionSubmissions,
            Self::NightshiftExportObservation(_) => ReadCommandNameV1::NightshiftExportObservation,
            Self::NightshiftExportAuthoringContext { .. } => {
                ReadCommandNameV1::NightshiftExportAuthoringContext
            }
            Self::NightshiftExportAuthoringCustody { .. } => {
                ReadCommandNameV1::NightshiftExportAuthoringCustody
            }
            Self::NightshiftExportExternalObservation { .. } => {
                ReadCommandNameV1::NightshiftExportExternalObservation
            }
            Self::MaudeExportObservationAcquisitions { .. } => {
                ReadCommandNameV1::MaudeExportObservationAcquisitions
            }
            Self::MaudeObjectiveRead => ReadCommandNameV1::MaudeObjectiveRead,
            Self::ObjectiveOwnerProjection => ReadCommandNameV1::ObjectiveOwnerProjection,
            Self::DocketInspect(_) => ReadCommandNameV1::DocketGovernedLoopInspect,
        }
    }
}

#[derive(Debug)]
struct CaptureFailureV1 {
    kind: SourceErrorKindV1,
    detail: String,
    exit_status: Option<i32>,
}

#[derive(Debug)]
struct CapturedJsonV1 {
    captured_at_unix_ms: u64,
    raw: Value,
}

/// Production read-model assembler. It owns only canonical read-command
/// coordinates and never opens a runtime database itself.
#[derive(Clone, Debug)]
enum OperatorReaderBackendV1 {
    Canonical(Box<OperatorSourceConfigV1>),
    Demo(Arc<DemoCorpusV1>),
}

/// Read-only live-command or deterministic-corpus projection source.
#[derive(Clone, Debug)]
pub struct OperatorReaderV1 {
    backend: OperatorReaderBackendV1,
}

impl OperatorReaderV1 {
    /// Constructs one validated read-only source adapter.
    ///
    /// # Errors
    ///
    /// Returns a configuration validation error.
    pub fn new(config: OperatorSourceConfigV1) -> Result<Self, String> {
        config.validate()?;
        Ok(Self {
            backend: OperatorReaderBackendV1::Canonical(Box::new(config)),
        })
    }

    /// Opens one bounded deterministic read-model corpus. This mode executes
    /// no subprocess and is visibly labeled by the renderer; it exists only
    /// to exercise presentation against captured canonical schemas.
    ///
    /// # Errors
    ///
    /// Returns an error for an oversized, malformed, drifted, or internally
    /// inconsistent corpus.
    pub fn from_demo_corpus(path: &Path) -> Result<Self, String> {
        let metadata =
            fs::metadata(path).map_err(|error| format!("read demo corpus metadata: {error}"))?;
        if !metadata.is_file() || metadata.len() > MAX_DEMO_CORPUS_BYTES {
            return Err("demo corpus must be a regular file no larger than 64 MiB".to_owned());
        }
        let bytes = fs::read(path).map_err(|error| format!("read demo corpus: {error}"))?;
        let corpus: DemoCorpusV1 = serde_json::from_slice(&bytes)
            .map_err(|error| format!("parse typed demo corpus: {error}"))?;
        validate_demo_corpus(&corpus)?;
        Ok(Self {
            backend: OperatorReaderBackendV1::Demo(Arc::new(corpus)),
        })
    }

    /// Presentation-only source-mode label.
    #[must_use]
    pub const fn mode_label(&self) -> &'static str {
        match self.backend {
            OperatorReaderBackendV1::Canonical(_) => "live canonical commands",
            OperatorReaderBackendV1::Demo(_) => "deterministic demo corpus",
        }
    }

    /// Lists all immediate regular campaign databases. Each failed canonical
    /// read remains a visible index entry.
    ///
    /// # Errors
    ///
    /// Returns an error when the configured campaign root cannot be listed.
    pub fn campaign_index(&self) -> Result<CampaignIndexV1, String> {
        if let OperatorReaderBackendV1::Demo(corpus) = &self.backend {
            return Ok(corpus.index.clone());
        }
        let config = self.canonical_config()?;
        let mut stores = discover_stores(&config.campaign_root)?;
        stores.sort_by(|left, right| left.0.cmp(&right.0));
        let campaigns = stores
            .into_iter()
            .map(|(token, locator, database)| {
                let inspect = self.ag_inspect(&database);
                let history = self.ag_history(&database);
                let refusals = self.ag_refusals(&database);
                let projection = projection_check(
                    inspect.value(),
                    None,
                    None,
                    history.value(),
                    refusals.value(),
                    &[
                        inspect.is_available(),
                        history.is_available(),
                        refusals.is_available(),
                    ],
                );
                CampaignIndexEntryV1 {
                    locator_token: token,
                    locator,
                    inspect,
                    history,
                    refusals,
                    projection,
                }
            })
            .collect();
        Ok(CampaignIndexV1 {
            schema: CAMPAIGN_INDEX_SCHEMA_V1.to_owned(),
            campaigns,
        })
    }

    /// Loads one exact configured-root child through all canonical sources.
    ///
    /// # Errors
    ///
    /// Returns an error when the locator is not one of the root's immediate
    /// regular campaign stores.
    pub fn campaign_detail(&self, locator_token: &str) -> Result<CampaignDetailV1, String> {
        if let OperatorReaderBackendV1::Demo(corpus) = &self.backend {
            return corpus
                .campaigns
                .iter()
                .find(|campaign| campaign.locator_token == locator_token)
                .cloned()
                .ok_or_else(|| "nonexistent demo campaign locator".to_owned());
        }
        let (locator, database) = self.resolve_store(locator_token)?;
        let inspect = self.ag_inspect(&database);
        let status = self.ag_status(&database);
        let replay = self.ag_replay(&database);
        let history = self.ag_history(&database);
        let refusals = self.ag_refusals(&database);
        let intervention_submissions = self.ag_intervention_submissions(&database);
        let availability = [
            inspect.is_available(),
            status.is_available(),
            replay.is_available(),
            history.is_available(),
            refusals.is_available(),
        ];
        let projection = projection_check(
            inspect.value(),
            status.value(),
            replay.value(),
            history.value(),
            refusals.value(),
            &availability,
        );

        let mut observations = BTreeSet::new();
        let mut issuances = BTreeSet::new();
        let mut occurrences = BTreeSet::new();
        if let Some(value) = history.value() {
            for transition in &value.transitions {
                collect_related(&transition.successor, &mut observations, &mut issuances);
                collect_occurrence(&transition.successor, &mut occurrences);
            }
        } else if let Some(value) = inspect.value() {
            collect_related(&value.current, &mut observations, &mut issuances);
            collect_occurrence(&value.current, &mut occurrences);
        } else if let Some(value) = status.value() {
            collect_related(value, &mut observations, &mut issuances);
            collect_occurrence(value, &mut occurrences);
        }

        let nightshift = self.collect_nightshift_sources(observations);
        let authoring_contexts = self.collect_authoring_sources(occurrences.clone());
        let authoring_custody = self.collect_authoring_custody_sources(occurrences.clone());
        let external_observations = self.collect_external_observations(occurrences.clone());
        let observation_acquisitions = self.collect_acquisition_sources(occurrences);
        let docket = self.collect_docket_sources(issuances);

        Ok(CampaignDetailV1 {
            schema: CAMPAIGN_DETAIL_SCHEMA_V1.to_owned(),
            locator_token: locator_token.to_owned(),
            locator,
            inspect,
            status,
            replay,
            history,
            refusals,
            intervention_submissions: Some(intervention_submissions),
            projection,
            nightshift,
            authoring_contexts,
            authoring_custody,
            external_observations,
            observation_acquisitions,
            docket,
        })
    }

    /// Returns one objective projection selected by its exact plan digest.
    ///
    /// # Errors
    ///
    /// Returns an error when the selector or an independently read owner does
    /// not satisfy the closed objective read contract.
    pub fn objective_detail(&self, objective_id: &str) -> Result<ObjectiveDetailV1, String> {
        match &self.backend {
            OperatorReaderBackendV1::Demo(corpus) => {
                let expected_plan_digest = format!("sha256:{objective_id}");
                corpus
                    .objectives
                    .iter()
                    .find(|objective| {
                        objective.objective.plan_digest.as_deref()
                            == Some(expected_plan_digest.as_str())
                    })
                    .cloned()
                    .ok_or_else(|| "nonexistent demo objective locator".to_owned())
            }
            OperatorReaderBackendV1::Canonical(_) => {
                let expected_plan_digest = format!("sha256:{objective_id}");
                let source = self
                    .canonical_config()?
                    .maude_objective
                    .as_ref()
                    .ok_or_else(|| "Maude objective read source is not configured".to_owned())?;
                if source.expected_plan_digest != expected_plan_digest {
                    return Err(
                        "objective selector does not match configured exact plan digest".to_owned(),
                    );
                }
                let owner = self.maude_objective_read();
                let objective = owner
                    .value()
                    .cloned()
                    .ok_or_else(|| "Maude objective source unavailable".to_owned())?;
                if objective.plan_digest.as_deref() != Some(expected_plan_digest.as_str()) {
                    return Err(
                        "Maude objective result did not bind configured exact plan digest"
                            .to_owned(),
                    );
                }
                let mut campaigns = Vec::new();
                let mut causal_unavailable = Vec::new();
                for entry in self.campaign_index()?.campaigns {
                    match self.campaign_detail(&entry.locator_token) {
                        Ok(detail) => campaigns.push(detail),
                        Err(detail) => causal_unavailable.push(ObjectiveCausalUnavailableV1 {
                            locator_token: entry.locator_token,
                            detail,
                        }),
                    }
                }
                let owner_projection = if objective.availability
                    == MaudeObjectiveAvailabilityV1::Available
                    && self
                        .canonical_config()?
                        .objective_owner_projection
                        .is_some()
                {
                    Some(bind_owner_projection_to_objective(
                        self.objective_owner_projection(),
                        &objective,
                    ))
                } else {
                    None
                };
                let detail = assemble_objective_detail(
                    objective,
                    &campaigns,
                    causal_unavailable,
                    owner_projection,
                );
                validate_objective_detail(&detail)?;
                Ok(detail)
            }
        }
    }

    /// Reads one separately approved public-safe projection. It never derives
    /// fields from the operator objective view and remains loopback-served.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing, changed, oversized, malformed, or
    /// non-allowlisted public projection artifact.
    pub fn public_objective_projection(
        &self,
        objective_id: &str,
    ) -> Result<PublicObjectiveProjectionV1, String> {
        let expected_plan_digest = format!("sha256:{objective_id}");
        let path = self
            .canonical_config()?
            .public_objective_projection
            .as_ref()
            .ok_or_else(|| "public objective projection is not configured".to_owned())?;
        let bytes = read_bounded_public_projection(path)?;
        let projection = serde_json::from_slice::<PublicObjectiveProjectionV1>(&bytes)
            .map_err(|error| format!("parse public objective projection: {error}"))?;
        validate_public_objective_projection(&projection)?;
        let approved_urls = &self.canonical_config()?.public_approved_receipt_urls;
        if projection
            .approved_receipt_urls
            .iter()
            .any(|url| !approved_urls.contains(url))
        {
            return Err("public objective receipt URL is not explicitly allowlisted".to_owned());
        }
        if projection.plan_digest != expected_plan_digest {
            return Err(
                "public objective selector does not match configured plan digest".to_owned(),
            );
        }
        Ok(projection)
    }

    fn collect_nightshift_sources(
        &self,
        observations: BTreeSet<String>,
    ) -> Vec<RelatedSourceV1<NightshiftObservationExportV1>> {
        observations
            .into_iter()
            .enumerate()
            .map(|(index, identity)| RelatedSourceV1 {
                result: if index < RELATED_SOURCE_PROCESS_LIMIT {
                    self.nightshift_export(&identity)
                } else {
                    unavailable(
                        "Nightshift",
                        ReadCommandNameV1::NightshiftExportObservation,
                        SourceErrorKindV1::Unavailable,
                        "related-source process limit exceeded; fact not queried".to_owned(),
                        None,
                    )
                },
                identity,
            })
            .collect()
    }

    fn collect_authoring_sources(
        &self,
        occurrences: BTreeSet<(String, String)>,
    ) -> Vec<RelatedSourceV1<NightshiftAuthoringContextExportV1>> {
        occurrences
            .into_iter()
            .enumerate()
            .map(|(index, (campaign, occurrence))| RelatedSourceV1 {
                identity: format!("{campaign}/{occurrence}"),
                result: if index < RELATED_SOURCE_PROCESS_LIMIT {
                    self.nightshift_authoring_export(&campaign, &occurrence)
                } else {
                    unavailable(
                        "Nightshift",
                        ReadCommandNameV1::NightshiftExportAuthoringContext,
                        SourceErrorKindV1::Unavailable,
                        "related-source process limit exceeded; fact not queried".to_owned(),
                        None,
                    )
                },
            })
            .collect()
    }

    fn collect_docket_sources(
        &self,
        issuances: BTreeSet<String>,
    ) -> Vec<RelatedSourceV1<DocketInspectionV1>> {
        issuances
            .into_iter()
            .enumerate()
            .map(|(index, identity)| RelatedSourceV1 {
                result: if index < RELATED_SOURCE_PROCESS_LIMIT {
                    self.docket_inspect(&identity)
                } else {
                    unavailable(
                        "Docket",
                        ReadCommandNameV1::DocketGovernedLoopInspect,
                        SourceErrorKindV1::Unavailable,
                        "related-source process limit exceeded; fact not queried".to_owned(),
                        None,
                    )
                },
                identity,
            })
            .collect()
    }

    fn collect_authoring_custody_sources(
        &self,
        occurrences: BTreeSet<(String, String)>,
    ) -> Vec<RelatedSourceV1<NightshiftAuthoringCustodyExportV1>> {
        occurrences
            .into_iter()
            .enumerate()
            .map(|(index, (campaign, occurrence))| RelatedSourceV1 {
                identity: format!("{campaign}/{occurrence}"),
                result: if index < RELATED_SOURCE_PROCESS_LIMIT {
                    self.nightshift_authoring_custody_export(&campaign, &occurrence)
                } else {
                    unavailable(
                        "Nightshift",
                        ReadCommandNameV1::NightshiftExportAuthoringCustody,
                        SourceErrorKindV1::Unavailable,
                        "related-source process limit exceeded; fact not queried".to_owned(),
                        None,
                    )
                },
            })
            .collect()
    }

    fn collect_external_observations(
        &self,
        occurrences: BTreeSet<(String, String)>,
    ) -> Vec<RelatedSourceV1<ExternalObservationExportV1>> {
        occurrences
            .into_iter()
            .enumerate()
            .map(|(index, (campaign, occurrence))| RelatedSourceV1 {
                identity: format!("{campaign}/{occurrence}"),
                result: if index < RELATED_SOURCE_PROCESS_LIMIT {
                    self.nightshift_external_observation_export(&campaign, &occurrence)
                } else {
                    unavailable(
                        "Nightshift",
                        ReadCommandNameV1::NightshiftExportExternalObservation,
                        SourceErrorKindV1::Unavailable,
                        "related-source process limit exceeded; fact not queried".to_owned(),
                        None,
                    )
                },
            })
            .collect()
    }

    fn collect_acquisition_sources(
        &self,
        occurrences: BTreeSet<(String, String)>,
    ) -> Vec<RelatedSourceV1<AcquisitionHistoryV1>> {
        occurrences
            .into_iter()
            .enumerate()
            .map(|(index, (campaign, occurrence))| RelatedSourceV1 {
                identity: format!("{campaign}/{occurrence}"),
                result: if index < RELATED_SOURCE_PROCESS_LIMIT {
                    self.maude_acquisition_export(&campaign, &occurrence)
                } else {
                    unavailable(
                        "Maude acquisition orchestrator",
                        ReadCommandNameV1::MaudeExportObservationAcquisitions,
                        SourceErrorKindV1::Unavailable,
                        "related-source process limit exceeded; fact not queried".to_owned(),
                        None,
                    )
                },
            })
            .collect()
    }

    /// Resolves one navigation-only semantic link without accepting a
    /// database path or treating the URL as authority.
    ///
    /// # Errors
    ///
    /// Returns an error when no exact identity binding exists or when more
    /// than one live campaign store claims the same semantic coordinates.
    pub fn campaign_detail_for_link(
        &self,
        link: &GovernedRuntimeLinkV1,
    ) -> Result<CampaignDetailV1, String> {
        if let OperatorReaderBackendV1::Demo(corpus) = &self.backend {
            let target = corpus
                .semantic_link_targets
                .iter()
                .find(|target| demo_target_matches(target, link))
                .ok_or_else(|| "demo corpus has no exact semantic link target".to_owned())?;
            return self.campaign_detail(&target.locator_token);
        }

        let index = self.campaign_index()?;
        let candidates = index
            .campaigns
            .iter()
            .filter(|entry| index_entry_matches_link(entry, link))
            .collect::<Vec<_>>();
        let [candidate] = candidates.as_slice() else {
            return Err(match candidates.len() {
                0 => "no campaign occurrence matches the canonical semantic link".to_owned(),
                count => format!(
                    "{count} campaign stores match the semantic link; refusing ambiguous locator resolution"
                ),
            });
        };
        let detail = self.campaign_detail(&candidate.locator_token)?;
        if !detail_matches_link(&detail, link) {
            return Err("campaign changed while resolving semantic link".to_owned());
        }
        Ok(detail)
    }

    fn resolve_store(&self, token: &str) -> Result<(String, PathBuf), String> {
        discover_stores(&self.canonical_config()?.campaign_root)?
            .into_iter()
            .find(|candidate| candidate.0 == token)
            .map(|(_, locator, path)| (locator, path))
            .ok_or_else(|| "nonexistent campaign source locator".to_owned())
    }

    fn ag_inspect(&self, database: &Path) -> SourceResultV1<AgInspectV1> {
        self.capture_typed(
            "AG",
            &CanonicalReadRequestV1::AgInspect(database.to_owned()),
            |value: &AgInspectV1| value.validate(),
        )
    }

    fn ag_status(&self, database: &Path) -> SourceResultV1<OccurrenceSnapshotV1> {
        self.capture_typed(
            "AG",
            &CanonicalReadRequestV1::AgStatus(database.to_owned()),
            |value: &OccurrenceSnapshotV1| {
                value
                    .validate_integrity()
                    .map_err(|error| format!("AG status snapshot integrity: {error}"))
            },
        )
    }

    fn ag_replay(&self, database: &Path) -> SourceResultV1<CampaignReplayReportV1> {
        self.capture_typed(
            "AG",
            &CanonicalReadRequestV1::AgReplay(database.to_owned()),
            |_| Ok(()),
        )
    }

    fn ag_history(&self, database: &Path) -> SourceResultV1<CampaignTransitionHistoryV1> {
        self.capture_typed(
            "AG",
            &CanonicalReadRequestV1::AgHistory(database.to_owned()),
            |value: &CampaignTransitionHistoryV1| {
                if value.schema != CAMPAIGN_TRANSITION_HISTORY_SCHEMA_V1 {
                    return Err(format!("unsupported AG history schema {}", value.schema));
                }
                for (index, transition) in value.transitions.iter().enumerate() {
                    let expected = u64::try_from(index + 1)
                        .map_err(|_| "AG history sequence overflow".to_owned())?;
                    transition
                        .successor
                        .validate_integrity()
                        .map_err(|error| format!("AG history snapshot integrity: {error}"))?;
                    if transition.sequence != expected
                        || transition.successor.state_digest() != &transition.successor_state_digest
                    {
                        return Err("AG history ordering/binding mismatch".to_owned());
                    }
                }
                let last = value
                    .transitions
                    .last()
                    .ok_or_else(|| "AG history is empty".to_owned())?;
                if last.successor_state_digest != value.current_state_digest {
                    return Err("AG history current-state binding mismatch".to_owned());
                }
                Ok(())
            },
        )
    }

    fn ag_refusals(&self, database: &Path) -> SourceResultV1<CampaignRefusalHistoryV1> {
        self.capture_typed(
            "AG",
            &CanonicalReadRequestV1::AgRefusals(database.to_owned()),
            |value: &CampaignRefusalHistoryV1| {
                if value.schema != CAMPAIGN_REFUSAL_HISTORY_SCHEMA_V1 {
                    return Err(format!(
                        "unsupported AG refusal-history schema {}",
                        value.schema
                    ));
                }
                if value
                    .refusals
                    .iter()
                    .any(|refusal| refusal.outcome.key.campaign != value.campaign)
                {
                    return Err("AG refusal-history campaign binding mismatch".to_owned());
                }
                Ok(())
            },
        )
    }

    fn ag_intervention_submissions(
        &self,
        database: &Path,
    ) -> SourceResultV1<InterventionSubmissionHistoryProjectionV1> {
        self.capture_typed(
            "AG intervention ingress",
            &CanonicalReadRequestV1::AgInterventionSubmissions(database.to_owned()),
            |value: &InterventionSubmissionHistoryProjectionV1| {
                if value.schema != AG_INTERVENTION_SUBMISSION_HISTORY_SCHEMA_V1 {
                    return Err(format!(
                        "unsupported AG intervention submission schema {}",
                        value.schema
                    ));
                }
                if value.receipts.iter().any(|receipt| {
                    receipt
                        .target_runtime_profile
                        .as_ref()
                        .is_some_and(|target| target != &value.target_runtime_profile)
                }) {
                    return Err("intervention receipt target-runtime mismatch".to_owned());
                }
                Ok(())
            },
        )
    }

    fn nightshift_export(
        &self,
        observation: &str,
    ) -> SourceResultV1<NightshiftObservationExportV1> {
        let Some(_) = &self
            .canonical_config()
            .ok()
            .and_then(|value| value.nightshift.as_ref())
        else {
            return unavailable(
                "Nightshift",
                ReadCommandNameV1::NightshiftExportObservation,
                SourceErrorKindV1::NotConfigured,
                "Nightshift source is not configured".to_owned(),
                None,
            );
        };
        self.capture_typed(
            "Nightshift",
            &CanonicalReadRequestV1::NightshiftExportObservation(observation.to_owned()),
            |value: &NightshiftObservationExportV1| value.validate(observation),
        )
    }

    fn nightshift_authoring_export(
        &self,
        campaign: &str,
        occurrence: &str,
    ) -> SourceResultV1<NightshiftAuthoringContextExportV1> {
        let Some(_) = &self
            .canonical_config()
            .ok()
            .and_then(|value| value.nightshift.as_ref())
        else {
            return unavailable(
                "Nightshift",
                ReadCommandNameV1::NightshiftExportAuthoringContext,
                SourceErrorKindV1::NotConfigured,
                "Nightshift source is not configured".to_owned(),
                None,
            );
        };
        self.capture_typed(
            "Nightshift",
            &CanonicalReadRequestV1::NightshiftExportAuthoringContext {
                campaign: campaign.to_owned(),
                occurrence: occurrence.to_owned(),
            },
            |value: &NightshiftAuthoringContextExportV1| {
                value.validate_for_occurrence(campaign, occurrence)
            },
        )
    }

    fn docket_inspect(&self, issuance: &str) -> SourceResultV1<DocketInspectionV1> {
        let Some(_) = &self
            .canonical_config()
            .ok()
            .and_then(|value| value.docket.as_ref())
        else {
            return unavailable(
                "Docket",
                ReadCommandNameV1::DocketGovernedLoopInspect,
                SourceErrorKindV1::NotConfigured,
                "Docket source is not configured".to_owned(),
                None,
            );
        };
        self.capture_typed(
            "Docket",
            &CanonicalReadRequestV1::DocketInspect(issuance.to_owned()),
            |value: &DocketInspectionV1| validate_docket(value, issuance),
        )
    }

    fn nightshift_authoring_custody_export(
        &self,
        campaign: &str,
        occurrence: &str,
    ) -> SourceResultV1<NightshiftAuthoringCustodyExportV1> {
        let Some(_) = &self
            .canonical_config()
            .ok()
            .and_then(|value| value.nightshift.as_ref())
        else {
            return unavailable(
                "Nightshift",
                ReadCommandNameV1::NightshiftExportAuthoringCustody,
                SourceErrorKindV1::NotConfigured,
                "Nightshift source is not configured".to_owned(),
                None,
            );
        };
        self.capture_typed(
            "Nightshift",
            &CanonicalReadRequestV1::NightshiftExportAuthoringCustody {
                campaign: campaign.to_owned(),
                occurrence: occurrence.to_owned(),
            },
            |value: &NightshiftAuthoringCustodyExportV1| {
                value.validate_for_occurrence(campaign, occurrence)
            },
        )
    }

    fn nightshift_external_observation_export(
        &self,
        campaign: &str,
        occurrence: &str,
    ) -> SourceResultV1<ExternalObservationExportV1> {
        let Some(_) = &self
            .canonical_config()
            .ok()
            .and_then(|value| value.nightshift.as_ref())
        else {
            return unavailable(
                "Nightshift",
                ReadCommandNameV1::NightshiftExportExternalObservation,
                SourceErrorKindV1::NotConfigured,
                "Nightshift source is not configured".to_owned(),
                None,
            );
        };
        let evaluated_at_unix_ms = i64::try_from(capture_time()).unwrap_or(i64::MAX);
        self.capture_typed(
            "Nightshift",
            &CanonicalReadRequestV1::NightshiftExportExternalObservation {
                campaign: campaign.to_owned(),
                occurrence: occurrence.to_owned(),
                evaluated_at_unix_ms,
                evidence_ttl_ms: EXTERNAL_OBSERVATION_DISPLAY_TTL_MS,
            },
            |value: &ExternalObservationExportV1| {
                value.validate_for_occurrence(campaign, occurrence)
            },
        )
    }

    fn maude_acquisition_export(
        &self,
        campaign: &str,
        occurrence: &str,
    ) -> SourceResultV1<AcquisitionHistoryV1> {
        let Some(_) = self
            .canonical_config()
            .ok()
            .and_then(|value| value.maude_acquisition.as_ref())
        else {
            return unavailable(
                "Maude acquisition orchestrator",
                ReadCommandNameV1::MaudeExportObservationAcquisitions,
                SourceErrorKindV1::NotConfigured,
                "Maude acquisition source is not configured".to_owned(),
                None,
            );
        };
        self.capture_typed(
            "Maude acquisition orchestrator",
            &CanonicalReadRequestV1::MaudeExportObservationAcquisitions {
                campaign: campaign.to_owned(),
                occurrence: occurrence.to_owned(),
            },
            |value: &AcquisitionHistoryV1| value.validate_for_occurrence(campaign, occurrence),
        )
    }

    fn maude_objective_read(&self) -> SourceResultV1<MaudeObjectiveReadV1> {
        let Some(_) = self
            .canonical_config()
            .ok()
            .and_then(|value| value.maude_objective.as_ref())
        else {
            return unavailable(
                "Maude",
                ReadCommandNameV1::MaudeObjectiveRead,
                SourceErrorKindV1::NotConfigured,
                "Maude objective source is not configured".to_owned(),
                None,
            );
        };
        self.capture_typed(
            "Maude",
            &CanonicalReadRequestV1::MaudeObjectiveRead,
            validate_maude_objective_read,
        )
    }

    fn objective_owner_projection(&self) -> SourceResultV1<ObjectiveOwnerProjectionV1> {
        let Some(source) = self
            .canonical_config()
            .ok()
            .and_then(|value| value.objective_owner_projection.as_ref())
        else {
            return unavailable(
                "application objective owner",
                ReadCommandNameV1::ObjectiveOwnerProjection,
                SourceErrorKindV1::NotConfigured,
                "objective owner projection source is not configured".to_owned(),
                None,
            );
        };
        self.capture_typed(
            "application objective owner",
            &CanonicalReadRequestV1::ObjectiveOwnerProjection,
            |value| validate_objective_owner_projection(value, source),
        )
    }

    fn capture_typed<T>(
        &self,
        source: &str,
        request: &CanonicalReadRequestV1,
        validate: impl FnOnce(&T) -> Result<(), String>,
    ) -> SourceResultV1<T>
    where
        T: DeserializeOwned,
    {
        let command = request.name();
        match self.capture_json(request) {
            Ok(captured) => {
                let typed = match serde_json::from_value::<T>(captured.raw.clone()) {
                    Ok(value) => value,
                    Err(error) => {
                        return unavailable_at(
                            source,
                            command,
                            captured.captured_at_unix_ms,
                            SourceErrorKindV1::MalformedOutput,
                            format!("typed canonical output refused: {error}"),
                            None,
                        );
                    }
                };
                if let Err(error) = validate(&typed) {
                    return unavailable_at(
                        source,
                        command,
                        captured.captured_at_unix_ms,
                        SourceErrorKindV1::IncompatibleSchema,
                        error,
                        None,
                    );
                }
                SourceResultV1::Available {
                    source: source.to_owned(),
                    command,
                    captured_at_unix_ms: captured.captured_at_unix_ms,
                    value: typed,
                    raw: captured.raw,
                }
            }
            Err(error) => unavailable(source, command, error.kind, error.detail, error.exit_status),
        }
    }

    fn capture_json(
        &self,
        request: &CanonicalReadRequestV1,
    ) -> Result<CapturedJsonV1, CaptureFailureV1> {
        let config = self.canonical_config().map_err(|detail| CaptureFailureV1 {
            kind: SourceErrorKindV1::Unavailable,
            detail,
            exit_status: None,
        })?;
        let mut command = canonical_command(config, request)?;
        let bytes = run_bounded(&mut command)?;
        let captured_at_unix_ms = capture_time();
        let mut deserializer = serde_json::Deserializer::from_slice(&bytes);
        let raw = Value::deserialize(&mut deserializer).map_err(|error| CaptureFailureV1 {
            kind: SourceErrorKindV1::MalformedOutput,
            detail: format!("canonical command output is not JSON: {error}"),
            exit_status: Some(0),
        })?;
        deserializer.end().map_err(|error| CaptureFailureV1 {
            kind: SourceErrorKindV1::MalformedOutput,
            detail: format!("canonical command output has trailing data: {error}"),
            exit_status: Some(0),
        })?;
        Ok(CapturedJsonV1 {
            captured_at_unix_ms,
            raw,
        })
    }

    fn canonical_config(&self) -> Result<&OperatorSourceConfigV1, String> {
        match &self.backend {
            OperatorReaderBackendV1::Canonical(config) => Ok(config.as_ref()),
            OperatorReaderBackendV1::Demo(_) => {
                Err("demo corpus has no executable canonical source".to_owned())
            }
        }
    }
}

fn read_bounded_public_projection(path: &Path) -> Result<Vec<u8>, String> {
    // Linux O_NOFOLLOW. The service is Linux-only and this protects the final
    // component while the descriptor, not the pathname, is checked and read.
    const O_NOFOLLOW: i32 = 0o400_000;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("public objective projection unavailable: {error}"))?;
    let before = file
        .metadata()
        .map_err(|error| format!("stat public objective projection: {error}"))?;
    if !before.is_file() || before.len() > MAX_DEMO_CORPUS_BYTES {
        return Err("public objective projection is not a bounded regular file".to_owned());
    }
    let mut bytes = Vec::with_capacity(usize::try_from(before.len()).unwrap_or(0));
    file.by_ref()
        .take(MAX_DEMO_CORPUS_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read public objective projection: {error}"))?;
    let after = file
        .metadata()
        .map_err(|error| format!("restat public objective projection: {error}"))?;
    if bytes.len() as u64 > MAX_DEMO_CORPUS_BYTES
        || before.len() != after.len()
        || before.modified().ok() != after.modified().ok()
    {
        return Err("public objective projection changed during bounded read".to_owned());
    }
    Ok(bytes)
}

fn canonical_command(
    config: &OperatorSourceConfigV1,
    request: &CanonicalReadRequestV1,
) -> Result<Command, CaptureFailureV1> {
    let command = match request {
        CanonicalReadRequestV1::AgInspect(database)
        | CanonicalReadRequestV1::AgStatus(database)
        | CanonicalReadRequestV1::AgReplay(database)
        | CanonicalReadRequestV1::AgHistory(database)
        | CanonicalReadRequestV1::AgRefusals(database)
        | CanonicalReadRequestV1::AgInterventionSubmissions(database) => {
            let verb = match request {
                CanonicalReadRequestV1::AgInspect(_) => "inspect",
                CanonicalReadRequestV1::AgStatus(_) => "status",
                CanonicalReadRequestV1::AgReplay(_) => "replay",
                CanonicalReadRequestV1::AgHistory(_) => "history",
                CanonicalReadRequestV1::AgRefusals(_) => "refusals",
                CanonicalReadRequestV1::AgInterventionSubmissions(_) => "intervention-submissions",
                _ => unreachable!(),
            };
            let mut command = Command::new(&config.ag_loopctl);
            command.args([verb, "--database"]).arg(database);
            command
        }
        CanonicalReadRequestV1::NightshiftExportObservation(observation) => {
            let source = require_nightshift_source(config)?;
            let mut command = Command::new(&source.program);
            command.args(["--store"]).arg(&source.store).args([
                "cycle",
                "export-observation",
                "--observation-id",
                observation,
            ]);
            command
        }
        CanonicalReadRequestV1::NightshiftExportAuthoringContext {
            campaign,
            occurrence,
        }
        | CanonicalReadRequestV1::NightshiftExportAuthoringCustody {
            campaign,
            occurrence,
        } => {
            let source = require_nightshift_source(config)?;
            let verb = match request {
                CanonicalReadRequestV1::NightshiftExportAuthoringContext { .. } => {
                    "export-authoring-context"
                }
                CanonicalReadRequestV1::NightshiftExportAuthoringCustody { .. } => {
                    "export-authoring-custody"
                }
                _ => unreachable!(),
            };
            let mut command = Command::new(&source.program);
            command.args(["--store"]).arg(&source.store).args([
                "cycle",
                verb,
                "--campaign-id",
                campaign,
                "--occurrence-id",
                occurrence,
            ]);
            command
        }
        CanonicalReadRequestV1::NightshiftExportExternalObservation {
            campaign,
            occurrence,
            evaluated_at_unix_ms,
            evidence_ttl_ms,
        } => {
            let source = require_nightshift_source(config)?;
            let mut command = Command::new(&source.program);
            let evaluated_at_unix_ms = evaluated_at_unix_ms.to_string();
            let evidence_ttl_ms = evidence_ttl_ms.to_string();
            command.args(["--store"]).arg(&source.store).args([
                "external-observation",
                "export",
                "--campaign-id",
                campaign,
                "--occurrence-id",
                occurrence,
                "--evaluated-at-unix-ms",
                &evaluated_at_unix_ms,
                "--evidence-ttl-ms",
                &evidence_ttl_ms,
            ]);
            command
        }
        CanonicalReadRequestV1::DocketInspect(issuance) => docket_command(config, issuance)?,
        CanonicalReadRequestV1::MaudeExportObservationAcquisitions {
            campaign,
            occurrence,
        } => maude_acquisition_command(config, campaign, occurrence)?,
        CanonicalReadRequestV1::MaudeObjectiveRead => maude_objective_command(config)?,
        CanonicalReadRequestV1::ObjectiveOwnerProjection => {
            objective_owner_projection_command(config)?
        }
    };
    Ok(command)
}

fn docket_command(
    config: &OperatorSourceConfigV1,
    issuance: &str,
) -> Result<Command, CaptureFailureV1> {
    let source = config.docket.as_ref().ok_or_else(|| CaptureFailureV1 {
        kind: SourceErrorKindV1::NotConfigured,
        detail: "Docket source is not configured".to_owned(),
        exit_status: None,
    })?;
    let mut command = Command::new(&source.program);
    command
        .args(["governed-loop", "inspect", "--state"])
        .arg(&source.state)
        .args(["--issuance", issuance]);
    Ok(command)
}

fn maude_acquisition_command(
    config: &OperatorSourceConfigV1,
    campaign: &str,
    occurrence: &str,
) -> Result<Command, CaptureFailureV1> {
    let source = config
        .maude_acquisition
        .as_ref()
        .ok_or_else(|| CaptureFailureV1 {
            kind: SourceErrorKindV1::NotConfigured,
            detail: "Maude acquisition source is not configured".to_owned(),
            exit_status: None,
        })?;
    let mut command = Command::new(&source.program);
    command
        .args(["export-occurrence", "--ledger"])
        .arg(&source.ledger)
        .args(["--campaign-id", campaign, "--occurrence-id", occurrence]);
    Ok(command)
}

fn maude_objective_command(config: &OperatorSourceConfigV1) -> Result<Command, CaptureFailureV1> {
    let source = config
        .maude_objective
        .as_ref()
        .ok_or_else(|| CaptureFailureV1 {
            kind: SourceErrorKindV1::NotConfigured,
            detail: "Maude objective source is not configured".to_owned(),
            exit_status: None,
        })?;
    let mut command = Command::new(&source.program);
    command
        .args(["objective-read", "--plan"])
        .arg(&source.plan)
        .args(["--expected-plan-digest", &source.expected_plan_digest]);
    Ok(command)
}

fn objective_owner_projection_command(
    config: &OperatorSourceConfigV1,
) -> Result<Command, CaptureFailureV1> {
    let source = config
        .objective_owner_projection
        .as_ref()
        .ok_or_else(|| CaptureFailureV1 {
            kind: SourceErrorKindV1::NotConfigured,
            detail: "objective owner source is not configured".to_owned(),
            exit_status: None,
        })?;
    let mut command = Command::new(&source.program);
    command.arg("--config").arg(&source.config).args([
        "objective-projection",
        "--plan-digest",
        &source.expected_plan_digest,
    ]);
    Ok(command)
}

fn require_nightshift_source(
    config: &OperatorSourceConfigV1,
) -> Result<&NightshiftReadSourceV1, CaptureFailureV1> {
    config.nightshift.as_ref().ok_or_else(|| CaptureFailureV1 {
        kind: SourceErrorKindV1::NotConfigured,
        detail: "Nightshift source is not configured".to_owned(),
        exit_status: None,
    })
}

fn validate_demo_corpus(corpus: &DemoCorpusV1) -> Result<(), String> {
    if corpus.schema != DEMO_CORPUS_SCHEMA_V1
        || corpus.index.schema != CAMPAIGN_INDEX_SCHEMA_V1
        || corpus.campaigns.len() > MAX_DEMO_CAMPAIGNS
    {
        return Err("unsupported or oversized demo corpus".to_owned());
    }
    let details = corpus
        .campaigns
        .iter()
        .map(|detail| (detail.locator_token.as_str(), detail))
        .collect::<BTreeMap<_, _>>();
    if details.len() != corpus.campaigns.len()
        || details.len() != corpus.index.campaigns.len()
        || corpus.index.campaigns.iter().any(|entry| {
            details
                .get(entry.locator_token.as_str())
                .is_none_or(|detail| detail.locator != entry.locator)
        })
    {
        return Err("demo corpus index/detail locator binding mismatch".to_owned());
    }
    for detail in &corpus.campaigns {
        validate_demo_detail(detail)?;
    }
    let mut objective_plan_digests = BTreeSet::new();
    for objective in &corpus.objectives {
        validate_objective_detail(objective)?;
        if !objective_plan_digests.insert(objective.objective.plan_digest.as_deref()) {
            return Err("duplicate demo objective plan digest".to_owned());
        }
        if objective
            .occurrences
            .iter()
            .any(|link| !demo_objective_link_has_lineage(link, &corpus.campaigns))
        {
            return Err("demo objective link lacks matching Nightshift owner lineage".to_owned());
        }
    }
    let mut semantic_keys = BTreeSet::new();
    for target in &corpus.semantic_link_targets {
        let key = (
            target.campaign.as_str().to_owned(),
            target.occurrence.to_string(),
            target
                .proposal
                .as_ref()
                .map(|proposal| proposal.as_str().to_owned()),
        );
        if !semantic_keys.insert(key) {
            return Err("duplicate demo semantic link target".to_owned());
        }
        let detail = details
            .get(target.locator_token.as_str())
            .ok_or_else(|| "demo semantic link target names an unknown locator".to_owned())?;
        let link = GovernedRuntimeLinkV1 {
            campaign: target.campaign.as_digest().clone(),
            occurrence: target.occurrence,
            proposal: target
                .proposal
                .as_ref()
                .map(|proposal| proposal.as_digest().clone()),
        };
        if !detail_matches_link(detail, &link) {
            return Err("demo semantic link target does not bind its exact identities".to_owned());
        }
    }
    Ok(())
}

fn bind_owner_projection_to_objective(
    result: SourceResultV1<ObjectiveOwnerProjectionV1>,
    objective: &MaudeObjectiveReadV1,
) -> SourceResultV1<ObjectiveOwnerProjectionV1> {
    let SourceResultV1::Available {
        source,
        command,
        captured_at_unix_ms,
        raw,
        value,
    } = result
    else {
        return result;
    };
    let criteria = objective
        .acceptance_criteria
        .as_ref()
        .into_iter()
        .flatten()
        .map(|criterion| criterion.condition_id.as_str())
        .collect::<BTreeSet<_>>();
    let exact_plan = objective.plan_digest.as_ref() == Some(&value.plan_digest);
    let exact_conditions = value
        .conditions
        .iter()
        .all(|condition| criteria.contains(condition.condition_id.as_str()));
    if !exact_plan || !exact_conditions {
        return unavailable_at(
            &source,
            command,
            captured_at_unix_ms,
            SourceErrorKindV1::IncompatibleSchema,
            "application-owner projection is outside the exact authored objective".to_owned(),
            None,
        );
    }
    SourceResultV1::Available {
        source,
        command,
        captured_at_unix_ms,
        raw,
        value,
    }
}

fn demo_objective_link_has_lineage(
    link: &ObjectiveOccurrenceLinkV1,
    campaigns: &[CampaignDetailV1],
) -> bool {
    campaigns.iter().any(|detail| {
        let Some(inspect) = detail.inspect.value() else {
            return false;
        };
        let snapshot = if inspect.current.key().occurrence.to_string() == link.occurrence_id {
            Some(&inspect.current)
        } else {
            detail.history.value().and_then(|history| {
                history
                    .transitions
                    .iter()
                    .rev()
                    .map(|transition| &transition.successor)
                    .find(|snapshot| snapshot.key().occurrence.to_string() == link.occurrence_id)
            })
        };
        link.detail_locator_token.as_deref() == Some(detail.locator_token.as_str())
            && snapshot.is_some_and(|snapshot| {
                snapshot.key().campaign.to_string() == link.campaign_id
                    && snapshot.proposal().is_some_and(|proposal| {
                        proposal.reference().as_digest().to_string() == link.proposal_id
                    })
            })
            && detail.authoring_contexts.iter().any(|related| {
                related.result.value().is_some_and(|export| {
                    export.matches.iter().any(|relation| {
                        relation.campaign_id == link.campaign_id
                            && relation.occurrence_id == link.occurrence_id
                            && relation.proposal_id == link.proposal_id
                            && relation.exact_work_id == link.exact_work_id
                            && relation.maude_plan_ref == link.maude_plan_ref
                    })
                })
            })
    })
}

/// Assembles exact objective-to-occurrence links from Maude's operator-authored plan
/// digest and Nightshift's already-validated authoring lineage. It accepts no
/// timestamp, label, filename, or summary as a join key. Both current and
/// retained historical snapshots are considered by exact identity.
#[must_use]
pub fn assemble_objective_detail(
    objective: MaudeObjectiveReadV1,
    campaigns: &[CampaignDetailV1],
    mut causal_unavailable: Vec<ObjectiveCausalUnavailableV1>,
    owner_projection: Option<SourceResultV1<ObjectiveOwnerProjectionV1>>,
) -> ObjectiveDetailV1 {
    let detail_schema = if owner_projection.is_some() {
        OBJECTIVE_DETAIL_SCHEMA_V2
    } else {
        OBJECTIVE_DETAIL_SCHEMA_V1
    };
    let plan_digest = objective.plan_digest.clone();
    if objective.availability != MaudeObjectiveAvailabilityV1::Available {
        return ObjectiveDetailV1 {
            schema: OBJECTIVE_DETAIL_SCHEMA_V1.to_owned(),
            objective,
            conditions: Vec::new(),
            occurrences: Vec::new(),
            causal_unavailable,
            prerequisites: ObjectivePrerequisitesV1::Unknown,
            owner_projection: None,
        };
    }
    let Some(plan_digest) = plan_digest else {
        return ObjectiveDetailV1 {
            schema: OBJECTIVE_DETAIL_SCHEMA_V1.to_owned(),
            objective,
            conditions: Vec::new(),
            occurrences: Vec::new(),
            causal_unavailable,
            prerequisites: ObjectivePrerequisitesV1::Unknown,
            owner_projection: None,
        };
    };
    let occurrences = assemble_objective_links(&plan_digest, campaigns, &mut causal_unavailable);
    let mut conditions = objective
        .acceptance_criteria
        .as_ref()
        .into_iter()
        .flatten()
        .map(|criterion| ObjectiveConditionV1 {
            condition_id: criterion.condition_id.clone(),
            criterion: criterion.text.clone(),
            disposition: ObjectiveConditionDispositionV1::Unknown,
            owner_record_ref: None,
            owner_record_digest: None,
            evidence: Vec::new(),
            reason: None,
        })
        .collect::<Vec<_>>();
    let prerequisites = apply_owner_projection(&mut conditions, owner_projection.as_ref());
    ObjectiveDetailV1 {
        schema: detail_schema.to_owned(),
        conditions,
        objective,
        occurrences,
        causal_unavailable,
        prerequisites,
        owner_projection,
    }
}

fn assemble_objective_links(
    plan_digest: &str,
    campaigns: &[CampaignDetailV1],
    causal_unavailable: &mut Vec<ObjectiveCausalUnavailableV1>,
) -> Vec<ObjectiveOccurrenceLinkV1> {
    let mut links = BTreeMap::new();
    for detail in campaigns {
        let Some(inspect) = detail.inspect.value() else {
            causal_unavailable.push(ObjectiveCausalUnavailableV1 {
                locator_token: detail.locator_token.clone(),
                detail: "AG inspection source unavailable for causal join".to_owned(),
            });
            continue;
        };
        for related in &detail.authoring_contexts {
            let Some(export) = related.result.value() else {
                causal_unavailable.push(ObjectiveCausalUnavailableV1 {
                    locator_token: detail.locator_token.clone(),
                    detail: "Nightshift authoring lineage source unavailable for causal join"
                        .to_owned(),
                });
                continue;
            };
            for relation in &export.matches {
                let snapshot =
                    if inspect.current.key().occurrence.to_string() == relation.occurrence_id {
                        Some(&inspect.current)
                    } else {
                        detail.history.value().and_then(|history| {
                            history
                                .transitions
                                .iter()
                                .rev()
                                .map(|transition| &transition.successor)
                                .find(|snapshot| {
                                    snapshot.key().occurrence.to_string() == relation.occurrence_id
                                })
                        })
                    };
                let Some(snapshot) = snapshot else {
                    if !detail.history.is_available() {
                        causal_unavailable.push(ObjectiveCausalUnavailableV1 {
                            locator_token: detail.locator_token.clone(),
                            detail: "AG retained history unavailable for historical causal join"
                                .to_owned(),
                        });
                    }
                    continue;
                };
                if relation.maude_plan_ref != plan_digest
                    || snapshot.key().campaign.to_string() != relation.campaign_id
                    || snapshot.proposal().is_none_or(|proposal| {
                        proposal.reference().as_digest().to_string() != relation.proposal_id
                    })
                {
                    continue;
                }
                let key = (
                    relation.campaign_id.clone(),
                    relation.occurrence_id.clone(),
                    relation.proposal_id.clone(),
                    relation.exact_work_id.clone(),
                    relation.maude_plan_ref.clone(),
                    detail.locator_token.clone(),
                );
                links.entry(key).or_insert_with(|| detail.clone());
            }
        }
    }
    links
        .into_iter()
        .map(
            |(
                (campaign_id, occurrence_id, proposal_id, exact_work_id, maude_plan_ref, token),
                detail,
            )| ObjectiveOccurrenceLinkV1 {
                campaign_id,
                occurrence_id,
                proposal_id,
                exact_work_id,
                maude_plan_ref,
                detail_locator_token: Some(token),
                detail: Some(detail),
            },
        )
        .collect()
}

fn apply_owner_projection(
    conditions: &mut [ObjectiveConditionV1],
    owner_projection: Option<&SourceResultV1<ObjectiveOwnerProjectionV1>>,
) -> ObjectivePrerequisitesV1 {
    let mut prerequisites = ObjectivePrerequisitesV1::Unknown;
    if let Some(SourceResultV1::Available { value, .. }) = owner_projection {
        for assessment in &value.conditions {
            if let Some(condition) = conditions
                .iter_mut()
                .find(|item| item.condition_id == assessment.condition_id)
            {
                condition.disposition = assessment.assessment;
                condition
                    .owner_record_ref
                    .clone_from(&assessment.owner_record_ref);
                condition
                    .owner_record_digest
                    .clone_from(&assessment.owner_record_digest);
                condition.evidence.clone_from(&assessment.evidence);
                condition.reason.clone_from(&assessment.reason);
            }
        }
        prerequisites = match value.prerequisites.availability {
            ObjectivePrerequisiteAvailabilityV1::Available => {
                ObjectivePrerequisitesV1::OwnerDeclared {
                    coverage: value.prerequisites.coverage.clone().unwrap_or_default(),
                    items: value.prerequisites.items.clone(),
                }
            }
            ObjectivePrerequisiteAvailabilityV1::Unavailable => {
                ObjectivePrerequisitesV1::Unavailable
            }
        };
    } else if matches!(owner_projection, Some(SourceResultV1::Unavailable { .. })) {
        prerequisites = ObjectivePrerequisitesV1::Unavailable;
    }
    prerequisites
}

fn validate_objective_detail(detail: &ObjectiveDetailV1) -> Result<(), String> {
    validate_objective_detail_header(detail)?;
    let objective = &detail.objective;
    let criteria = objective
        .acceptance_criteria
        .as_ref()
        .map(|criteria| {
            criteria
                .iter()
                .map(|criterion| (criterion.condition_id.as_str(), criterion.text.as_str()))
                .collect::<BTreeMap<_, _>>()
        })
        .unwrap_or_default();
    validate_objective_detail_bindings(detail, &criteria)?;
    for link in &detail.occurrences {
        if link.campaign_id.is_empty()
            || link.occurrence_id.is_empty()
            || link.proposal_id.is_empty()
            || link.exact_work_id.is_empty()
            || objective.plan_digest.as_ref() != Some(&link.maude_plan_ref)
        {
            return Err("objective occurrence link lacks an exact matching lineage".to_owned());
        }
    }
    Ok(())
}

fn validate_objective_detail_header(detail: &ObjectiveDetailV1) -> Result<(), String> {
    let enriched = detail.schema == OBJECTIVE_DETAIL_SCHEMA_V2;
    if detail.schema != OBJECTIVE_DETAIL_SCHEMA_V1 && !enriched {
        return Err("unsupported objective-detail schema".to_owned());
    }
    if enriched != detail.owner_projection.is_some() {
        return Err("objective-detail schema does not match owner projection presence".to_owned());
    }
    if !enriched
        && (detail.conditions.iter().any(|condition| {
            condition.disposition != ObjectiveConditionDispositionV1::Unknown
                || condition.owner_record_ref.is_some()
                || condition.owner_record_digest.is_some()
                || !condition.evidence.is_empty()
                || condition.reason.is_some()
        }) || detail.prerequisites != ObjectivePrerequisitesV1::Unknown)
    {
        return Err("objective-detail/v1 cannot carry application-owner assertions".to_owned());
    }
    let objective = &detail.objective;
    if objective.schema != MAUDE_OBJECTIVE_READ_SCHEMA_V1 || objective.source != "maude" {
        return Err("unsupported Maude objective-read schema".to_owned());
    }
    if objective.publication != "operator_only" {
        return Err("objective owner result is missing its read boundary".to_owned());
    }
    let available = objective.availability == MaudeObjectiveAvailabilityV1::Available;
    if available
        != (objective.plan_schema.as_deref() == Some("maude.plan-document/v1")
            && objective
                .plan_digest
                .as_ref()
                .is_some_and(|value| is_sha256_digest(value))
            && objective
                .goal
                .as_ref()
                .is_some_and(|value| !value.is_empty())
            && objective.acceptance_criteria.is_some()
            && objective.error_code.is_none())
    {
        return Err("objective availability and authored material disagree".to_owned());
    }
    if !available
        && (objective.plan_schema.as_deref() != Some("maude.plan-document/v1")
            || objective
                .plan_digest
                .as_ref()
                .is_none_or(|value| !is_sha256_digest(value))
            || objective.goal.is_some()
            || objective.acceptance_criteria.is_some()
            || objective.error_code.as_ref().is_none_or(String::is_empty))
    {
        return Err(
            "unavailable objective exposed authored material or lacks an error code".to_owned(),
        );
    }
    Ok(())
}

fn validate_objective_detail_bindings(
    detail: &ObjectiveDetailV1,
    criteria: &BTreeMap<&str, &str>,
) -> Result<(), String> {
    let objective = &detail.objective;
    let owner = detail
        .owner_projection
        .as_ref()
        .and_then(SourceResultV1::value);
    if let Some(projection) = owner {
        validate_objective_owner_projection_shape(projection)?;
    }
    if owner.is_some_and(|projection| {
        objective.plan_digest.as_ref() != Some(&projection.plan_digest)
            || projection
                .conditions
                .iter()
                .any(|assessment| !criteria.contains_key(assessment.condition_id.as_str()))
    }) {
        return Err("application owner projection is outside the authored objective".to_owned());
    }
    let mut condition_ids = BTreeSet::new();
    for condition in &detail.conditions {
        if condition.condition_id.is_empty()
            || criteria.get(condition.condition_id.as_str()) != Some(&condition.criterion.as_str())
            || !condition_ids.insert(condition.condition_id.as_str())
        {
            return Err("objective condition is outside the approved public contract".to_owned());
        }
        let assessment = owner.and_then(|projection| {
            projection
                .conditions
                .iter()
                .find(|assessment| assessment.condition_id == condition.condition_id)
        });
        match assessment {
            Some(assessment)
                if assessment.assessment == condition.disposition
                    && assessment.owner_record_ref == condition.owner_record_ref
                    && assessment.owner_record_digest == condition.owner_record_digest
                    && serde_jcs::to_vec(&assessment.evidence).ok()
                        == serde_jcs::to_vec(&condition.evidence).ok()
                    && assessment.reason == condition.reason => {}
            None if condition.disposition == ObjectiveConditionDispositionV1::Unknown
                && condition.owner_record_ref.is_none()
                && condition.owner_record_digest.is_none()
                && condition.evidence.is_empty()
                && condition.reason.is_none() => {}
            _ => {
                return Err(
                    "objective condition differs from its application-owner assertion".to_owned(),
                );
            }
        }
    }
    match (&detail.owner_projection, &detail.prerequisites) {
        (None, ObjectivePrerequisitesV1::Unknown)
        | (Some(SourceResultV1::Unavailable { .. }), ObjectivePrerequisitesV1::Unavailable) => {}
        (
            Some(SourceResultV1::Available { value, .. }),
            ObjectivePrerequisitesV1::OwnerDeclared { coverage, items },
        ) if value.prerequisites.availability == ObjectivePrerequisiteAvailabilityV1::Available
            && value.prerequisites.coverage.as_ref() == Some(coverage)
            && serde_jcs::to_vec(&value.prerequisites.items).ok()
                == serde_jcs::to_vec(items).ok() => {}
        (Some(SourceResultV1::Available { value, .. }), ObjectivePrerequisitesV1::Unavailable)
            if value.prerequisites.availability
                == ObjectivePrerequisiteAvailabilityV1::Unavailable => {}
        _ => {
            return Err(
                "objective prerequisites differ from the application-owner source".to_owned(),
            );
        }
    }
    Ok(())
}

fn validate_objective_owner_projection(
    value: &ObjectiveOwnerProjectionV1,
    expected: &ObjectiveOwnerProjectionSourceV1,
) -> Result<(), String> {
    validate_objective_owner_projection_shape(value)?;
    if value.plan_digest != expected.expected_plan_digest
        || value.owner_id != expected.expected_owner_id
        || value.owner_capability != expected.expected_owner_capability
        || value.owner_source_revision != expected.expected_source_revision
    {
        return Err("objective owner projection does not match its declared enrollment".to_owned());
    }
    Ok(())
}

fn validate_objective_owner_projection_shape(
    value: &ObjectiveOwnerProjectionV1,
) -> Result<(), String> {
    if value.schema != OBJECTIVE_OWNER_PROJECTION_SCHEMA_V1
        || !is_sha256_digest(&value.plan_digest)
        || value.owner_id.is_empty()
        || value.owner_capability.is_empty()
        || value.owner_source_revision.is_empty()
        || value.authority != "none"
        || !is_rfc3339_timestamp(&value.projected_at)
    {
        return Err("objective owner projection shape is invalid".to_owned());
    }
    let mut identity_material = value.clone();
    identity_material.projection_id.clear();
    let bytes = serde_jcs::to_vec(&identity_material)
        .map_err(|error| format!("canonicalize objective owner projection: {error}"))?;
    if value.projection_id != format!("sha256:{:x}", Sha256::digest(bytes)) {
        return Err("objective owner projection identity mismatch".to_owned());
    }
    validate_owner_conditions(&value.conditions)?;
    validate_owner_prerequisites(&value.prerequisites)
}

fn validate_owner_conditions(
    conditions: &[crate::model::ObjectiveOwnerConditionV1],
) -> Result<(), String> {
    let mut condition_ids = BTreeSet::new();
    for condition in conditions {
        if condition.condition_id.is_empty() || !condition_ids.insert(&condition.condition_id) {
            return Err("objective owner projection has an invalid condition identity".to_owned());
        }
        let paired = condition.owner_record_ref.as_ref().is_some()
            == condition.owner_record_digest.as_ref().is_some();
        if !paired
            || condition
                .owner_record_digest
                .as_ref()
                .is_some_and(|digest| !is_sha256_digest(digest))
            || condition.reason.as_ref().is_some_and(String::is_empty)
        {
            return Err("objective owner assessment record binding is invalid".to_owned());
        }
        match condition.assessment {
            ObjectiveConditionDispositionV1::Satisfied
            | ObjectiveConditionDispositionV1::NotSatisfied => {
                if condition
                    .owner_record_ref
                    .as_ref()
                    .is_none_or(String::is_empty)
                    || condition.evidence.is_empty()
                    || condition.evidence.iter().any(|evidence| {
                        evidence.source_currentness != ObjectiveEvidenceCurrentnessV1::Fresh
                    })
                    || condition.reason.is_some()
                {
                    return Err(
                        "decisive application assessment lacks exact fresh evidence".to_owned()
                    );
                }
            }
            ObjectiveConditionDispositionV1::Indeterminate => {
                if condition.reason.as_ref().is_none_or(String::is_empty) {
                    return Err("indeterminate application assessment lacks a reason".to_owned());
                }
            }
            ObjectiveConditionDispositionV1::Unavailable => {
                if condition.owner_record_ref.is_some()
                    || !condition.evidence.is_empty()
                    || condition.reason.as_ref().is_none_or(String::is_empty)
                {
                    return Err(
                        "unavailable application assessment carries contradictory custody"
                            .to_owned(),
                    );
                }
            }
            ObjectiveConditionDispositionV1::OwnerAttested
            | ObjectiveConditionDispositionV1::Unknown => {
                return Err(
                    "legacy or unknown disposition is not an owner projection assessment"
                        .to_owned(),
                );
            }
        }
        for evidence in &condition.evidence {
            if evidence.owner_schema.is_empty()
                || evidence.owner_record_id.is_empty()
                || !is_sha256_digest(&evidence.owner_record_digest)
                || condition.owner_record_ref.as_ref() != Some(&evidence.owner_record_id)
                || condition.owner_record_digest.as_ref() != Some(&evidence.owner_record_digest)
            {
                return Err("application assessment evidence identity is invalid".to_owned());
            }
            for label in [&evidence.owner_outcome, &evidence.maintenance_annotation]
                .into_iter()
                .flatten()
            {
                if label.is_empty()
                    || label.len() > 128
                    || !label.bytes().all(|byte| byte.is_ascii_graphic())
                {
                    return Err("application assessment evidence label is invalid".to_owned());
                }
            }
            for timestamp in [
                &evidence.source_observed_at,
                &evidence.read_attempted_at,
                &evidence.projected_at,
            ]
            .into_iter()
            .flatten()
            {
                if !is_rfc3339_timestamp(timestamp) {
                    return Err("application assessment evidence timestamp is invalid".to_owned());
                }
            }
        }
    }
    Ok(())
}

fn validate_owner_prerequisites(
    prerequisites: &crate::model::ObjectiveOwnerPrerequisitesV1,
) -> Result<(), String> {
    match prerequisites.availability {
        ObjectivePrerequisiteAvailabilityV1::Available => {
            if prerequisites.coverage.as_deref() != Some("owner_asserted_complete")
                || prerequisites.reason.is_some()
            {
                return Err(
                    "available prerequisite projection lacks explicit owner coverage".to_owned(),
                );
            }
        }
        ObjectivePrerequisiteAvailabilityV1::Unavailable => {
            if prerequisites.coverage.is_some()
                || !prerequisites.items.is_empty()
                || prerequisites.reason.as_ref().is_none_or(String::is_empty)
            {
                return Err("unavailable prerequisite projection is contradictory".to_owned());
            }
        }
    }
    let mut prerequisite_ids = BTreeSet::new();
    for item in &prerequisites.items {
        if item.prerequisite_id.is_empty()
            || item.relation.is_empty()
            || item.owner_record_ref.is_empty()
            || !is_sha256_digest(&item.owner_record_digest)
            || !prerequisite_ids.insert(&item.prerequisite_id)
        {
            return Err("application prerequisite identity is invalid".to_owned());
        }
    }
    Ok(())
}

fn validate_maude_objective_read(objective: &MaudeObjectiveReadV1) -> Result<(), String> {
    if objective.schema != MAUDE_OBJECTIVE_READ_SCHEMA_V1
        || objective.source != "maude"
        || objective.publication != "operator_only"
    {
        return Err("unsupported Maude objective source boundary".to_owned());
    }
    let available = objective.availability == MaudeObjectiveAvailabilityV1::Available;
    if available
        != (objective.plan_schema.as_deref() == Some("maude.plan-document/v1")
            && objective
                .plan_digest
                .as_ref()
                .is_some_and(|value| is_sha256_digest(value))
            && objective
                .goal
                .as_ref()
                .is_some_and(|value| !value.is_empty())
            && objective.acceptance_criteria.is_some()
            && objective.error_code.is_none())
    {
        return Err("Maude objective availability and authored material disagree".to_owned());
    }
    if !available
        && (objective.plan_schema.as_deref() != Some("maude.plan-document/v1")
            || objective
                .plan_digest
                .as_ref()
                .is_none_or(|value| !is_sha256_digest(value))
            || objective.goal.is_some()
            || objective.acceptance_criteria.is_some()
            || objective.error_code.as_ref().is_none_or(String::is_empty))
    {
        return Err("unavailable Maude objective exposed authored material".to_owned());
    }
    if let Some(criteria) = &objective.acceptance_criteria {
        let mut ids = BTreeSet::new();
        if criteria.iter().any(|criterion| {
            criterion.condition_id.is_empty()
                || criterion.text.is_empty()
                || !ids.insert(criterion.condition_id.as_str())
        }) {
            return Err("Maude objective criteria are not a unique nonempty set".to_owned());
        }
    }
    Ok(())
}

fn validate_public_objective_projection(
    projection: &PublicObjectiveProjectionV1,
) -> Result<(), String> {
    if projection.schema != PUBLIC_OBJECTIVE_PROJECTION_SCHEMA_V1
        || !is_sha256_digest(&projection.plan_digest)
        || projection.approved_summary.is_empty()
        || projection.approved_summary.len() > 8 * 1024
        || ["/data/", "/tmp/", "file://", ".sqlite"]
            .iter()
            .any(|marker| projection.approved_summary.contains(marker))
        || projection
            .approved_receipt_urls
            .iter()
            .any(|url| !url.starts_with("https://") || url.len() > 2 * 1024 || url.contains('\n'))
    {
        return Err(
            "public objective projection is outside the explicit allowlist contract".to_owned(),
        );
    }
    Ok(())
}

fn is_sha256_digest(value: &str) -> bool {
    value.len() == "sha256:".len() + 64
        && value
            .strip_prefix("sha256:")
            .is_some_and(|suffix| suffix.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn is_rfc3339_timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 20
        || bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || bytes.get(10) != Some(&b'T')
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
    {
        return false;
    }
    let number = |start: usize, end: usize| {
        bytes
            .get(start..end)
            .filter(|part| part.iter().all(u8::is_ascii_digit))
            .and_then(|part| std::str::from_utf8(part).ok())
            .and_then(|part| part.parse::<u32>().ok())
    };
    let (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) = (
        number(0, 4),
        number(5, 7),
        number(8, 10),
        number(11, 13),
        number(14, 16),
        number(17, 19),
    ) else {
        return false;
    };
    if year == 0 {
        return false;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    if day == 0 || day > days || hour > 23 || minute > 59 || second > 60 {
        return false;
    }
    let mut cursor = 19;
    if bytes.get(cursor) == Some(&b'.') {
        cursor += 1;
        let start = cursor;
        while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
            cursor += 1;
        }
        if cursor == start {
            return false;
        }
    }
    match bytes.get(cursor..) {
        Some(b"Z") => true,
        Some(zone)
            if zone.len() == 6
                && matches!(zone[0], b'+' | b'-')
                && zone[3] == b':'
                && zone[1..3].iter().all(u8::is_ascii_digit)
                && zone[4..6].iter().all(u8::is_ascii_digit) =>
        {
            let hours = u32::from(zone[1] - b'0') * 10 + u32::from(zone[2] - b'0');
            let minutes = u32::from(zone[4] - b'0') * 10 + u32::from(zone[5] - b'0');
            hours <= 23 && minutes <= 59
        }
        _ => false,
    }
}

#[cfg(test)]
mod objective_projection_tests {
    use super::*;
    use crate::model::{
        MaudeAcceptanceCriterionV1, MaudeObjectiveAvailabilityV1, ObjectiveEvidenceCurrentnessV1,
        ObjectiveOwnerConditionV1, ObjectiveOwnerEvidenceV1, ObjectiveOwnerPrerequisitesV1,
    };
    use std::os::unix::fs::PermissionsExt as _;

    fn available() -> ObjectiveDetailV1 {
        ObjectiveDetailV1 {
            schema: OBJECTIVE_DETAIL_SCHEMA_V1.to_owned(),
            objective: MaudeObjectiveReadV1 {
                schema: MAUDE_OBJECTIVE_READ_SCHEMA_V1.to_owned(),
                source: "maude".to_owned(),
                availability: MaudeObjectiveAvailabilityV1::Available,
                captured_at_unix_ms: 7,
                plan_schema: Some("maude.plan-document/v1".to_owned()),
                plan_digest: Some(format!("sha256:{}", "b".repeat(64))),
                goal: Some("Preserve the exact authored objective".to_owned()),
                acceptance_criteria: Some(vec![MaudeAcceptanceCriterionV1 {
                    condition_id: format!("sha256:{}", "c".repeat(64)),
                    text: "A real owner assessment is present".to_owned(),
                }]),
                error_code: None,
                publication: "operator_only".to_owned(),
            },
            conditions: vec![ObjectiveConditionV1 {
                condition_id: format!("sha256:{}", "c".repeat(64)),
                criterion: "A real owner assessment is present".to_owned(),
                disposition: ObjectiveConditionDispositionV1::Unknown,
                owner_record_ref: None,
                owner_record_digest: None,
                evidence: Vec::new(),
                reason: None,
            }],
            occurrences: Vec::new(),
            causal_unavailable: Vec::new(),
            prerequisites: ObjectivePrerequisitesV1::Unknown,
            owner_projection: None,
        }
    }

    fn owner_source() -> ObjectiveOwnerProjectionSourceV1 {
        ObjectiveOwnerProjectionSourceV1 {
            program: PathBuf::from("/bin/phosphor-objective-owner-reader"),
            config: PathBuf::from("/owner.json"),
            expected_owner_id: "example-owner".into(),
            expected_owner_capability: "saved-check-interpretation/v1".into(),
            expected_source_revision: "revision-1".into(),
            expected_plan_digest: format!("sha256:{}", "b".repeat(64)),
        }
    }

    fn owner_projection() -> ObjectiveOwnerProjectionV1 {
        let evidence = ObjectiveOwnerEvidenceV1 {
            owner_schema: "nq.saved-check-condition/v1".into(),
            owner_record_id: "evaluation-1".into(),
            owner_record_digest: format!("sha256:{}", "e".repeat(64)),
            source_observed_at: Some("2026-09-14T00:00:00Z".into()),
            read_attempted_at: Some("2026-09-14T00:00:01.123Z".into()),
            projected_at: Some("2026-09-14T00:00:02+00:00".into()),
            source_currentness: ObjectiveEvidenceCurrentnessV1::Fresh,
            owner_outcome: Some("failed".into()),
            maintenance_annotation: Some("covered".into()),
        };
        let mut value = ObjectiveOwnerProjectionV1 {
            schema: OBJECTIVE_OWNER_PROJECTION_SCHEMA_V1.into(),
            projection_id: String::new(),
            plan_digest: format!("sha256:{}", "b".repeat(64)),
            owner_id: "example-owner".into(),
            owner_capability: "saved-check-interpretation/v1".into(),
            owner_source_revision: "revision-1".into(),
            projected_at: "2026-09-14T00:00:03.456789+00:00".into(),
            conditions: vec![ObjectiveOwnerConditionV1 {
                condition_id: format!("sha256:{}", "c".repeat(64)),
                assessment: ObjectiveConditionDispositionV1::Satisfied,
                owner_record_ref: Some("evaluation-1".into()),
                owner_record_digest: Some(format!("sha256:{}", "e".repeat(64))),
                evidence: vec![evidence],
                reason: None,
            }],
            prerequisites: ObjectiveOwnerPrerequisitesV1 {
                availability: ObjectivePrerequisiteAvailabilityV1::Available,
                coverage: Some("owner_asserted_complete".into()),
                items: Vec::new(),
                reason: None,
            },
            authority: "none".into(),
        };
        let bytes = serde_jcs::to_vec(&value).unwrap();
        value.projection_id = format!("sha256:{:x}", Sha256::digest(bytes));
        value
    }

    #[test]
    fn objective_conditions_remain_unknown_without_owner_assessment() {
        let detail = available();
        assert!(validate_objective_detail(&detail).is_ok());
        let wire = serde_json::to_value(detail).unwrap();
        assert_eq!(wire["schema"], OBJECTIVE_DETAIL_SCHEMA_V1);
        assert!(wire.get("owner_projection").is_none());
        assert!(wire["conditions"][0].get("evidence").is_none());
        assert!(wire["conditions"][0].get("owner_record_digest").is_none());
        assert!(wire["conditions"][0].get("reason").is_none());
    }

    #[test]
    fn exact_application_owner_projection_overlays_without_completion_verdict() {
        let owner = owner_projection();
        assert!(validate_objective_owner_projection(&owner, &owner_source()).is_ok());
        let source = SourceResultV1::Available {
            source: "application objective owner".into(),
            command: ReadCommandNameV1::ObjectiveOwnerProjection,
            captured_at_unix_ms: 9,
            raw: serde_json::to_value(&owner).unwrap(),
            value: owner,
        };
        let detail =
            assemble_objective_detail(available().objective, &[], Vec::new(), Some(source));
        assert_eq!(detail.schema, OBJECTIVE_DETAIL_SCHEMA_V2);
        assert_eq!(
            detail.conditions[0].disposition,
            ObjectiveConditionDispositionV1::Satisfied
        );
        assert!(
            matches!(detail.prerequisites,ObjectivePrerequisitesV1::OwnerDeclared { ref items, .. } if items.is_empty())
        );
        assert!(validate_objective_detail(&detail).is_ok());
        let mut mislabeled = detail.clone();
        mislabeled.schema = OBJECTIVE_DETAIL_SCHEMA_V1.to_owned();
        assert!(validate_objective_detail(&mislabeled).is_err());
    }

    #[test]
    fn owner_projection_refuses_wrong_identity_contradiction_and_bad_time() {
        let source = owner_source();
        let mut value = owner_projection();
        value.plan_digest = format!("sha256:{}", "a".repeat(64));
        assert!(validate_objective_owner_projection(&value, &source).is_err());
        let mut value = owner_projection();
        value.conditions[0].assessment = ObjectiveConditionDispositionV1::Unavailable;
        assert!(validate_objective_owner_projection(&value, &source).is_err());
        let mut value = owner_projection();
        value.conditions[0].evidence[0].projected_at = Some("not-time".into());
        assert!(validate_objective_owner_projection(&value, &source).is_err());
    }

    #[test]
    fn stale_owner_fact_remains_indeterminate_with_original_labels() {
        let source = owner_source();
        let mut value = owner_projection();
        value.conditions[0].assessment = ObjectiveConditionDispositionV1::Indeterminate;
        value.conditions[0].reason = Some("owner evidence is stale".into());
        value.conditions[0].evidence[0].source_currentness = ObjectiveEvidenceCurrentnessV1::Stale;
        let bytes = serde_jcs::to_vec(&ObjectiveOwnerProjectionV1 {
            projection_id: String::new(),
            ..value.clone()
        })
        .unwrap();
        value.projection_id = format!("sha256:{:x}", Sha256::digest(bytes));
        assert!(validate_objective_owner_projection(&value, &source).is_ok());
        assert_eq!(
            value.conditions[0].evidence[0].owner_outcome.as_deref(),
            Some("failed")
        );
        assert_eq!(
            value.conditions[0].evidence[0]
                .maintenance_annotation
                .as_deref(),
            Some("covered")
        );

        value.conditions[0].assessment = ObjectiveConditionDispositionV1::Satisfied;
        value.conditions[0].reason = None;
        value.projection_id.clear();
        value.projection_id = format!(
            "sha256:{:x}",
            Sha256::digest(serde_jcs::to_vec(&value).unwrap())
        );
        assert!(validate_objective_owner_projection_shape(&value).is_err());
    }

    #[test]
    fn owner_projection_uses_only_the_enrolled_config_and_exact_plan() {
        let root = tempfile::tempdir().unwrap();
        let program = root.path().join("phosphor-objective-owner-reader");
        let arguments = root.path().join("arguments");
        let config = root.path().join("owner.json");
        let output = serde_json::to_string(&owner_projection()).unwrap();
        std::fs::write(
            &program,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\nprintf '%s' '{}'\n",
                arguments.display(),
                output
            ),
        )
        .unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
        let source = ObjectiveOwnerProjectionSourceV1 {
            program,
            config: config.clone(),
            ..owner_source()
        };
        let expected_plan_digest = source.expected_plan_digest.clone();
        let reader = OperatorReaderV1::new(OperatorSourceConfigV1 {
            campaign_root: root.path().to_owned(),
            ag_loopctl: root.path().join("ag-loopctl"),
            nightshift: None,
            docket: None,
            maude_acquisition: None,
            maude_objective: None,
            objective_owner_projection: Some(source),
            public_objective_projection: None,
            public_approved_receipt_urls: BTreeSet::new(),
        })
        .unwrap();
        let result = reader.objective_owner_projection();
        assert!(
            matches!(&result, SourceResultV1::Available { .. }),
            "unexpected owner-projection result: {result:?}"
        );
        assert_eq!(
            std::fs::read_to_string(arguments).unwrap(),
            format!(
                "--config\n{}\nobjective-projection\n--plan-digest\n{}\n",
                config.display(),
                expected_plan_digest
            )
        );
    }

    #[test]
    fn canonical_objective_read_refuses_owner_condition_outside_maude() {
        let root = tempfile::tempdir().unwrap();
        let owner_program = root.path().join("phosphor-objective-owner-reader");
        let maude_program = root.path().join("maude-plan");
        let plan = root.path().join("plan.json");
        let digest = format!("sha256:{}", "b".repeat(64));
        let mut owner = owner_projection();
        owner.conditions[0].condition_id = format!("sha256:{}", "d".repeat(64));
        owner.projection_id.clear();
        owner.projection_id = format!(
            "sha256:{:x}",
            Sha256::digest(serde_jcs::to_vec(&owner).unwrap())
        );
        let maude = available().objective;
        for (program, output) in [
            (&owner_program, serde_json::to_string(&owner).unwrap()),
            (&maude_program, serde_json::to_string(&maude).unwrap()),
        ] {
            std::fs::write(program, format!("#!/bin/sh\nprintf '%s' '{output}'\n")).unwrap();
            std::fs::set_permissions(program, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let reader = OperatorReaderV1::new(OperatorSourceConfigV1 {
            campaign_root: root.path().to_owned(),
            ag_loopctl: root.path().join("ag-loopctl"),
            nightshift: None,
            docket: None,
            maude_acquisition: None,
            maude_objective: Some(MaudeObjectiveReadSourceV1 {
                program: maude_program,
                plan,
                expected_plan_digest: digest.clone(),
            }),
            objective_owner_projection: Some(ObjectiveOwnerProjectionSourceV1 {
                program: owner_program,
                config: root.path().join("owner.json"),
                expected_plan_digest: digest.clone(),
                ..owner_source()
            }),
            public_objective_projection: None,
            public_approved_receipt_urls: BTreeSet::new(),
        })
        .unwrap();
        let detail = reader
            .objective_detail(digest.trim_start_matches("sha256:"))
            .unwrap();
        assert_eq!(detail.schema, OBJECTIVE_DETAIL_SCHEMA_V2);
        assert!(
            matches!(
                &detail.owner_projection,
                Some(SourceResultV1::Unavailable {
                    error_kind: SourceErrorKindV1::IncompatibleSchema,
                    ..
                })
            ),
            "unexpected owner-binding result: {:?}",
            detail.owner_projection
        );
        assert_eq!(
            detail.conditions[0].disposition,
            ObjectiveConditionDispositionV1::Unknown
        );
        assert_eq!(detail.prerequisites, ObjectivePrerequisitesV1::Unavailable);
    }

    #[test]
    fn objective_refuses_occurrence_completion_substitution() {
        let mut detail = available();
        detail.conditions[0].disposition = ObjectiveConditionDispositionV1::OwnerAttested;
        detail.conditions[0].owner_record_ref = Some("occurrence outcome".to_owned());
        assert!(validate_objective_detail(&detail).is_err());
    }

    #[test]
    fn unavailable_maude_result_keeps_only_exact_identity_and_error() {
        let mut detail = available();
        detail.objective.availability = MaudeObjectiveAvailabilityV1::Unavailable;
        detail.objective.error_code = Some("missing_plan".to_owned());
        detail.objective.goal = None;
        detail.objective.acceptance_criteria = None;
        detail.conditions.clear();
        assert!(validate_objective_detail(&detail).is_ok());
        detail.objective.goal = Some("must not be present".to_owned());
        assert!(validate_objective_detail(&detail).is_err());
    }

    #[test]
    fn maude_objective_uses_only_the_closed_exact_digest_read() {
        let root = tempfile::tempdir().unwrap();
        let program = root.path().join("maude-plan");
        let arguments = root.path().join("arguments");
        let plan = root.path().join("plan.json");
        let digest = format!("sha256:{}", "b".repeat(64));
        let output = format!(
            "{{\"schema\":\"maude.objective-source/v1\",\"source\":\"maude\",\"availability\":\"available\",\"captured_at_unix_ms\":1,\"plan_schema\":\"maude.plan-document/v1\",\"plan_digest\":\"{digest}\",\"goal\":\"Goal\",\"acceptance_criteria\":[],\"error_code\":null,\"publication\":\"operator_only\"}}"
        );
        std::fs::write(
            &program,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\nprintf '%s' '{}'\n",
                arguments.display(),
                output
            ),
        )
        .unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
        let reader = OperatorReaderV1::new(OperatorSourceConfigV1 {
            campaign_root: root.path().to_owned(),
            ag_loopctl: root.path().join("ag-loopctl"),
            nightshift: None,
            docket: None,
            maude_acquisition: None,
            maude_objective: Some(MaudeObjectiveReadSourceV1 {
                program,
                plan: plan.clone(),
                expected_plan_digest: digest.clone(),
            }),
            objective_owner_projection: None,
            public_objective_projection: None,
            public_approved_receipt_urls: BTreeSet::new(),
        })
        .unwrap();
        let result = reader.maude_objective_read();
        assert!(
            matches!(&result, SourceResultV1::Available { .. }),
            "unexpected Maude objective result: {result:?}"
        );
        assert_eq!(
            std::fs::read_to_string(arguments).unwrap(),
            format!(
                "objective-read\n--plan\n{}\n--expected-plan-digest\n{}\n",
                plan.display(),
                digest
            )
        );
    }

    #[test]
    fn public_projection_is_an_explicit_summary_and_https_url_allowlist() {
        let valid = PublicObjectiveProjectionV1 {
            schema: PUBLIC_OBJECTIVE_PROJECTION_SCHEMA_V1.to_owned(),
            plan_digest: format!("sha256:{}", "d".repeat(64)),
            approved_summary: "A separately approved public summary.".to_owned(),
            approved_receipt_urls: vec!["https://public.example/receipt".to_owned()],
        };
        assert!(validate_public_objective_projection(&valid).is_ok());
        let mut private_path = valid.clone();
        private_path.approved_summary = "copied from /data/private/source".to_owned();
        assert!(validate_public_objective_projection(&private_path).is_err());
        let mut non_https = valid;
        non_https.approved_receipt_urls = vec!["file:///private/receipt".to_owned()];
        assert!(validate_public_objective_projection(&non_https).is_err());
    }
}

fn demo_target_matches(
    target: &crate::model::DemoSemanticLinkTargetV1,
    link: &GovernedRuntimeLinkV1,
) -> bool {
    target.campaign.as_digest() == &link.campaign
        && target.occurrence == link.occurrence
        && target
            .proposal
            .as_ref()
            .map(ag_campaign::governed::ProposalRefV1::as_digest)
            == link.proposal.as_ref()
}

fn index_entry_matches_link(entry: &CampaignIndexEntryV1, link: &GovernedRuntimeLinkV1) -> bool {
    entry
        .inspect
        .value()
        .and_then(|inspect| snapshot_for_link(&inspect.current, entry.history.value(), link))
        .is_some()
}

fn detail_matches_link(detail: &CampaignDetailV1, link: &GovernedRuntimeLinkV1) -> bool {
    selected_snapshot(detail, link).is_some()
}

/// Selects the most recent verified snapshot of the exact linked occurrence.
/// A supplied proposal identity must match that snapshot exactly.
#[must_use]
pub fn selected_snapshot<'a>(
    detail: &'a CampaignDetailV1,
    link: &GovernedRuntimeLinkV1,
) -> Option<&'a OccurrenceSnapshotV1> {
    let current = detail.inspect.value().map(|inspect| &inspect.current)?;
    snapshot_for_link(current, detail.history.value(), link)
}

fn snapshot_for_link<'a>(
    current: &'a OccurrenceSnapshotV1,
    history: Option<&'a CampaignTransitionHistoryV1>,
    link: &GovernedRuntimeLinkV1,
) -> Option<&'a OccurrenceSnapshotV1> {
    let candidate = if current.key().occurrence == link.occurrence {
        Some(current)
    } else {
        history.and_then(|history| {
            history
                .transitions
                .iter()
                .rev()
                .map(|transition| &transition.successor)
                .find(|snapshot| snapshot.key().occurrence == link.occurrence)
        })
    }?;
    if candidate.key().campaign.as_digest() != &link.campaign {
        return None;
    }
    if let Some(expected) = &link.proposal {
        let actual = candidate.proposal()?.reference();
        if actual.as_digest() != expected {
            return None;
        }
    }
    Some(candidate)
}

fn validate_demo_detail(detail: &CampaignDetailV1) -> Result<(), String> {
    if detail.schema != CAMPAIGN_DETAIL_SCHEMA_V1 {
        return Err("unsupported demo campaign-detail schema".to_owned());
    }
    validate_source_raw(&detail.inspect)?;
    validate_source_raw(&detail.status)?;
    validate_source_raw(&detail.replay)?;
    validate_source_raw(&detail.history)?;
    validate_source_raw(&detail.refusals)?;
    if let Some(value) = detail.inspect.value() {
        value.validate()?;
    }
    if let Some(value) = detail.status.value() {
        value
            .validate_integrity()
            .map_err(|error| format!("demo status integrity: {error}"))?;
    }
    for related in &detail.nightshift {
        validate_source_raw(&related.result)?;
        if let Some(value) = related.result.value() {
            value.validate(&related.identity)?;
        }
    }
    for related in &detail.authoring_contexts {
        validate_source_raw(&related.result)?;
        if let Some(value) = related.result.value() {
            let NightshiftAuthoringContextQueryV1::GovernedOccurrence {
                campaign_id,
                occurrence_id,
            } = &value.query
            else {
                return Err("demo authoring-context query is not occurrence-scoped".to_owned());
            };
            value.validate_for_occurrence(campaign_id, occurrence_id)?;
            if related.identity != format!("{campaign_id}/{occurrence_id}") {
                return Err("demo authoring-context related identity drift".to_owned());
            }
        }
    }
    for related in &detail.authoring_custody {
        validate_source_raw(&related.result)?;
        if let Some(value) = related.result.value() {
            let NightshiftAuthoringContextQueryV1::GovernedOccurrence {
                campaign_id,
                occurrence_id,
            } = &value.query
            else {
                return Err("demo authoring-custody query is not occurrence-scoped".to_owned());
            };
            value.validate_for_occurrence(campaign_id, occurrence_id)?;
            if related.identity != format!("{campaign_id}/{occurrence_id}") {
                return Err("demo authoring-custody related identity drift".to_owned());
            }
        }
    }
    for related in &detail.external_observations {
        validate_source_raw(&related.result)?;
        if let Some(value) = related.result.value() {
            let crate::model::ExternalObservationQueryV1::GovernedOccurrence {
                campaign_id,
                occurrence_id,
            } = &value.query
            else {
                return Err("demo external-observation query is not occurrence-scoped".to_owned());
            };
            value.validate_for_occurrence(campaign_id, occurrence_id)?;
            if related.identity != format!("{campaign_id}/{occurrence_id}") {
                return Err("demo external-observation related identity drift".to_owned());
            }
        }
    }
    for related in &detail.observation_acquisitions {
        validate_source_raw(&related.result)?;
        if let Some(value) = related.result.value() {
            value.validate_for_occurrence(&value.campaign_id, &value.occurrence_id)?;
            if related.identity != format!("{}/{}", value.campaign_id, value.occurrence_id) {
                return Err("demo acquisition-history related identity drift".to_owned());
            }
        }
    }
    for related in &detail.docket {
        validate_source_raw(&related.result)?;
        if let Some(value) = related.result.value() {
            validate_docket(value, &related.identity)?;
        }
    }
    Ok(())
}

fn validate_source_raw<T: serde::Serialize>(source: &SourceResultV1<T>) -> Result<(), String> {
    if let SourceResultV1::Available { value, raw, .. } = source
        && serde_json::to_value(value).map_err(|error| error.to_string())? != *raw
    {
        return Err("demo typed value/raw canonical capture drift".to_owned());
    }
    Ok(())
}

fn require_program_name(path: &Path, expected: &str) -> Result<(), String> {
    if !path.is_absolute() || path.file_name().and_then(|name| name.to_str()) != Some(expected) {
        return Err(format!(
            "read source must be the absolute canonical {expected} executable"
        ));
    }
    Ok(())
}

fn discover_stores(root: &Path) -> Result<Vec<(String, String, PathBuf)>, String> {
    let mut stores = Vec::new();
    for entry in fs::read_dir(root).map_err(|error| format!("read campaign root: {error}"))? {
        let entry = entry.map_err(|error| format!("read campaign entry: {error}"))?;
        let file_type = entry
            .file_type()
            .map_err(|error| format!("read campaign entry type: {error}"))?;
        if !file_type.is_file()
            || entry.path().extension().and_then(|value| value.to_str()) != Some("sqlite")
        {
            continue;
        }
        let name = entry.file_name();
        let token = hex_encode(name.as_bytes());
        stores.push((token, name.to_string_lossy().into_owned(), entry.path()));
    }
    Ok(stores)
}

fn collect_related(
    snapshot: &OccurrenceSnapshotV1,
    observations: &mut BTreeSet<String>,
    issuances: &mut BTreeSet<String>,
) {
    if let Some(observation) = snapshot.observation() {
        observations.insert(observation.observation().as_str().to_owned());
    }
    if let Some(completed) = snapshot.completed() {
        observations.insert(
            completed
                .terminal_observation()
                .observation()
                .as_str()
                .to_owned(),
        );
    }
    if let Some(issuance) = snapshot.issuance() {
        issuances.insert(issuance.issuance.as_str().to_owned());
    }
}

fn collect_occurrence(
    snapshot: &OccurrenceSnapshotV1,
    occurrences: &mut BTreeSet<(String, String)>,
) {
    occurrences.insert((
        snapshot.key().campaign.to_string(),
        snapshot.key().occurrence.to_string(),
    ));
}

fn projection_check(
    inspect: Option<&AgInspectV1>,
    status: Option<&OccurrenceSnapshotV1>,
    replay: Option<&CampaignReplayReportV1>,
    history: Option<&CampaignTransitionHistoryV1>,
    refusals: Option<&CampaignRefusalHistoryV1>,
    availability: &[bool],
) -> ProjectionCheckV1 {
    let mut coordinates = Vec::new();
    if let Some(value) = inspect {
        coordinates.push((
            "inspect",
            value.current.key().campaign.as_str(),
            value.current.state_digest().as_str(),
        ));
    }
    if let Some(value) = status {
        coordinates.push((
            "status",
            value.key().campaign.as_str(),
            value.state_digest().as_str(),
        ));
    }
    if let Some(value) = replay {
        coordinates.push((
            "replay",
            value.campaign.as_str(),
            value.current_state_digest.as_str(),
        ));
    }
    if let Some(value) = history {
        coordinates.push((
            "history",
            value.campaign.as_str(),
            value.current_state_digest.as_str(),
        ));
    }
    if let Some(value) = refusals {
        coordinates.push((
            "refusals",
            value.campaign.as_str(),
            value.verified_at_state_digest.as_str(),
        ));
    }
    let disagreement = coordinates
        .windows(2)
        .any(|pair| pair[0].1 != pair[1].1 || pair[0].2 != pair[1].2);
    let correspondence = if disagreement {
        ProjectionCorrespondenceV1::Disagreement
    } else if availability.iter().all(|available| *available) {
        ProjectionCorrespondenceV1::Exact
    } else {
        ProjectionCorrespondenceV1::Partial
    };
    let mut findings = coordinates
        .iter()
        .map(|(source, campaign, digest)| {
            format!("{source}: campaign={campaign}, current_state={digest}")
        })
        .collect::<Vec<_>>();
    if availability.iter().any(|available| !*available) {
        findings.push("one or more canonical AG projections are unavailable".to_owned());
    }
    if disagreement {
        findings.push("canonical AG projections disagree; no value was reconciled".to_owned());
    }
    ProjectionCheckV1 {
        correspondence,
        findings,
    }
}

fn validate_docket(value: &DocketInspectionV1, issuance: &str) -> Result<(), String> {
    if value.schema != DOCKET_INSPECTION_SCHEMA_V1 {
        return Err(format!(
            "unsupported Docket inspection schema {}",
            value.schema
        ));
    }
    if value.requested_issuance != issuance {
        return Err("Docket inspection substituted issuance identity".to_owned());
    }
    let Some(record) = &value.record else {
        return Ok(());
    };
    if record.issuance.issuance.as_str() != issuance
        || record.custody.issuance.as_str() != issuance
        || record.custody.ag_spend != record.issuance.spend
    {
        return Err("Docket inspection issuance/custody binding mismatch".to_owned());
    }
    match record.status {
        crate::model::DocketRecordStatusV1::Accepted => {
            if record.settlement.is_some() || record.indeterminate.is_some() {
                return Err("Docket accepted record has outcome fields".to_owned());
            }
        }
        crate::model::DocketRecordStatusV1::Settled => {
            let settlement = record
                .settlement
                .as_ref()
                .ok_or_else(|| "Docket settled record lacks settlement".to_owned())?;
            if record.indeterminate.is_some()
                || settlement.issuance.as_str() != issuance
                || settlement.attempt != record.custody.attempt
            {
                return Err("Docket custody/settlement binding mismatch".to_owned());
            }
        }
        crate::model::DocketRecordStatusV1::Indeterminate => {
            let indeterminate = record
                .indeterminate
                .as_ref()
                .ok_or_else(|| "Docket indeterminate record lacks evidence".to_owned())?;
            if record.settlement.is_some()
                || indeterminate.issuance.as_str() != issuance
                || indeterminate.attempt != record.custody.attempt
            {
                return Err("Docket custody/indeterminate binding mismatch".to_owned());
            }
        }
    }
    Ok(())
}

fn run_bounded(command: &mut Command) -> Result<Vec<u8>, CaptureFailureV1> {
    let mut child = command
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| CaptureFailureV1 {
            kind: if error.kind() == std::io::ErrorKind::NotFound {
                SourceErrorKindV1::Missing
            } else {
                SourceErrorKindV1::Unavailable
            },
            detail: format!("canonical command could not start: {error}"),
            exit_status: None,
        })?;
    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    let stdout_reader = thread::spawn(move || read_bounded(stdout, MAX_STDOUT_BYTES));
    let stderr_reader = thread::spawn(move || read_bounded(stderr, MAX_STDERR_BYTES));
    let deadline = Instant::now() + COMMAND_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            Ok(None) => {
                terminate_command_group(&mut child);
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return Err(CaptureFailureV1 {
                    kind: SourceErrorKindV1::Timeout,
                    detail: "canonical read command exceeded 5 seconds".to_owned(),
                    exit_status: None,
                });
            }
            Err(error) => {
                terminate_command_group(&mut child);
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return Err(CaptureFailureV1 {
                    kind: SourceErrorKindV1::Unavailable,
                    detail: format!("canonical command wait failed: {error}"),
                    exit_status: None,
                });
            }
        }
    };
    // Enrolled read programs must keep descendants in this process group.
    // Close inherited pipes before joining readers after the leader exits.
    terminate_command_group(&mut child);
    let stdout = stdout_reader.join().map_err(|_| CaptureFailureV1 {
        kind: SourceErrorKindV1::Unavailable,
        detail: "canonical command stdout reader failed".to_owned(),
        exit_status: status.code(),
    })??;
    let stderr = stderr_reader.join().map_err(|_| CaptureFailureV1 {
        kind: SourceErrorKindV1::Unavailable,
        detail: "canonical command stderr reader failed".to_owned(),
        exit_status: status.code(),
    })??;
    if !status.success() {
        return Err(CaptureFailureV1 {
            kind: SourceErrorKindV1::CommandRefused,
            detail: format!(
                "canonical command refused: {}",
                String::from_utf8_lossy(&stderr).trim()
            ),
            exit_status: status.code(),
        });
    }
    Ok(stdout)
}

fn terminate_command_group(child: &mut std::process::Child) {
    if let Ok(pid) = i32::try_from(child.id()) {
        let _ = nix::sys::signal::killpg(
            nix::unistd::Pid::from_raw(pid),
            nix::sys::signal::Signal::SIGKILL,
        );
    }
    let _ = child.kill();
    let _ = child.wait();
}

fn read_bounded(mut stream: impl Read, limit: u64) -> Result<Vec<u8>, CaptureFailureV1> {
    let mut bytes = Vec::new();
    stream
        .by_ref()
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| CaptureFailureV1 {
            kind: SourceErrorKindV1::Unavailable,
            detail: format!("canonical command output read failed: {error}"),
            exit_status: None,
        })?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
        return Err(CaptureFailureV1 {
            kind: SourceErrorKindV1::OutputTooLarge,
            detail: format!("canonical command output exceeded {limit} bytes"),
            exit_status: None,
        });
    }
    Ok(bytes)
}

fn unavailable<T>(
    source: &str,
    command: ReadCommandNameV1,
    error_kind: SourceErrorKindV1,
    detail: String,
    exit_status: Option<i32>,
) -> SourceResultV1<T> {
    unavailable_at(
        source,
        command,
        capture_time(),
        error_kind,
        detail,
        exit_status,
    )
}

fn unavailable_at<T>(
    source: &str,
    command: ReadCommandNameV1,
    captured_at_unix_ms: u64,
    error_kind: SourceErrorKindV1,
    detail: String,
    exit_status: Option<i32>,
) -> SourceResultV1<T> {
    SourceResultV1::Unavailable {
        source: source.to_owned(),
        command,
        captured_at_unix_ms,
        error_kind,
        detail,
        exit_status,
    }
}

fn capture_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .unwrap_or(0)
}

/// Encodes an operational locator into an opaque URL token.
#[must_use]
pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[allow(dead_code, reason = "kept adjacent to encoding for route-level tests")]
fn decode_locator(token: &str) -> Result<OsString, String> {
    if !token.len().is_multiple_of(2) || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("invalid locator token".to_owned());
    }
    let mut bytes = Vec::with_capacity(token.len() / 2);
    for pair in token.as_bytes().chunks_exact(2) {
        let text = std::str::from_utf8(pair).map_err(|_| "invalid locator token".to_owned())?;
        bytes.push(u8::from_str_radix(text, 16).map_err(|_| "invalid locator token".to_owned())?);
    }
    Ok(OsString::from_vec(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn locator_token_round_trips_without_becoming_campaign_identity() {
        let locator = OsString::from_vec(b"campaign one.sqlite".to_vec());
        let token = hex_encode(locator.as_bytes());
        assert_eq!(decode_locator(&token).unwrap(), locator);
        assert!(decode_locator("../campaign.sqlite").is_err());
    }

    #[test]
    fn configured_program_names_are_closed() {
        assert!(require_program_name(Path::new("/opt/ag-loopctl"), "ag-loopctl").is_ok());
        assert!(require_program_name(Path::new("/opt/other"), "ag-loopctl").is_err());
        assert!(require_program_name(Path::new("ag-loopctl"), "ag-loopctl").is_err());
    }

    #[test]
    fn malformed_canonical_output_stays_visible_and_is_not_inferred() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("campaign.sqlite"), b"not a database").unwrap();
        let program = root.path().join("ag-loopctl");
        std::fs::write(&program, b"#!/bin/sh\nprintf '{} trailing'\n").unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
        let reader = OperatorReaderV1::new(OperatorSourceConfigV1 {
            campaign_root: root.path().to_owned(),
            ag_loopctl: program,
            nightshift: None,
            docket: None,
            maude_acquisition: None,
            maude_objective: None,
            objective_owner_projection: None,
            public_objective_projection: None,
            public_approved_receipt_urls: BTreeSet::new(),
        })
        .unwrap();
        let index = reader.campaign_index().unwrap();
        assert_eq!(index.campaigns.len(), 1);
        assert!(
            matches!(
                &index.campaigns[0].inspect,
                SourceResultV1::Unavailable {
                    error_kind: SourceErrorKindV1::MalformedOutput,
                    ..
                }
            ),
            "unexpected malformed-output result: {:?}",
            index.campaigns[0].inspect
        );
        assert_eq!(
            index.campaigns[0].projection.correspondence,
            ProjectionCorrespondenceV1::Partial
        );
    }

    #[test]
    fn owner_schema_and_identity_substitution_are_refused() {
        let nightshift = NightshiftObservationExportV1 {
            schema: "nightshift.observation_export.v2".to_owned(),
            observation_id: "observation-b".to_owned(),
            matches: Vec::new(),
        };
        assert!(nightshift.validate("observation-a").is_err());

        let docket = DocketInspectionV1 {
            schema: DOCKET_INSPECTION_SCHEMA_V1.to_owned(),
            requested_issuance: "issuance-b".to_owned(),
            record: None,
        };
        assert!(validate_docket(&docket, "issuance-a").is_err());
    }

    #[test]
    fn authoring_context_uses_only_the_closed_nightshift_read_verb() {
        let root = tempfile::tempdir().unwrap();
        let ag = root.path().join("ag-loopctl");
        std::fs::write(&ag, b"#!/bin/sh\nexit 1\n").unwrap();
        let nightshift = root.path().join("nightshift");
        let arguments = root.path().join("nightshift-arguments");
        let campaign = ag_primitives::Digest::hash_bytes(b"campaign").to_string();
        let occurrence = "00000000-0000-0000-0000-000000000001";
        let payload = serde_json::json!({
            "schema": crate::model::NIGHTSHIFT_AUTHORING_CONTEXT_EXPORT_SCHEMA_V1,
            "query": {
                "by": "governed_occurrence",
                "campaign_id": campaign,
                "occurrence_id": occurrence,
            },
            "matches": [],
        });
        std::fs::write(
            &nightshift,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\nprintf '%s' '{}'\n",
                arguments.display(),
                payload
            )
            .as_bytes(),
        )
        .unwrap();
        std::fs::set_permissions(&ag, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&nightshift, std::fs::Permissions::from_mode(0o700)).unwrap();
        let reader = OperatorReaderV1::new(OperatorSourceConfigV1 {
            campaign_root: root.path().to_owned(),
            ag_loopctl: ag,
            nightshift: Some(NightshiftReadSourceV1 {
                program: nightshift,
                store: root.path().join("nightshift.sqlite"),
            }),
            docket: None,
            maude_acquisition: None,
            maude_objective: None,
            objective_owner_projection: None,
            public_objective_projection: None,
            public_approved_receipt_urls: BTreeSet::new(),
        })
        .unwrap();
        let result = reader.nightshift_authoring_export(&campaign, occurrence);
        assert!(
            matches!(
                &result,
                SourceResultV1::Available {
                    command: ReadCommandNameV1::NightshiftExportAuthoringContext,
                    value: NightshiftAuthoringContextExportV1 { matches, .. },
                    ..
                } if matches.is_empty()
            ),
            "unexpected authoring-context result: {result:?}"
        );
        assert_eq!(
            std::fs::read_to_string(arguments).unwrap(),
            format!(
                "--store\n{}\ncycle\nexport-authoring-context\n--campaign-id\n{}\n--occurrence-id\n{}\n",
                root.path().join("nightshift.sqlite").display(),
                campaign,
                occurrence,
            )
        );
    }

    #[test]
    fn bounded_reader_closes_same_group_inherited_pipe_after_leader_exit() {
        let started = Instant::now();
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "sleep 30 & printf '{}'"]);
        assert_eq!(run_bounded(&mut command).unwrap(), b"{}");
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn bounded_reader_terminates_same_group_descendant_at_deadline() {
        let started = Instant::now();
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "sleep 30 & wait"]);
        let error = run_bounded(&mut command).unwrap_err();
        assert_eq!(error.kind, SourceErrorKindV1::Timeout);
        assert!(started.elapsed() < COMMAND_TIMEOUT + Duration::from_secs(2));
    }

    #[test]
    fn authoring_custody_uses_only_the_closed_nightshift_read_verb() {
        let root = tempfile::tempdir().unwrap();
        let ag = root.path().join("ag-loopctl");
        std::fs::write(&ag, b"#!/bin/sh\nexit 1\n").unwrap();
        let nightshift = root.path().join("nightshift");
        let arguments = root.path().join("nightshift-arguments");
        let campaign = ag_primitives::Digest::hash_bytes(b"campaign").to_string();
        let occurrence = "00000000-0000-0000-0000-000000000001";
        let payload = serde_json::json!({
            "schema": crate::model::NIGHTSHIFT_AUTHORING_CUSTODY_EXPORT_SCHEMA_V1,
            "query": {
                "by": "governed_occurrence",
                "campaign_id": campaign,
                "occurrence_id": occurrence,
            },
            "matches": [],
        });
        std::fs::write(
            &nightshift,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\nprintf '%s' '{}'\n",
                arguments.display(),
                payload
            )
            .as_bytes(),
        )
        .unwrap();
        std::fs::set_permissions(&ag, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&nightshift, std::fs::Permissions::from_mode(0o700)).unwrap();
        let reader = OperatorReaderV1::new(OperatorSourceConfigV1 {
            campaign_root: root.path().to_owned(),
            ag_loopctl: ag,
            nightshift: Some(NightshiftReadSourceV1 {
                program: nightshift,
                store: root.path().join("nightshift.sqlite"),
            }),
            docket: None,
            maude_acquisition: None,
            maude_objective: None,
            objective_owner_projection: None,
            public_objective_projection: None,
            public_approved_receipt_urls: BTreeSet::new(),
        })
        .unwrap();
        let result = reader.nightshift_authoring_custody_export(&campaign, occurrence);
        assert!(
            matches!(
                &result,
                SourceResultV1::Available {
                    command: ReadCommandNameV1::NightshiftExportAuthoringCustody,
                    value: NightshiftAuthoringCustodyExportV1 { matches, .. },
                    ..
                } if matches.is_empty()
            ),
            "unexpected authoring-custody result: {result:?}"
        );
        assert_eq!(
            std::fs::read_to_string(arguments).unwrap(),
            format!(
                "--store\n{}\ncycle\nexport-authoring-custody\n--campaign-id\n{}\n--occurrence-id\n{}\n",
                root.path().join("nightshift.sqlite").display(),
                campaign,
                occurrence,
            )
        );
    }

    #[test]
    fn external_observation_uses_only_occurrence_scoped_read_verb() {
        let root = tempfile::tempdir().unwrap();
        let ag = root.path().join("ag-loopctl");
        std::fs::write(&ag, b"#!/bin/sh\nexit 1\n").unwrap();
        let nightshift = root.path().join("nightshift");
        let arguments = root.path().join("nightshift-arguments");
        let campaign = ag_primitives::Digest::hash_bytes(b"campaign").to_string();
        let occurrence = "00000000-0000-0000-0000-000000000001";
        let payload = serde_json::json!({
            "schema": crate::model::NIGHTSHIFT_EXTERNAL_OBSERVATION_EXPORT_SCHEMA_V1,
            "query": {
                "kind": "governed_occurrence",
                "campaign_id": campaign,
                "occurrence_id": occurrence,
            },
            "matches": [],
        });
        std::fs::write(
            &nightshift,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\nprintf '%s' '{}'\n",
                arguments.display(),
                payload
            )
            .as_bytes(),
        )
        .unwrap();
        std::fs::set_permissions(&ag, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&nightshift, std::fs::Permissions::from_mode(0o700)).unwrap();
        let reader = OperatorReaderV1::new(OperatorSourceConfigV1 {
            campaign_root: root.path().to_owned(),
            ag_loopctl: ag,
            nightshift: Some(NightshiftReadSourceV1 {
                program: nightshift,
                store: root.path().join("nightshift.sqlite"),
            }),
            docket: None,
            maude_acquisition: None,
            maude_objective: None,
            objective_owner_projection: None,
            public_objective_projection: None,
            public_approved_receipt_urls: BTreeSet::new(),
        })
        .unwrap();
        let result = reader.nightshift_external_observation_export(&campaign, occurrence);
        assert!(
            matches!(
                &result,
                SourceResultV1::Available {
                    command: ReadCommandNameV1::NightshiftExportExternalObservation,
                    value: ExternalObservationExportV1 { matches, .. },
                    ..
                } if matches.is_empty()
            ),
            "unexpected external-observation result: {result:?}"
        );
        let arguments = std::fs::read_to_string(arguments).unwrap();
        assert!(arguments.contains("\nexternal-observation\nexport\n"));
        assert!(arguments.contains(&format!(
            "--campaign-id\n{campaign}\n--occurrence-id\n{occurrence}\n"
        )));
        assert!(arguments.contains(&format!(
            "--evidence-ttl-ms\n{EXTERNAL_OBSERVATION_DISPLAY_TTL_MS}\n"
        )));
        assert!(!arguments.contains("cycle\nrun"));
    }

    #[test]
    fn acquisition_history_uses_only_closed_occurrence_scoped_maude_read_verb() {
        let root = tempfile::tempdir().unwrap();
        let ag = root.path().join("ag-loopctl");
        std::fs::write(&ag, b"#!/bin/sh\nexit 1\n").unwrap();
        let program = root.path().join("maude-observation-acquisition");
        let arguments = root.path().join("maude-acquisition-arguments");
        let campaign = ag_primitives::Digest::hash_bytes(b"campaign").to_string();
        let occurrence = "00000000-0000-0000-0000-000000000001";
        let payload = serde_json::json!({
            "schema": crate::model::MAUDE_ACQUISITION_HISTORY_SCHEMA_V1,
            "campaign_id": campaign,
            "occurrence_id": occurrence,
            "acquisitions": [],
        });
        std::fs::write(
            &program,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\nprintf '%s' '{}'\n",
                arguments.display(),
                payload
            )
            .as_bytes(),
        )
        .unwrap();
        std::fs::set_permissions(&ag, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
        let reader = OperatorReaderV1::new(OperatorSourceConfigV1 {
            campaign_root: root.path().to_owned(),
            ag_loopctl: ag,
            nightshift: None,
            docket: None,
            maude_acquisition: Some(MaudeAcquisitionReadSourceV1 {
                program,
                ledger: root.path().join("acquisition.sqlite"),
            }),
            maude_objective: None,
            objective_owner_projection: None,
            public_objective_projection: None,
            public_approved_receipt_urls: BTreeSet::new(),
        })
        .unwrap();
        let result = reader.maude_acquisition_export(&campaign, occurrence);
        assert!(
            matches!(
                &result,
                SourceResultV1::Available {
                    command: ReadCommandNameV1::MaudeExportObservationAcquisitions,
                    value: AcquisitionHistoryV1 { acquisitions, .. },
                    ..
                } if acquisitions.is_empty()
            ),
            "unexpected acquisition-history result: {result:?}"
        );
        assert_eq!(
            std::fs::read_to_string(arguments).unwrap(),
            format!(
                "export-occurrence\n--ledger\n{}\n--campaign-id\n{}\n--occurrence-id\n{}\n",
                root.path().join("acquisition.sqlite").display(),
                campaign,
                occurrence,
            )
        );
    }

    #[test]
    fn deterministic_corpus_is_typed_bounded_and_does_not_need_commands() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("corpus.json");
        let corpus = DemoCorpusV1 {
            schema: DEMO_CORPUS_SCHEMA_V1.to_owned(),
            generated_by: "test".to_owned(),
            canonical_schemas: vec![crate::model::AG_INSPECT_SCHEMA_V1.to_owned()],
            index: CampaignIndexV1 {
                schema: CAMPAIGN_INDEX_SCHEMA_V1.to_owned(),
                campaigns: Vec::new(),
            },
            campaigns: Vec::new(),
            objectives: Vec::new(),
            semantic_link_targets: Vec::new(),
        };
        std::fs::write(&path, serde_json::to_vec(&corpus).unwrap()).unwrap();
        let reader = OperatorReaderV1::from_demo_corpus(&path).unwrap();
        assert_eq!(reader.mode_label(), "deterministic demo corpus");
        assert!(reader.campaign_index().unwrap().campaigns.is_empty());
    }

    #[test]
    fn corpus_index_detail_drift_is_refused() {
        let corpus = DemoCorpusV1 {
            schema: DEMO_CORPUS_SCHEMA_V1.to_owned(),
            generated_by: "test".to_owned(),
            canonical_schemas: Vec::new(),
            index: CampaignIndexV1 {
                schema: CAMPAIGN_INDEX_SCHEMA_V1.to_owned(),
                campaigns: Vec::new(),
            },
            campaigns: vec![],
            objectives: Vec::new(),
            semantic_link_targets: Vec::new(),
        };
        let mut drifted = corpus;
        drifted.index.campaigns.push(CampaignIndexEntryV1 {
            locator_token: "00".to_owned(),
            locator: "missing.sqlite".to_owned(),
            inspect: unavailable(
                "AG",
                ReadCommandNameV1::AgInspect,
                SourceErrorKindV1::Missing,
                "fixture".to_owned(),
                None,
            ),
            history: unavailable(
                "AG",
                ReadCommandNameV1::AgHistory,
                SourceErrorKindV1::Missing,
                "fixture".to_owned(),
                None,
            ),
            refusals: unavailable(
                "AG",
                ReadCommandNameV1::AgRefusals,
                SourceErrorKindV1::Missing,
                "fixture".to_owned(),
                None,
            ),
            projection: ProjectionCheckV1 {
                correspondence: ProjectionCorrespondenceV1::Partial,
                findings: Vec::new(),
            },
        });
        assert!(validate_demo_corpus(&drifted).is_err());
    }
}
