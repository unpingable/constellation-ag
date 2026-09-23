//! Read-only AG decision over one Monitor-acquired civild observation.
//!
//! This is deliberately outside the governed effect loop. It authorizes only
//! use of one exact observation as decision input and grants no mutation,
//! execution, retry, or Docket authority.

use ag_primitives::Digest;
use serde::{Deserialize, Serialize};
use serde_json::Value;

const INVENTORY_SCHEMA: &str = "monitor.project-observation.inventory/v1";
const PROJECT: &str = "civild";
const PRODUCER: &str = "civild.host-observer";
const CONCERN: &str = "civild.listening-ports";
const PORTS_SCHEMA: &str = "civild.listening-ports-observation";

#[derive(Debug, Deserialize)]
struct Inventory {
    schema: String,
    project: String,
    acquisition: Acquisition,
    concerns: Vec<Concern>,
}

#[derive(Debug, Deserialize)]
struct Acquisition {
    disposition: String,
    producer: String,
    status_digest: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Concern {
    declaration: Declaration,
    monitor_state: String,
    observation: Option<Observation>,
}

#[derive(Debug, Deserialize)]
struct Declaration {
    id: String,
}

#[derive(Debug, Deserialize)]
struct Observation {
    #[serde(rename = "observation_present")]
    present: bool,
    local_state: String,
    facts: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
/// Whether AG may use the exact observation as a decision input.
pub enum ObservationUseDecision {
    /// The exact inventory contains a typed, acquired observation.
    Authorized,
    /// The inventory is valid but does not contain usable evidence.
    Refused,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
/// Read-only AG decision bound to one exact Monitor inventory.
pub struct CivildObservationDecision {
    /// Closed output schema.
    pub schema: &'static str,
    /// Decision about observation use only.
    pub decision: ObservationUseDecision,
    /// Digest of the exact Monitor inventory bytes supplied to AG.
    pub observation_sha256: String,
    /// Digest of the producer status retained by Monitor, when acquisition reached it.
    pub monitor_status_digest: Option<String>,
    /// Human-readable basis for the decision.
    pub reason: String,
    /// Explicitly confirms this read-only decision carries no mutation authority.
    pub mutation_authority: &'static str,
}

impl CivildObservationDecision {
    /// Returns canonical JSON followed by exactly one LF.
    ///
    /// # Errors
    ///
    /// Returns an error if canonical JSON serialization fails.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        let mut bytes = serde_jcs::to_vec(self)
            .map_err(|error| format!("canonicalize civild observation decision: {error}"))?;
        bytes.push(b'\n');
        Ok(bytes)
    }
}

/// Decides whether one exact Monitor inventory supplies a usable civild
/// listening-port observation. Unavailable or missing evidence is a refusal,
/// never an empty-port authorization.
///
/// # Errors
///
/// Returns an error for malformed or foreign Monitor inventories, or for a
/// civild fact that omits its required typed outcome.
pub fn decide_civild_observation(bytes: &[u8]) -> Result<CivildObservationDecision, String> {
    let inventory: Inventory = serde_json::from_slice(bytes)
        .map_err(|error| format!("decode Monitor inventory: {error}"))?;
    if inventory.schema != INVENTORY_SCHEMA {
        return Err(format!(
            "unsupported Monitor inventory schema {}",
            inventory.schema
        ));
    }
    if inventory.project != PROJECT {
        return Err(format!(
            "Monitor inventory is for project {}",
            inventory.project
        ));
    }
    if inventory.acquisition.producer != PRODUCER {
        return Err(format!(
            "Monitor inventory names producer {}",
            inventory.acquisition.producer
        ));
    }
    let digest = Digest::hash_bytes(bytes).to_string();
    let status_digest = inventory.acquisition.status_digest.clone();
    let refused = |reason: String| CivildObservationDecision {
        schema: "ag.civild-observation-decision/v1",
        decision: ObservationUseDecision::Refused,
        observation_sha256: digest.clone(),
        monitor_status_digest: status_digest.clone(),
        reason,
        mutation_authority: "none",
    };
    if inventory.acquisition.disposition != "ACQUIRED_AND_VALIDATED" {
        return Ok(refused(format!(
            "Monitor acquisition was {}",
            inventory.acquisition.disposition
        )));
    }
    let Some(concern) = inventory
        .concerns
        .iter()
        .find(|concern| concern.declaration.id == CONCERN)
    else {
        return Ok(refused("required civild concern is missing".to_owned()));
    };
    if concern.monitor_state != "OBSERVED" {
        return Ok(refused(format!(
            "Monitor concern state was {}",
            concern.monitor_state
        )));
    }
    let Some(observation) = &concern.observation else {
        return Ok(refused("Monitor supplied no civild observation".to_owned()));
    };
    if !observation.present {
        return Ok(refused(
            "civild observation was explicitly not present".to_owned(),
        ));
    }
    if observation.facts.get("schema").and_then(Value::as_str) != Some(PORTS_SCHEMA) {
        return Err("civild observation has a foreign facts schema".to_owned());
    }
    let outcome = observation
        .facts
        .pointer("/outcome/status")
        .and_then(Value::as_str)
        .ok_or_else(|| "civild observation omitted its typed outcome".to_owned())?;
    if observation.local_state == "OBSERVED" && outcome == "observed" {
        Ok(CivildObservationDecision {
            schema: "ag.civild-observation-decision/v1",
            decision: ObservationUseDecision::Authorized,
            observation_sha256: digest,
            monitor_status_digest: status_digest,
            reason: "Monitor acquired a typed civild listening-port observation".to_owned(),
            mutation_authority: "none",
        })
    } else {
        Ok(refused(format!(
            "civild listening-port observation was {}/{}",
            observation.local_state, outcome
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inventory(local_state: &str, outcome: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schema": INVENTORY_SCHEMA,
            "project": PROJECT,
            "repository": "/tmp/civild",
            "acquisition": {
                "disposition": "ACQUIRED_AND_VALIDATED",
                "producer": PRODUCER,
                "status_digest": "sha256:status"
            },
            "validation_issues": [],
            "concerns": [{
                "declaration": {"id": CONCERN},
                "monitor_state": "OBSERVED",
                "observation": {
                    "observation_present": true,
                    "local_state": local_state,
                    "facts": {
                        "schema": PORTS_SCHEMA,
                        "outcome": {"status": outcome}
                    }
                }
            }]
        }))
        .unwrap()
    }

    #[test]
    fn typed_observed_ports_authorize_observation_use_only() {
        let decision = decide_civild_observation(&inventory("OBSERVED", "observed")).unwrap();
        assert_eq!(decision.decision, ObservationUseDecision::Authorized);
        assert_eq!(decision.mutation_authority, "none");
    }

    #[test]
    fn typed_unavailable_refuses_instead_of_authorizing_an_empty_inventory() {
        let decision = decide_civild_observation(&inventory("UNAVAILABLE", "unavailable")).unwrap();
        assert_eq!(decision.decision, ObservationUseDecision::Refused);
        assert!(decision.reason.contains("UNAVAILABLE/unavailable"));
        assert_eq!(decision.mutation_authority, "none");
    }

    #[test]
    fn foreign_producer_is_not_a_decision_basis() {
        let mut value: Value = serde_json::from_slice(&inventory("OBSERVED", "observed")).unwrap();
        value["acquisition"]["producer"] = Value::String("other".to_owned());
        assert!(decide_civild_observation(&serde_json::to_vec(&value).unwrap()).is_err());
    }
}
