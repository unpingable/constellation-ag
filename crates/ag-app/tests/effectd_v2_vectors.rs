//! Candidate placement: AG `crates/ag-app/tests/effectd_v2_vectors.rs`.
//! Copy the Docket-owned corpus verbatim to `tests/fixtures/docket-v2-corpus.json`
//! with its reviewed SHA-256. This test is not a substitute for AG effectd's
//! adjacent-process admission test with an independently enrolled profile.

use ag_app::effect_executor_adapter::{AuthorizedEffectDispatchV2, EffectExecutorDispatchV1};
use ag_campaign::governed::AgIssuanceV1;
use ag_primitives::Digest;
use ag_protocol::strict_json_from_slice;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ring::signature::{UnparsedPublicKey, ED25519};

const SIGNATURE_PREFIX: &[u8] = b"ag-ng\0governed-loop-issuance-signature\0v1\0";

#[test]
fn shared_positive_bytes_decode_and_bind_external_fixture_issuer() {
    let corpus: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/docket-v2-corpus.json")).unwrap();
    let input = corpus["cases"][0]["input"].as_str().unwrap();
    let wrapper: AuthorizedEffectDispatchV2 = strict_json_from_slice(input.as_bytes()).unwrap();
    assert_eq!(wrapper.schema, "docket.governed-executor-dispatch/v2");
    let trust: serde_json::Value =
        strict_json_from_slice(corpus["issuer_trust_bytes"].as_str().unwrap().as_bytes()).unwrap();
    let enrolled = &trust["issuers"][0];
    let authentication = &wrapper.signed_issuance.authentication;
    assert_eq!(
        authentication.issuer_principal,
        enrolled["issuer_principal"].as_str().unwrap()
    );
    assert_eq!(
        authentication.signer_key_id,
        enrolled["key_id"].as_str().unwrap()
    );
    assert_eq!(
        authentication.signer_public_key,
        enrolled["public_key"].as_str().unwrap()
    );
    let body = URL_SAFE_NO_PAD
        .decode(&wrapper.signed_issuance.body_b64)
        .unwrap();
    assert_eq!(
        body,
        corpus["issuance_body_bytes"].as_str().unwrap().as_bytes()
    );
    let signature = URL_SAFE_NO_PAD.decode(&authentication.signature).unwrap();
    let public = URL_SAFE_NO_PAD
        .decode(enrolled["public_key"].as_str().unwrap())
        .unwrap();
    let mut signed = SIGNATURE_PREFIX.to_vec();
    signed.extend_from_slice(&body);
    UnparsedPublicKey::new(&ED25519, &public)
        .verify(&signed, &signature)
        .unwrap();
    let issuance: AgIssuanceV1 = strict_json_from_slice(&body).unwrap();
    assert_eq!(
        issuance.issuance.as_str(),
        corpus["issuance"].as_str().unwrap()
    );
    assert_eq!(wrapper.custody.issuance, issuance.issuance);
    assert_eq!(
        wrapper.dispatch.attempt.as_str(),
        corpus["attempt"].as_str().unwrap()
    );
    assert_eq!(
        wrapper.dispatch.marker.as_str(),
        corpus["marker"].as_str().unwrap()
    );
    assert_eq!(wrapper.dispatch.work, issuance.work);
    assert_eq!(wrapper.dispatch.subject, issuance.subject);
    assert_eq!(wrapper.dispatch.scope, issuance.scope);
}

fn classify_shared_wire(input: &str, trust: &serde_json::Value) -> Result<(), &'static str> {
    let wrapper: AuthorizedEffectDispatchV2 =
        strict_json_from_slice(input.as_bytes()).map_err(|_| "decode")?;
    if wrapper.schema != "docket.governed-executor-dispatch/v2" {
        return Err("schema");
    }
    let authentication = &wrapper.signed_issuance.authentication;
    let enrolled = &trust["issuers"][0];
    if authentication.issuer_principal != enrolled["issuer_principal"].as_str().unwrap()
        || authentication.signer_key_id != enrolled["key_id"].as_str().unwrap()
        || authentication.signer_public_key != enrolled["public_key"].as_str().unwrap()
    {
        return Err("trust");
    }
    let body = URL_SAFE_NO_PAD
        .decode(&wrapper.signed_issuance.body_b64)
        .map_err(|_| "body")?;
    let signature = URL_SAFE_NO_PAD
        .decode(&authentication.signature)
        .map_err(|_| "signature")?;
    let public = URL_SAFE_NO_PAD
        .decode(enrolled["public_key"].as_str().unwrap())
        .map_err(|_| "trust")?;
    let mut signed = SIGNATURE_PREFIX.to_vec();
    signed.extend_from_slice(&body);
    UnparsedPublicKey::new(&ED25519, &public)
        .verify(&signed, &signature)
        .map_err(|_| "signature")?;
    let issuance: AgIssuanceV1 = strict_json_from_slice(&body).map_err(|_| "body")?;
    let custody = &wrapper.custody;
    let dispatch = &wrapper.dispatch;
    if custody.issuance != issuance.issuance
        || custody.ag_spend != issuance.spend
        || dispatch.work != issuance.work
        || dispatch.work_schema != issuance.work_schema
        || dispatch.subject != issuance.subject
        || dispatch.scope != issuance.scope
        || dispatch.attempt.as_str() != custody.attempt.as_str()
        || dispatch.marker.as_str() != custody.executor_marker.as_str()
    {
        return Err("binding");
    }
    let attempt = Digest::hash_domain(
        "ag.governed-loop.docket-attempt/v1",
        serde_json::to_string(issuance.issuance.as_str())
            .unwrap()
            .as_bytes(),
    );
    let marker = Digest::hash_domain(
        "docket.governed-loop.executor-marker/v1",
        attempt.as_str().as_bytes(),
    );
    if custody.attempt.as_str() != attempt.as_str()
        || custody.executor_marker.as_str() != marker.as_str()
    {
        return Err("binding");
    }
    Ok(())
}

#[test]
fn every_shared_negative_byte_case_is_closed_and_classified() {
    let corpus: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/docket-v2-corpus.json")).unwrap();
    let trust: serde_json::Value =
        strict_json_from_slice(corpus["issuer_trust_bytes"].as_str().unwrap().as_bytes()).unwrap();
    let expected = [
        ("valid-v2-typed-and-signed", Ok(())),
        ("wrong-v2-schema", Err("schema")),
        ("changed-work", Err("binding")),
        ("changed-marker", Err("binding")),
        ("wrapper-key-not-trusted", Err("trust")),
        ("signature-substitution", Err("signature")),
        (
            "valid-signature-different-issuance-old-custody",
            Err("binding"),
        ),
        ("bare-v1-is-not-v2", Err("decode")),
        ("v2-is-not-bare-v1", Err("closed-v1")),
        ("duplicate-v2-schema", Err("decode")),
    ];
    let cases = corpus["cases"].as_array().unwrap();
    assert_eq!(cases.len(), expected.len());
    for (case, (id, result)) in cases.iter().zip(expected) {
        assert_eq!(case["id"], id);
        let input = case["input"].as_str().unwrap();
        let observed = if id == "v2-is-not-bare-v1" {
            assert!(strict_json_from_slice::<EffectExecutorDispatchV1>(input.as_bytes()).is_err());
            Err("closed-v1")
        } else {
            classify_shared_wire(input, &trust)
        };
        assert_eq!(observed, result, "{id}");
    }
}
