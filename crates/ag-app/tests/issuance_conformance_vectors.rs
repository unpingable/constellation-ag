//! AG-owned conformance corpus for the governed-loop issuance law.
//!
//! `conformance/governed-loop-issuance/v2-vectors.json` is produced by an
//! independent generator (`make_vectors.py`) and mirrored byte-for-byte by
//! Docket, whose test pins the same SHA-256. This test proves AG's production
//! canonicalization, identity law, signer, and not-after predicate agree with
//! every vector. Changing the corpus is a cross-repository change.

use ag_app::governed_ports::{AgIssuanceSignerV1, SignedAgIssuanceEnvelopeV1};
use ag_campaign::governed::{AG_ISSUANCE_SCHEMA_V1, AG_ISSUANCE_SCHEMA_V2, AgIssuanceV1};
use ag_primitives::JcsDocument;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::signature::{ED25519, UnparsedPublicKey};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

const CORPUS: &[u8] = include_bytes!("../../../conformance/governed-loop-issuance/v2-vectors.json");
/// Pinned identically in Docket's mirror test.
const CORPUS_SHA256: &str = "b715ddcf1d04ca751d8bfb9d81dee1a4dc68db131a7d3c05df3f7f6133eaf513";

fn b64(value: &Value) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(value.as_str().unwrap()).unwrap()
}

fn signature_valid(corpus: &Value, envelope: &SignedAgIssuanceEnvelopeV1) -> bool {
    let issuer = corpus["trust"]["issuers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|issuer| {
            issuer["issuer_principal"] == envelope.authentication.issuer_principal.as_str()
                && issuer["key_id"] == envelope.authentication.signer_key_id.as_str()
        })
        .expect("vector issuer is in the corpus trust set");
    let mut signed = b64(&corpus["signature_prefix_b64"]);
    signed.extend(URL_SAFE_NO_PAD.decode(&envelope.body_b64).unwrap());
    UnparsedPublicKey::new(&ED25519, b64(&issuer["public_key"]))
        .verify(
            &signed,
            &URL_SAFE_NO_PAD
                .decode(&envelope.authentication.signature)
                .unwrap(),
        )
        .is_ok()
}

#[test]
fn ag_production_law_agrees_with_every_issuance_vector() {
    assert_eq!(hex(&Sha256::digest(CORPUS)), CORPUS_SHA256);
    let corpus: Value = serde_json::from_slice(CORPUS).unwrap();
    assert_eq!(
        b64(&corpus["signature_prefix_b64"]),
        b"ag-ng\0governed-loop-issuance-signature\0v1\0"
    );
    let signer = AgIssuanceSignerV1::from_pkcs8(
        "conformance.ag-issuer",
        "conformance.ag-issuer.v2-vectors",
        &b64(&corpus["test_signing_key_pkcs8_v2_b64"]),
    )
    .unwrap();
    let mut seen = Vec::new();
    for vector in corpus["vectors"].as_array().unwrap() {
        let name = vector["name"].as_str().unwrap();
        seen.push(name);
        let envelope: SignedAgIssuanceEnvelopeV1 =
            serde_json::from_value(vector["envelope"].clone()).unwrap();
        let body = URL_SAFE_NO_PAD.decode(&envelope.body_b64).unwrap();
        assert_eq!(
            body,
            vector["body_jcs"].as_str().unwrap().as_bytes(),
            "{name}"
        );
        let issuance: AgIssuanceV1 = serde_json::from_slice(&body).unwrap();
        // AG's canonical bytes are exactly the signed body bytes.
        assert_eq!(
            JcsDocument::canonicalize(&issuance).unwrap().as_bytes(),
            body.as_slice(),
            "{name}"
        );
        let identity = issuance.expected_identity();
        let authentic = signature_valid(&corpus, &envelope);
        match vector["verify"].as_str().unwrap() {
            "ok" => {
                assert!(authentic, "{name}");
                assert_eq!(
                    identity.unwrap().as_str(),
                    vector["issuance"].as_str().unwrap()
                );
            }
            "governed-issuance-signature-invalid" => assert!(!authentic, "{name}"),
            "governed-issuance-identity-mismatch" => {
                assert!(authentic, "{name}");
                assert_ne!(identity.unwrap(), issuance.issuance, "{name}");
            }
            "governed-issuance-not-after-shape" => assert!(identity.is_err(), "{name}"),
            other => panic!("unknown expectation {other}"),
        }
        for check in vector["dispatch"].as_array().unwrap() {
            let now = check["now_unix_ms"].as_u64().unwrap();
            assert_eq!(
                issuance.is_current_at(now),
                check["expect"] == "current",
                "{name} at {now}"
            );
        }
        match name {
            // AG's own signer reproduces the vector envelope exactly.
            "v2-current" => {
                assert_eq!(issuance.schema, AG_ISSUANCE_SCHEMA_V2);
                assert_eq!(signer.sign(&issuance).unwrap(), envelope);
            }
            "v1-alpha6-retained" => {
                assert_eq!(issuance.schema, AG_ISSUANCE_SCHEMA_V1);
                assert_eq!(
                    issuance.issuance.as_str(),
                    "sha256:2f33d498a0753457402c2afe99ec05da25dd9c425a0f53adddc01fed640013d9"
                );
            }
            _ => {}
        }
    }
    assert_eq!(
        seen,
        [
            "v2-current",
            "v1-alpha6-retained",
            "v2-not-after-extended-under-original-signature",
            "v2-not-after-extended-resigned-with-stale-identity",
            "v2-without-not-after",
            "v1-with-not-after",
        ]
    );
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut output, byte| {
        let _ = write!(output, "{byte:02x}");
        output
    })
}
