#!/usr/bin/env python3
"""Independent generator for the AG governed-loop issuance conformance corpus.

A third implementation (Python) of the identity and signature law. AG and
Docket each verify the emitted corpus with their own production code.
"""
import base64, hashlib, json, sys
from nacl.signing import SigningKey, VerifyKey

PREFIX = b"ag-ng\0governed-loop-issuance-signature\0v1\0"

def hash_domain(domain: str, payload: bytes) -> str:
    h = hashlib.sha256()
    h.update(b"ag-ng\0digest\0v1\0")
    h.update(len(domain).to_bytes(16, "big")); h.update(domain.encode())
    h.update(len(payload).to_bytes(16, "big")); h.update(payload)
    return "sha256:" + h.hexdigest()

def jcs(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def identity(body: dict) -> str:
    basis = {k: v for k, v in body.items() if k not in ("schema", "issuance")}
    return hash_domain(body["schema"], jcs(basis))

SEED = hashlib.sha256(b"constellation conformance vector key: ag governed-loop issuance v2; NOT A DEPLOYMENT KEY").digest()
KEY = SigningKey(SEED)
PUB = bytes(KEY.verify_key)
PKCS8_V2 = bytes.fromhex("3053020101300506032b657004220420") + SEED + bytes.fromhex("a123032100") + PUB
TEST_ISSUER = {"issuer_principal": "conformance.ag-issuer", "key_id": "conformance.ag-issuer.v2-vectors", "public_key": b64(PUB)}

def sign(body_bytes: bytes) -> dict:
    return {
        "issuer_principal": TEST_ISSUER["issuer_principal"],
        "signer_key_id": TEST_ISSUER["key_id"],
        "signer_public_key": TEST_ISSUER["public_key"],
        "signature": b64(KEY.sign(PREFIX + body_bytes).signature),
    }

def envelope(body_bytes: bytes, auth: dict) -> dict:
    return {"schema": "ag.governed-loop.signed-issuance/v1", "body_b64": b64(body_bytes), "authentication": auth}

def h(c): return "sha256:" + c * 64

NOT_AFTER = 1_790_000_060_000
v2 = {
    "schema": "ag.governed-loop.issuance/v2",
    "key": {"campaign": h("1"), "occurrence": "00000000-0000-4000-8000-0000000000e1"},
    "program": h("2"), "proposal": h("3"), "work_schema": "conformance.exact-work/v1",
    "work": h("4"), "subject": h("5"), "scope": h("6"), "observation": h("7"),
    "standing_resolution": h("8"), "mandate": h("9"), "spend": h("a"),
    "not_after_unix_ms": NOT_AFTER,
}
v2["issuance"] = identity(v2)
v2_bytes = jcs(v2)
v2_auth = sign(v2_bytes)

# Retained alpha.6 public evidence (unpingable-site constellation/releases/0.1.0-alpha.6/evidence/objective.json,
# occurrences[0].detail.docket[0].result.raw.record).
objective = json.load(open(sys.argv[1]))
record = objective["occurrences"][0]["detail"]["docket"][0]["result"]["raw"]["record"]
v1 = record["issuance"]; v1_auth = record["authentication"]
v1_bytes = jcs(v1)
assert identity(v1) == v1["issuance"] == "sha256:2f33d498a0753457402c2afe99ec05da25dd9c425a0f53adddc01fed640013d9"
VerifyKey(base64.urlsafe_b64decode(v1_auth["signer_public_key"] + "==")).verify(
    PREFIX + v1_bytes, base64.urlsafe_b64decode(v1_auth["signature"] + "=="))
ALPHA6_ISSUER = {"issuer_principal": v1_auth["issuer_principal"], "key_id": v1_auth["signer_key_id"], "public_key": v1_auth["signer_public_key"]}

tampered = dict(v2); tampered["not_after_unix_ms"] = NOT_AFTER + 3_600_000
tampered_bytes = jcs(tampered)
missing = {k: v for k, v in v2.items() if k != "not_after_unix_ms"}
missing_bytes = jcs(missing)
v1_with = dict(v1); v1_with["not_after_unix_ms"] = NOT_AFTER
v1_with_bytes = jcs(v1_with)

vectors = [
    {"name": "v2-current", "envelope": envelope(v2_bytes, v2_auth), "body_jcs": v2_bytes.decode(),
     "issuance": v2["issuance"], "verify": "ok",
     "dispatch": [{"now_unix_ms": NOT_AFTER - 1, "expect": "current"},
                  {"now_unix_ms": NOT_AFTER, "expect": "governed-issuance-expired"},
                  {"now_unix_ms": NOT_AFTER + 1, "expect": "governed-issuance-expired"}]},
    {"name": "v1-alpha6-retained", "envelope": envelope(v1_bytes, v1_auth), "body_jcs": v1_bytes.decode(),
     "issuance": v1["issuance"], "verify": "ok",
     "dispatch": [{"now_unix_ms": 0, "expect": "governed-issuance-not-after-absent"},
                  {"now_unix_ms": NOT_AFTER, "expect": "governed-issuance-not-after-absent"}]},
    {"name": "v2-not-after-extended-under-original-signature", "envelope": envelope(tampered_bytes, v2_auth),
     "body_jcs": tampered_bytes.decode(), "issuance": v2["issuance"], "verify": "governed-issuance-signature-invalid",
     "dispatch": []},
    {"name": "v2-not-after-extended-resigned-with-stale-identity", "envelope": envelope(tampered_bytes, sign(tampered_bytes)),
     "body_jcs": tampered_bytes.decode(), "issuance": v2["issuance"], "verify": "governed-issuance-identity-mismatch",
     "dispatch": []},
    {"name": "v2-without-not-after", "envelope": envelope(missing_bytes, sign(missing_bytes)),
     "body_jcs": missing_bytes.decode(), "issuance": v2["issuance"], "verify": "governed-issuance-not-after-shape",
     "dispatch": []},
    {"name": "v1-with-not-after", "envelope": envelope(v1_with_bytes, sign(v1_with_bytes)),
     "body_jcs": v1_with_bytes.decode(), "issuance": v1["issuance"], "verify": "governed-issuance-not-after-shape",
     "dispatch": []},
]
corpus = {
    "schema": "constellation.conformance.ag-governed-loop-issuance/v2",
    "owner": "unpingable/constellation-ag",
    "law": "AG governed-loop issuance identity (ag.governed-loop.issuance/v1 and /v2), canonical JCS body bytes, Ed25519 signature over prefix||body, and exclusive not-after at dispatch",
    "signature_prefix_b64": b64(PREFIX),
    "test_signing_key_pkcs8_v2_b64": b64(PKCS8_V2),
    "test_signing_key_note": "conformance-only key derived from a public seed; never trust it in a deployment",
    "trust": {"issuers": [TEST_ISSUER, ALPHA6_ISSUER]},
    "vectors": vectors,
}
sys.stdout.write(json.dumps(corpus, indent=2, sort_keys=True) + "\n")
