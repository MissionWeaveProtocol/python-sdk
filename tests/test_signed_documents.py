from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from missionweaveprotocol import (
    ExpectedSignerRule,
    KeyRegistryCompleteness,
    KeyRegistrySnapshot,
    KeyResolutionRequest,
    PrincipalEvidence,
    SignedDocumentCodec,
    SignedDocumentKind,
    SignedDocumentSigningError,
    SignedDocumentVerificationError,
    VerificationStage,
)
from missionweaveprotocol.canonical import canonical_bytes

ROOT = Path(__file__).resolve().parents[1]


class FixtureSigningKey:
    algorithm = "Ed25519"

    def __init__(self, fixture: dict[str, object]) -> None:
        self.key_id = str(fixture["keyId"])
        self.signed_messages: list[bytes] = []
        seed = base64.urlsafe_b64decode(str(fixture["seed"]) + "==")
        self._private_key = Ed25519PrivateKey.from_private_bytes(seed)
        self.public_key_bytes = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def sign(self, message: bytes) -> bytes:
        self.signed_messages.append(message)
        return self._private_key.sign(message)


class FixtureKeyResolver:
    def __init__(self, path: str) -> None:
        self._evidence = (ROOT / path).read_bytes()
        self.requests: list[KeyResolutionRequest] = []

    @property
    def requested_key_ids(self) -> list[str]:
        return [request.key_id for request in self.requests]

    def resolve(self, request: KeyResolutionRequest) -> KeyRegistrySnapshot:
        self.requests.append(request)
        return KeyRegistrySnapshot(
            completeness=KeyRegistryCompleteness.ORGANIZATION_WIDE,
            registry_bytes=self._evidence,
        )


class StaticSigningKey:
    algorithm = "Ed25519"

    def __init__(self, key_id: str, public_key: str, signature: str) -> None:
        self.key_id = key_id
        self.public_key_bytes = base64.urlsafe_b64decode(public_key + "==")
        self._signature = base64.urlsafe_b64decode(signature + "==")

    def sign(self, message: bytes) -> bytes:
        del message
        return self._signature


def _json(path: str) -> dict[str, object]:
    value = json.loads((ROOT / path).read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def test_signs_the_golden_command_without_mutating_the_unsigned_object() -> None:
    expected = _json("cryptography/vectors/signed-documents/valid/command.json")
    unsigned = dict(expected)
    signature = unsigned.pop("signature")
    assert isinstance(signature, dict)
    signing_key = FixtureSigningKey(_json("cryptography/keys/signing-coordinator.json"))

    signed = SignedDocumentCodec().sign(SignedDocumentKind.COMMAND, unsigned, signing_key)

    assert "signature" not in unsigned
    assert signed.document == expected
    assert signed.protected_time.text == "2026-07-15T00:00:00Z"
    assert signed.signature.created_at == signed.protected_time.text
    assert signed.signature.key_id == signature["keyId"]
    assert signed.signature.value == signature["value"]
    assert (
        signed.canonical_signing_bytes
        == (ROOT / "cryptography/vectors/canonicalization/command.signing.jcs").read_bytes()
    )
    assert signed.signing_hash == (
        "sha256:6655c5d67ae3ecc19a4ed04bda7f1372aeaafc7adf939a77715de96ef2100695"
    )
    assert signed.document_hash == (
        "sha256:1d17d0bd5379e554d48d14a6b328671f12860c6c3278bc1e7ca4e1163a74353f"
    )


def test_verifies_the_golden_command_and_returns_complete_immutable_evidence() -> None:
    raw = (ROOT / "cryptography/vectors/signed-documents/valid/command.json").read_bytes()
    resolver = FixtureKeyResolver("cryptography/keys/registry-valid.json")

    verified = SignedDocumentCodec().verify(SignedDocumentKind.COMMAND, raw, resolver)

    assert verified.received_bytes == raw
    assert verified.document == _json("cryptography/vectors/signed-documents/valid/command.json")
    with pytest.raises(TypeError):
        verified.document["kind"] = "tampered"  # type: ignore[index]
    assert (
        verified.canonical_signing_bytes
        == (ROOT / "cryptography/vectors/canonicalization/command.signing.jcs").read_bytes()
    )
    assert verified.signing_hash == (
        "sha256:6655c5d67ae3ecc19a4ed04bda7f1372aeaafc7adf939a77715de96ef2100695"
    )
    assert verified.document_hash == (
        "sha256:1d17d0bd5379e554d48d14a6b328671f12860c6c3278bc1e7ca4e1163a74353f"
    )
    assert verified.protected_time.text == "2026-07-15T00:00:00Z"
    assert verified.signature.value == (
        "PMeeKgpw-HlGNwHbQbEMrfAxbw1815fBdFhOSTHy31ss90eTcuQ4rWeRZbmqFFtHgLKzd0gNm67-HenzwGVhAg"
    )
    assert verified.resolved_key.key_id == resolver.requested_key_ids[0]
    assert verified.resolved_key.principal == PrincipalEvidence(
        type="agent",
        id="urn:missionweaveprotocol:agent:crypto-vector-coordinator",
    )
    assert verified.resolved_key.organization_id == "urn:missionweaveprotocol:organization:acme"


def test_executes_all_protocol_owned_cryptography_evaluations() -> None:
    manifest = _json("cryptography/manifest.json")
    cases = manifest["cases"]
    assert isinstance(cases, list)
    codec = SignedDocumentCodec()
    evaluation_count = 0
    completed_count = 0

    for case in cases:
        assert isinstance(case, dict)
        evaluations = case["evaluations"]
        assert isinstance(evaluations, list)
        for evaluation in evaluations:
            evaluation_count += 1
            assert isinstance(evaluation, dict)
            if case["kind"] == "canonicalization":
                value = json.loads((ROOT / str(evaluation["input"])).read_text(encoding="utf-8"))
                actual = canonical_bytes(value)
                assert actual == (ROOT / str(evaluation["expectedJcs"])).read_bytes()
                assert f"sha256:{hashlib.sha256(actual).hexdigest()}" == evaluation["sha256"]
                completed_count += 1
                continue

            kind = SignedDocumentKind(str(evaluation["profileId"]))
            raw = (ROOT / str(evaluation["document"])).read_bytes()
            resolver = FixtureKeyResolver(str(evaluation["registry"]))
            expected = evaluation["expect"]
            assert isinstance(expected, dict)
            if expected["stage"] != "complete":
                with pytest.raises(SignedDocumentVerificationError) as rejected:
                    codec.verify(kind, raw, resolver)
                assert rejected.value.protected_error.stage.value == expected["stage"]
                assert rejected.value.wire_error.code.value == expected["wireCode"]
                continue

            verified = codec.verify(kind, raw, resolver)
            evidence = expected["verified"]
            assert isinstance(evidence, dict)
            principal = evidence["principal"]
            assert isinstance(principal, dict)
            assert verified.resolved_key.key_id == evidence["keyId"]
            assert verified.resolved_key.principal == PrincipalEvidence(
                type=str(principal["type"]), id=str(principal["id"])
            )
            assert verified.protected_time.text == evidence["protectedTime"]
            assert (
                verified.canonical_signing_bytes
                == (ROOT / str(evidence["signingBytes"])).read_bytes()
            )
            assert verified.signing_hash == evidence["signingHash"]
            assert verified.signature.value == evidence["signature"]
            assert verified.document_hash == evidence["signedDocumentHash"]

            document = json.loads(raw)
            assert isinstance(document, dict)
            document.pop("signature")
            signing_key = FixtureSigningKey(_json(str(evaluation["signingKey"])))
            signed = codec.sign(kind, document, signing_key)
            assert signed.canonical_signing_bytes == verified.canonical_signing_bytes
            assert signed.signing_hash == verified.signing_hash
            assert signed.signature.value == verified.signature.value
            assert signed.document_hash == verified.document_hash
            completed_count += 1

    assert len(cases) == 22
    assert evaluation_count == 58
    assert completed_count == 12


def test_sign_rejects_a_non_prime_order_public_key_before_backend_verification() -> None:
    document = _json("cryptography/vectors/signed-documents/invalid/command-weak-key-forgery.json")
    signature = document.pop("signature")
    assert isinstance(signature, dict)
    registry = _json("cryptography/keys/registry-public-key-identity.json")
    bindings = registry["bindings"]
    assert isinstance(bindings, list) and isinstance(bindings[0], dict)
    key = StaticSigningKey(
        str(signature["keyId"]),
        str(bindings[0]["publicKey"]),
        str(signature["value"]),
    )

    with pytest.raises(SignedDocumentSigningError, match="prime-order"):
        SignedDocumentCodec().sign(SignedDocumentKind.COMMAND, document, key)


def test_sign_rejects_a_returned_signature_with_non_prime_order_r() -> None:
    document = _json(
        "cryptography/vectors/signed-documents/invalid/command-signature-r-small-order.json"
    )
    signature = document.pop("signature")
    assert isinstance(signature, dict)
    signing_fixture = _json("cryptography/keys/signing-coordinator.json")
    key = StaticSigningKey(
        str(signature["keyId"]),
        str(signing_fixture["publicKey"]),
        str(signature["value"]),
    )

    with pytest.raises(SignedDocumentSigningError, match=r"signature R.*prime-order"):
        SignedDocumentCodec().sign(SignedDocumentKind.COMMAND, document, key)


def test_sign_rejects_a_returned_signature_with_an_out_of_range_s() -> None:
    document = _json(
        "cryptography/vectors/signed-documents/invalid/command-signature-s-out-of-range.json"
    )
    signature = document.pop("signature")
    assert isinstance(signature, dict)
    signing_fixture = _json("cryptography/keys/signing-coordinator.json")
    key = StaticSigningKey(
        str(signature["keyId"]),
        str(signing_fixture["publicKey"]),
        str(signature["value"]),
    )

    with pytest.raises(SignedDocumentSigningError, match=r"signature S.*scalar range"):
        SignedDocumentCodec().sign(SignedDocumentKind.COMMAND, document, key)


@pytest.mark.parametrize("invalid_kind", ["command", None])
def test_public_operations_require_an_explicit_signed_document_kind(
    invalid_kind: object,
) -> None:
    unsigned = _json("cryptography/vectors/signed-documents/valid/command.json")
    unsigned.pop("signature")
    signing_key = FixtureSigningKey(_json("cryptography/keys/signing-coordinator.json"))
    raw = (ROOT / "cryptography/vectors/signed-documents/valid/command.json").read_bytes()
    resolver = FixtureKeyResolver("cryptography/keys/registry-valid.json")
    codec = SignedDocumentCodec()

    with pytest.raises(TypeError, match="kind inference"):
        codec.sign(invalid_kind, unsigned, signing_key)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="kind inference"):
        codec.verify(invalid_kind, raw, resolver)  # type: ignore[arg-type]

    assert resolver.requested_key_ids == []


def test_sign_rejects_an_existing_top_level_signature_without_using_the_key() -> None:
    complete = _json("cryptography/vectors/signed-documents/valid/command.json")
    signing_key = FixtureSigningKey(_json("cryptography/keys/signing-coordinator.json"))

    with pytest.raises(SignedDocumentSigningError, match="already contains top-level signature"):
        SignedDocumentCodec().sign(SignedDocumentKind.COMMAND, complete, signing_key)

    assert signing_key.signed_messages == []


@pytest.mark.parametrize(
    ("unsupported", "type_name"),
    [
        pytest.param(("not", "a", "JSON array"), "tuple", id="tuple"),
        pytest.param(
            datetime(2026, 7, 15, tzinfo=UTC),
            "datetime",
            id="datetime",
        ),
        pytest.param(object(), "object", id="custom-object"),
    ],
)
def test_sign_rejects_host_values_instead_of_coercing_them(
    unsupported: object, type_name: str
) -> None:
    unsigned = _json("cryptography/vectors/signed-documents/valid/command.json")
    unsigned.pop("signature")
    unsigned["payload"] = {"unsupported": unsupported}
    signing_key = FixtureSigningKey(_json("cryptography/keys/signing-coordinator.json"))

    with pytest.raises(SignedDocumentSigningError, match=f"unsupported host value {type_name}"):
        SignedDocumentCodec().sign(SignedDocumentKind.COMMAND, unsigned, signing_key)

    assert signing_key.signed_messages == []


def test_authentication_failures_share_one_non_oracular_wire_error() -> None:
    cases = [
        (
            "cryptography/vectors/signed-documents/invalid/command-created-at-mismatch.json",
            VerificationStage.SIGNATURE_ENVELOPE,
        ),
        (
            "cryptography/vectors/signed-documents/invalid/command-unknown-key.json",
            VerificationStage.KEY_RESOLUTION,
        ),
        (
            "cryptography/vectors/signed-documents/invalid/command-payload-tamper.json",
            VerificationStage.SIGNATURE,
        ),
    ]
    rejected_errors: list[SignedDocumentVerificationError] = []

    for path, expected_stage in cases:
        resolver = FixtureKeyResolver("cryptography/keys/registry-valid.json")
        with pytest.raises(SignedDocumentVerificationError) as rejected:
            SignedDocumentCodec().verify(
                SignedDocumentKind.COMMAND, (ROOT / path).read_bytes(), resolver
            )
        error = rejected.value
        assert error.protected_error.stage == expected_stage
        assert error.protected_error.reason
        assert error.protected_error.reason not in str(error)
        rejected_errors.append(error)

    expected_wire_error = rejected_errors[0].wire_error
    assert expected_wire_error.message == "signed document rejected"
    assert expected_wire_error.retryable is False
    assert all(error.wire_error == expected_wire_error for error in rejected_errors)
    assert len({str(error) for error in rejected_errors}) == 1


@pytest.mark.parametrize(
    ("path", "expected_stage"),
    [
        pytest.param(
            "cryptography/vectors/signed-documents/invalid/command-invalid-utf8.bin",
            VerificationStage.PARSE,
            id="parse",
        ),
        pytest.param(
            "cryptography/vectors/signed-documents/invalid/command-padded-signature.json",
            VerificationStage.SCHEMA,
            id="schema",
        ),
        pytest.param(
            "cryptography/vectors/signed-documents/invalid/command-created-at-mismatch.json",
            VerificationStage.SIGNATURE_ENVELOPE,
            id="signature-envelope",
        ),
    ],
)
def test_verify_does_not_resolve_a_key_before_key_resolution(
    path: str, expected_stage: VerificationStage
) -> None:
    resolver = FixtureKeyResolver("cryptography/keys/registry-valid.json")

    with pytest.raises(SignedDocumentVerificationError) as rejected:
        SignedDocumentCodec().verify(
            SignedDocumentKind.COMMAND, (ROOT / path).read_bytes(), resolver
        )

    assert rejected.value.protected_error.stage == expected_stage
    assert resolver.requested_key_ids == []


def test_verify_resolves_exactly_the_envelope_key_at_key_resolution() -> None:
    path = "cryptography/vectors/signed-documents/invalid/command-unknown-key.json"
    document = _json(path)
    signature = document["signature"]
    assert isinstance(signature, dict)
    resolver = FixtureKeyResolver("cryptography/keys/registry-valid.json")

    with pytest.raises(SignedDocumentVerificationError) as rejected:
        SignedDocumentCodec().verify(
            SignedDocumentKind.COMMAND, (ROOT / path).read_bytes(), resolver
        )

    assert rejected.value.protected_error.stage == VerificationStage.KEY_RESOLUTION
    assert resolver.requested_key_ids == [str(signature["keyId"])]
    request = resolver.requests[0]
    assert request.kind is SignedDocumentKind.COMMAND
    assert request.expected_signer.rule is ExpectedSignerRule.EXACT_PRINCIPAL
    assert request.expected_signer.principal == PrincipalEvidence(
        type="agent",
        id="urn:missionweaveprotocol:agent:crypto-vector-coordinator",
    )
    assert request.protected_time.text == "2026-07-15T00:00:00Z"


def test_verify_fails_closed_without_organization_wide_registry_completeness() -> None:
    raw = (ROOT / "cryptography/vectors/signed-documents/valid/command.json").read_bytes()
    registry = (ROOT / "cryptography/keys/registry-valid.json").read_bytes()

    class PartialKeyResolver:
        def resolve(self, request: KeyResolutionRequest) -> KeyRegistrySnapshot:
            del request
            return KeyRegistrySnapshot(
                completeness="partial",  # type: ignore[arg-type]
                registry_bytes=registry,
            )

    with pytest.raises(SignedDocumentVerificationError) as rejected:
        SignedDocumentCodec().verify(
            SignedDocumentKind.COMMAND,
            raw,
            PartialKeyResolver(),
        )

    assert rejected.value.protected_error.stage is VerificationStage.KEY_RESOLUTION
    assert rejected.value.wire_error.code.value == "AUTH_INVALID_SIGNATURE"
    assert "organization-wide" in rejected.value.protected_error.reason


def test_runtime_registry_is_not_limited_by_the_test_fixture_max_items() -> None:
    raw = (ROOT / "cryptography/vectors/signed-documents/valid/command.json").read_bytes()
    registry = _json("cryptography/keys/registry-valid.json")
    bindings = registry["bindings"]
    assert isinstance(bindings, list) and isinstance(bindings[0], dict)
    registry["bindings"] = [dict(bindings[0]) for _ in range(65)]
    registry_bytes = json.dumps(registry, separators=(",", ":")).encode()

    class LargeRegistryResolver:
        def resolve(self, request: KeyResolutionRequest) -> KeyRegistrySnapshot:
            del request
            return KeyRegistrySnapshot(
                completeness=KeyRegistryCompleteness.ORGANIZATION_WIDE,
                registry_bytes=registry_bytes,
            )

    verified = SignedDocumentCodec().verify(
        SignedDocumentKind.COMMAND,
        raw,
        LargeRegistryResolver(),
    )

    assert verified.resolved_key.key_id == bindings[0]["keyId"]


def test_sign_normalizes_host_integers_to_binary64_without_losing_exact_values() -> None:
    unsigned = _json("cryptography/vectors/signed-documents/valid/command.json")
    unsigned.pop("signature")
    payload = unsigned["payload"]
    assert isinstance(payload, dict)
    payload["binary64Integer"] = 9_007_199_254_740_992
    signing_key = FixtureSigningKey(_json("cryptography/keys/signing-coordinator.json"))
    codec = SignedDocumentCodec()

    signed = codec.sign(SignedDocumentKind.COMMAND, unsigned, signing_key)
    verified = codec.verify(
        SignedDocumentKind.COMMAND,
        signed.canonical_document_bytes,
        FixtureKeyResolver("cryptography/keys/registry-valid.json"),
    )

    assert b'"binary64Integer":9007199254740992' in signed.canonical_signing_bytes
    signed_payload = signed.document["payload"]
    assert isinstance(signed_payload, Mapping)
    assert type(signed_payload["binary64Integer"]) is float
    assert signed.document == verified.document


def test_verify_classifies_a_signature_metadata_surrogate_at_canonicalization() -> None:
    document = _json("cryptography/vectors/signed-documents/valid/command.json")
    signature = document["signature"]
    assert isinstance(signature, dict)
    original_key_id = signature["keyId"]
    bad_key_id = "urn:missionweaveprotocol:key:\ud800"
    signature["keyId"] = bad_key_id

    registry = _json("cryptography/keys/registry-valid.json")
    bindings = registry["bindings"]
    assert isinstance(bindings, list)
    for binding in bindings:
        assert isinstance(binding, dict)
        if binding["keyId"] == original_key_id:
            binding["keyId"] = bad_key_id

    raw = json.dumps(document, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    registry_raw = json.dumps(registry, ensure_ascii=True, separators=(",", ":")).encode("utf-8")

    class SurrogateRegistryResolver:
        def resolve(self, request: KeyResolutionRequest) -> KeyRegistrySnapshot:
            assert request.key_id == bad_key_id
            return KeyRegistrySnapshot(
                completeness=KeyRegistryCompleteness.ORGANIZATION_WIDE,
                registry_bytes=registry_raw,
            )

    with pytest.raises(SignedDocumentVerificationError) as rejected:
        SignedDocumentCodec().verify(SignedDocumentKind.COMMAND, raw, SurrogateRegistryResolver())

    assert rejected.value.protected_error.stage == VerificationStage.CANONICALIZATION
    assert rejected.value.wire_error.code.value == "PROTOCOL_VIOLATION"


def test_verify_preserves_a_labeled_diagnostic_for_trailing_json_data() -> None:
    resolver = FixtureKeyResolver("cryptography/keys/registry-valid.json")

    with pytest.raises(SignedDocumentVerificationError) as rejected:
        SignedDocumentCodec().verify(SignedDocumentKind.COMMAND, b"{} {}", resolver)

    assert rejected.value.protected_error.stage == VerificationStage.PARSE
    assert rejected.value.protected_error.reason == (
        "Signed Document is not exactly one JSON value: Extra data at offset 3"
    )
    assert resolver.requested_key_ids == []
