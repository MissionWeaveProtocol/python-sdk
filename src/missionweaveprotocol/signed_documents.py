"""Strict signing and verification for the nine v0.1 Signed Document profiles."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal
from enum import StrEnum
from functools import total_ordering
from types import MappingProxyType
from typing import Any, NoReturn, Protocol, runtime_checkable

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import ValidationError
from jsonschema.validators import extend, validator_for
from referencing import Registry, Resource

from .conformance import default_schema_root
from .schema_formats import protocol_format_checker
from .wire import ErrorCode


class SignedDocumentKind(StrEnum):
    """The nine Signed Document Verification Profile kinds."""

    AGENT_CARD = "agent-card"
    APPROVAL = "approval"
    ARTIFACT = "artifact"
    COMMAND = "command"
    CONTEXT_PACKAGE = "context-package"
    EVENT = "event"
    EVIDENCE = "evidence"
    EXTENSION_PROFILE = "extension-profile"
    GROUP_SNAPSHOT = "group-snapshot"


class SignedDocumentSigningError(ValueError):
    """An unsigned value or signing adapter cannot produce a conforming document."""


class VerificationStage(StrEnum):
    """Normative first-failure stages from Protocol Section 6.4."""

    PARSE = "parse"
    SCHEMA = "schema"
    SIGNATURE_ENVELOPE = "signature-envelope"
    KEY_RESOLUTION = "key-resolution"
    CANONICALIZATION = "canonicalization"
    SIGNATURE = "signature"


@dataclass(frozen=True, slots=True)
class WireVerificationError:
    """Non-oracular wire-safe verification failure."""

    code: ErrorCode
    message: str = "signed document rejected"
    retryable: bool = False


@dataclass(frozen=True, slots=True)
class ProtectedVerificationError:
    """Protected operator detail identifying the exact normative failure."""

    stage: VerificationStage
    reason: str


class SignedDocumentVerificationError(ValueError):
    """A verification failure with separate wire-safe and protected detail."""

    def __init__(self, stage: VerificationStage, reason: str) -> None:
        self.wire_error = WireVerificationError(_WIRE_CODES[stage])
        self.protected_error = ProtectedVerificationError(stage, reason)
        super().__init__(f"{self.wire_error.code.value}: {self.wire_error.message}")


@total_ordering
@dataclass(frozen=True, slots=True)
class ProtectedInstant:
    """An RFC 3339 instant with arbitrary fractional-second precision."""

    epoch_second: int
    fraction: str

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, ProtectedInstant):
            return NotImplemented
        if self.epoch_second != other.epoch_second:
            return self.epoch_second < other.epoch_second
        width = max(len(self.fraction), len(other.fraction))
        return self.fraction.ljust(width, "0") < other.fraction.ljust(width, "0")


@dataclass(frozen=True, slots=True)
class ProtectedTime:
    """Exact protected timestamp text together with its parsed instant."""

    text: str
    instant: ProtectedInstant


@dataclass(frozen=True, slots=True)
class SignatureMaterial:
    """The exact Signed Document signature envelope and decoded signature bytes."""

    algorithm: str
    key_id: str
    created_at: str
    value: str
    bytes: bytes


@dataclass(frozen=True, slots=True)
class PrincipalEvidence:
    """Exact Principal bound to the resolved signing key."""

    type: str
    id: str


class ExpectedSignerRule(StrEnum):
    """Signer constraint already derived from the selected Signed Document profile."""

    EXACT_PRINCIPAL = "exact-principal"
    SERVICE_PRINCIPAL = "service-principal"


@dataclass(frozen=True, slots=True)
class ExpectedSignerEvidence:
    """Signer identity evidence supplied to a KeyResolver request."""

    rule: ExpectedSignerRule
    principal: PrincipalEvidence | None = None


class KeyRegistryCompleteness(StrEnum):
    """Scope over which Registry uniqueness and alias checks can be proven."""

    ORGANIZATION_WIDE = "organization-wide"


@dataclass(frozen=True, slots=True)
class KeyRegistrySnapshot:
    """Raw Agent Registry evidence plus an explicit completeness assertion."""

    completeness: KeyRegistryCompleteness
    registry_bytes: bytes


@dataclass(frozen=True, slots=True)
class KeyResolutionRequest:
    """Context needed to select one complete Organization-wide Agent Registry snapshot."""

    kind: SignedDocumentKind
    key_id: str
    expected_signer: ExpectedSignerEvidence
    protected_time: ProtectedTime


@dataclass(frozen=True, slots=True)
class KeyValidityEvidence:
    """Effective historical key-validity evidence."""

    valid_from: ProtectedInstant
    valid_until: ProtectedInstant | None
    revoked_at: ProtectedInstant | None


@dataclass(frozen=True, slots=True)
class ResolvedKeyEvidence:
    """Validated immutable key binding and effective validity evidence."""

    organization_id: str
    key_id: str
    principal: PrincipalEvidence
    algorithm: str
    public_key_text: str
    public_key_bytes: bytes
    validity: KeyValidityEvidence


@dataclass(frozen=True, slots=True)
class SignedDocument:
    """One newly signed immutable protocol document and its canonical evidence."""

    kind: SignedDocumentKind
    document: Mapping[str, object]
    canonical_signing_bytes: bytes
    signing_hash: str
    canonical_document_bytes: bytes
    document_hash: str
    protected_time: ProtectedTime
    signature: SignatureMaterial


@dataclass(frozen=True, slots=True)
class VerifiedSignedDocument:
    """One cryptographically verified immutable Signed Document and its evidence."""

    kind: SignedDocumentKind
    document: Mapping[str, object]
    received_bytes: bytes
    canonical_signing_bytes: bytes
    signing_hash: str
    canonical_document_bytes: bytes
    document_hash: str
    protected_time: ProtectedTime
    signature: SignatureMaterial
    resolved_key: ResolvedKeyEvidence


@runtime_checkable
class SigningKey(Protocol):
    """Adapter supplying one pure-Ed25519 signing identity."""

    @property
    def algorithm(self) -> str:
        """Return the signing algorithm identifier."""

    @property
    def key_id(self) -> str:
        """Return the Registry key identifier."""

    @property
    def public_key_bytes(self) -> bytes:
        """Return the raw 32-byte Ed25519 public key."""

    def sign(self, message: bytes) -> bytes:
        """Return a raw 64-byte pure-Ed25519 signature."""


@runtime_checkable
class KeyResolver(Protocol):
    """Adapter returning complete Organization-wide Agent Registry evidence for one key lookup."""

    def resolve(self, request: KeyResolutionRequest) -> KeyRegistrySnapshot:
        """Return an explicitly complete Agent Registry snapshot for ``request``."""


@dataclass(frozen=True, slots=True)
class AgentRegistryKeyResolver:
    """Resolve keys from one trusted, complete Organization-controlled Agent Registry snapshot."""

    registry_bytes: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.registry_bytes, bytes):
            raise TypeError("registry_bytes must be bytes")
        object.__setattr__(self, "registry_bytes", bytes(self.registry_bytes))

    def resolve(self, request: KeyResolutionRequest) -> KeyRegistrySnapshot:
        if not isinstance(request, KeyResolutionRequest):
            raise TypeError("request must be a KeyResolutionRequest")
        return KeyRegistrySnapshot(
            completeness=KeyRegistryCompleteness.ORGANIZATION_WIDE,
            registry_bytes=self.registry_bytes,
        )


@dataclass(frozen=True, slots=True)
class _Profile:
    schema_name: str
    protected_time_pointer: str
    signer_rule: str
    signer_pointer: str | None = None


_PROFILES = {
    SignedDocumentKind.AGENT_CARD: _Profile(
        "agent-card.schema.json", "/issuedAt", "service-principal"
    ),
    SignedDocumentKind.APPROVAL: _Profile(
        "approval.schema.json", "/occurredAt", "principal-object", "/approver"
    ),
    SignedDocumentKind.ARTIFACT: _Profile(
        "artifact.schema.json", "/createdAt", "agent-id", "/producer/agentId"
    ),
    SignedDocumentKind.COMMAND: _Profile(
        "command.schema.json", "/issuedAt", "principal-object", "/actor"
    ),
    SignedDocumentKind.CONTEXT_PACKAGE: _Profile(
        "context-package.schema.json", "/generatedAt", "principal-object", "/generatedBy"
    ),
    SignedDocumentKind.EVENT: _Profile(
        "event.schema.json", "/occurredAt", "principal-object", "/acceptedBy"
    ),
    SignedDocumentKind.EVIDENCE: _Profile(
        "evidence.schema.json", "/createdAt", "principal-object", "/generatedBy"
    ),
    SignedDocumentKind.EXTENSION_PROFILE: _Profile(
        "extension-profile.schema.json", "/approvedAt", "principal-object", "/approvedBy"
    ),
    SignedDocumentKind.GROUP_SNAPSHOT: _Profile(
        "group-snapshot.schema.json", "/createdAt", "principal-object", "/createdBy"
    ),
}

_WIRE_CODES = {
    VerificationStage.PARSE: ErrorCode.PROTOCOL_VIOLATION,
    VerificationStage.SCHEMA: ErrorCode.SCHEMA_VALIDATION_FAILED,
    VerificationStage.SIGNATURE_ENVELOPE: ErrorCode.AUTH_INVALID_SIGNATURE,
    VerificationStage.KEY_RESOLUTION: ErrorCode.AUTH_INVALID_SIGNATURE,
    VerificationStage.CANONICALIZATION: ErrorCode.PROTOCOL_VIOLATION,
    VerificationStage.SIGNATURE: ErrorCode.AUTH_INVALID_SIGNATURE,
}

_BASE64URL = re.compile(r"^[A-Za-z0-9_-]+$")
_ED25519_FIELD = 2**255 - 19
_ED25519_ORDER = 2**252 + 27742317777372353535851937790883648493
_ED25519_D = (-121665 * pow(121666, _ED25519_FIELD - 2, _ED25519_FIELD)) % _ED25519_FIELD
_ED25519_SQRT_M1 = pow(2, (_ED25519_FIELD - 1) // 4, _ED25519_FIELD)
_ED25519_IDENTITY = (0, 1, 1, 0)

_RFC3339 = re.compile(
    r"^(?P<year>[0-9]{4})-(?P<month>[0-9]{2})-(?P<day>[0-9]{2})"
    r"[Tt](?P<hour>[0-9]{2}):(?P<minute>[0-9]{2}):(?P<second>[0-9]{2})"
    r"(?:\.(?P<fraction>[0-9]+))?"
    r"(?P<offset>[Zz]|[+-][0-9]{2}:[0-9]{2})$"
)


@dataclass(frozen=True, slots=True)
class _Envelope:
    protected_time: ProtectedTime
    signature: SignatureMaterial
    expected_principal: PrincipalEvidence | None
    service_principal: bool


_FORMAT_CHECKER = protocol_format_checker()


@_FORMAT_CHECKER.checks("date-time")
def _protocol_date_time(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        _parse_rfc3339(value)
    except ValueError:
        return False
    return True


def _is_json_number(_checker: object, value: object) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, Decimal):
        return value.is_finite()
    if isinstance(value, float):
        return math.isfinite(value)
    return isinstance(value, int)


def _is_json_integer(_checker: object, value: object) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, Decimal):
        return value.is_finite() and value == value.to_integral_value()
    if isinstance(value, float):
        return math.isfinite(value) and value.is_integer()
    return isinstance(value, int)


class _SchemaSet:
    def __init__(self) -> None:
        self._root = default_schema_root().resolve()
        schemas: dict[str, Mapping[str, object]] = {}
        resources: list[tuple[str, Resource[Any]]] = []
        for path in sorted(self._root.glob("*.json")):
            value = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(value, dict):
                raise RuntimeError(f"normative schema {path.name} is not an object")
            identifier = value.get("$id")
            if not isinstance(identifier, str):
                raise RuntimeError(f"normative schema {path.name} lacks $id")
            schemas[path.name] = value
            resources.append((identifier, Resource.from_contents(value)))
        self._schemas = schemas
        self._registry = Registry().with_resources(resources)

    def validate(self, schema_name: str, value: object) -> None:
        self._validator(self._schemas[schema_name], registry=self._registry).validate(value)

    @staticmethod
    def _validator(schema: Mapping[str, object], *, registry: Registry | None = None) -> Any:
        validator_type = validator_for(schema)
        type_checker = validator_type.TYPE_CHECKER.redefine("number", _is_json_number).redefine(
            "integer", _is_json_integer
        )
        extended = extend(  # type: ignore[no-untyped-call]
            validator_type, type_checker=type_checker
        )
        options: dict[str, object] = {"format_checker": _FORMAT_CHECKER}
        if registry is not None:
            options["registry"] = registry
        return extended(schema, **options)


class SignedDocumentCodec:
    """Deep module implementing the v0.1 Signed Document cryptographic profile."""

    def __init__(self) -> None:
        self._schemas = _SchemaSet()

    def sign(
        self,
        kind: SignedDocumentKind,
        unsigned_json_object: Mapping[str, object],
        signing_key: SigningKey,
    ) -> SignedDocument:
        """Sign one explicitly selected Signed Document kind."""

        profile = _profile(kind)
        unsigned = _copy_json_object(unsigned_json_object)
        if "signature" in unsigned:
            raise SignedDocumentSigningError(
                "unsigned document already contains top-level signature"
            )
        protected_text = _json_pointer(unsigned, profile.protected_time_pointer)
        if not isinstance(protected_text, str):
            raise SignedDocumentSigningError("protected signed time is not a string")
        if not protected_text.endswith("Z"):
            raise SignedDocumentSigningError("protected signed time must use uppercase Z")
        try:
            protected_instant = _parse_rfc3339(protected_text)
        except ValueError as error:
            raise SignedDocumentSigningError(
                f"protected signed time is invalid: {error}"
            ) from error

        algorithm = getattr(signing_key, "algorithm", None)
        key_id = getattr(signing_key, "key_id", None)
        public_key = getattr(signing_key, "public_key_bytes", None)
        if algorithm != "Ed25519" or not isinstance(key_id, str) or not key_id:
            raise SignedDocumentSigningError("signing key must identify one Ed25519 key")
        if not isinstance(public_key, bytes) or len(public_key) != 32:
            raise SignedDocumentSigningError("signing key must expose a 32-byte Ed25519 public key")
        try:
            _strict_ed25519_point(
                public_key,
                stage=VerificationStage.SIGNATURE,
                label="signing public key",
                allow_identity=False,
            )
        except SignedDocumentVerificationError as error:
            raise SignedDocumentSigningError(
                "signing key must expose a non-identity prime-order Ed25519 public key"
            ) from error

        signing_bytes = _canonicalize(unsigned)
        try:
            signature_bytes = signing_key.sign(signing_bytes)
        except Exception as error:
            raise SignedDocumentSigningError("signing key failed") from error
        if not isinstance(signature_bytes, bytes) or len(signature_bytes) != 64:
            raise SignedDocumentSigningError("signing key did not return a 64-byte signature")
        try:
            _strict_ed25519_point(
                signature_bytes[:32],
                stage=VerificationStage.SIGNATURE,
                label="signature R",
                allow_identity=True,
            )
        except SignedDocumentVerificationError as error:
            raise SignedDocumentSigningError(
                f"signing key returned an invalid Ed25519 signature: {error.protected_error.reason}"
            ) from error
        if int.from_bytes(signature_bytes[32:], "little") >= _ED25519_ORDER:
            raise SignedDocumentSigningError(
                "signing key returned an invalid Ed25519 signature: "
                "signature S is outside the Ed25519 scalar range"
            )
        try:
            Ed25519PublicKey.from_public_bytes(public_key).verify(signature_bytes, signing_bytes)
        except (InvalidSignature, ValueError) as error:
            raise SignedDocumentSigningError(
                "signing key returned an invalid Ed25519 signature"
            ) from error

        signature_value = base64.urlsafe_b64encode(signature_bytes).rstrip(b"=").decode("ascii")
        signature = {
            "algorithm": "Ed25519",
            "keyId": key_id,
            "createdAt": protected_text,
            "value": signature_value,
        }
        complete = dict(unsigned)
        complete["signature"] = signature
        try:
            self._schemas.validate(profile.schema_name, complete)
        except ValidationError as error:
            raise SignedDocumentSigningError(
                f"signed document fails {profile.schema_name}: {_validation_reason(error)}"
            ) from error
        normalized_complete = _jcs_input(complete)
        assert isinstance(normalized_complete, dict)
        complete_bytes = _canonicalize(normalized_complete)
        return SignedDocument(
            kind=kind,
            document=_freeze(normalized_complete),
            canonical_signing_bytes=signing_bytes,
            signing_hash=_sha256(signing_bytes),
            canonical_document_bytes=complete_bytes,
            document_hash=_sha256(complete_bytes),
            protected_time=ProtectedTime(protected_text, protected_instant),
            signature=SignatureMaterial(
                algorithm="Ed25519",
                key_id=key_id,
                created_at=protected_text,
                value=signature_value,
                bytes=signature_bytes,
            ),
        )

    def verify(
        self,
        kind: SignedDocumentKind,
        raw_utf8_json_bytes: bytes,
        key_resolver: KeyResolver,
    ) -> VerifiedSignedDocument:
        """Verify one explicitly selected Signed Document kind through all six stages."""

        profile = _profile(kind)
        if not isinstance(raw_utf8_json_bytes, bytes):
            raise TypeError("raw_utf8_json_bytes must be bytes")
        try:
            document = _strict_json(raw_utf8_json_bytes, label="Signed Document")
        except ValueError as error:
            _verification_failure(VerificationStage.PARSE, str(error))

        try:
            self._schemas.validate(profile.schema_name, document)
        except ValidationError as error:
            _verification_failure(VerificationStage.SCHEMA, _validation_reason(error))
        if not isinstance(document, Mapping):
            _verification_failure(VerificationStage.SCHEMA, "document is not an object")

        envelope = _verify_signature_envelope(document, profile)
        expected_signer = ExpectedSignerEvidence(ExpectedSignerRule.SERVICE_PRINCIPAL)
        if envelope.expected_principal is not None:
            expected_signer = ExpectedSignerEvidence(
                ExpectedSignerRule.EXACT_PRINCIPAL,
                envelope.expected_principal,
            )
        try:
            snapshot = key_resolver.resolve(
                KeyResolutionRequest(
                    kind=kind,
                    key_id=envelope.signature.key_id,
                    expected_signer=expected_signer,
                    protected_time=envelope.protected_time,
                )
            )
        except Exception as error:
            _verification_failure(
                VerificationStage.KEY_RESOLUTION,
                f"key resolver failed: {type(error).__name__}: {error}",
            )
        if not isinstance(snapshot, KeyRegistrySnapshot):
            _verification_failure(
                VerificationStage.KEY_RESOLUTION,
                "key resolver did not return a KeyRegistrySnapshot",
            )
        if snapshot.completeness != KeyRegistryCompleteness.ORGANIZATION_WIDE:
            _verification_failure(
                VerificationStage.KEY_RESOLUTION,
                "key resolver did not establish organization-wide Registry completeness",
            )
        if not isinstance(snapshot.registry_bytes, bytes):
            _verification_failure(
                VerificationStage.KEY_RESOLUTION,
                "KeyRegistrySnapshot.registry_bytes is not bytes",
            )
        resolved_key = _resolve_key(bytes(snapshot.registry_bytes), envelope)

        unsigned = dict(document)
        unsigned.pop("signature", None)
        try:
            signing_bytes = _jcs_bytes(unsigned)
            complete_bytes = _jcs_bytes(document)
        except (rfc8785.CanonicalizationError, UnicodeError, ValueError, OverflowError) as error:
            _verification_failure(
                VerificationStage.CANONICALIZATION,
                f"document is outside the JCS/I-JSON domain: {error}",
            )

        try:
            Ed25519PublicKey.from_public_bytes(resolved_key.public_key_bytes).verify(
                envelope.signature.bytes, signing_bytes
            )
        except (InvalidSignature, ValueError):
            _verification_failure(VerificationStage.SIGNATURE, "Ed25519 signature does not verify")

        return VerifiedSignedDocument(
            kind=kind,
            document=_freeze(_jcs_input(document)),
            received_bytes=bytes(raw_utf8_json_bytes),
            canonical_signing_bytes=signing_bytes,
            signing_hash=_sha256(signing_bytes),
            canonical_document_bytes=complete_bytes,
            document_hash=_sha256(complete_bytes),
            protected_time=envelope.protected_time,
            signature=envelope.signature,
            resolved_key=resolved_key,
        )


def _verification_failure(stage: VerificationStage, reason: str) -> NoReturn:
    raise SignedDocumentVerificationError(stage, reason)


def _validation_reason(error: ValidationError) -> str:
    location = "/" + "/".join(str(part) for part in error.absolute_path)
    return f"{location if location != '/' else '<root>'}: {error.message}"


def _strict_json(raw: bytes, *, label: str) -> object:
    if raw.startswith(b"\xef\xbb\xbf"):
        raise ValueError(f"{label} starts with a UTF-8 byte-order mark")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ValueError(f"{label} is not strict UTF-8: {error}") from error

    def reject_constant(value: str) -> NoReturn:
        raise ValueError(f"non-JSON numeric constant {value!r}")

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for name, value in pairs:
            if name in result:
                raise ValueError(f"duplicate decoded object member {name!r}")
            result[name] = value
        return result

    try:
        return json.loads(
            text,
            parse_int=Decimal,
            parse_float=Decimal,
            parse_constant=reject_constant,
            object_pairs_hook=reject_duplicates,
        )
    except json.JSONDecodeError as error:
        raise ValueError(
            f"{label} is not exactly one JSON value: {error.msg} at offset {error.pos}"
        ) from error
    except ValueError:
        raise


def _verify_signature_envelope(document: object, profile: _Profile) -> _Envelope:
    if not isinstance(document, Mapping):
        _verification_failure(VerificationStage.SIGNATURE_ENVELOPE, "document is not an object")
    signature = document.get("signature")
    if not isinstance(signature, Mapping):
        _verification_failure(
            VerificationStage.SIGNATURE_ENVELOPE, "signature envelope is not an object"
        )
    protected = _json_pointer_for_verification(
        document, profile.protected_time_pointer, VerificationStage.SIGNATURE_ENVELOPE
    )
    created_at = signature.get("createdAt")
    if not isinstance(protected, str) or not isinstance(created_at, str):
        _verification_failure(
            VerificationStage.SIGNATURE_ENVELOPE, "protected timestamps are not strings"
        )
    try:
        protected_instant = _parse_rfc3339(protected)
        _parse_rfc3339(created_at)
    except ValueError as error:
        _verification_failure(
            VerificationStage.SIGNATURE_ENVELOPE, f"protected timestamp is invalid: {error}"
        )
    if not protected.endswith("Z") or not created_at.endswith("Z"):
        _verification_failure(
            VerificationStage.SIGNATURE_ENVELOPE,
            "protected time and signature.createdAt must use uppercase Z",
        )
    if protected != created_at:
        _verification_failure(
            VerificationStage.SIGNATURE_ENVELOPE,
            "protected time and signature.createdAt are not byte-equal",
        )
    if signature.get("algorithm") != "Ed25519":
        _verification_failure(
            VerificationStage.SIGNATURE_ENVELOPE, "signature.algorithm is not Ed25519"
        )
    key_id = signature.get("keyId")
    if not isinstance(key_id, str):
        _verification_failure(
            VerificationStage.SIGNATURE_ENVELOPE, "signature.keyId is not a string"
        )
    signature_text = signature.get("value")
    signature_bytes = _canonical_base64url(
        signature_text, VerificationStage.SIGNATURE_ENVELOPE, "signature.value"
    )
    if len(signature_bytes) != 64:
        _verification_failure(
            VerificationStage.SIGNATURE_ENVELOPE,
            "signature.value does not decode to 64 bytes",
        )
    _strict_ed25519_point(
        signature_bytes[:32],
        stage=VerificationStage.SIGNATURE_ENVELOPE,
        label="signature R",
        allow_identity=True,
    )
    if int.from_bytes(signature_bytes[32:], "little") >= _ED25519_ORDER:
        _verification_failure(
            VerificationStage.SIGNATURE_ENVELOPE,
            "signature S is outside the Ed25519 scalar range",
        )

    expected_principal: PrincipalEvidence | None = None
    service_principal = profile.signer_rule == "service-principal"
    if profile.signer_rule == "principal-object":
        selected = _json_pointer_for_verification(
            document,
            profile.signer_pointer or "",
            VerificationStage.SIGNATURE_ENVELOPE,
        )
        expected_principal = _principal(
            selected, VerificationStage.SIGNATURE_ENVELOPE, "expected signer"
        )
    elif profile.signer_rule == "agent-id":
        selected = _json_pointer_for_verification(
            document,
            profile.signer_pointer or "",
            VerificationStage.SIGNATURE_ENVELOPE,
        )
        if not isinstance(selected, str):
            _verification_failure(
                VerificationStage.SIGNATURE_ENVELOPE,
                "expected Agent signer ID is not a string",
            )
        expected_principal = PrincipalEvidence("agent", selected)
    return _Envelope(
        protected_time=ProtectedTime(protected, protected_instant),
        signature=SignatureMaterial(
            algorithm="Ed25519",
            key_id=key_id,
            created_at=created_at,
            value=signature_text if isinstance(signature_text, str) else "",
            bytes=signature_bytes,
        ),
        expected_principal=expected_principal,
        service_principal=service_principal,
    )


def _json_pointer_for_verification(
    document: object, pointer: str, stage: VerificationStage
) -> object:
    if not pointer.startswith("/"):
        _verification_failure(stage, f"trusted JSON pointer {pointer!r} is invalid")
    current = document
    for encoded in pointer[1:].split("/"):
        token = encoded.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, Mapping) or token not in current:
            _verification_failure(stage, f"trusted JSON pointer {pointer!r} does not resolve")
        current = current[token]
    return current


def _canonical_base64url(value: object, stage: VerificationStage, label: str) -> bytes:
    if not isinstance(value, str) or not _BASE64URL.fullmatch(value):
        _verification_failure(stage, f"{label} is not unpadded base64url")
    if len(value) % 4 == 1:
        _verification_failure(stage, f"{label} has an impossible base64url length")
    try:
        decoded = base64.b64decode(value + "=" * ((-len(value)) % 4), altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as error:
        _verification_failure(stage, f"{label} cannot be decoded as base64url: {error}")
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    if canonical != value:
        _verification_failure(stage, f"{label} has noncanonical base64url spelling")
    return decoded


def _principal(value: object, stage: VerificationStage, label: str) -> PrincipalEvidence:
    if not isinstance(value, Mapping) or set(value) != {"type", "id"}:
        _verification_failure(stage, f"{label} is not an exact Principal object")
    principal_type = value.get("type")
    principal_id = value.get("id")
    if principal_type not in {"agent", "human", "service"} or not isinstance(principal_id, str):
        _verification_failure(stage, f"{label} is not a supported Principal")
    assert isinstance(principal_type, str)
    return PrincipalEvidence(principal_type, principal_id)


def _resolve_key(raw: bytes, envelope: _Envelope) -> ResolvedKeyEvidence:
    try:
        registry_document = _strict_json(raw, label="Agent Registry evidence")
    except ValueError as error:
        _verification_failure(VerificationStage.KEY_RESOLUTION, str(error))
    if not isinstance(registry_document, Mapping):
        _verification_failure(
            VerificationStage.KEY_RESOLUTION, "Agent Registry evidence is not an object"
        )
    if set(registry_document) != {"organizationId", "bindings"}:
        _verification_failure(
            VerificationStage.KEY_RESOLUTION, "Agent Registry evidence has invalid fields"
        )
    organization_id = registry_document.get("organizationId")
    bindings = registry_document.get("bindings")
    if not isinstance(organization_id, str) or not isinstance(bindings, list) or not bindings:
        _verification_failure(
            VerificationStage.KEY_RESOLUTION, "Agent Registry evidence has invalid fields"
        )

    normalized: dict[str, dict[str, object]] = {}
    public_key_owners: dict[bytes, tuple[str, PrincipalEvidence]] = {}
    tuple_ids: dict[tuple[str, str, bytes], str] = {}
    for index, raw_binding in enumerate(bindings):
        label = f"Registry bindings[{index}]"
        if not isinstance(raw_binding, Mapping):
            _verification_failure(VerificationStage.KEY_RESOLUTION, f"{label} is not an object")
        binding = raw_binding
        if set(binding) != {
            "keyId",
            "principal",
            "algorithm",
            "publicKey",
            "validFrom",
            "validityHistory",
        }:
            _verification_failure(VerificationStage.KEY_RESOLUTION, f"{label} has invalid fields")
        key_id = binding.get("keyId")
        if not isinstance(key_id, str):
            _verification_failure(VerificationStage.KEY_RESOLUTION, f"{label}.keyId is invalid")
        principal = _principal(
            binding.get("principal"), VerificationStage.KEY_RESOLUTION, f"{label}.principal"
        )
        if binding.get("algorithm") != "Ed25519":
            _verification_failure(VerificationStage.KEY_RESOLUTION, f"{label}.algorithm is invalid")
        public_key_text = binding.get("publicKey")
        public_key_bytes = _canonical_base64url(
            public_key_text, VerificationStage.KEY_RESOLUTION, f"{label}.publicKey"
        )
        if len(public_key_bytes) != 32:
            _verification_failure(
                VerificationStage.KEY_RESOLUTION,
                f"{label}.publicKey does not decode to 32 bytes",
            )
        _strict_ed25519_point(
            public_key_bytes,
            stage=VerificationStage.KEY_RESOLUTION,
            label=f"{label}.publicKey",
            allow_identity=False,
        )
        valid_from_text = binding.get("validFrom")
        if not isinstance(valid_from_text, str):
            _verification_failure(VerificationStage.KEY_RESOLUTION, f"{label}.validFrom is invalid")
        try:
            valid_from = _parse_rfc3339(valid_from_text)
        except ValueError as error:
            _verification_failure(
                VerificationStage.KEY_RESOLUTION, f"{label}.validFrom is invalid: {error}"
            )
        history = binding.get("validityHistory")
        if not isinstance(history, list):
            _verification_failure(
                VerificationStage.KEY_RESOLUTION, f"{label}.validityHistory is not an array"
            )
        immutable = (principal, public_key_bytes)
        existing = normalized.get(key_id)
        if existing is not None:
            if existing["immutable"] != immutable or existing["valid_from"] != valid_from:
                _verification_failure(
                    VerificationStage.KEY_RESOLUTION,
                    f"key ID {key_id!r} is reused for another immutable binding",
                )
        else:
            existing = {
                "immutable": immutable,
                "principal": principal,
                "public_key_text": public_key_text,
                "public_key_bytes": public_key_bytes,
                "valid_from": valid_from,
                "history": {},
            }
            normalized[key_id] = existing

        owner = public_key_owners.get(public_key_bytes)
        owner_value = (key_id, principal)
        if owner is not None and owner != owner_value:
            _verification_failure(
                VerificationStage.KEY_RESOLUTION,
                "the same public key is registered under another Principal or key ID",
            )
        public_key_owners[public_key_bytes] = owner_value
        principal_key = (principal.type, principal.id, public_key_bytes)
        alias = tuple_ids.get(principal_key)
        if alias is not None and alias != key_id:
            _verification_failure(
                VerificationStage.KEY_RESOLUTION,
                "a Principal and public-key tuple has a key-ID alias",
            )
        tuple_ids[principal_key] = key_id

        status_map = existing["history"]
        assert isinstance(status_map, dict)
        for history_index, raw_status in enumerate(history):
            status_label = f"{label}.validityHistory[{history_index}]"
            if not isinstance(raw_status, Mapping):
                _verification_failure(
                    VerificationStage.KEY_RESOLUTION, f"{status_label} is not an object"
                )
            if not {"sequence", "recordedAt"}.issubset(raw_status) or not set(raw_status).issubset(
                {"sequence", "recordedAt", "validUntil", "revokedAt"}
            ):
                _verification_failure(
                    VerificationStage.KEY_RESOLUTION,
                    f"{status_label} has invalid fields",
                )
            sequence = raw_status.get("sequence")
            if (
                not isinstance(sequence, Decimal)
                or sequence != sequence.to_integral_value()
                or sequence < 1
                or sequence > 9_007_199_254_740_991
            ):
                _verification_failure(
                    VerificationStage.KEY_RESOLUTION, f"{status_label}.sequence is invalid"
                )
            sequence_number = int(sequence)
            recorded_text = raw_status.get("recordedAt")
            if not isinstance(recorded_text, str):
                _verification_failure(
                    VerificationStage.KEY_RESOLUTION, f"{status_label}.recordedAt is invalid"
                )
            try:
                recorded_status = _parse_rfc3339(recorded_text)
            except ValueError as error:
                _verification_failure(
                    VerificationStage.KEY_RESOLUTION,
                    f"{status_label}.recordedAt is invalid: {error}",
                )
            status: dict[str, object] = {
                "sequence": sequence_number,
                "recorded": recorded_status,
            }
            for field in ("validUntil", "revokedAt"):
                if field in raw_status:
                    text = raw_status[field]
                    if not isinstance(text, str):
                        _verification_failure(
                            VerificationStage.KEY_RESOLUTION, f"{status_label}.{field} is invalid"
                        )
                    try:
                        status[field] = _parse_rfc3339(text)
                    except ValueError as error:
                        _verification_failure(
                            VerificationStage.KEY_RESOLUTION,
                            f"{status_label}.{field} is invalid: {error}",
                        )
            previous = status_map.get(sequence_number)
            if previous is not None and previous != status:
                _verification_failure(
                    VerificationStage.KEY_RESOLUTION,
                    f"{status_label} rewrites an earlier status sequence",
                )
            status_map[sequence_number] = status

    for key_id, binding in normalized.items():
        history = binding["history"]
        assert isinstance(history, dict)
        sequence_numbers = sorted(history)
        if sequence_numbers != list(range(1, len(sequence_numbers) + 1)):
            _verification_failure(
                VerificationStage.KEY_RESOLUTION,
                f"key {key_id!r} validity history is not contiguous",
            )
        recorded_at: ProtectedInstant | None = None
        effective_until: ProtectedInstant | None = None
        effective_revoked: ProtectedInstant | None = None
        for sequence in sequence_numbers:
            status = history[sequence]
            assert isinstance(status, dict)
            history_recorded = status["recorded"]
            assert isinstance(history_recorded, ProtectedInstant)
            if recorded_at is not None and history_recorded < recorded_at:
                _verification_failure(
                    VerificationStage.KEY_RESOLUTION,
                    f"key {key_id!r} validity history is not append ordered",
                )
            recorded_at = history_recorded
            for field in ("validUntil", "revokedAt"):
                candidate = status.get(field)
                if candidate is None:
                    continue
                assert isinstance(candidate, ProtectedInstant)
                current = effective_until if field == "validUntil" else effective_revoked
                if current is not None and candidate > current:
                    _verification_failure(
                        VerificationStage.KEY_RESOLUTION,
                        f"key {key_id!r} moves {field} later in history",
                    )
                if field == "validUntil":
                    effective_until = candidate
                else:
                    effective_revoked = candidate
        binding["valid_until"] = effective_until
        binding["revoked_at"] = effective_revoked

    selected = normalized.get(envelope.signature.key_id)
    if selected is None:
        _verification_failure(VerificationStage.KEY_RESOLUTION, "signature.keyId is unknown")
    resolved_principal = selected["principal"]
    assert isinstance(resolved_principal, PrincipalEvidence)
    if envelope.service_principal:
        if resolved_principal.type != "service":
            _verification_failure(
                VerificationStage.KEY_RESOLUTION,
                "Agent Card signer is not a service Principal",
            )
    elif resolved_principal != envelope.expected_principal:
        _verification_failure(
            VerificationStage.KEY_RESOLUTION, "resolved key is bound to the wrong Principal"
        )
    resolved_valid_from = selected["valid_from"]
    resolved_valid_until = selected["valid_until"]
    resolved_revoked_at = selected["revoked_at"]
    assert isinstance(resolved_valid_from, ProtectedInstant)
    assert resolved_valid_until is None or isinstance(resolved_valid_until, ProtectedInstant)
    assert resolved_revoked_at is None or isinstance(resolved_revoked_at, ProtectedInstant)
    protected = envelope.protected_time.instant
    if protected < resolved_valid_from:
        _verification_failure(VerificationStage.KEY_RESOLUTION, "signing key is not yet valid")
    if resolved_valid_until is not None and protected >= resolved_valid_until:
        _verification_failure(VerificationStage.KEY_RESOLUTION, "signing key is expired")
    if resolved_revoked_at is not None and protected >= resolved_revoked_at:
        _verification_failure(VerificationStage.KEY_RESOLUTION, "signing key is revoked")
    resolved_public_key_text = selected["public_key_text"]
    resolved_public_key_bytes = selected["public_key_bytes"]
    assert isinstance(resolved_public_key_text, str)
    assert isinstance(resolved_public_key_bytes, bytes)
    return ResolvedKeyEvidence(
        organization_id=organization_id,
        key_id=envelope.signature.key_id,
        principal=resolved_principal,
        algorithm="Ed25519",
        public_key_text=resolved_public_key_text,
        public_key_bytes=resolved_public_key_bytes,
        validity=KeyValidityEvidence(
            resolved_valid_from, resolved_valid_until, resolved_revoked_at
        ),
    )


def _strict_ed25519_point(
    encoded: bytes,
    *,
    stage: VerificationStage,
    label: str,
    allow_identity: bool,
) -> tuple[int, int, int, int]:
    if len(encoded) != 32:
        _verification_failure(stage, f"{label} does not encode a 32-byte Ed25519 point")
    compressed = int.from_bytes(encoded, "little")
    x_sign = compressed >> 255
    y = compressed & ((1 << 255) - 1)
    if y >= _ED25519_FIELD:
        _verification_failure(stage, f"{label} is not a canonical Ed25519 point encoding")
    y_squared = y * y % _ED25519_FIELD
    numerator = (y_squared - 1) % _ED25519_FIELD
    denominator = (_ED25519_D * y_squared + 1) % _ED25519_FIELD
    x_squared = numerator * pow(denominator, _ED25519_FIELD - 2, _ED25519_FIELD) % _ED25519_FIELD
    x = pow(x_squared, (_ED25519_FIELD + 3) // 8, _ED25519_FIELD)
    if (x * x - x_squared) % _ED25519_FIELD:
        x = x * _ED25519_SQRT_M1 % _ED25519_FIELD
    if (x * x - x_squared) % _ED25519_FIELD:
        _verification_failure(stage, f"{label} is not an Edwards25519 point")
    if x == 0 and x_sign:
        _verification_failure(stage, f"{label} uses a negative-zero encoding")
    if (x & 1) != x_sign:
        x = _ED25519_FIELD - x
    point = (x, y, 1, x * y % _ED25519_FIELD)
    if _ed25519_is_identity(point) and not allow_identity:
        _verification_failure(stage, f"{label} encodes the Ed25519 identity point")
    if not _ed25519_is_identity(_ed25519_scalar_multiply(point, _ED25519_ORDER)):
        _verification_failure(stage, f"{label} is not in the prime-order Ed25519 subgroup")
    return point


def _ed25519_point_add(
    left: tuple[int, int, int, int], right: tuple[int, int, int, int]
) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = left
    x2, y2, z2, t2 = right
    a = (y1 - x1) * (y2 - x2) % _ED25519_FIELD
    b = (y1 + x1) * (y2 + x2) % _ED25519_FIELD
    c = 2 * _ED25519_D * t1 * t2 % _ED25519_FIELD
    d = 2 * z1 * z2 % _ED25519_FIELD
    e = (b - a) % _ED25519_FIELD
    f = (d - c) % _ED25519_FIELD
    g = (d + c) % _ED25519_FIELD
    h = (b + a) % _ED25519_FIELD
    return (
        e * f % _ED25519_FIELD,
        g * h % _ED25519_FIELD,
        f * g % _ED25519_FIELD,
        e * h % _ED25519_FIELD,
    )


def _ed25519_scalar_multiply(
    point: tuple[int, int, int, int], scalar: int
) -> tuple[int, int, int, int]:
    result = _ED25519_IDENTITY
    addend = point
    while scalar:
        if scalar & 1:
            result = _ed25519_point_add(result, addend)
        addend = _ed25519_point_add(addend, addend)
        scalar >>= 1
    return result


def _ed25519_is_identity(point: tuple[int, int, int, int]) -> bool:
    x, y, z, _ = point
    return x % _ED25519_FIELD == 0 and (y - z) % _ED25519_FIELD == 0


def _jcs_input(value: object) -> Any:
    if type(value) is int or isinstance(value, Decimal):
        try:
            converted = float(value)
        except (OverflowError, ValueError) as error:
            raise ValueError(f"number {value!s} is outside the binary64 domain") from error
        if not math.isfinite(converted):
            raise ValueError(f"number {value!s} is outside the finite binary64 domain")
        return converted
    if isinstance(value, list):
        return [_jcs_input(item) for item in value]
    if isinstance(value, Mapping):
        return {str(key): _jcs_input(item) for key, item in value.items()}
    return value


def _jcs_bytes(value: object) -> bytes:
    return rfc8785.dumps(_jcs_input(value))


def _profile(kind: SignedDocumentKind) -> _Profile:
    if not isinstance(kind, SignedDocumentKind):
        raise TypeError("kind must be a SignedDocumentKind; kind inference is not supported")
    return _PROFILES[kind]


def _copy_json_object(value: Mapping[str, object]) -> dict[str, object]:
    if type(value) is not dict:
        raise SignedDocumentSigningError("unsigned document must be a JSON object")
    copied = _copy_json_value(value)
    assert isinstance(copied, dict)
    return copied


def _copy_json_value(value: object) -> object:
    if value is None or type(value) in {bool, str}:
        return value
    if type(value) is int:
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise SignedDocumentSigningError("JSON numbers must be finite")
        return value
    if type(value) is list:
        return [_copy_json_value(item) for item in value]
    if type(value) is dict:
        result: dict[str, object] = {}
        for key, item in value.items():
            if type(key) is not str:
                raise SignedDocumentSigningError("JSON object member names must be strings")
            result[key] = _copy_json_value(item)
        return result
    raise SignedDocumentSigningError(
        f"unsupported host value {type(value).__name__}; signing accepts JSON-domain values only"
    )


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return _FrozenList(_freeze(item) for item in value)
    return value


class _FrozenList(tuple[object, ...]):
    def __new__(cls, values: object) -> _FrozenList:
        return super().__new__(cls, values)  # type: ignore[arg-type]

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Sequence) and not isinstance(other, (str, bytes, bytearray)):
            return tuple(self) == tuple(other)
        return False

    __hash__ = tuple.__hash__


def _json_pointer(document: Mapping[str, object], pointer: str) -> object:
    current: object = document
    for encoded in pointer.removeprefix("/").split("/"):
        token = encoded.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, Mapping) or token not in current:
            raise SignedDocumentSigningError(f"protected-time pointer {pointer!r} does not resolve")
        current = current[token]
    return current


def _canonicalize(value: object) -> bytes:
    try:
        return _jcs_bytes(value)
    except (rfc8785.CanonicalizationError, UnicodeError, ValueError, OverflowError) as error:
        raise SignedDocumentSigningError(
            f"document is outside the JCS/I-JSON domain: {error}"
        ) from error


def _sha256(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _parse_rfc3339(value: str) -> ProtectedInstant:
    match = _RFC3339.fullmatch(value)
    if match is None:
        raise ValueError("not an RFC 3339 timestamp")
    year = int(match.group("year"))
    month = int(match.group("month"))
    day = int(match.group("day"))
    hour = int(match.group("hour"))
    minute = int(match.group("minute"))
    second = int(match.group("second"))
    if year == 0:
        raise ValueError("year 0000 is not supported")
    leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
    month_lengths = (31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)
    if month < 1 or month > 12 or day < 1 or day > month_lengths[month - 1]:
        raise ValueError("invalid Gregorian date")
    if hour > 23 or minute > 59 or second > 59:
        raise ValueError("invalid time of day")
    offset = match.group("offset")
    if offset == "-00:00":
        raise ValueError("unknown local offset is not supported")
    offset_seconds = 0
    if offset not in {"Z", "z"}:
        offset_hour = int(offset[1:3])
        offset_minute = int(offset[4:6])
        if offset_hour > 23 or offset_minute > 59:
            raise ValueError("numeric offset is outside RFC 3339 bounds")
        offset_seconds = (1 if offset[0] == "+" else -1) * (offset_hour * 3600 + offset_minute * 60)
    adjusted_year = year - (1 if month <= 2 else 0)
    era = adjusted_year // 400
    year_of_era = adjusted_year - era * 400
    adjusted_month = month + (-3 if month > 2 else 9)
    day_of_year = (153 * adjusted_month + 2) // 5 + day - 1
    day_of_era = year_of_era * 365 + year_of_era // 4 - year_of_era // 100 + day_of_year
    epoch_day = era * 146097 + day_of_era - 719468
    epoch_second = epoch_day * 86400 + hour * 3600 + minute * 60 + second - offset_seconds
    return ProtectedInstant(epoch_second, (match.group("fraction") or "").rstrip("0"))
