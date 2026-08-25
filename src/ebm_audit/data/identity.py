"""Private participant tokenization and run-local aliases."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Never, SupportsIndex, cast

from ebm_audit.protocol import domain_separated_bytes_sha256
from ebm_audit.protocol.canonical import MAX_SAFE_INTEGER
from ebm_audit.schema import SchemaValidationError, validate_instance

type PrivateParticipantId = str | int
_TOKEN_DOMAIN = b"ebm-audit/participant-token/1"
_NAMESPACE_KEY_BYTES = 32
_KEY_CONSTRUCTION_TOKEN = object()
_KEY_INSTANCE_SEAL = secrets.token_bytes(_NAMESPACE_KEY_BYTES)


class ParticipantIdentityError(ValueError):
    """Safe failure at the private participant-identity boundary."""


class _NamespaceKey:
    """Opaque proof that a namespace key came from the approved generator."""

    __slots__ = ("__key_bytes", "__provenance_tag")

    def __init__(self, key_bytes: bytes, construction_token: object) -> None:
        if construction_token is not _KEY_CONSTRUCTION_TOKEN:
            raise ParticipantIdentityError(
                "Namespace keys must be created by generate_namespace_key()."
            )
        if not isinstance(key_bytes, bytes) or len(key_bytes) != _NAMESPACE_KEY_BYTES:
            raise ParticipantIdentityError(
                "The generated alias namespace key must contain exactly 32 bytes."
            )
        object.__setattr__(self, "_NamespaceKey__key_bytes", key_bytes)
        object.__setattr__(
            self,
            "_NamespaceKey__provenance_tag",
            hmac.new(_KEY_INSTANCE_SEAL, key_bytes, hashlib.sha256).digest(),
        )

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("Namespace keys are immutable.")

    def __repr__(self) -> str:
        return "_NamespaceKey(<redacted>)"

    def __copy__(self) -> _NamespaceKey:
        return self

    def __deepcopy__(self, memo: dict[int, object]) -> _NamespaceKey:
        return self

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        raise TypeError("Namespace keys cannot be serialized.")

    def _validated_bytes(self) -> bytes:
        key = cast(bytes, object.__getattribute__(self, "_NamespaceKey__key_bytes"))
        tag = cast(bytes, object.__getattribute__(self, "_NamespaceKey__provenance_tag"))
        expected = hmac.new(_KEY_INSTANCE_SEAL, key, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected):
            raise ParticipantIdentityError("The alias namespace key is invalid.")
        return key


@dataclass(frozen=True, slots=True)
class IdentityRow:
    """One private identity row; sensitive values are excluded from ``repr``."""

    participant_private_id: PrivateParticipantId = field(repr=False)
    participant_private_token: str = field(repr=False)
    participant_internal_index: int
    participant_alias: str


@dataclass(frozen=True, slots=True)
class IdentityMap:
    """One run-local, row-order-invariant mapping held only by the core."""

    schema_version: str
    dataset_variant_id: str
    alias_namespace_id: str
    token_parameters: Mapping[str, object]
    rows: tuple[IdentityRow, ...] = field(repr=False)

    def __repr__(self) -> str:
        return (
            "IdentityMap(schema_version="
            f"{self.schema_version!r}, dataset_variant_id={self.dataset_variant_id!r}, "
            f"alias_namespace_id={self.alias_namespace_id!r}, row_count={len(self.rows)})"
        )


def generate_namespace_key() -> _NamespaceKey:
    """Return an opaque 32-byte namespace key from the operating-system CSPRNG."""

    return _NamespaceKey(
        secrets.token_bytes(_NAMESPACE_KEY_BYTES),
        _KEY_CONSTRUCTION_TOKEN,
    )


def _validated_key(namespace_key: _NamespaceKey) -> bytes:
    if not isinstance(namespace_key, _NamespaceKey):
        raise ParticipantIdentityError(
            "Namespace keys must be created by generate_namespace_key()."
        )
    try:
        key = namespace_key._validated_bytes()
    except (AttributeError, TypeError):
        raise ParticipantIdentityError("The alias namespace key is invalid.") from None
    if not isinstance(key, bytes) or len(key) != _NAMESPACE_KEY_BYTES:
        raise ParticipantIdentityError("The alias namespace key is invalid.")
    return key


def participant_token_parameters(namespace_key: _NamespaceKey) -> dict[str, object]:
    """Return the public method record without exposing the namespace key."""

    key = _validated_key(namespace_key)
    parameters: dict[str, object] = {
        "method_id": "hmac-sha256-typed-private-id/1",
        "key_generation_method": "os-csprng/1",
        "minimum_key_bytes": _NAMESPACE_KEY_BYTES,
        "key_byte_length": len(key),
        "key_id_digest": domain_separated_bytes_sha256("ebm-audit/participant-token-key-id/1", key),
        "message_framing": "domain-nul-type-nul-u64be-length-value/1",
        "token_encoding": "hmac-sha256:<64-lowercase-hex>",
    }
    validate_instance(
        parameters,
        "canonical-records.schema.json",
        definition="ParticipantTokenParameters",
    )
    return parameters


def validate_participant_private_id(value: object) -> PrivateParticipantId:
    """Validate one exact private participant ID without normalizing or coercing it."""

    if type(value) is str:
        text = value
        if not text or text.isspace():
            raise ParticipantIdentityError(
                "String participant identifiers must contain visible non-whitespace text."
            )
        if not unicodedata.is_normalized("NFC", text):
            raise ParticipantIdentityError(
                "String participant identifiers must already be Unicode NFC."
            )
        try:
            text.encode("utf-8", errors="strict")
        except UnicodeEncodeError:
            raise ParticipantIdentityError(
                "String participant identifiers must be valid Unicode scalar values."
            ) from None
        if any(unicodedata.category(character) in {"Cc", "Cf", "Cs"} for character in text):
            raise ParticipantIdentityError(
                "String participant identifiers must not contain control or format characters."
            )
        return text
    if type(value) is int:
        integer = value
        if abs(integer) > MAX_SAFE_INTEGER:
            raise ParticipantIdentityError(
                "Integer participant identifiers must be in the interoperable safe range."
            )
        return integer
    raise ParticipantIdentityError("Participant identifiers must be strings or integers.")


def _private_id_bytes(value: PrivateParticipantId) -> tuple[bytes, bytes]:
    validated = validate_participant_private_id(value)
    if type(validated) is str:
        return b"string", validated.encode("utf-8", errors="strict")
    return b"integer", str(validated).encode("ascii")


def _token_bytes(namespace_key: bytes, value: PrivateParticipantId) -> bytes:
    type_tag, value_bytes = _private_id_bytes(value)
    message = (
        _TOKEN_DOMAIN
        + b"\x00"
        + type_tag
        + b"\x00"
        + len(value_bytes).to_bytes(8, byteorder="big", signed=False)
        + value_bytes
    )
    return hmac.new(namespace_key, message, hashlib.sha256).digest()


def _typed_identity_key(value: PrivateParticipantId) -> tuple[str, PrivateParticipantId]:
    type_tag, _value_bytes = _private_id_bytes(value)
    return type_tag.decode("ascii"), value


def build_identity_map(
    participant_private_ids: Sequence[PrivateParticipantId],
    *,
    dataset_variant_id: str,
    namespace_key: _NamespaceKey,
) -> IdentityMap:
    """Build deterministic tokens, internal indexes, and aliases for one run."""

    key = _validated_key(namespace_key)
    try:
        validate_instance(
            dataset_variant_id,
            "canonical-records.schema.json",
            definition="MachineId",
        )
    except SchemaValidationError as exc:
        raise ParticipantIdentityError(
            "The dataset variant ID must be a valid stable machine identifier."
        ) from exc
    if isinstance(participant_private_ids, (str, bytes)) or not isinstance(
        participant_private_ids, Sequence
    ):
        raise ParticipantIdentityError(
            "Participant identifiers must be supplied as a sequence of complete values."
        )
    if not participant_private_ids:
        raise ParticipantIdentityError("At least one participant identifier is required.")
    validated = tuple(participant_private_ids)
    typed_keys = tuple(_typed_identity_key(value) for value in validated)
    if len(set(typed_keys)) != len(typed_keys):
        raise ParticipantIdentityError("Participant identifiers must be unique by exact type.")

    token_rows = [(value, _token_bytes(key, value)) for value in validated]
    if len({token for _value, token in token_rows}) != len(token_rows):
        raise ParticipantIdentityError("Participant token collision detected.")
    token_rows.sort(key=lambda row: row[1])
    alias_width = max(3, len(str(len(token_rows))))
    rows = tuple(
        IdentityRow(
            participant_private_id=value,
            participant_private_token=f"hmac-sha256:{token.hex()}",
            participant_internal_index=index,
            participant_alias=f"P-{index + 1:0{alias_width}d}",
        )
        for index, (value, token) in enumerate(token_rows)
    )
    parameters = participant_token_parameters(namespace_key)
    return IdentityMap(
        schema_version="ebm-audit-identity-map/1.0",
        dataset_variant_id=dataset_variant_id,
        alias_namespace_id=str(parameters["key_id_digest"]),
        token_parameters=MappingProxyType(dict(parameters)),
        rows=rows,
    )
