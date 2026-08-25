"""One bounded YAML-to-JSON parser for every operator-authored configuration.

The project accepts YAML as a convenience syntax only.  The resulting value
must be in the strict JSON data model used by the hashing and schema layers.
Aliases, tags, merge keys, duplicate keys, implicit timestamps, YAML's legacy
booleans, and non-JSON numbers are rejected instead of being guessed.
"""

from __future__ import annotations

import re
from collections.abc import Mapping

import yaml  # type: ignore[import-untyped]

from ebm_audit.protocol import CanonicalizationError, canonical_json_bytes

_JSON_INTEGER = re.compile(r"^-?(?:0|[1-9][0-9]*)$")
_JSON_FLOAT = re.compile(
    r"^-?(?:(?:0|[1-9][0-9]*)\.[0-9]+(?:[eE][+-]?[0-9]+)?|"
    r"(?:0|[1-9][0-9]*)[eE][+-]?[0-9]+)$"
)
_YAML_BOOLEAN_SURPRISES = frozenset(
    {"y", "yes", "n", "no", "on", "off", "true", "false"}
)
_YAML_NONFINITE = frozenset({".nan", ".inf", "+.inf", "-.inf"})
_YAML_IMPLICIT_NUMBER = re.compile(
    r"""
    ^[-+]?(?:
        0[bB][01_]+
        |0[oO][0-7_]+
        |0[xX][0-9a-fA-F_]+
        |[1-9][0-9_]*(?::[0-5]?[0-9])+(?:\.[0-9_]*)?
        |(?:\.[0-9_]+|[0-9][0-9_]*(?:\.[0-9_]*)?)(?:[eE][-+]?[0-9]+)?
    )$
    """,
    re.VERBOSE,
)
_YAML_TIMESTAMP = re.compile(
    r"^(?:[0-9]{4}-[0-9]{2}-[0-9]{2}$|"
    r"[0-9]{4}-[0-9]{1,2}-[0-9]{1,2}[Tt \t])"
)
_EMPTY_PLAIN_SCALAR_TAG = "tag:ebm-audit.local,2026:empty-plain-scalar"


class StrictYamlError(ValueError):
    """Raised without retaining or echoing rejected configuration content."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__("Configuration is not strict JSON-model YAML.")


class _StrictJsonModelLoader(yaml.SafeLoader):  # type: ignore[misc]
    """Safe loader with only JSON-model scalar resolvers."""


_StrictJsonModelLoader.yaml_implicit_resolvers = {}
_StrictJsonModelLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool",
    re.compile(r"^(?:true|false)$"),
    list("tf"),
)
_StrictJsonModelLoader.add_implicit_resolver(
    "tag:yaml.org,2002:null",
    re.compile(r"^null$"),
    ["n"],
)
_StrictJsonModelLoader.add_implicit_resolver(
    "tag:yaml.org,2002:int",
    _JSON_INTEGER,
    list("-0123456789"),
)
_StrictJsonModelLoader.add_implicit_resolver(
    "tag:yaml.org,2002:float",
    _JSON_FLOAT,
    list("-0123456789"),
)
_StrictJsonModelLoader.add_implicit_resolver(
    _EMPTY_PLAIN_SCALAR_TAG,
    re.compile(r"^$"),
    [""],
)


def _reject_empty_plain_scalar(
    _loader: _StrictJsonModelLoader,
    _node: yaml.ScalarNode,
) -> object:
    raise StrictYamlError("AMBIGUOUS_NULL")


_StrictJsonModelLoader.add_constructor(
    _EMPTY_PLAIN_SCALAR_TAG,
    _reject_empty_plain_scalar,
)


def _construct_unique_mapping(
    loader: _StrictJsonModelLoader,
    node: yaml.MappingNode,
    *,
    deep: bool = False,
) -> dict[object, object]:
    result: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in result
        except TypeError as exc:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found a non-scalar mapping key",
                key_node.start_mark,
            ) from exc
        if duplicate:
            raise StrictYamlError("DUPLICATE_KEY")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_StrictJsonModelLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _scan_syntax(text: str) -> None:
    has_document_content = False
    for token in yaml.scan(text, Loader=_StrictJsonModelLoader):
        if not isinstance(token, (yaml.tokens.StreamStartToken, yaml.tokens.StreamEndToken)):
            has_document_content = True
        if isinstance(
            token,
            (
                yaml.tokens.AliasToken,
                yaml.tokens.AnchorToken,
                yaml.tokens.TagToken,
                yaml.tokens.DocumentStartToken,
                yaml.tokens.DocumentEndToken,
            ),
        ):
            if isinstance(token, (yaml.tokens.AliasToken, yaml.tokens.AnchorToken)):
                raise StrictYamlError("REFERENCE")
            if isinstance(token, yaml.tokens.TagToken):
                raise StrictYamlError("TAG")
            raise StrictYamlError("DOCUMENT_MARKER")
        if not isinstance(token, yaml.tokens.ScalarToken) or token.style is not None:
            continue
        value = token.value
        lowered = value.lower()
        if value == "<<":
            raise StrictYamlError("MERGE")
        if lowered in _YAML_NONFINITE:
            raise StrictYamlError("NONFINITE")
        if lowered in _YAML_BOOLEAN_SURPRISES and value not in {"true", "false"}:
            raise StrictYamlError("AMBIGUOUS_BOOLEAN")
        if (lowered == "null" or value == "~") and value != "null":
            raise StrictYamlError("AMBIGUOUS_NULL")
        if (
            _YAML_IMPLICIT_NUMBER.fullmatch(value)
            and _JSON_INTEGER.fullmatch(value) is None
            and _JSON_FLOAT.fullmatch(value) is None
        ) or _YAML_TIMESTAMP.match(value):
            raise StrictYamlError("AMBIGUOUS_NUMBER_OR_TIMESTAMP")
    if not has_document_content:
        raise StrictYamlError("AMBIGUOUS_NULL")


def _validate_bounds(
    value: object,
    *,
    maximum_depth: int,
    maximum_nodes: int,
) -> None:
    node_count = 0

    def visit(node: object, depth: int) -> None:
        nonlocal node_count
        node_count += 1
        if depth > maximum_depth or node_count > maximum_nodes:
            raise StrictYamlError("STRUCTURAL_BOUND")
        if isinstance(node, Mapping):
            for key, child in node.items():
                if not isinstance(key, str):
                    raise StrictYamlError("NON_STRING_KEY")
                visit(key, depth + 1)
                visit(child, depth + 1)
        elif isinstance(node, list):
            for child in node:
                visit(child, depth + 1)

    visit(value, 0)


def load_strict_yaml_bytes(
    raw: bytes | bytearray | memoryview,
    *,
    maximum_bytes: int,
    maximum_depth: int = 64,
    maximum_nodes: int = 100_000,
) -> object:
    """Parse bounded UTF-8 YAML into the project's strict JSON data model."""

    data = bytes(raw)
    if len(data) > maximum_bytes:
        raise StrictYamlError("BYTE_BOUND")
    if data.startswith(b"\xef\xbb\xbf"):
        raise StrictYamlError("BOM")
    try:
        text = data.decode("utf-8", errors="strict")
        _scan_syntax(text)
        value = yaml.load(text, Loader=_StrictJsonModelLoader)
        _validate_bounds(
            value,
            maximum_depth=maximum_depth,
            maximum_nodes=maximum_nodes,
        )
        canonical_json_bytes(value)
    except StrictYamlError:
        raise
    except (
        CanonicalizationError,
        UnicodeError,
        ValueError,
        TypeError,
        RecursionError,
        yaml.YAMLError,
    ) as exc:
        raise StrictYamlError("SYNTAX_OR_CANONICAL_VALUE") from exc
    return value


__all__ = ["StrictYamlError", "load_strict_yaml_bytes"]
