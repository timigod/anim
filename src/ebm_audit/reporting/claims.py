"""Versioned deterministic claim-language gate."""

from __future__ import annotations

import re
from dataclasses import dataclass

REPORT_LANGUAGE_RULE_ID = "report-language/v0.1.0"

MANDATORY_OPENING = (
    "This audit measures how a cross-sectional event-based model behaves across "
    "the declared data, modelling, resampling, influence, and no-signal checks. "
    "It does not establish a true biological sequence, diagnosis, prognosis, "
    "treatment effect, causal mechanism, or time to an event."
)

BASELINE_WORDING_GATE = (
    "This run has not fully reproduced a supplied canonical baseline from the "
    "original analysis. The results below describe this connected model and "
    "configuration; they must not be interpreted as a robustness audit of the "
    "original analysis."
)

NULL_SAFE_FALLBACK = (
    "This audit describes sensitivity across the tested choices, but it does not "
    "establish that the dataset contains a recoverable disease-order signal."
)

INFLUENCE_CAVEAT = (
    "Influence means that a refitted result moved after a declared removal. It "
    "does not by itself identify bad data, an erroneous participant, or a reason "
    "for exclusion."
)


@dataclass(frozen=True, slots=True)
class ClaimRule:
    """One deterministic prohibited-claim matcher."""

    rule_id: str
    pattern: re.Pattern[str]


_RULES = (
    ClaimRule("CLAIM.PROVED", re.compile(r"\b(?:proved|proven)\b", re.IGNORECASE)),
    ClaimRule(
        "CLAIM.TRUE_SEQUENCE",
        re.compile(
            r"\b(?:true|actual)\s+(?:biological|disease)\s+sequence\b",
            re.IGNORECASE,
        ),
    ),
    ClaimRule(
        "CLAIM.TRUE_ORDER",
        re.compile(r"\b(?:true|actual|ground[- ]truth)\s+(?:event\s+)?order\b", re.IGNORECASE),
    ),
    ClaimRule(
        "CLAIM.CAUSAL",
        re.compile(
            r"\b(?:caused?|causal(?:ity|\s+effect)?|determines?|"
            r"responsible\s+for)\b",
            re.IGNORECASE,
        ),
    ),
    ClaimRule(
        "CLAIM.DEMENTIA_PREDICTION",
        re.compile(r"\bwill\s+develop\s+dementia\b", re.IGNORECASE),
    ),
    ClaimRule(
        "CLAIM.CLINICAL_DIAGNOSIS",
        re.compile(
            r"\b(?:diagnos(?:is|es)|diagnosed\s+with|diagnostic\s+of|"
            r"diagnostic\s+test|can\s+diagnose)\b",
            re.IGNORECASE,
        ),
    ),
    ClaimRule(
        "CLAIM.PROGNOSIS",
        re.compile(r"\b(?:prognos(?:is|tic)|predicts?\s+progression)\b", re.IGNORECASE),
    ),
    ClaimRule(
        "CLAIM.TREATMENT",
        re.compile(
            r"\b(?:treatment\s+(?:recommendation|response|is\s+effective)|"
            r"effective\s+treatment|recommends?\s+treatment)\b",
            re.IGNORECASE,
        ),
    ),
    ClaimRule(
        "CLAIM.CLINICALLY_VALIDATED",
        re.compile(r"\bclinically\s+validated\b", re.IGNORECASE),
    ),
    ClaimRule(
        "CLAIM.UNIVERSALLY_ROBUST",
        re.compile(r"\buniversally\s+robust\b", re.IGNORECASE),
    ),
    ClaimRule(
        "CLAIM.MEDICAL_DEVICE",
        re.compile(r"\bmedical\s+device\b", re.IGNORECASE),
    ),
    ClaimRule(
        "CLAIM.BAD_PARTICIPANT",
        re.compile(r"\b(?:bad|wrong)\s+participant\b|\bbad\s+data\b", re.IGNORECASE),
    ),
    ClaimRule(
        "CLAIM.REGULATORY",
        re.compile(
            r"\b(?:regulatory|GDPR|HIPAA|NHS|KCL)\s+(?:approved|compliant|validated)\b",
            re.IGNORECASE,
        ),
    ),
    ClaimRule(
        "CLAIM.PROJECT_READINESS",
        re.compile(
            r"(?<![A-Z0-9])READY[\s_-]+FOR[\s_-]+MINA(?=$|[^A-Z0-9])",
            re.IGNORECASE,
        ),
    ),
    ClaimRule(
        "CLAIM.BASELINE_OVERSTATEMENT",
        re.compile(
            r"\b(?:a\s+)?robustness\s+audit\s+of\s+the\s+original\s+analysis\b",
            re.IGNORECASE,
        ),
    ),
)

_TECHNICAL_DIAGNOSTIC = re.compile(
    r"\b(?:convergence|calibration|order|likelihood)\s+diagnostics?\b",
    re.IGNORECASE,
)

_EXEMPT_FROZEN_TEXT = (
    MANDATORY_OPENING,
    BASELINE_WORDING_GATE,
    NULL_SAFE_FALLBACK,
    INFLUENCE_CAVEAT,
)


def prohibited_claim_codes(text: str) -> tuple[str, ...]:
    """Return ordered rule IDs for unallowlisted product-authored claims."""

    candidate = text
    for frozen in _EXEMPT_FROZEN_TEXT:
        candidate = candidate.replace(frozen, "")
    candidate = _TECHNICAL_DIAGNOSTIC.sub("", candidate)
    return tuple(rule.rule_id for rule in _RULES if rule.pattern.search(candidate))


def claim_is_allowed(text: str) -> bool:
    """Return whether product-authored text passes the frozen lexical gate."""

    return not prohibited_claim_codes(text)


def assert_claims_allowed(text: str) -> None:
    """Fail closed if a renderer template violates the claim rules."""

    codes = prohibited_claim_codes(text)
    if codes:
        joined = ",".join(codes)
        raise ValueError(
            f"{REPORT_LANGUAGE_RULE_ID} rejected product-authored text: {joined}"
        )
