"""Authenticate existing Plan/3 owners before operation-matrix adaptation.

This package-private seam deliberately accepts no operation rows.  A later
frozen benchmark owner may project its rows only after this function returns
the exact prepared authorizations published by the supplied planning authority.
"""

from __future__ import annotations

import hmac
from collections.abc import Mapping, Sequence
from typing import Any, cast

from ebm_audit.universe.identities import (
    UniverseIdentityError,
    _plan_preimage,
    _receipt_preimage,
    _universe_preimage,
    analysis_plan_digest,
    analysis_spec_content_id,
    chain_execution_id,
    preparation_receipt_digest,
    universe_id,
)
from ebm_audit.universe.planning import (
    PlanningAuthority,
    _assert_planning_description_states_current,
    _rebuild_plan_from_state,
)
from ebm_audit.universe.preparation import (
    PreparationTransaction,
    PreparedExecutionAuthorization,
    _preparation_transaction_publication_token,
)


def _same_digest(observed: object, expected: str) -> bool:
    return isinstance(observed, str) and hmac.compare_digest(observed, expected)


def _authenticate_existing_plan_operation_matrix(
    authority: object,
    transaction: object,
) -> tuple[PreparedExecutionAuthorization, ...]:
    """Return only the exact ordered PREPARED owners of one published plan.

    The returned tuple is not a caller-authored matrix.  It is the existing
    transaction's genuine authorization sequence after complete owner and
    identity readback.  Benchmark operation rows must be supplied later by a
    separately validated frozen benchmark owner and compared at that boundary.
    """

    if type(authority) is not PlanningAuthority:
        raise TypeError("A genuine planning authority is required.")
    if type(transaction) is not PreparationTransaction:
        raise TypeError("A genuine preparation transaction is required.")

    state = authority._state()
    _assert_planning_description_states_current(state)
    publication = state.preparation_publication
    if (
        publication is None
        or publication.transaction is not transaction
        or state.preparation_publication_token
        is not (_preparation_transaction_publication_token(transaction))
    ):
        raise TypeError("The preparation transaction is detached from its planning authority.")

    plan = _rebuild_plan_from_state(state)
    plan_digest = cast(str, plan["plan_digest"])
    if not _same_digest(plan_digest, analysis_plan_digest(_plan_preimage(plan))):
        raise UniverseIdentityError("The existing AnalysisPlan/3 digest is invalid.")

    receipt = transaction.receipt
    receipt_digest = cast(str, receipt["receipt_digest"])
    if not _same_digest(receipt["plan_digest"], plan_digest) or not _same_digest(
        receipt_digest,
        preparation_receipt_digest(_receipt_preimage(receipt)),
    ):
        raise UniverseIdentityError("The existing PreparationReceipt/2 identity is invalid.")

    candidates = cast(Sequence[Mapping[str, Any]], plan["candidates"])
    records = cast(Sequence[Mapping[str, Any]], receipt["records"])
    authorizations = transaction.authorizations
    if len(records) != len(candidates):
        raise UniverseIdentityError("Preparation candidate coverage is incomplete.")

    prepared_index = 0
    for candidate_ordinal, (candidate, record) in enumerate(zip(candidates, records, strict=True)):
        analysis_spec_id = analysis_spec_content_id(
            cast(Mapping[str, Any], candidate["analysis_spec"])
        )
        candidate_id = candidate["candidate_id"]
        if (
            candidate["candidate_ordinal"] != candidate_ordinal
            or record["candidate_ordinal"] != candidate_ordinal
            or candidate_id != analysis_spec_id
            or candidate["analysis_spec_id"] != analysis_spec_id
            or record["candidate_id"] != candidate_id
            or record["analysis_spec_id"] != analysis_spec_id
        ):
            raise UniverseIdentityError("The ordered candidate identity is detached.")

        if record["state"] != "PREPARED":
            continue
        if prepared_index >= len(authorizations):
            raise UniverseIdentityError("Prepared authorization coverage is incomplete.")
        authorization = authorizations[prepared_index]
        prepared_index += 1
        if type(authorization) is not PreparedExecutionAuthorization:
            raise TypeError("A genuine prepared execution authorization is required.")

        universe = authorization.universe_spec
        record_universe = record["universe_spec"]
        if not isinstance(record_universe, Mapping) or universe != record_universe:
            raise UniverseIdentityError("The prepared universe owner is detached.")
        expected_universe_id = universe_id(_universe_preimage(universe))
        if (
            authorization.plan_digest != plan_digest
            or authorization.receipt_digest != receipt_digest
            or authorization.candidate_ordinal != candidate_ordinal
            or authorization.candidate_id != candidate_id
            or authorization.analysis_spec_id != analysis_spec_id
            or universe["plan_digest"] != plan_digest
            or universe["candidate_ordinal"] != candidate_ordinal
            or universe["candidate_id"] != candidate_id
            or universe["analysis_spec_id"] != analysis_spec_id
            or not _same_digest(universe["universe_id"], expected_universe_id)
            or not _same_digest(authorization.universe_id, expected_universe_id)
        ):
            raise UniverseIdentityError("The prepared UniverseSpec/3 identity is invalid.")

        chain_slots = cast(Sequence[Mapping[str, Any]], candidate["chain_slots"])
        chain_plan = cast(Sequence[Mapping[str, Any]], universe["chain_plan"])
        if len(chain_plan) != len(chain_slots):
            raise UniverseIdentityError("The frozen chain-plan coverage is invalid.")
        for chain_ordinal, (slot, chain) in enumerate(zip(chain_slots, chain_plan, strict=True)):
            expected_chain_execution_id = chain_execution_id(
                expected_universe_id,
                cast(str, chain["chain_id"]),
                cast(str, chain["seed"]),
            )
            if (
                slot["chain_ordinal"] != chain_ordinal
                or chain["chain_ordinal"] != chain_ordinal
                or slot["chain_id"] != chain["chain_id"]
                or not _same_digest(
                    chain["chain_execution_id"],
                    expected_chain_execution_id,
                )
            ):
                raise UniverseIdentityError("A chain execution identity is detached.")

    if prepared_index != len(authorizations):
        raise UniverseIdentityError("Prepared authorization coverage is not exact.")
    return authorizations


__all__: list[str] = []
