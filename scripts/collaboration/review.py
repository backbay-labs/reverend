from __future__ import annotations

from dataclasses import dataclass, field

from .models import (
    AnalystIdentity,
    DeltaReview,
    ReviewAction,
    ReviewPacket,
    ReviewVerdict,
    SpecPacket,
)


@dataclass
class ReviewSession:
    reviewer: AnalystIdentity
    spec_packet: SpecPacket
    _reviews: dict[str, DeltaReview] = field(default_factory=dict)

    def accept_delta(self, delta_id: str, rationale: str) -> None:
        self._reviews[delta_id] = DeltaReview(delta_id=delta_id, action=ReviewAction.ACCEPT, rationale=rationale)

    def reject_delta(self, delta_id: str, rationale: str) -> None:
        self._reviews[delta_id] = DeltaReview(delta_id=delta_id, action=ReviewAction.REJECT, rationale=rationale)

    def request_changes(self, delta_id: str, rationale: str) -> None:
        self._reviews[delta_id] = DeltaReview(
            delta_id=delta_id,
            action=ReviewAction.REQUEST_CHANGES,
            rationale=rationale,
        )

    def finalize(self, summary: str) -> ReviewPacket:
        deltas = self.spec_packet.changeset.deltas
        delta_ids = [d.id for d in deltas]
        delta_reviews = [self._reviews.get(did) for did in delta_ids]

        missing = [delta_ids[i] for i, dr in enumerate(delta_reviews) if dr is None]
        if missing:
            for did in missing:
                self._reviews[did] = DeltaReview(
                    delta_id=did,
                    action=ReviewAction.REQUEST_CHANGES,
                    rationale="No decision recorded; defaulting to request_changes.",
                )

        delta_reviews_final = [self._reviews[did] for did in delta_ids]

        actions = {dr.action for dr in delta_reviews_final}
        if ReviewAction.REQUEST_CHANGES in actions:
            verdict = ReviewVerdict.OPEN
        elif ReviewAction.ACCEPT in actions:
            verdict = ReviewVerdict.APPROVED
        else:
            verdict = ReviewVerdict.REJECTED

        return ReviewPacket(
            schema_version=1,
            spec_packet_hash=self.spec_packet.compute_content_hash(),
            reviewer=self.reviewer,
            overall_verdict=verdict,
            summary=summary,
            delta_reviews=delta_reviews_final,
            metadata={"workflow": "scripts/collaboration/review.ReviewWorkflow"},
        )


@dataclass
class ReviewWorkflow:
    reviewer: AnalystIdentity

    def create_review_session(self, spec_packet: SpecPacket) -> ReviewSession:
        return ReviewSession(reviewer=self.reviewer, spec_packet=spec_packet)

