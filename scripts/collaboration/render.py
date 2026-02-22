from __future__ import annotations

from .models import ReviewAction, ReviewPacket, SpecPacket, SpecType


def render_spec_packet_markdown(packet: SpecPacket) -> str:
    lines: list[str] = []
    lines.append(f"# Spec Extraction Packet: {packet.program_name}")
    lines.append("")
    lines.append("## Summary")
    lines.append(f"- Program SHA256: `{packet.program_sha256}`")
    lines.append(f"- Analysis SHA256: `{packet.analysis_sha256}`")
    lines.append(f"- Content hash: `{packet.compute_content_hash()}`")
    lines.append(f"- Hypotheses: `{len(packet.hypotheses)}`")
    lines.append(f"- Deltas: `{len(packet.changeset.deltas)}`")
    lines.append("")

    lines.append("## Hypotheses")
    lines.append("| ID | Type | Name | Confidence | Evidence |")
    lines.append("|---|---|---|---:|---:|")
    for h in packet.hypotheses:
        lines.append(f"| `{h.id}` | `{h.spec_type.value}` | `{h.name}` | {h.confidence:.2f} | {len(h.evidence)} |")
    lines.append("")

    lines.append("## Deltas (Evidence-Backed)")
    lines.append("| Delta ID | Artifact | Address | Confidence | Evidence IDs |")
    lines.append("|---|---|---|---:|---|")
    for d in packet.changeset.deltas:
        ev = ", ".join(f"`{eid}`" for eid in d.evidence_link_ids) if d.evidence_link_ids else ""
        addr = f"`{d.address}`" if d.address else ""
        lines.append(f"| `{d.id}` | `{d.artifact_type.value}` | {addr} | {d.confidence:.2f} | {ev} |")
    lines.append("")

    lines.append("## Evidence")
    evidence_by_id = {}
    for h in packet.hypotheses:
        for ev in h.evidence:
            evidence_by_id[ev.id] = ev
    for evid in sorted(evidence_by_id.keys()):
        ev = evidence_by_id[evid]
        refs = ", ".join(f"`{r}`" for r in ev.refs) if ev.refs else "(none)"
        lines.append(f"- `{ev.id}` ({ev.kind}): {ev.summary} — refs: {refs}")

    return "\n".join(lines).rstrip() + "\n"


def render_review_packet_markdown(review: ReviewPacket, spec: SpecPacket) -> str:
    lines: list[str] = []
    lines.append(f"# Review Packet: {spec.program_name}")
    lines.append("")
    lines.append("## Summary")
    lines.append(f"- Spec packet hash: `{review.spec_packet_hash}`")
    lines.append(f"- Review content hash: `{review.compute_content_hash()}`")
    lines.append(f"- Reviewer: `{review.reviewer.display_name}` (`{review.reviewer.id}`)")
    lines.append(f"- Verdict: **{review.overall_verdict.value}**")
    lines.append("")
    lines.append(review.summary.strip() or "(no summary)")
    lines.append("")

    by_delta_id = {dr.delta_id: dr for dr in review.delta_reviews}
    lines.append("## Delta Decisions (Inline Evidence)")
    lines.append("| Delta ID | Decision | Confidence | Type | Evidence | Rationale |")
    lines.append("|---|---|---:|---|---|---|")
    for d in spec.changeset.deltas:
        dr = by_delta_id.get(d.id)
        action = dr.action.value if dr else ReviewAction.REQUEST_CHANGES.value
        ev = ", ".join(f"`{eid}`" for eid in d.evidence_link_ids) if d.evidence_link_ids else ""
        rat = (dr.rationale if dr else "No decision recorded.").replace("\n", " ").strip()
        lines.append(
            f"| `{d.id}` | `{action}` | {d.confidence:.2f} | `{d.artifact_type.value}` | {ev} | {rat} |"
        )
    lines.append("")

    lines.append("## Hypothesis Rollup")
    counts = {SpecType.SCHEMA: 0, SpecType.API: 0, SpecType.STATE_MACHINE: 0}
    for h in spec.hypotheses:
        counts[h.spec_type] = counts.get(h.spec_type, 0) + 1
    lines.append(f"- schema: `{counts.get(SpecType.SCHEMA, 0)}`")
    lines.append(f"- api: `{counts.get(SpecType.API, 0)}`")
    lines.append(f"- state_machine: `{counts.get(SpecType.STATE_MACHINE, 0)}`")

    return "\n".join(lines).rstrip() + "\n"

