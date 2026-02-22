#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS_DIR = ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))


def _load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def _require(cond: bool, message: str) -> None:
    if not cond:
        raise ValueError(message)


def run_spec_review_benchmark(
    *,
    analysis_path: Path,
    decisions_path: Path,
    expected_path: Path | None = None,
) -> dict[str, Any]:
    from collaboration.extractor import extract_from_doc
    from collaboration.models import AnalystIdentity, DeltaSource, ReviewAction
    from collaboration.render import render_review_packet_markdown, render_spec_packet_markdown
    from collaboration.review import ReviewWorkflow

    analysis_doc = _load_json(analysis_path)
    _require(isinstance(analysis_doc, dict), "analysis fixture must be a JSON object")

    reviewer = AnalystIdentity(id="bench:spec-review", actor_type=DeltaSource.SCRIPT, display_name="spec-review-bench")
    spec_packet = extract_from_doc(analysis_doc, reviewer=reviewer)
    spec_hash = spec_packet.compute_content_hash()

    decisions = _load_json(decisions_path)
    _require(isinstance(decisions, dict), "decisions fixture must be a JSON object")

    workflow = ReviewWorkflow(reviewer=reviewer)
    session = workflow.create_review_session(spec_packet)
    for delta_id, info in decisions.items():
        _require(isinstance(delta_id, str) and delta_id, "decision keys must be non-empty delta_id strings")
        _require(isinstance(info, dict), f"decisions[{delta_id!r}] must be an object")
        action = info.get("action")
        rationale = info.get("rationale")
        _require(isinstance(action, str), f"decisions[{delta_id!r}].action must be a string")
        _require(isinstance(rationale, str), f"decisions[{delta_id!r}].rationale must be a string")
        if action == ReviewAction.ACCEPT.value:
            session.accept_delta(delta_id, rationale=rationale)
        elif action == ReviewAction.REJECT.value:
            session.reject_delta(delta_id, rationale=rationale)
        else:
            session.request_changes(delta_id, rationale=rationale)

    review_packet = session.finalize(summary="spec-review benchmark fixture run")
    review_hash = review_packet.compute_content_hash()

    spec_md = render_spec_packet_markdown(spec_packet)
    review_md = render_review_packet_markdown(review_packet, spec_packet)
    _require("Inline Evidence" in review_md, "review markdown missing Inline Evidence section")
    for delta in spec_packet.changeset.deltas:
        for evid in delta.evidence_link_ids:
            _require(f"`{evid}`" in review_md, f"review markdown missing evidence id: {evid}")

    expected_ok = True
    expected: dict[str, Any] = {}
    if expected_path is not None and expected_path.exists():
        raw = _load_json(expected_path)
        _require(isinstance(raw, dict), "expected fixture must be a JSON object")
        expected = raw

        expected_spec_hash = expected.get("spec_packet_hash")
        expected_review_hash = expected.get("review_packet_hash")
        expected_verdict = expected.get("overall_verdict")

        if expected_spec_hash and expected_spec_hash != spec_hash:
            expected_ok = False
        if expected_review_hash and expected_review_hash != review_hash:
            expected_ok = False
        if expected_verdict and expected_verdict != review_packet.overall_verdict.value:
            expected_ok = False

    return {
        "passed": 1.0 if expected_ok else 0.0,
        "spec_packet_hash_match": 1.0 if (not expected or expected.get("spec_packet_hash") == spec_hash) else 0.0,
        "review_packet_hash_match": 1.0 if (not expected or expected.get("review_packet_hash") == review_hash) else 0.0,
        "verdict_open": 1.0 if review_packet.overall_verdict.value == "open" else 0.0,
        "hypotheses": float(len(spec_packet.hypotheses)),
        "deltas": float(len(spec_packet.changeset.deltas)),
        "detail": {
            "analysis_path": str(analysis_path),
            "decisions_path": str(decisions_path),
            "expected_path": str(expected_path) if expected_path is not None else None,
            "spec_packet_hash": spec_hash,
            "review_packet_hash": review_hash,
            "review_verdict": review_packet.overall_verdict.value,
            "reviewer": asdict(reviewer),
            "spec_packet_schema_version": spec_packet.schema_version,
            "review_packet_schema_version": review_packet.schema_version,
        },
        "artifacts": {
            "spec_packet": spec_packet.to_dict(),
            "review_packet": review_packet.to_dict(),
            "spec_markdown": spec_md,
            "review_markdown": review_md,
        },
    }


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Spec extraction + review benchmark")
    parser.add_argument("--analysis", type=Path, required=True)
    parser.add_argument("--decisions", type=Path, required=True)
    parser.add_argument("--expected", type=Path, default=None)
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args(argv)

    try:
        result = run_spec_review_benchmark(
            analysis_path=args.analysis,
            decisions_path=args.decisions,
            expected_path=args.expected,
        )
    except ValueError as exc:
        print(f"[spec-review] ERROR: {exc}", file=sys.stderr)
        return 2

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    ok = result.get("passed") == 1.0
    if not ok:
        detail = result.get("detail") if isinstance(result.get("detail"), dict) else {}
        print("[spec-review] FAILED: expected hashes/verdict mismatch", file=sys.stderr)
        print(f"[spec-review] spec_packet_hash={detail.get('spec_packet_hash')}", file=sys.stderr)
        print(f"[spec-review] review_packet_hash={detail.get('review_packet_hash')}", file=sys.stderr)
        print(f"[spec-review] review_verdict={detail.get('review_verdict')}", file=sys.stderr)
        return 1

    print("[spec-review] OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

