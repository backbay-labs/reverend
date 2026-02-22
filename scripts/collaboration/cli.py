from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR.parent) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR.parent))

from collaboration.extractor import extract_from_json  # noqa: E402
from collaboration.models import AnalystIdentity, DeltaSource, ReviewAction  # noqa: E402
from collaboration.render import render_review_packet_markdown, render_spec_packet_markdown  # noqa: E402
from collaboration.review import ReviewWorkflow  # noqa: E402


def _read_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _parse_actor_type(raw: str) -> DeltaSource:
    try:
        return DeltaSource(raw)
    except ValueError as exc:
        raise SystemExit(f"invalid actor_type={raw!r} (expected one of: {[e.value for e in DeltaSource]})") from exc


def cmd_extract(args: argparse.Namespace) -> int:
    analysis_json = Path(args.analysis).read_text(encoding="utf-8")
    reviewer = AnalystIdentity(
        id=args.reviewer_id,
        actor_type=_parse_actor_type(args.reviewer_type),
        display_name=args.reviewer_name,
    )
    packet = extract_from_json(analysis_json, reviewer=reviewer)
    content_hash = packet.compute_content_hash()

    out_json = Path(args.out_json) if args.out_json else Path(args.out_dir) / f"spec-packet-{content_hash}.json"
    out_md = Path(args.out_md) if args.out_md else Path(args.out_dir) / f"spec-packet-{content_hash}.md"

    _write_json(out_json, packet.to_dict())
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text(render_spec_packet_markdown(packet), encoding="utf-8")
    print(f"[spec] wrote {out_json}")
    print(f"[spec] wrote {out_md}")
    return 0


def _load_decisions(path: Path) -> dict[str, dict[str, str]]:
    raw = _read_json(path)
    if not isinstance(raw, dict):
        raise SystemExit("decisions JSON must be an object mapping delta_id -> {action,rationale}")
    out: dict[str, dict[str, str]] = {}
    for delta_id, info in raw.items():
        if not isinstance(delta_id, str) or not delta_id.strip():
            raise SystemExit("decisions keys must be non-empty strings (delta_id)")
        if not isinstance(info, dict):
            raise SystemExit(f"decisions[{delta_id!r}] must be an object")
        action = info.get("action")
        rationale = info.get("rationale")
        if not isinstance(action, str) or action not in {a.value for a in ReviewAction}:
            raise SystemExit(
                f"decisions[{delta_id!r}].action must be one of: {[a.value for a in ReviewAction]} (got {action!r})"
            )
        if not isinstance(rationale, str) or not rationale.strip():
            raise SystemExit(f"decisions[{delta_id!r}].rationale must be a non-empty string")
        out[delta_id] = {"action": action, "rationale": rationale}
    return out


def cmd_review(args: argparse.Namespace) -> int:
    spec_doc = _read_json(Path(args.spec))
    if not isinstance(spec_doc, dict):
        raise SystemExit("spec must be a JSON object")

    reviewer = AnalystIdentity(
        id=args.reviewer_id,
        actor_type=_parse_actor_type(args.reviewer_type),
        display_name=args.reviewer_name,
    )

    from collaboration import models  # noqa: E402

    spec_packet = models.spec_packet_from_dict(spec_doc)
    workflow = ReviewWorkflow(reviewer=reviewer)
    session = workflow.create_review_session(spec_packet)

    decisions = _load_decisions(Path(args.decisions))
    for delta_id, info in decisions.items():
        action = info["action"]
        rationale = info["rationale"]
        if action == ReviewAction.ACCEPT.value:
            session.accept_delta(delta_id, rationale=rationale)
        elif action == ReviewAction.REJECT.value:
            session.reject_delta(delta_id, rationale=rationale)
        else:
            session.request_changes(delta_id, rationale=rationale)

    review_packet = session.finalize(summary=args.summary)
    content_hash = review_packet.compute_content_hash()

    out_json = Path(args.out_json) if args.out_json else Path(args.out_dir) / f"review-packet-{content_hash}.json"
    out_md = Path(args.out_md) if args.out_md else Path(args.out_dir) / f"review-packet-{content_hash}.md"

    _write_json(out_json, review_packet.to_dict())
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text(render_review_packet_markdown(review_packet, spec_packet), encoding="utf-8")
    print(f"[review] wrote {out_json}")
    print(f"[review] wrote {out_md}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="spec-review", description="Spec extraction + review packet workflow")
    sub = parser.add_subparsers(dest="cmd", required=True)

    extract = sub.add_parser("extract", help="Extract SpecPacket from analysis JSON")
    extract.add_argument("--analysis", required=True, help="Path to analysis JSON")
    extract.add_argument("--reviewer-id", required=True)
    extract.add_argument("--reviewer-type", required=True, help="One of: human|ml_model|import|script")
    extract.add_argument("--reviewer-name", required=True)
    extract.add_argument("--out-dir", default="docs/spec-packets", help="Output directory (default: docs/spec-packets)")
    extract.add_argument("--out-json", default=None)
    extract.add_argument("--out-md", default=None)
    extract.set_defaults(func=cmd_extract)

    review = sub.add_parser("review", help="Create ReviewPacket from SpecPacket + decisions")
    review.add_argument("--spec", required=True, help="Path to spec packet JSON")
    review.add_argument("--decisions", required=True, help="Path to decisions JSON")
    review.add_argument("--reviewer-id", required=True)
    review.add_argument("--reviewer-type", required=True, help="One of: human|ml_model|import|script")
    review.add_argument("--reviewer-name", required=True)
    review.add_argument("--summary", required=True, help="Review summary text")
    review.add_argument("--out-dir", default="docs/spec-packets", help="Output directory (default: docs/spec-packets)")
    review.add_argument("--out-json", default=None)
    review.add_argument("--out-md", default=None)
    review.set_defaults(func=cmd_review)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
