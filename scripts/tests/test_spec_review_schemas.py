from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS_DIR = ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

SPEC_SCHEMA_PATH = ROOT / "docs/schemas/spec-packet.schema.json"
REVIEW_SCHEMA_PATH = ROOT / "docs/schemas/review-packet.schema.json"

ANALYSIS_FIXTURE = ROOT / "eval/fixtures/spec-review-v1/analysis.json"
DECISIONS_FIXTURE = ROOT / "eval/fixtures/spec-review-v1/review_decisions.json"


def _load_validator(path: Path) -> Draft202012Validator:
    schema = json.loads(path.read_text(encoding="utf-8"))
    return Draft202012Validator(schema, format_checker=FormatChecker())


class SpecReviewSchemaTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.spec_validator = _load_validator(SPEC_SCHEMA_PATH)
        cls.review_validator = _load_validator(REVIEW_SCHEMA_PATH)

    def _assert_valid(self, validator: Draft202012Validator, payload: object) -> None:
        errors = sorted(validator.iter_errors(payload), key=lambda error: list(error.absolute_path))
        if errors:
            formatted = "\n".join(f"{'/'.join(map(str, err.absolute_path))}: {err.message}" for err in errors)
            self.fail(f"expected payload to be valid, but got:\n{formatted}")

    def test_extraction_and_review_packets_validate_against_schemas(self) -> None:
        from collaboration.extractor import extract_from_doc
        from collaboration.models import AnalystIdentity, DeltaSource, ReviewAction
        from collaboration.models import spec_packet_from_dict
        from collaboration.render import render_review_packet_markdown
        from collaboration.review import ReviewWorkflow

        analysis_doc = json.loads(ANALYSIS_FIXTURE.read_text(encoding="utf-8"))
        reviewer = AnalystIdentity(id="user:alice", actor_type=DeltaSource.HUMAN, display_name="Alice")
        spec_packet = extract_from_doc(analysis_doc, reviewer=reviewer)
        spec_payload = spec_packet.to_dict()
        self._assert_valid(self.spec_validator, spec_payload)

        reloaded = spec_packet_from_dict(spec_payload)
        self.assertEqual(reloaded.compute_content_hash(), spec_packet.compute_content_hash())

        decisions = json.loads(DECISIONS_FIXTURE.read_text(encoding="utf-8"))
        workflow = ReviewWorkflow(reviewer=reviewer)
        session = workflow.create_review_session(spec_packet)
        for delta_id, info in decisions.items():
            action = info["action"]
            rationale = info["rationale"]
            if action == ReviewAction.ACCEPT.value:
                session.accept_delta(delta_id, rationale=rationale)
            elif action == ReviewAction.REJECT.value:
                session.reject_delta(delta_id, rationale=rationale)
            else:
                session.request_changes(delta_id, rationale=rationale)

        review_packet = session.finalize(summary="Fixture review.")
        review_payload = review_packet.to_dict()
        self._assert_valid(self.review_validator, review_payload)

        markdown = render_review_packet_markdown(review_packet, spec_packet)
        self.assertIn("Inline Evidence", markdown)
        for delta in spec_packet.changeset.deltas:
            for evid in delta.evidence_link_ids:
                self.assertIn(f"`{evid}`", markdown)

