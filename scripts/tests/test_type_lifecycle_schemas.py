from __future__ import annotations

import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[2]
TYPE_ASSERTION_SCHEMA_PATH = ROOT / "docs/schemas/type-assertion.schema.json"
RECEIPT_SCHEMA_PATH = ROOT / "docs/schemas/receipt.schema.json"

TS_1 = "2026-02-20T07:00:00Z"
TS_2 = "2026-02-20T07:05:00Z"

UUID_1 = "11111111-1111-4111-8111-111111111111"
UUID_2 = "22222222-2222-4222-8222-222222222222"
UUID_3 = "33333333-3333-4333-8333-333333333333"
UUID_4 = "44444444-4444-4444-8444-444444444444"
UUID_5 = "55555555-5555-4555-8555-555555555555"
UUID_6 = "66666666-6666-4666-8666-666666666666"
UUID_7 = "77777777-7777-4777-8777-777777777777"
UUID_8 = "88888888-8888-4888-8888-888888888888"
UUID_9 = "99999999-9999-4999-8999-999999999999"
UUID_10 = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
UUID_11 = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
UUID_12 = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
UUID_13 = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
UUID_14 = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
UUID_15 = "ffffffff-ffff-4fff-8fff-ffffffffffff"
UUID_16 = "12121212-1212-4121-8121-121212121212"
UUID_17 = "13131313-1313-4131-8131-131313131313"
UUID_18 = "14141414-1414-4141-8141-141414141414"
UUID_19 = "15151515-1515-4151-8151-151515151515"
UUID_20 = "16161616-1616-4161-8161-161616161616"
UUID_21 = "17171717-1717-4171-8171-171717171717"


def _load_validator(path: Path) -> Draft202012Validator:
    schema = json.loads(path.read_text(encoding="utf-8"))
    return Draft202012Validator(schema, format_checker=FormatChecker())


class TypeLifecycleSchemaTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.type_validator = _load_validator(TYPE_ASSERTION_SCHEMA_PATH)
        cls.receipt_validator = _load_validator(RECEIPT_SCHEMA_PATH)

    def _assert_valid(self, validator: Draft202012Validator, payload: object) -> None:
        errors = sorted(validator.iter_errors(payload), key=lambda error: list(error.absolute_path))
        if errors:
            formatted = "\n".join(f"{'/'.join(map(str, err.absolute_path))}: {err.message}" for err in errors)
            self.fail(f"expected payload to be valid, but got:\n{formatted}")

    def _assert_invalid(self, validator: Draft202012Validator, payload: object) -> None:
        errors = list(validator.iter_errors(payload))
        self.assertTrue(errors, "expected payload to be invalid")

    def _propagation_policy(self) -> dict[str, object]:
        return {
            "same_program": {
                "mode": "AUTO_PROPAGATE",
                "min_confidence": 0.8,
                "confidence_adjustment": -0.05,
                "require_review_on_conflict": True,
                "allow_replace_lower_priority": True,
            },
            "cross_program": {
                "mode": "PROPOSE",
                "min_confidence": 0.85,
                "confidence_adjustment": -0.1,
                "require_review_on_conflict": True,
                "allow_replace_lower_priority": False,
            },
            "corpus_kb": {
                "mode": "PROPOSE",
                "min_confidence": 0.9,
                "confidence_adjustment": -0.1,
                "require_review_on_conflict": True,
                "allow_replace_lower_priority": False,
            },
            "conflict_resolution": {
                "source_priority_order": [
                    "DWARF",
                    "ANALYST",
                    "CONSTRAINT_SOLVER",
                    "ML_MODEL",
                    "HEURISTIC",
                    "GHIDRA_DEFAULT",
                ],
                "confidence_margin": 0.15,
                "tie_breaker": "ASSERTION_ID_ASC",
                "workflow": [
                    "SOURCE_PRIORITY",
                    "CONFIDENCE",
                    "TIE_BREAKER",
                ],
            },
        }

    def _base_type_assertion(self) -> dict[str, object]:
        return {
            "assertion_id": UUID_1,
            "annotation_id": UUID_2,
            "program_id": UUID_3,
            "target": {
                "target_type": "VARIABLE",
                "target_id": UUID_4,
                "target_scope": "VARIABLE",
                "target_address": 4096,
            },
            "asserted_type": {
                "name": "uint32_t",
            },
            "source": {
                "source_type": "ML_MODEL",
                "source_id": "idioms",
                "source_version": "2.1",
            },
            "confidence": 0.82,
            "state": "PROPOSED",
            "created_receipt_id": UUID_5,
            "last_receipt_id": UUID_5,
            "evidence_ids": [
                UUID_6,
            ],
            "created_at": TS_1,
            "updated_at": TS_1,
        }

    def _propagation_event(
        self,
        event_id: str,
        outcome: str,
        policy_mode: str = "AUTO_PROPAGATE",
    ) -> dict[str, object]:
        event: dict[str, object] = {
            "event_id": event_id,
            "scope": "SAME_PROGRAM",
            "rule": "SAME_PROGRAM_DIRECT_DATAFLOW",
            "policy_mode": policy_mode,
            "outcome": outcome,
            "target_program_id": UUID_3,
            "target_assertion_id": UUID_8,
            "resulting_confidence": 0.8,
            "propagated_at": TS_1,
        }

        if outcome == "APPLIED":
            event["applied_receipt_id"] = UUID_9
        elif outcome == "CONFLICT":
            event["conflict_id"] = UUID_10
            event["competing_assertion_id"] = UUID_11
        elif outcome == "ROLLED_BACK":
            event["applied_receipt_id"] = UUID_9
            event["rollback_receipt_id"] = UUID_12
            event["rolled_back_at"] = TS_2
        elif outcome == "SKIPPED":
            event["reason"] = "scope disabled by policy"

        return event

    def _open_conflict(self) -> dict[str, object]:
        return {
            "conflict_id": UUID_10,
            "category": "PRIMITIVE_TYPE_DISAGREEMENT",
            "detected_during": "PROPAGATION",
            "competing_assertion_id": UUID_11,
            "competing_source_type": "ANALYST",
            "status": "OPEN",
            "workflow_version": "source-priority-confidence-tiebreak-v1",
            "queue_position": 0,
            "queued_at": TS_1,
        }

    def _base_receipt(self) -> dict[str, object]:
        return {
            "receipt_id": UUID_14,
            "timestamp": TS_1,
            "actor": {
                "actor": "user:alice",
                "actor_type": "ANALYST",
            },
            "action": "apply",
            "target": {
                "target_type": "TYPE_ASSERTION",
                "target_id": UUID_1,
                "program_id": UUID_3,
                "address": 4096,
                "old_value": {
                    "state": "APPROVED",
                },
                "new_value": {
                    "state": "APPLIED",
                },
            },
            "evidence": [
                {
                    "evidence_type": "CALLSITE",
                    "metadata": {
                        "count": 3,
                    },
                }
            ],
            "chain": {
                "sequence_number": 12,
                "previous_receipt_id": UUID_15,
                "previous_hash": "a" * 64,
            },
            "transaction": {
                "transaction_id": UUID_16,
                "scope": "single",
                "phase": "apply",
                "program_transaction_id": 77,
                "pre_apply_state_hash": "b" * 64,
                "post_apply_state_hash": "c" * 64,
            },
            "receipt_links": [
                {
                    "receipt_id": UUID_17,
                    "link_type": "APPLIES_PROPOSAL",
                }
            ],
            "metadata": {},
            "hash": "d" * 64,
        }

    def test_accepted_state_requires_propagation_policy(self) -> None:
        payload = self._base_type_assertion()
        payload["state"] = "ACCEPTED"
        self._assert_invalid(self.type_validator, payload)

        payload["propagation_policy"] = self._propagation_policy()
        self._assert_valid(self.type_validator, payload)

    def test_propagated_state_requires_applied_event(self) -> None:
        payload = self._base_type_assertion()
        payload["state"] = "PROPAGATED"
        payload["propagation_policy"] = self._propagation_policy()
        payload["propagation_events"] = [
            self._propagation_event(UUID_7, "PROPOSED", policy_mode="PROPOSE")
        ]
        self._assert_invalid(self.type_validator, payload)

        payload["propagation_events"] = [
            self._propagation_event(UUID_7, "APPLIED")
        ]
        self._assert_valid(self.type_validator, payload)

    def test_conflict_outcome_requires_conflict_records(self) -> None:
        payload = self._base_type_assertion()
        payload["state"] = "PROPAGATED"
        payload["propagation_policy"] = self._propagation_policy()
        payload["propagation_events"] = [
            self._propagation_event(UUID_7, "APPLIED"),
            self._propagation_event(UUID_18, "CONFLICT"),
        ]
        self._assert_invalid(self.type_validator, payload)

        payload["conflicts"] = [
            self._open_conflict(),
        ]
        self._assert_valid(self.type_validator, payload)

    def test_rolled_back_event_requires_rollback_receipt(self) -> None:
        payload = self._base_type_assertion()
        payload["state"] = "PROPAGATED"
        payload["propagation_policy"] = self._propagation_policy()
        rolled_back = self._propagation_event(UUID_18, "ROLLED_BACK")
        del rolled_back["rollback_receipt_id"]
        del rolled_back["rolled_back_at"]
        payload["propagation_events"] = [
            self._propagation_event(UUID_7, "APPLIED"),
            rolled_back,
        ]
        self._assert_invalid(self.type_validator, payload)

        payload["propagation_events"][1]["rollback_receipt_id"] = UUID_12
        payload["propagation_events"][1]["rolled_back_at"] = TS_2
        self._assert_valid(self.type_validator, payload)

    def test_auto_resolved_conflict_requires_resolution(self) -> None:
        payload = self._base_type_assertion()
        payload["state"] = "PROPAGATED"
        payload["propagation_policy"] = self._propagation_policy()
        payload["propagation_events"] = [
            self._propagation_event(UUID_7, "APPLIED")
        ]
        payload["conflicts"] = [
            {
                **self._open_conflict(),
                "status": "AUTO_RESOLVED",
            }
        ]
        self._assert_invalid(self.type_validator, payload)

        payload["conflicts"] = [
            {
                **self._open_conflict(),
                "status": "AUTO_RESOLVED",
                "resolution": {
                    "strategy": "SOURCE_PRIORITY",
                    "requires_review": False,
                    "winner_assertion_id": UUID_1,
                    "loser_assertion_id": UUID_11,
                    "priority_gap": 1,
                    "resolved_receipt_id": UUID_13,
                    "resolved_at": TS_2,
                    "reason": "source priority",
                },
                "resolved_receipt_id": UUID_13,
                "resolved_at": TS_2,
            }
        ]
        self._assert_valid(self.type_validator, payload)

    def test_propagate_action_requires_propagation_link(self) -> None:
        payload = self._base_receipt()
        payload["action"] = "propagate"
        self._assert_invalid(self.receipt_validator, payload)

        payload["receipt_links"] = [
            {
                "receipt_id": UUID_17,
                "link_type": "APPLIES_PROPAGATION",
            }
        ]
        self._assert_valid(self.receipt_validator, payload)

    def test_apply_action_requires_approved_pre_state(self) -> None:
        payload = self._base_receipt()
        payload["target"]["old_value"]["state"] = "PROPOSED"
        self._assert_invalid(self.receipt_validator, payload)

        payload["target"]["old_value"]["state"] = "APPROVED"
        self._assert_valid(self.receipt_validator, payload)

    def test_rollback_propagation_receipt_requires_rollback_phase(self) -> None:
        payload = self._base_receipt()
        payload["action"] = "rollback"
        payload["receipt_links"] = [
            {
                "receipt_id": UUID_17,
                "link_type": "ROLLS_BACK_PROPAGATION",
            }
        ]
        self._assert_invalid(self.receipt_validator, payload)

        payload["transaction"]["phase"] = "rollback"
        self._assert_valid(self.receipt_validator, payload)

    def test_resolve_conflict_action_requires_conflict_link(self) -> None:
        payload = self._base_receipt()
        payload["action"] = "resolve_conflict"
        payload["receipt_links"] = [
            {
                "receipt_id": UUID_20,
                "link_type": "APPLIES_PROPAGATION",
            }
        ]
        self._assert_invalid(self.receipt_validator, payload)

        payload["receipt_links"] = [
            {
                "receipt_id": UUID_21,
                "link_type": "RESOLVES_TYPE_CONFLICT",
            }
        ]
        self._assert_valid(self.receipt_validator, payload)

    def test_propagation_link_enforces_propagate_action(self) -> None:
        payload = self._base_receipt()
        payload["receipt_links"] = [
            {
                "receipt_id": UUID_19,
                "link_type": "APPLIES_PROPAGATION",
            }
        ]
        self._assert_invalid(self.receipt_validator, payload)

        payload["action"] = "propagate"
        self._assert_valid(self.receipt_validator, payload)

    def test_receipt_evidence_source_link_requires_source_pair(self) -> None:
        payload = self._base_receipt()
        payload["evidence"] = [
            {
                "evidence_type": "CALLSITE",
                "source_id": UUID_6,
                "metadata": {},
            }
        ]
        self._assert_invalid(self.receipt_validator, payload)

        payload["evidence"][0]["source_type"] = "EVIDENCE_REF"
        self._assert_valid(self.receipt_validator, payload)


if __name__ == "__main__":
    unittest.main()
