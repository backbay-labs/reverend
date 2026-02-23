from __future__ import annotations

import copy
import importlib.util
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts" / "ml" / "mission_dsl_validator.py"
SPEC = importlib.util.spec_from_file_location("mission_dsl_validator", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"failed to load module spec from {MODULE_PATH}")
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

SCHEMA_PATH = ROOT / "docs" / "schemas" / "mission-dsl.schema.json"
EXAMPLE_DIR = ROOT / "docs" / "schemas" / "examples" / "mission-dsl"


class MissionDslValidatorTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    def _load_example(self, filename: str) -> dict[str, object]:
        return json.loads((EXAMPLE_DIR / filename).read_text(encoding="utf-8"))

    def test_examples_validate(self) -> None:
        for filename in sorted(path.name for path in EXAMPLE_DIR.glob("*.json")):
            with self.subTest(example=filename):
                payload = self._load_example(filename)
                MODULE.validate_mission_dsl(payload, schema=self.schema)

    def test_rejects_non_deterministic_retry_jitter(self) -> None:
        payload = copy.deepcopy(self._load_example("triage-mission.json"))
        payload["policies"]["retry_defaults"]["jitter"] = "full"

        with self.assertRaises(MODULE.MissionDslValidationError):
            MODULE.validate_mission_dsl(payload, schema=self.schema)

    def test_rejects_implicit_stage_dependency(self) -> None:
        payload = copy.deepcopy(self._load_example("triage-mission.json"))
        payload["stages"][1]["depends_on"] = []

        with self.assertRaises(MODULE.MissionDslValidationError):
            MODULE.validate_mission_dsl(payload, schema=self.schema)

    def test_rejects_dependency_cycle(self) -> None:
        payload = copy.deepcopy(self._load_example("triage-mission.json"))
        payload["stages"][0]["depends_on"] = ["render_report"]

        with self.assertRaises(MODULE.MissionDslValidationError):
            MODULE.validate_mission_dsl(payload, schema=self.schema)

    def test_compile_mission_spec_returns_typed_stage_order(self) -> None:
        payload = self._load_example("triage-mission.json")
        spec = MODULE.compile_mission_spec(payload, schema=self.schema)

        self.assertEqual(spec.schema_version, 1)
        self.assertEqual(spec.mission_id, "triage.core.v1")
        self.assertEqual(
            spec.stage_order,
            ("ingest_records", "score_triage", "render_report"),
        )
        self.assertEqual(spec.retry_defaults.jitter, "none")
        self.assertEqual(spec.stages[0].stage_id, "ingest_records")
        self.assertEqual(spec.stages[-1].stage_id, "render_report")


if __name__ == "__main__":
    unittest.main()
