from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict, deque
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SCHEMA_PATH = ROOT / "docs" / "schemas" / "mission-dsl.schema.json"


class MissionDslValidationError(ValueError):
    """Raised when mission DSL payload fails schema or determinism checks."""



def _load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise MissionDslValidationError(f"{path}: expected top-level JSON object")
    return payload



def _schema_errors(payload: dict[str, Any], schema: dict[str, Any]) -> list[str]:
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(payload), key=lambda err: list(err.absolute_path))
    formatted: list[str] = []
    for err in errors:
        path = "/".join(map(str, err.absolute_path))
        formatted.append(f"{path or '<root>'}: {err.message}")
    return formatted



def _determinism_errors(payload: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    determinism_policy = payload.get("policies", {}).get("determinism", {})
    if isinstance(determinism_policy, dict) and determinism_policy.get("allow_randomness") is not False:
        errors.append("policies.determinism.allow_randomness: must be false for deterministic missions")

    stages = payload.get("stages")
    if not isinstance(stages, list):
        return ["stages: expected list"]

    stage_ids: list[str] = []
    stage_by_id: dict[str, dict[str, Any]] = {}
    order_to_stage: dict[int, str] = {}

    for idx, stage in enumerate(stages):
        if not isinstance(stage, dict):
            errors.append(f"stages[{idx}]: expected object")
            continue

        stage_id = stage.get("id")
        if not isinstance(stage_id, str) or not stage_id:
            errors.append(f"stages[{idx}].id: required non-empty string")
            continue

        if stage_id in stage_by_id:
            errors.append(f"stages[{idx}].id: duplicate stage id '{stage_id}'")
            continue

        stage_by_id[stage_id] = stage
        stage_ids.append(stage_id)

        order = stage.get("order")
        if isinstance(order, int):
            if order in order_to_stage:
                errors.append(
                    f"stages[{idx}].order: duplicate order '{order}' shared by '{order_to_stage[order]}' and '{stage_id}'"
                )
            else:
                order_to_stage[order] = stage_id

        stage_outputs = stage.get("outputs")
        if isinstance(stage_outputs, list):
            names = [item.get("name") for item in stage_outputs if isinstance(item, dict)]
            duplicates = sorted({name for name in names if isinstance(name, str) and names.count(name) > 1})
            if duplicates:
                errors.append(f"stages[{idx}].outputs: duplicate output name(s): {', '.join(duplicates)}")

    if errors:
        return errors

    expected_orders = list(range(1, len(stages) + 1))
    actual_orders = sorted(order_to_stage.keys())
    if actual_orders != expected_orders:
        errors.append(
            "stages.order: must be unique contiguous integers starting at 1 "
            f"(got {actual_orders}, expected {expected_orders})"
        )

    # Build graph for cycle checks.
    incoming: dict[str, set[str]] = {stage_id: set() for stage_id in stage_ids}
    outgoing: dict[str, set[str]] = defaultdict(set)

    for stage_id in stage_ids:
        stage = stage_by_id[stage_id]
        depends_on = stage.get("depends_on")
        if not isinstance(depends_on, list):
            continue
        seen_dependencies: set[str] = set()
        for dep in depends_on:
            if not isinstance(dep, str):
                continue
            if dep == stage_id:
                errors.append(f"stages[{stage_id}].depends_on: stage cannot depend on itself")
                continue
            if dep in seen_dependencies:
                errors.append(f"stages[{stage_id}].depends_on: duplicate dependency '{dep}'")
                continue
            seen_dependencies.add(dep)
            if dep not in stage_by_id:
                errors.append(f"stages[{stage_id}].depends_on: unknown dependency '{dep}'")
                continue
            incoming[stage_id].add(dep)
            outgoing[dep].add(stage_id)

    # Input source checks: stage_output inputs must be explicit dependencies and prior order.
    for stage_id in stage_ids:
        stage = stage_by_id[stage_id]
        stage_order = stage.get("order")
        depends_on = set(stage.get("depends_on") or [])
        stage_inputs = stage.get("inputs")
        if not isinstance(stage_inputs, list):
            continue
        for binding in stage_inputs:
            if not isinstance(binding, dict):
                continue
            source = binding.get("source")
            if not isinstance(source, dict):
                continue
            if source.get("kind") != "stage_output":
                continue

            upstream = source.get("stage_id")
            output = source.get("output")
            input_name = binding.get("name")
            input_desc = f"input '{input_name}'" if isinstance(input_name, str) else "stage input"

            if not isinstance(upstream, str) or upstream not in stage_by_id:
                errors.append(f"stages[{stage_id}].inputs: {input_desc} references unknown stage '{upstream}'")
                continue

            if upstream not in depends_on:
                errors.append(
                    f"stages[{stage_id}].inputs: {input_desc} must declare upstream stage '{upstream}' in depends_on"
                )

            upstream_order = stage_by_id[upstream].get("order")
            if isinstance(upstream_order, int) and isinstance(stage_order, int) and upstream_order >= stage_order:
                errors.append(
                    f"stages[{stage_id}].inputs: {input_desc} references stage '{upstream}' with non-prior order"
                )

            if isinstance(output, str):
                outputs = stage_by_id[upstream].get("outputs")
                output_names = {
                    item.get("name")
                    for item in outputs
                    if isinstance(item, dict) and isinstance(item.get("name"), str)
                }
                if output not in output_names:
                    errors.append(
                        f"stages[{stage_id}].inputs: {input_desc} references unknown output '{output}' on stage '{upstream}'"
                    )

    # Deterministic retry policy checks.
    default_retry = payload.get("policies", {}).get("retry_defaults", {})
    if isinstance(default_retry, dict):
        if default_retry.get("jitter") != "none":
            errors.append("policies.retry_defaults.jitter: must be 'none' for deterministic retry behavior")

    for stage_id in stage_ids:
        retry = stage_by_id[stage_id].get("retry")
        if isinstance(retry, dict) and retry.get("jitter") != "none":
            errors.append(f"stages[{stage_id}].retry.jitter: must be 'none' for deterministic retry behavior")

    # Mission outputs must reference known stage outputs.
    mission_outputs = payload.get("outputs")
    if isinstance(mission_outputs, list):
        seen_output_names: set[str] = set()
        for idx, output in enumerate(mission_outputs):
            if not isinstance(output, dict):
                continue
            output_name = output.get("name")
            if isinstance(output_name, str):
                if output_name in seen_output_names:
                    errors.append(f"outputs[{idx}].name: duplicate mission output name '{output_name}'")
                seen_output_names.add(output_name)
            source = output.get("source")
            if not isinstance(source, dict) or source.get("kind") != "stage_output":
                continue
            source_stage = source.get("stage_id")
            source_output = source.get("output")
            if not isinstance(source_stage, str) or source_stage not in stage_by_id:
                errors.append(f"outputs[{idx}].source.stage_id: unknown stage '{source_stage}'")
                continue
            source_names = {
                item.get("name")
                for item in stage_by_id[source_stage].get("outputs", [])
                if isinstance(item, dict) and isinstance(item.get("name"), str)
            }
            if isinstance(source_output, str) and source_output not in source_names:
                errors.append(
                    f"outputs[{idx}].source.output: unknown output '{source_output}' on stage '{source_stage}'"
                )

    # Cycle detection using Kahn's algorithm.
    queue = deque(sorted([stage_id for stage_id, deps in incoming.items() if not deps]))
    visited_count = 0
    incoming_copy = {k: set(v) for k, v in incoming.items()}
    while queue:
        current = queue.popleft()
        visited_count += 1
        for neighbor in sorted(outgoing.get(current, set())):
            incoming_copy[neighbor].discard(current)
            if not incoming_copy[neighbor]:
                queue.append(neighbor)
    if visited_count != len(stage_ids):
        errors.append("stages.depends_on: cycle detected in stage dependency graph")

    return errors



def validate_mission_dsl(payload: dict[str, Any], *, schema: dict[str, Any]) -> None:
    errors = _schema_errors(payload, schema)
    errors.extend(_determinism_errors(payload))
    if errors:
        formatted = "\n".join(f"- {entry}" for entry in errors)
        raise MissionDslValidationError(f"mission DSL validation failed:\n{formatted}")



def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate mission DSL schema and deterministic constraints")
    parser.add_argument("--mission", required=True, help="Path to mission DSL JSON file")
    parser.add_argument(
        "--schema",
        default=str(DEFAULT_SCHEMA_PATH),
        help="Path to mission DSL JSON schema (default: docs/schemas/mission-dsl.schema.json)",
    )
    return parser.parse_args(argv)



def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    mission_path = Path(args.mission)
    schema_path = Path(args.schema)

    try:
        payload = _load_json(mission_path)
        schema = _load_json(schema_path)
        validate_mission_dsl(payload, schema=schema)
    except (MissionDslValidationError, json.JSONDecodeError, OSError) as exc:
        print(f"[mission-dsl-validator] ERROR: {exc}", file=sys.stderr)
        return 1

    print(f"[mission-dsl-validator] OK: {mission_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
