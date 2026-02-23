#!/usr/bin/env python3
"""Append-only receipt store with hash-chain integrity verification."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import hmac
import io
import json
import os
import re
import subprocess
import sys
import tarfile
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
ENTITY_ID_PATTERNS: dict[str, re.Pattern[str]] = {
    "static": re.compile(r"^evs_[a-z0-9][a-z0-9._:-]*$"),
    "dynamic": re.compile(r"^evd_[a-z0-9][a-z0-9._:-]*$"),
    "symbolic": re.compile(r"^evy_[a-z0-9][a-z0-9._:-]*$"),
    "taint": re.compile(r"^evt_[a-z0-9][a-z0-9._:-]*$"),
    "proposal": re.compile(r"^evp_[a-z0-9][a-z0-9._:-]*$"),
    "receipt": re.compile(r"^evr_[a-z0-9][a-z0-9._:-]*$"),
}
EDGE_CONTRACTS: dict[str, set[tuple[str, str]]] = {
    "supports": {
        ("static", "proposal"),
        ("dynamic", "proposal"),
        ("symbolic", "proposal"),
        ("taint", "proposal"),
        ("receipt", "proposal"),
    },
    "derived_from": {
        ("proposal", "static"),
        ("proposal", "dynamic"),
        ("proposal", "symbolic"),
        ("proposal", "taint"),
    },
    "corroborates": {
        ("static", "dynamic"),
        ("dynamic", "static"),
        ("symbolic", "taint"),
        ("taint", "symbolic"),
    },
    "supersedes": {
        ("proposal", "proposal"),
        ("receipt", "receipt"),
    },
}
RAW_SIGNAL_ENTITY_TYPES = frozenset({"static", "dynamic", "symbolic", "taint"})


def _utc_now() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _json_copy(value: Any) -> Any:
    return json.loads(json.dumps(value))


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _required_string(value: Any, *, field: str) -> str:
    normalized = str(value or "").strip()
    if not normalized:
        raise ValueError(f"receipt missing required {field}")
    return normalized


def _validate_entity_id(entity_type: str, entity_id: str, *, field: str) -> None:
    pattern = ENTITY_ID_PATTERNS.get(entity_type)
    if pattern is None:
        allowed = ", ".join(sorted(ENTITY_ID_PATTERNS.keys()))
        raise ValueError(f"{field} has unsupported entity_type '{entity_type}' (allowed: {allowed})")
    if not pattern.match(entity_id):
        raise ValueError(f"{field} '{entity_id}' is invalid for entity_type '{entity_type}'")


def _validate_canonical_evidence_contract(item: Mapping[str, Any], *, index: int) -> None:
    canonical_present = any(
        key in item for key in ("entity_type", "entity_id", "entity_schema_version", "edge")
    )
    if not canonical_present:
        return

    entity_type = _required_string(item.get("entity_type"), field=f"evidence[{index}].entity_type")
    entity_id = _required_string(item.get("entity_id"), field=f"evidence[{index}].entity_id")
    _validate_entity_id(entity_type, entity_id, field=f"evidence[{index}].entity_id")

    version_raw = item.get("entity_schema_version")
    try:
        entity_schema_version = int(version_raw)
    except (TypeError, ValueError):
        raise ValueError(f"evidence[{index}].entity_schema_version must be an integer") from None
    if entity_schema_version != 1:
        raise ValueError(
            f"evidence[{index}].entity_schema_version '{version_raw}' is unsupported (expected 1)"
        )

    edge_raw = item.get("edge")
    if edge_raw is None:
        return
    if not isinstance(edge_raw, Mapping):
        raise ValueError(f"evidence[{index}].edge must be an object")

    edge_type = _required_string(edge_raw.get("edge_type"), field=f"evidence[{index}].edge.edge_type")
    target_entity_type = _required_string(
        edge_raw.get("target_entity_type"),
        field=f"evidence[{index}].edge.target_entity_type",
    )
    target_entity_id = _required_string(
        edge_raw.get("target_entity_id"),
        field=f"evidence[{index}].edge.target_entity_id",
    )
    _validate_entity_id(target_entity_type, target_entity_id, field=f"evidence[{index}].edge.target_entity_id")

    target_version_raw = edge_raw.get("target_entity_schema_version")
    try:
        target_entity_schema_version = int(target_version_raw)
    except (TypeError, ValueError):
        raise ValueError(f"evidence[{index}].edge.target_entity_schema_version must be an integer") from None
    if target_entity_schema_version != 1:
        raise ValueError(
            f"evidence[{index}].edge.target_entity_schema_version "
            f"'{target_version_raw}' is unsupported (expected 1)"
        )

    allowed_contracts = EDGE_CONTRACTS.get(edge_type)
    if allowed_contracts is None:
        allowed_edges = ", ".join(sorted(EDGE_CONTRACTS.keys()))
        raise ValueError(
            f"evidence[{index}].edge.edge_type '{edge_type}' is unsupported (allowed: {allowed_edges})"
        )

    pair = (entity_type, target_entity_type)
    if pair not in allowed_contracts:
        raise ValueError(
            f"evidence[{index}].edge '{edge_type}' does not allow "
            f"{entity_type} -> {target_entity_type}"
        )


def _validate_receipt_linkage(receipt: Mapping[str, Any]) -> None:
    actor_raw = receipt.get("actor")
    if not isinstance(actor_raw, Mapping):
        raise ValueError("receipt actor must be an object")
    _required_string(actor_raw.get("actor"), field="actor.actor")
    _required_string(actor_raw.get("actor_type"), field="actor.actor_type")

    _required_string(receipt.get("action"), field="action")

    target_raw = receipt.get("target")
    if not isinstance(target_raw, Mapping):
        raise ValueError("receipt target must be an object")
    _required_string(target_raw.get("target_type"), field="target.target_type")
    _required_string(target_raw.get("target_id"), field="target.target_id")

    evidence_raw = receipt.get("evidence")
    if not isinstance(evidence_raw, list):
        raise ValueError("receipt evidence must be an array")
    for idx, item in enumerate(evidence_raw):
        if not isinstance(item, Mapping):
            raise ValueError(f"receipt evidence[{idx}] must be an object")
        _required_string(item.get("evidence_type"), field=f"evidence[{idx}].evidence_type")
        source_type = str(item.get("source_type") or "").strip()
        source_id = str(item.get("source_id") or "").strip()
        if source_type and not source_id:
            raise ValueError(f"receipt evidence[{idx}] source_type requires source_id")
        if source_id and not source_type:
            raise ValueError(f"receipt evidence[{idx}] source_id requires source_type")
        _validate_canonical_evidence_contract(item, index=idx)


def compute_receipt_hash(receipt: Mapping[str, Any]) -> str:
    payload = dict(receipt)
    payload.pop("hash", None)
    canonical = _canonical_json_bytes(payload)
    return hashlib.sha256(canonical).hexdigest()


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _resolve_signing_key(*, key_inline: str | None, key_env: str) -> bytes:
    if key_inline:
        return key_inline.encode("utf-8")
    key = os.environ.get(key_env, "")
    if key:
        return key.encode("utf-8")
    raise ValueError(f"missing signing key: provide --signing-key or set ${key_env}")


def _sign_manifest_payload(manifest_payload: Mapping[str, Any], *, key: bytes) -> str:
    canonical = _canonical_json_bytes(manifest_payload)
    return hmac.new(key, canonical, digestmod=hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class ReceiptIntegrityIssue:
    index: int
    receipt_id: str | None
    reason: str


@dataclass(frozen=True)
class ReceiptIntegrityReport:
    ok: bool
    issues: tuple[ReceiptIntegrityIssue, ...]

    @property
    def issue_count(self) -> int:
        return len(self.issues)


@dataclass(frozen=True)
class ProvenanceChainIssue:
    proposal_id: str | None
    receipt_id: str | None
    reason: str


@dataclass(frozen=True)
class ProvenanceChainReport:
    ok: bool
    issues: tuple[ProvenanceChainIssue, ...]
    explainability_packet: Mapping[str, Any]

    @property
    def issue_count(self) -> int:
        return len(self.issues)

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "kind": "provenance_chain_verification_report",
            "ok": self.ok,
            "issue_count": self.issue_count,
            "issues": [
                {
                    "proposal_id": issue.proposal_id,
                    "receipt_id": issue.receipt_id,
                    "reason": issue.reason,
                }
                for issue in self.issues
            ],
            "explainability_packet": _json_copy(self.explainability_packet),
        }


@dataclass(frozen=True)
class BundleVerificationIssue:
    reason: str


@dataclass(frozen=True)
class BundleVerificationReport:
    ok: bool
    issues: tuple[BundleVerificationIssue, ...]
    manifest: Mapping[str, Any] | None
    provenance_report: Mapping[str, Any] | None

    @property
    def issue_count(self) -> int:
        return len(self.issues)

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "kind": "mission_artifact_bundle_verification_report",
            "ok": self.ok,
            "issue_count": self.issue_count,
            "issues": [{"reason": issue.reason} for issue in self.issues],
            "manifest": _json_copy(self.manifest) if self.manifest is not None else None,
            "provenance_report": _json_copy(self.provenance_report) if self.provenance_report is not None else None,
        }


@dataclass(frozen=True)
class BundleReplayDivergence:
    stage_id: str
    field: str
    expected: str
    actual: str
    detail: str


@dataclass(frozen=True)
class BundleReplayReport:
    ok: bool
    verification: BundleVerificationReport
    restored_dir: str | None
    runtime_profile: str
    toolchain: Mapping[str, str]
    divergences: tuple[BundleReplayDivergence, ...]

    @property
    def divergence_count(self) -> int:
        return len(self.divergences)

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "kind": "mission_artifact_bundle_replay_report",
            "ok": self.ok,
            "runtime_profile": self.runtime_profile,
            "restored_dir": self.restored_dir,
            "toolchain": dict(self.toolchain),
            "divergence_count": self.divergence_count,
            "divergences": [
                {
                    "stage_id": item.stage_id,
                    "field": item.field,
                    "expected": item.expected,
                    "actual": item.actual,
                    "detail": item.detail,
                }
                for item in self.divergences
            ],
            "verification": self.verification.as_dict(),
        }


class ReceiptStoreIntegrityError(ValueError):
    """Raised when receipt history fails integrity verification."""


class AppendOnlyViolationError(ValueError):
    """Raised when an append operation would mutate existing history."""


def _safe_tar_read_member(reader: tarfile.TarFile, *, member_name: str) -> bytes:
    member = reader.getmember(member_name)
    if not member.isfile():
        raise ValueError(f"tar member '{member_name}' is not a regular file")
    handle = reader.extractfile(member)
    if handle is None:
        raise ValueError(f"tar member '{member_name}' cannot be read")
    return handle.read()


def _normalize_bundle_artifact_paths(paths: Sequence[Path]) -> list[tuple[Path, str]]:
    if not paths:
        raise ValueError("bundle requires at least one --artifact path")
    resolved: list[tuple[Path, str]] = []
    seen: set[str] = set()
    for raw in paths:
        source = raw.resolve()
        if not source.exists() or not source.is_file():
            raise ValueError(f"artifact path '{raw}' must exist and be a file")
        arcname = source.name
        if arcname in seen:
            raise ValueError(f"artifact filename collision for '{arcname}'")
        seen.add(arcname)
        resolved.append((source, f"artifacts/{arcname}"))
    resolved.sort(key=lambda item: item[1])
    return resolved


def _build_bundle_manifest_payload(
    *,
    mission_id: str,
    receipt_store_name: str,
    receipt_store_sha256: str,
    receipt_count: int,
    provenance_report_name: str,
    provenance_report_sha256: str,
    artifacts: Sequence[tuple[str, str, int]],
    replay_manifest: tuple[str, str] | None = None,
    environment_manifest: tuple[str, str] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": 1,
        "kind": "mission_artifact_bundle_manifest",
        "mission_id": mission_id,
        "receipt_store": {
            "path": receipt_store_name,
            "sha256": receipt_store_sha256,
            "receipt_count": receipt_count,
        },
        "provenance_report": {
            "path": provenance_report_name,
            "sha256": provenance_report_sha256,
        },
        "artifacts": [
            {
                "path": path,
                "sha256": checksum,
                "size_bytes": size_bytes,
            }
            for path, checksum, size_bytes in artifacts
        ],
    }
    if replay_manifest is not None:
        replay_path, replay_sha256 = replay_manifest
        payload["replay_manifest"] = {
            "path": replay_path,
            "sha256": replay_sha256,
        }
    if environment_manifest is not None:
        env_path, env_sha256 = environment_manifest
        payload["environment_manifest"] = {
            "path": env_path,
            "sha256": env_sha256,
        }
    return payload


def _write_manifest_json(*, payload: Mapping[str, Any], signature: Mapping[str, Any]) -> bytes:
    manifest = dict(payload)
    manifest["signature"] = dict(signature)
    return json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=True).encode("utf-8") + b"\n"


def _normalize_provenance_payload_for_bundle(payload: Mapping[str, Any]) -> dict[str, Any]:
    normalized = _json_copy(payload)
    explainability = normalized.get("explainability_packet")
    if isinstance(explainability, dict):
        # Keep report content deterministic for identical receipt histories.
        explainability["generated_at_utc"] = "1970-01-01T00:00:00+00:00"
    return normalized


def _write_deterministic_bundle(
    *,
    output_path: Path,
    manifest_bytes: bytes,
    receipt_store_bytes: bytes,
    provenance_report_bytes: bytes,
    artifacts: Sequence[tuple[str, bytes]],
    extra_members: Sequence[tuple[str, bytes]] = (),
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("wb") as raw_handle:
        with gzip.GzipFile(fileobj=raw_handle, mode="wb", mtime=0, filename="") as gz_handle:
            with tarfile.open(fileobj=gz_handle, mode="w") as tar:
                entries: list[tuple[str, bytes]] = [
                    ("manifest.json", manifest_bytes),
                    ("receipts.json", receipt_store_bytes),
                    ("provenance-verification-report.json", provenance_report_bytes),
                ]
                entries.extend((path, payload) for path, payload in artifacts)
                entries.extend((path, payload) for path, payload in extra_members)
                for name, payload in sorted(entries, key=lambda item: item[0]):
                    info = tarfile.TarInfo(name=name)
                    info.size = len(payload)
                    info.mtime = 0
                    info.uid = 0
                    info.gid = 0
                    info.uname = ""
                    info.gname = ""
                    info.mode = 0o644
                    tar.addfile(info, io.BytesIO(payload))


def _load_json_mapping(path: Path, *, field: str) -> dict[str, Any]:
    if not path.exists() or not path.is_file():
        raise ValueError(f"{field} path '{path}' must exist and be a file")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError(f"failed to parse {field} JSON '{path}': {exc}") from exc
    if not isinstance(raw, Mapping):
        raise ValueError(f"{field} JSON '{path}' must decode to an object")
    return dict(raw)


def _stage_output_spec(stage_raw: Mapping[str, Any]) -> tuple[str, str] | None:
    output_raw = stage_raw.get("output")
    if isinstance(output_raw, Mapping):
        path = str(output_raw.get("path") or "").strip()
        sha = str(output_raw.get("sha256") or "").strip().lower()
    else:
        path = str(stage_raw.get("output_path") or "").strip()
        sha = str(stage_raw.get("output_sha256") or "").strip().lower()
    if not path and not sha:
        return None
    if not path or not sha:
        raise ValueError("replay stage output must include both path and sha256")
    if not HEX64_RE.match(sha):
        raise ValueError(f"replay stage output sha256 '{sha}' must be hex64")
    return path, sha


def _parse_stage_input_bindings(values: Sequence[str]) -> dict[str, Path]:
    bindings: dict[str, Path] = {}
    for raw in values:
        entry = str(raw or "").strip()
        if not entry:
            continue
        if "=" not in entry:
            raise ValueError(f"invalid --stage-input '{entry}' (expected <stage_id>=<path>)")
        stage_id, path_raw = entry.split("=", 1)
        stage_id = stage_id.strip()
        path_raw = path_raw.strip()
        if not stage_id or not path_raw:
            raise ValueError(f"invalid --stage-input '{entry}' (expected <stage_id>=<path>)")
        path = Path(path_raw)
        if not path.exists() or not path.is_file():
            raise ValueError(f"stage input path '{path}' must exist and be a file")
        bindings[stage_id] = path
    return bindings


def _normalize_runtime_profile(profile: str | None) -> str:
    raw = str(profile or "").strip().lower()
    if raw == "auto":
        ci_env = str(os.environ.get("CI") or "").strip().lower()
        return "ci" if ci_env in {"1", "true", "yes", "on"} else "local"
    if raw in {"local", "ci"}:
        return raw
    raise ValueError(f"unsupported runtime profile '{profile}' (expected local, ci, or auto)")


def _runtime_toolchain_versions() -> dict[str, str]:
    versions = {
        "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
    }

    def _run_version(cmd: Sequence[str]) -> str:
        try:
            completed = subprocess.run(
                cmd,
                check=False,
                capture_output=True,
                text=True,
            )
        except Exception:
            return ""
        stream = completed.stdout if completed.stdout.strip() else completed.stderr
        first_line = stream.strip().splitlines()
        if not first_line:
            return ""
        line = first_line[0].strip()
        match = re.search(r"(\d+\.\d+(?:\.\d+)?)", line)
        return match.group(1) if match else ""

    java_version = _run_version(("java", "-version"))
    if java_version:
        versions["java"] = java_version
    javac_version = _run_version(("javac", "-version"))
    if javac_version:
        versions["javac"] = javac_version
    return versions


def _load_bundle_members(bundle_path: Path) -> dict[str, bytes]:
    members: dict[str, bytes] = {}
    with tarfile.open(bundle_path, mode="r:gz") as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            if member.name.startswith("/") or ".." in Path(member.name).parts:
                continue
            handle = tar.extractfile(member)
            if handle is None:
                continue
            members[member.name] = handle.read()
    return members


def verify_receipt_history(receipts: Sequence[Mapping[str, Any]]) -> ReceiptIntegrityReport:
    issues: list[ReceiptIntegrityIssue] = []
    previous_receipt_id: str | None = None
    previous_hash: str | None = None
    seen_ids: set[str] = set()

    for idx, receipt in enumerate(receipts):
        receipt_id_raw = receipt.get("receipt_id")
        receipt_id = str(receipt_id_raw).strip() if receipt_id_raw is not None else ""
        resolved_receipt_id = receipt_id or None

        if not receipt_id:
            issues.append(ReceiptIntegrityIssue(index=idx, receipt_id=None, reason="missing receipt_id"))
        elif receipt_id in seen_ids:
            issues.append(
                ReceiptIntegrityIssue(
                    index=idx,
                    receipt_id=receipt_id,
                    reason=f"duplicate receipt_id '{receipt_id}'",
                )
            )
        else:
            seen_ids.add(receipt_id)

        chain_raw = receipt.get("chain")
        if not isinstance(chain_raw, Mapping):
            issues.append(
                ReceiptIntegrityIssue(index=idx, receipt_id=resolved_receipt_id, reason="missing chain object")
            )
            chain_raw = {}

        sequence_number_raw = chain_raw.get("sequence_number")
        try:
            sequence_number = int(sequence_number_raw)
        except (TypeError, ValueError):
            sequence_number = -1
        if sequence_number != idx:
            issues.append(
                ReceiptIntegrityIssue(
                    index=idx,
                    receipt_id=resolved_receipt_id,
                    reason=f"invalid sequence_number '{sequence_number_raw}' (expected {idx})",
                )
            )

        expected_previous_receipt_id = previous_receipt_id
        previous_receipt_id_raw = chain_raw.get("previous_receipt_id")
        resolved_previous_receipt_id = (
            str(previous_receipt_id_raw).strip() if previous_receipt_id_raw is not None else ""
        )
        expected_previous_receipt_id_norm = expected_previous_receipt_id or ""
        if resolved_previous_receipt_id != expected_previous_receipt_id_norm:
            issues.append(
                ReceiptIntegrityIssue(
                    index=idx,
                    receipt_id=resolved_receipt_id,
                    reason=(
                        "invalid previous_receipt_id "
                        f"'{resolved_previous_receipt_id or None}' "
                        f"(expected '{expected_previous_receipt_id or None}')"
                    ),
                )
            )

        expected_previous_hash = previous_hash
        previous_hash_raw = chain_raw.get("previous_hash")
        resolved_previous_hash = str(previous_hash_raw).strip() if previous_hash_raw is not None else ""
        expected_previous_hash_norm = expected_previous_hash or ""
        if resolved_previous_hash != expected_previous_hash_norm:
            issues.append(
                ReceiptIntegrityIssue(
                    index=idx,
                    receipt_id=resolved_receipt_id,
                    reason=(
                        f"invalid previous_hash '{resolved_previous_hash or None}' "
                        f"(expected '{expected_previous_hash or None}')"
                    ),
                )
            )

        receipt_hash = str(receipt.get("hash") or "").strip()
        if not HEX64_RE.match(receipt_hash):
            issues.append(
                ReceiptIntegrityIssue(index=idx, receipt_id=resolved_receipt_id, reason="receipt hash must be hex64")
            )
        else:
            expected_hash = compute_receipt_hash(receipt)
            if receipt_hash != expected_hash:
                issues.append(
                    ReceiptIntegrityIssue(
                        index=idx,
                        receipt_id=resolved_receipt_id,
                        reason=f"receipt hash mismatch (expected '{expected_hash}')",
                    )
                )

        try:
            _validate_receipt_linkage(receipt)
        except ValueError as exc:
            issues.append(
                ReceiptIntegrityIssue(index=idx, receipt_id=resolved_receipt_id, reason=str(exc))
            )

        if receipt_id:
            previous_receipt_id = receipt_id
        if receipt_hash:
            previous_hash = receipt_hash

    return ReceiptIntegrityReport(ok=not issues, issues=tuple(issues))


def _extract_applied_proposal_id(receipt: Mapping[str, Any]) -> str:
    target_raw = receipt.get("target")
    if isinstance(target_raw, Mapping):
        target_type = str(target_raw.get("target_type") or "").strip().lower()
        target_id = str(target_raw.get("target_id") or "").strip()
        if target_type == "proposal" and target_id:
            return target_id

    metadata_raw = receipt.get("metadata")
    if isinstance(metadata_raw, Mapping):
        for key in ("applied_proposal_id", "proposal_id"):
            proposal_id = str(metadata_raw.get(key) or "").strip()
            if proposal_id:
                return proposal_id
    return ""


def _oriented_provenance_edges(item: Mapping[str, Any]) -> tuple[tuple[tuple[str, str], tuple[str, str], str], ...]:
    source_entity_type = str(item.get("entity_type") or "").strip()
    source_entity_id = str(item.get("entity_id") or "").strip()
    edge_raw = item.get("edge")
    if not source_entity_type or not source_entity_id or not isinstance(edge_raw, Mapping):
        return ()

    edge_type = str(edge_raw.get("edge_type") or "").strip()
    target_entity_type = str(edge_raw.get("target_entity_type") or "").strip()
    target_entity_id = str(edge_raw.get("target_entity_id") or "").strip()
    if not edge_type or not target_entity_type or not target_entity_id:
        return ()

    source = (source_entity_type, source_entity_id)
    target = (target_entity_type, target_entity_id)

    if edge_type == "derived_from":
        return ((target, source, edge_type),)
    if edge_type == "corroborates":
        return (
            (source, target, edge_type),
            (target, source, edge_type),
        )
    return ((source, target, edge_type),)


def _resolve_canonical_signal_chain(
    *,
    raw_signal_nodes: set[tuple[str, str]],
    proposal_node: tuple[str, str],
    adjacency: Mapping[tuple[str, str], Sequence[tuple[tuple[str, str], str]]],
) -> tuple[tuple[tuple[str, str], ...], tuple[str, ...]] | None:
    if not raw_signal_nodes:
        return None

    queue: deque[tuple[str, str]] = deque(sorted(raw_signal_nodes))
    parents: dict[tuple[str, str], tuple[str, str] | None] = {node: None for node in raw_signal_nodes}
    inbound_edges: dict[tuple[str, str], str] = {}

    while queue:
        node = queue.popleft()
        if node == proposal_node:
            break
        neighbors = sorted(
            adjacency.get(node, ()),
            key=lambda item: (item[0][0], item[0][1], item[1]),
        )
        for next_node, edge_type in neighbors:
            if next_node in parents:
                continue
            parents[next_node] = node
            inbound_edges[next_node] = edge_type
            queue.append(next_node)

    if proposal_node not in parents:
        return None

    nodes: list[tuple[str, str]] = []
    edges: list[str] = []
    cursor = proposal_node
    while True:
        nodes.append(cursor)
        parent = parents[cursor]
        if parent is None:
            break
        edges.append(inbound_edges[cursor])
        cursor = parent

    nodes.reverse()
    edges.reverse()
    return (tuple(nodes), tuple(edges))


def _build_canonical_explainability_chain(
    *,
    path_nodes: Sequence[tuple[str, str]],
    path_edges: Sequence[str],
    proposal_id: str,
    receipt: Mapping[str, Any],
) -> list[dict[str, Any]]:
    chain: list[dict[str, Any]] = []
    for idx, node in enumerate(path_nodes):
        entry: dict[str, Any] = {
            "step_index": idx,
            "kind": "entity",
            "entity_type": node[0],
            "entity_id": node[1],
        }
        if idx > 0:
            entry["edge_type"] = path_edges[idx - 1]
        chain.append(entry)

    chain_raw = receipt.get("chain")
    if isinstance(chain_raw, Mapping):
        sequence_number = chain_raw.get("sequence_number")
        previous_receipt_id = chain_raw.get("previous_receipt_id")
    else:
        sequence_number = None
        previous_receipt_id = None

    receipt_id = str(receipt.get("receipt_id") or "").strip()
    receipt_step: dict[str, Any] = {
        "step_index": len(chain),
        "kind": "receipt",
        "receipt_id": receipt_id,
        "link_type": "APPLIED_BY_RECEIPT",
    }
    if sequence_number is not None:
        receipt_step["sequence_number"] = sequence_number
    if previous_receipt_id is not None:
        receipt_step["previous_receipt_id"] = previous_receipt_id
    chain.append(receipt_step)

    target_raw = receipt.get("target")
    if isinstance(target_raw, Mapping):
        target_type = str(target_raw.get("target_type") or "").strip()
        target_id = str(target_raw.get("target_id") or "").strip()
        if target_type and target_id:
            if target_type.lower() != "proposal" or target_id != proposal_id:
                chain.append(
                    {
                        "step_index": len(chain),
                        "kind": "annotation",
                        "target_type": target_type,
                        "target_id": target_id,
                        "link_type": "APPLIES_ANNOTATION",
                    }
                )

    return chain


def verify_provenance_chain(receipts: Sequence[Mapping[str, Any]]) -> ProvenanceChainReport:
    issues: list[ProvenanceChainIssue] = []
    integrity_report = verify_receipt_history(receipts)
    if not integrity_report.ok:
        for issue in integrity_report.issues:
            issues.append(
                ProvenanceChainIssue(
                    proposal_id=None,
                    receipt_id=issue.receipt_id,
                    reason=f"receipt_integrity: {issue.reason}",
                )
            )

    explainability_by_proposal: dict[str, dict[str, Any]] = {}
    for receipt in receipts:
        proposal_id = _extract_applied_proposal_id(receipt)
        if not proposal_id:
            continue

        receipt_id = str(receipt.get("receipt_id") or "").strip() or None
        try:
            _validate_entity_id("proposal", proposal_id, field="proposal_id")
        except ValueError as exc:
            issues.append(
                ProvenanceChainIssue(
                    proposal_id=proposal_id,
                    receipt_id=receipt_id,
                    reason=str(exc),
                )
            )
            continue

        chain_raw = receipt.get("chain")
        previous_receipt_id = (
            str(chain_raw.get("previous_receipt_id") or "").strip()
            if isinstance(chain_raw, Mapping)
            else ""
        )
        if not previous_receipt_id:
            issues.append(
                ProvenanceChainIssue(
                    proposal_id=proposal_id,
                    receipt_id=receipt_id,
                    reason="applied proposal receipt is missing previous_receipt_id provenance link",
                )
            )

        evidence_raw = receipt.get("evidence")
        evidence_items = [item for item in evidence_raw if isinstance(item, Mapping)] if isinstance(evidence_raw, list) else []
        if not evidence_items:
            issues.append(
                ProvenanceChainIssue(
                    proposal_id=proposal_id,
                    receipt_id=receipt_id,
                    reason="applied proposal receipt has no canonical evidence entries",
                )
            )
            continue

        raw_signal_nodes: set[tuple[str, str]] = set()
        seen_nodes: set[tuple[str, str]] = set()
        adjacency: dict[tuple[str, str], list[tuple[tuple[str, str], str]]] = {}
        for item in evidence_items:
            source_entity_type = str(item.get("entity_type") or "").strip()
            source_entity_id = str(item.get("entity_id") or "").strip()
            if source_entity_type and source_entity_id:
                source = (source_entity_type, source_entity_id)
                seen_nodes.add(source)
                if source_entity_type in RAW_SIGNAL_ENTITY_TYPES:
                    raw_signal_nodes.add(source)

            edge_raw = item.get("edge")
            if isinstance(edge_raw, Mapping):
                target_entity_type = str(edge_raw.get("target_entity_type") or "").strip()
                target_entity_id = str(edge_raw.get("target_entity_id") or "").strip()
                if target_entity_type and target_entity_id:
                    target = (target_entity_type, target_entity_id)
                    seen_nodes.add(target)
                    if target_entity_type in RAW_SIGNAL_ENTITY_TYPES:
                        raw_signal_nodes.add(target)

            for src, dst, edge_type in _oriented_provenance_edges(item):
                adjacency.setdefault(src, []).append((dst, edge_type))

        proposal_node = ("proposal", proposal_id)
        if proposal_node not in seen_nodes:
            issues.append(
                ProvenanceChainIssue(
                    proposal_id=proposal_id,
                    receipt_id=receipt_id,
                    reason="missing proposal evidence node in canonical evidence chain",
                )
            )
            continue
        if not raw_signal_nodes:
            issues.append(
                ProvenanceChainIssue(
                    proposal_id=proposal_id,
                    receipt_id=receipt_id,
                    reason="missing raw-signal evidence chain to proposal",
                )
            )
            continue

        canonical_path = _resolve_canonical_signal_chain(
            raw_signal_nodes=raw_signal_nodes,
            proposal_node=proposal_node,
            adjacency=adjacency,
        )
        if canonical_path is None:
            issues.append(
                ProvenanceChainIssue(
                    proposal_id=proposal_id,
                    receipt_id=receipt_id,
                    reason="no canonical provenance path from raw signals to applied proposal",
                )
            )
            continue

        path_nodes, path_edges = canonical_path
        explainability_by_proposal[proposal_id] = {
            "proposal_id": proposal_id,
            "applied_receipt_id": receipt_id,
            "canonical_chain": _build_canonical_explainability_chain(
                path_nodes=path_nodes,
                path_edges=path_edges,
                proposal_id=proposal_id,
                receipt=receipt,
            ),
        }

    explainability_packet = {
        "schema_version": 1,
        "kind": "applied_proposal_explainability_packet",
        "generated_at_utc": _utc_now(),
        "applied_proposals": [
            _json_copy(explainability_by_proposal[proposal_id])
            for proposal_id in sorted(explainability_by_proposal)
        ],
    }

    return ProvenanceChainReport(
        ok=not issues,
        issues=tuple(issues),
        explainability_packet=explainability_packet,
    )


class ReceiptStore:
    """JSON-backed append-only receipt store."""

    def __init__(self, path: Path):
        self._path = path
        self._loaded = False
        self._doc: dict[str, Any] = {}

    def append(self, receipt: Mapping[str, Any]) -> Mapping[str, Any]:
        if not isinstance(receipt, Mapping):
            raise ValueError("receipt must be a JSON object")

        self._ensure_loaded()
        history = self._doc["receipts"]
        if not isinstance(history, list):
            raise ValueError("receipt store 'receipts' must be an array")

        report = verify_receipt_history(history)
        if not report.ok:
            first_issue = report.issues[0]
            raise ReceiptStoreIntegrityError(
                "receipt history integrity check failed before append: "
                f"index={first_issue.index} reason={first_issue.reason}"
            )

        receipt_id = _required_string(receipt.get("receipt_id"), field="receipt_id")
        if any(str(item.get("receipt_id") or "").strip() == receipt_id for item in history):
            raise AppendOnlyViolationError(f"receipt_id '{receipt_id}' already exists")

        _validate_receipt_linkage(receipt)

        previous_receipt_id: str | None = None
        previous_hash: str | None = None
        if history:
            previous = history[-1]
            previous_receipt_id = _required_string(previous.get("receipt_id"), field="receipt_id")
            previous_hash = _required_string(previous.get("hash"), field="hash")

        expected_chain = {
            "sequence_number": len(history),
            "previous_receipt_id": previous_receipt_id,
            "previous_hash": previous_hash,
        }
        provided_chain = receipt.get("chain")
        if provided_chain is not None:
            if not isinstance(provided_chain, Mapping):
                raise ValueError("receipt chain must be an object")
            for key, expected_value in expected_chain.items():
                provided_value = provided_chain.get(key)
                normalized_provided = str(provided_value).strip() if provided_value is not None else None
                normalized_expected = str(expected_value).strip() if expected_value is not None else None
                if key == "sequence_number":
                    try:
                        provided_sequence = int(provided_value)
                    except (TypeError, ValueError):
                        raise ValueError("receipt chain sequence_number must be an integer") from None
                    try:
                        expected_sequence = int(expected_value)
                    except (TypeError, ValueError):
                        raise ValueError("internal receipt chain sequence_number is invalid") from None
                    if provided_sequence != expected_sequence:
                        raise ValueError(
                            f"receipt chain sequence_number '{provided_value}' "
                            f"does not match expected '{expected_value}'"
                        )
                elif normalized_provided != normalized_expected:
                    raise ValueError(
                        f"receipt chain {key} '{provided_value}' does not match expected '{expected_value}'"
                    )

        stored = _json_copy(receipt)
        if not isinstance(stored, dict):
            raise ValueError("receipt must encode as a JSON object")

        stored["receipt_id"] = receipt_id
        stored["timestamp"] = _required_string(stored.get("timestamp") or _utc_now(), field="timestamp")
        stored["chain"] = expected_chain

        expected_hash = compute_receipt_hash(stored)
        provided_hash = str(receipt.get("hash") or "").strip()
        if provided_hash and provided_hash != expected_hash:
            raise ValueError("provided receipt hash does not match canonical hash")
        stored["hash"] = expected_hash

        history.append(stored)
        self._flush()
        return _json_copy(stored)

    def list_receipts(self) -> tuple[Mapping[str, Any], ...]:
        self._ensure_loaded()
        history = self._doc["receipts"]
        if not isinstance(history, list):
            raise ValueError("receipt store 'receipts' must be an array")
        return tuple(_json_copy(item) for item in history if isinstance(item, Mapping))

    def verify_integrity(self) -> ReceiptIntegrityReport:
        self._ensure_loaded()
        history = self._doc["receipts"]
        if not isinstance(history, list):
            raise ValueError("receipt store 'receipts' must be an array")
        normalized: list[Mapping[str, Any]] = []
        for idx, item in enumerate(history):
            if not isinstance(item, Mapping):
                return ReceiptIntegrityReport(
                    ok=False,
                    issues=(
                        ReceiptIntegrityIssue(
                            index=idx,
                            receipt_id=None,
                            reason="receipt entry must be an object",
                        ),
                    ),
                )
            normalized.append(item)
        return verify_receipt_history(normalized)

    def verify_provenance(self) -> ProvenanceChainReport:
        self._ensure_loaded()
        history = self._doc["receipts"]
        if not isinstance(history, list):
            raise ValueError("receipt store 'receipts' must be an array")
        normalized: list[Mapping[str, Any]] = []
        for idx, item in enumerate(history):
            if not isinstance(item, Mapping):
                return ProvenanceChainReport(
                    ok=False,
                    issues=(
                        ProvenanceChainIssue(
                            proposal_id=None,
                            receipt_id=None,
                            reason=f"receipt entry at index {idx} must be an object",
                        ),
                    ),
                    explainability_packet={
                        "schema_version": 1,
                        "kind": "applied_proposal_explainability_packet",
                        "generated_at_utc": _utc_now(),
                        "applied_proposals": [],
                    },
                )
            normalized.append(item)
        return verify_provenance_chain(normalized)

    def build_explainability_packet(self) -> Mapping[str, Any]:
        report = self.verify_provenance()
        return _json_copy(report.explainability_packet)

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return

        if not self._path.exists():
            self._doc = {
                "schema_version": 1,
                "kind": "receipt_store",
                "receipts": [],
            }
            self._loaded = True
            return

        raw = json.loads(self._path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("receipt store file must be a JSON object")
        receipts = raw.get("receipts")
        if receipts is None:
            raw["receipts"] = []
        elif not isinstance(receipts, list):
            raise ValueError("receipt store 'receipts' must be an array")
        self._doc = raw
        self._loaded = True

    def _flush(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(self._path.suffix + ".tmp")
        tmp.write_text(json.dumps(self._doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        tmp.replace(self._path)


def _verify_provenance_command(args: argparse.Namespace) -> int:
    store = ReceiptStore(args.store)
    report = store.verify_provenance()
    payload = report.as_dict()
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    else:
        print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if report.ok else 1


def _pack_bundle_command(args: argparse.Namespace) -> int:
    mission_id = _required_string(args.mission_id, field="mission_id")
    signing_key = _resolve_signing_key(key_inline=args.signing_key, key_env=args.signing_key_env)
    artifact_paths = _normalize_bundle_artifact_paths(args.artifact)

    store = ReceiptStore(args.store)
    receipts = list(store.list_receipts())
    provenance_report = store.verify_provenance()
    if not provenance_report.ok:
        payload = provenance_report.as_dict()
        if args.report is not None:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        else:
            print(json.dumps(payload, indent=2, sort_keys=True))
        return 1

    receipt_store_bytes = args.store.read_bytes()
    provenance_payload = _normalize_provenance_payload_for_bundle(provenance_report.as_dict())
    provenance_report_bytes = json.dumps(
        provenance_payload, indent=2, sort_keys=True, ensure_ascii=True
    ).encode("utf-8") + b"\n"

    artifact_payloads: list[tuple[str, bytes]] = []
    artifact_manifest_entries: list[tuple[str, str, int]] = []
    for source, arcname in artifact_paths:
        payload = source.read_bytes()
        artifact_payloads.append((arcname, payload))
        artifact_manifest_entries.append((arcname, _sha256_bytes(payload), len(payload)))

    extra_members: list[tuple[str, bytes]] = []
    replay_manifest_spec: tuple[str, str] | None = None
    if args.replay_manifest is not None:
        replay_payload = _load_json_mapping(args.replay_manifest, field="replay-manifest")
        replay_bytes = json.dumps(replay_payload, indent=2, sort_keys=True, ensure_ascii=True).encode("utf-8") + b"\n"
        replay_path = "replay-manifest.json"
        replay_manifest_spec = (replay_path, _sha256_bytes(replay_bytes))
        extra_members.append((replay_path, replay_bytes))

    environment_manifest_spec: tuple[str, str] | None = None
    if args.environment_manifest is not None:
        environment_payload = _load_json_mapping(args.environment_manifest, field="environment-manifest")
        environment_bytes = (
            json.dumps(environment_payload, indent=2, sort_keys=True, ensure_ascii=True).encode("utf-8") + b"\n"
        )
        environment_path = "environment-manifest.json"
        environment_manifest_spec = (environment_path, _sha256_bytes(environment_bytes))
        extra_members.append((environment_path, environment_bytes))

    manifest_payload = _build_bundle_manifest_payload(
        mission_id=mission_id,
        receipt_store_name="receipts.json",
        receipt_store_sha256=_sha256_bytes(receipt_store_bytes),
        receipt_count=len(receipts),
        provenance_report_name="provenance-verification-report.json",
        provenance_report_sha256=_sha256_bytes(provenance_report_bytes),
        artifacts=artifact_manifest_entries,
        replay_manifest=replay_manifest_spec,
        environment_manifest=environment_manifest_spec,
    )
    signature = {
        "algorithm": "hmac-sha256",
        "key_id": _required_string(args.key_id, field="key_id"),
        "digest": _sign_manifest_payload(manifest_payload, key=signing_key),
    }
    manifest_bytes = _write_manifest_json(payload=manifest_payload, signature=signature)

    _write_deterministic_bundle(
        output_path=args.output,
        manifest_bytes=manifest_bytes,
        receipt_store_bytes=receipt_store_bytes,
        provenance_report_bytes=provenance_report_bytes,
        artifacts=artifact_payloads,
        extra_members=extra_members,
    )

    output_payload = {
        "schema_version": 1,
        "kind": "mission_artifact_bundle_pack_result",
        "ok": True,
        "bundle_path": str(args.output),
        "bundle_sha256": _sha256_file(args.output),
        "manifest_digest": signature["digest"],
        "artifact_count": len(artifact_manifest_entries),
    }
    if args.report is not None:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(output_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    else:
        print(json.dumps(output_payload, indent=2, sort_keys=True))
    return 0


def verify_bundle(*, bundle_path: Path, signing_key: bytes) -> BundleVerificationReport:
    issues: list[BundleVerificationIssue] = []
    manifest: Mapping[str, Any] | None = None
    provenance_report: Mapping[str, Any] | None = None
    bundle_receipts: list[Mapping[str, Any]] = []
    receipts_bytes = b""
    provenance_bytes = b""
    manifest_raw: Mapping[str, Any] = {}

    with tarfile.open(bundle_path, mode="r:gz") as tar:
        required_members = {
            "manifest.json",
            "receipts.json",
            "provenance-verification-report.json",
        }
        member_names = {member.name for member in tar.getmembers()}
        for required in sorted(required_members):
            if required not in member_names:
                issues.append(BundleVerificationIssue(reason=f"bundle missing '{required}'"))

        for member_name in sorted(member_names):
            if member_name.startswith("/") or ".." in Path(member_name).parts:
                issues.append(BundleVerificationIssue(reason=f"bundle has unsafe member path '{member_name}'"))

        try:
            manifest_bytes = _safe_tar_read_member(tar, member_name="manifest.json")
            manifest_raw = json.loads(manifest_bytes.decode("utf-8"))
            if not isinstance(manifest_raw, Mapping):
                issues.append(BundleVerificationIssue(reason="manifest.json must decode to a JSON object"))
                manifest_raw = {}
            manifest = manifest_raw
        except Exception as exc:  # pragma: no cover - defensive parse guard
            issues.append(BundleVerificationIssue(reason=f"failed to parse manifest.json: {exc}"))
            manifest_raw = {}

        try:
            receipts_bytes = _safe_tar_read_member(tar, member_name="receipts.json")
            store_raw = json.loads(receipts_bytes.decode("utf-8"))
            receipts_raw = store_raw.get("receipts") if isinstance(store_raw, Mapping) else None
            if isinstance(receipts_raw, list):
                bundle_receipts = [item for item in receipts_raw if isinstance(item, Mapping)]
            else:
                issues.append(BundleVerificationIssue(reason="receipts.json missing receipts array"))
        except Exception as exc:  # pragma: no cover - defensive parse guard
            issues.append(BundleVerificationIssue(reason=f"failed to parse receipts.json: {exc}"))
            receipts_bytes = b""

        try:
            provenance_bytes = _safe_tar_read_member(tar, member_name="provenance-verification-report.json")
            provenance_raw = json.loads(provenance_bytes.decode("utf-8"))
            if isinstance(provenance_raw, Mapping):
                provenance_report = provenance_raw
            else:
                issues.append(
                    BundleVerificationIssue(reason="provenance-verification-report.json must decode to object")
                )
        except Exception as exc:  # pragma: no cover - defensive parse guard
            issues.append(BundleVerificationIssue(reason=f"failed to parse provenance-verification-report.json: {exc}"))
            provenance_bytes = b""

        if isinstance(manifest_raw, Mapping):
            signature_raw = manifest_raw.get("signature")
            if not isinstance(signature_raw, Mapping):
                issues.append(BundleVerificationIssue(reason="manifest missing signature object"))
            else:
                algorithm = str(signature_raw.get("algorithm") or "").strip()
                digest = str(signature_raw.get("digest") or "").strip()
                if algorithm != "hmac-sha256":
                    issues.append(BundleVerificationIssue(reason=f"unsupported signature algorithm '{algorithm}'"))
                if not HEX64_RE.match(digest):
                    issues.append(BundleVerificationIssue(reason="manifest signature digest must be hex64"))
                unsigned_manifest = dict(manifest_raw)
                unsigned_manifest.pop("signature", None)
                expected_digest = _sign_manifest_payload(unsigned_manifest, key=signing_key)
                if digest and digest != expected_digest:
                    issues.append(BundleVerificationIssue(reason="manifest signature verification failed"))

            receipt_spec = manifest_raw.get("receipt_store")
            if isinstance(receipt_spec, Mapping):
                path = str(receipt_spec.get("path") or "").strip()
                expected_sha = str(receipt_spec.get("sha256") or "").strip()
                if path != "receipts.json":
                    issues.append(BundleVerificationIssue(reason="manifest receipt_store.path must be 'receipts.json'"))
                if expected_sha and expected_sha != _sha256_bytes(receipts_bytes):
                    issues.append(BundleVerificationIssue(reason="receipts.json checksum mismatch"))
            else:
                issues.append(BundleVerificationIssue(reason="manifest missing receipt_store section"))

            prov_spec = manifest_raw.get("provenance_report")
            if isinstance(prov_spec, Mapping):
                path = str(prov_spec.get("path") or "").strip()
                expected_sha = str(prov_spec.get("sha256") or "").strip()
                if path != "provenance-verification-report.json":
                    issues.append(
                        BundleVerificationIssue(
                            reason="manifest provenance_report.path must be 'provenance-verification-report.json'"
                        )
                    )
                if expected_sha and expected_sha != _sha256_bytes(provenance_bytes):
                    issues.append(BundleVerificationIssue(reason="provenance-verification-report.json checksum mismatch"))
            else:
                issues.append(BundleVerificationIssue(reason="manifest missing provenance_report section"))

            artifacts_raw = manifest_raw.get("artifacts")
            if isinstance(artifacts_raw, list):
                for idx, item in enumerate(artifacts_raw):
                    if not isinstance(item, Mapping):
                        issues.append(BundleVerificationIssue(reason=f"manifest artifacts[{idx}] must be object"))
                        continue
                    artifact_path = str(item.get("path") or "").strip()
                    expected_sha = str(item.get("sha256") or "").strip()
                    if not artifact_path.startswith("artifacts/"):
                        issues.append(
                            BundleVerificationIssue(
                                reason=f"manifest artifacts[{idx}].path must be under artifacts/"
                            )
                        )
                        continue
                    if artifact_path not in member_names:
                        issues.append(BundleVerificationIssue(reason=f"bundle missing artifact '{artifact_path}'"))
                        continue
                    payload = _safe_tar_read_member(tar, member_name=artifact_path)
                    if expected_sha and expected_sha != _sha256_bytes(payload):
                        issues.append(BundleVerificationIssue(reason=f"artifact checksum mismatch: '{artifact_path}'"))
            else:
                issues.append(BundleVerificationIssue(reason="manifest missing artifacts array"))

            replay_spec = manifest_raw.get("replay_manifest")
            if replay_spec is not None:
                if not isinstance(replay_spec, Mapping):
                    issues.append(BundleVerificationIssue(reason="manifest replay_manifest must be an object"))
                else:
                    replay_path = str(replay_spec.get("path") or "").strip()
                    replay_sha = str(replay_spec.get("sha256") or "").strip().lower()
                    if replay_path != "replay-manifest.json":
                        issues.append(
                            BundleVerificationIssue(reason="manifest replay_manifest.path must be 'replay-manifest.json'")
                        )
                    if replay_sha and not HEX64_RE.match(replay_sha):
                        issues.append(BundleVerificationIssue(reason="manifest replay_manifest.sha256 must be hex64"))
                    if replay_path in member_names:
                        payload = _safe_tar_read_member(tar, member_name=replay_path)
                        if replay_sha and replay_sha != _sha256_bytes(payload):
                            issues.append(BundleVerificationIssue(reason="replay-manifest.json checksum mismatch"))
                    else:
                        issues.append(BundleVerificationIssue(reason="bundle missing replay-manifest.json"))

            environment_spec = manifest_raw.get("environment_manifest")
            if environment_spec is not None:
                if not isinstance(environment_spec, Mapping):
                    issues.append(BundleVerificationIssue(reason="manifest environment_manifest must be an object"))
                else:
                    env_path = str(environment_spec.get("path") or "").strip()
                    env_sha = str(environment_spec.get("sha256") or "").strip().lower()
                    if env_path != "environment-manifest.json":
                        issues.append(
                            BundleVerificationIssue(
                                reason="manifest environment_manifest.path must be 'environment-manifest.json'"
                            )
                        )
                    if env_sha and not HEX64_RE.match(env_sha):
                        issues.append(BundleVerificationIssue(reason="manifest environment_manifest.sha256 must be hex64"))
                    if env_path in member_names:
                        payload = _safe_tar_read_member(tar, member_name=env_path)
                        if env_sha and env_sha != _sha256_bytes(payload):
                            issues.append(BundleVerificationIssue(reason="environment-manifest.json checksum mismatch"))
                    else:
                        issues.append(BundleVerificationIssue(reason="bundle missing environment-manifest.json"))

    if bundle_receipts:
        provenance_runtime = verify_provenance_chain(bundle_receipts)
        if not provenance_runtime.ok:
            for issue in provenance_runtime.issues:
                issues.append(
                    BundleVerificationIssue(
                        reason=(
                            "provenance verification failed: "
                            f"{issue.reason}"
                        )
                    )
                )
        if isinstance(provenance_report, Mapping):
            expected = _normalize_provenance_payload_for_bundle(provenance_runtime.as_dict())
            if _canonical_json_bytes(provenance_report) != _canonical_json_bytes(expected):
                issues.append(BundleVerificationIssue(reason="embedded provenance report does not match receipts"))

    return BundleVerificationReport(
        ok=not issues,
        issues=tuple(issues),
        manifest=manifest,
        provenance_report=provenance_report,
    )


def _verify_bundle_command(args: argparse.Namespace) -> int:
    signing_key = _resolve_signing_key(key_inline=args.signing_key, key_env=args.signing_key_env)
    report = verify_bundle(bundle_path=args.bundle, signing_key=signing_key)
    payload = report.as_dict()
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    else:
        print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if report.ok else 1


def _resolve_profile_toolchain(environment_manifest: Mapping[str, Any], *, runtime_profile: str) -> dict[str, str]:
    profiles_raw = environment_manifest.get("profiles")
    selected: Mapping[str, Any] | None = None
    if isinstance(profiles_raw, Mapping):
        profile_raw = profiles_raw.get(runtime_profile)
        if isinstance(profile_raw, Mapping):
            selected = profile_raw
    if selected is None:
        toolchain_raw = environment_manifest.get("toolchain")
        if isinstance(toolchain_raw, Mapping):
            selected = toolchain_raw
    if selected is None:
        return {}
    resolved: dict[str, str] = {}
    for key in ("python", "java", "javac"):
        value = str(selected.get(key) or "").strip()
        if value:
            resolved[key] = value
    return resolved


def replay_bundle(
    *,
    bundle_path: Path,
    signing_key: bytes,
    restore_dir: Path | None,
    runtime_profile: str,
    stage_inputs: Mapping[str, Path],
    enforce_toolchain: bool,
) -> BundleReplayReport:
    verification = verify_bundle(bundle_path=bundle_path, signing_key=signing_key)
    members = _load_bundle_members(bundle_path)
    divergences: list[BundleReplayDivergence] = []
    selected_profile = _normalize_runtime_profile(runtime_profile)
    runtime_toolchain = _runtime_toolchain_versions()

    if restore_dir is not None:
        restore_dir.mkdir(parents=True, exist_ok=True)
        for name in sorted(members):
            dest = restore_dir / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(members[name])

    replay_manifest: Mapping[str, Any] = {}
    replay_manifest_bytes = members.get("replay-manifest.json")
    if replay_manifest_bytes:
        try:
            parsed = json.loads(replay_manifest_bytes.decode("utf-8"))
            if isinstance(parsed, Mapping):
                replay_manifest = parsed
            else:
                divergences.append(
                    BundleReplayDivergence(
                        stage_id="bundle",
                        field="replay_manifest",
                        expected="json-object",
                        actual=type(parsed).__name__,
                        detail="replay-manifest.json must decode to object",
                    )
                )
        except Exception as exc:
            divergences.append(
                BundleReplayDivergence(
                    stage_id="bundle",
                    field="replay_manifest",
                    expected="parseable-json",
                    actual="invalid",
                    detail=f"failed to parse replay-manifest.json: {exc}",
                )
            )

    environment_manifest: Mapping[str, Any] = {}
    environment_manifest_bytes = members.get("environment-manifest.json")
    if environment_manifest_bytes:
        try:
            parsed = json.loads(environment_manifest_bytes.decode("utf-8"))
            if isinstance(parsed, Mapping):
                environment_manifest = parsed
            else:
                divergences.append(
                    BundleReplayDivergence(
                        stage_id="bundle",
                        field="environment_manifest",
                        expected="json-object",
                        actual=type(parsed).__name__,
                        detail="environment-manifest.json must decode to object",
                    )
                )
        except Exception as exc:
            divergences.append(
                BundleReplayDivergence(
                    stage_id="bundle",
                    field="environment_manifest",
                    expected="parseable-json",
                    actual="invalid",
                    detail=f"failed to parse environment-manifest.json: {exc}",
                )
            )

    if enforce_toolchain and environment_manifest:
        pinned = _resolve_profile_toolchain(environment_manifest, runtime_profile=selected_profile)
        if not pinned:
            divergences.append(
                BundleReplayDivergence(
                    stage_id="environment",
                    field="runtime_profile",
                    expected=selected_profile,
                    actual="missing",
                    detail=f"environment manifest does not define toolchain for profile '{selected_profile}'",
                )
            )
        for key, expected_value in pinned.items():
            actual_value = str(runtime_toolchain.get(key) or "")
            if actual_value != expected_value:
                divergences.append(
                    BundleReplayDivergence(
                        stage_id="environment",
                        field=f"{key}_version",
                        expected=expected_value,
                        actual=actual_value or "missing",
                        detail=f"toolchain mismatch for profile '{selected_profile}'",
                    )
                )

    stages_raw = replay_manifest.get("stages")
    stages = stages_raw if isinstance(stages_raw, list) else []
    for stage_entry in stages:
        if not isinstance(stage_entry, Mapping):
            continue
        stage_id = str(stage_entry.get("stage_id") or stage_entry.get("stage") or "").strip()
        if not stage_id:
            continue

        expected_input_sha = str(stage_entry.get("input_sha256") or "").strip().lower()
        if expected_input_sha:
            if not HEX64_RE.match(expected_input_sha):
                divergences.append(
                    BundleReplayDivergence(
                        stage_id=stage_id,
                        field="input_sha256",
                        expected="hex64",
                        actual=expected_input_sha,
                        detail="invalid expected input hash",
                    )
                )
            elif stage_id not in stage_inputs:
                divergences.append(
                    BundleReplayDivergence(
                        stage_id=stage_id,
                        field="input_sha256",
                        expected=expected_input_sha,
                        actual="missing",
                        detail="no --stage-input binding provided for stage",
                    )
                )
            else:
                actual_input_sha = _sha256_file(stage_inputs[stage_id]).lower()
                if actual_input_sha != expected_input_sha:
                    divergences.append(
                        BundleReplayDivergence(
                            stage_id=stage_id,
                            field="input_sha256",
                            expected=expected_input_sha,
                            actual=actual_input_sha,
                            detail=f"input hash mismatch ({stage_inputs[stage_id]})",
                        )
                    )

        try:
            output_spec = _stage_output_spec(stage_entry)
        except ValueError as exc:
            divergences.append(
                BundleReplayDivergence(
                    stage_id=stage_id,
                    field="output_sha256",
                    expected="valid-output-spec",
                    actual="invalid",
                    detail=str(exc),
                )
            )
            continue
        if output_spec is None:
            continue
        output_path, expected_output_sha = output_spec
        payload = members.get(output_path)
        if payload is None:
            divergences.append(
                BundleReplayDivergence(
                    stage_id=stage_id,
                    field="output_sha256",
                    expected=expected_output_sha,
                    actual="missing",
                    detail=f"bundle member '{output_path}' is missing",
                )
            )
            continue
        actual_output_sha = _sha256_bytes(payload).lower()
        if actual_output_sha != expected_output_sha:
            divergences.append(
                BundleReplayDivergence(
                    stage_id=stage_id,
                    field="output_sha256",
                    expected=expected_output_sha,
                    actual=actual_output_sha,
                    detail=f"output hash mismatch ({output_path})",
                )
            )

    ok = verification.ok and not divergences
    return BundleReplayReport(
        ok=ok,
        verification=verification,
        restored_dir=str(restore_dir) if restore_dir is not None else None,
        runtime_profile=selected_profile,
        toolchain=runtime_toolchain,
        divergences=tuple(divergences),
    )


def _replay_bundle_command(args: argparse.Namespace) -> int:
    signing_key = _resolve_signing_key(key_inline=args.signing_key, key_env=args.signing_key_env)
    stage_inputs = _parse_stage_input_bindings(args.stage_input)
    report = replay_bundle(
        bundle_path=args.bundle,
        signing_key=signing_key,
        restore_dir=args.restore_dir,
        runtime_profile=args.runtime_profile,
        stage_inputs=stage_inputs,
        enforce_toolchain=not args.no_enforce_toolchain,
    )
    payload = report.as_dict()
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    else:
        print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if report.ok else 1


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Receipt-store provenance utilities")
    subparsers = parser.add_subparsers(dest="command", required=True)

    verify_parser = subparsers.add_parser(
        "verify-provenance",
        help="Verify applied-proposal provenance links and emit explainability packet JSON",
    )
    verify_parser.add_argument(
        "--store",
        type=Path,
        required=True,
        help="Path to receipt store JSON file",
    )
    verify_parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional path to write machine-readable verifier report JSON",
    )
    verify_parser.set_defaults(func=_verify_provenance_command)

    pack_parser = subparsers.add_parser(
        "pack-bundle",
        help="Build a deterministic signed mission artifact bundle from receipt/provenance data",
    )
    pack_parser.add_argument("--store", type=Path, required=True, help="Path to receipt store JSON file")
    pack_parser.add_argument(
        "--artifact",
        type=Path,
        action="append",
        required=True,
        help="Artifact file path to include (repeatable)",
    )
    pack_parser.add_argument("--mission-id", type=str, required=True, help="Stable mission identifier")
    pack_parser.add_argument("--output", type=Path, required=True, help="Output bundle path (.tar.gz)")
    pack_parser.add_argument(
        "--key-id",
        type=str,
        default="default",
        help="Signing key identifier embedded in the manifest",
    )
    pack_parser.add_argument(
        "--signing-key",
        type=str,
        default=None,
        help="Inline HMAC signing key; prefer --signing-key-env in production",
    )
    pack_parser.add_argument(
        "--signing-key-env",
        type=str,
        default="MISSION_BUNDLE_SIGNING_KEY",
        help="Environment variable name containing the HMAC signing key",
    )
    pack_parser.add_argument(
        "--report",
        type=Path,
        default=None,
        help="Optional path for pack result JSON",
    )
    pack_parser.add_argument(
        "--replay-manifest",
        type=Path,
        default=None,
        help="Optional replay stage/hash manifest JSON to embed as replay-manifest.json",
    )
    pack_parser.add_argument(
        "--environment-manifest",
        type=Path,
        default=None,
        help="Optional pinned toolchain manifest JSON to embed as environment-manifest.json",
    )
    pack_parser.set_defaults(func=_pack_bundle_command)

    verify_bundle_parser = subparsers.add_parser(
        "verify-bundle",
        help="Verify mission artifact bundle checksums, signature, and provenance chain",
    )
    verify_bundle_parser.add_argument("--bundle", type=Path, required=True, help="Path to bundle (.tar.gz)")
    verify_bundle_parser.add_argument(
        "--signing-key",
        type=str,
        default=None,
        help="Inline HMAC signing key; prefer --signing-key-env in production",
    )
    verify_bundle_parser.add_argument(
        "--signing-key-env",
        type=str,
        default="MISSION_BUNDLE_SIGNING_KEY",
        help="Environment variable name containing the HMAC signing key",
    )
    verify_bundle_parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional path to write machine-readable verification report JSON",
    )
    verify_bundle_parser.set_defaults(func=_verify_bundle_command)

    replay_bundle_parser = subparsers.add_parser(
        "replay-bundle",
        help="Restore a bundle and detect replay divergence by stage input/output hashes",
    )
    replay_bundle_parser.add_argument("--bundle", type=Path, required=True, help="Path to bundle (.tar.gz)")
    replay_bundle_parser.add_argument(
        "--signing-key",
        type=str,
        default=None,
        help="Inline HMAC signing key; prefer --signing-key-env in production",
    )
    replay_bundle_parser.add_argument(
        "--signing-key-env",
        type=str,
        default="MISSION_BUNDLE_SIGNING_KEY",
        help="Environment variable name containing the HMAC signing key",
    )
    replay_bundle_parser.add_argument(
        "--restore-dir",
        type=Path,
        default=None,
        help="Optional directory to restore bundle state files",
    )
    replay_bundle_parser.add_argument(
        "--runtime-profile",
        type=str,
        default="auto",
        help="Toolchain profile to enforce from environment manifest: local|ci|auto",
    )
    replay_bundle_parser.add_argument(
        "--stage-input",
        action="append",
        default=[],
        help="Stage input binding for hash replay check: <stage_id>=<path> (repeatable)",
    )
    replay_bundle_parser.add_argument(
        "--no-enforce-toolchain",
        action="store_true",
        help="Disable pinned toolchain checks from embedded environment-manifest.json",
    )
    replay_bundle_parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional path to write machine-readable replay report JSON",
    )
    replay_bundle_parser.set_defaults(func=_replay_bundle_command)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
