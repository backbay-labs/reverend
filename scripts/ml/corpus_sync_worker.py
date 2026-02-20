#!/usr/bin/env python3
"""E7-S2: secured corpus sync/read worker.

This module syncs approved proposals from a local store into a shared corpus
backend representation while enforcing provenance continuity and access policy
checks for both sync and retrieval operations.
"""

from __future__ import annotations

import argparse
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Protocol
from urllib.parse import urlparse

SYNC_WRITE_CAPABILITY = "WRITE.CORPUS_SYNC"
READ_CAPABILITY = "READ.CORPUS"
DEFAULT_SYSTEM_PRINCIPAL = "system:corpus_sync_worker"
DEFAULT_SYSTEM_CAPABILITIES = frozenset({"WRITE.*", "READ.*"})
POLICY_MODE_OFFLINE = "offline"
POLICY_MODE_ALLOWLIST = "allowlist"
POLICY_MODE_CLOUD = "cloud"
_POLICY_MODES = frozenset({POLICY_MODE_OFFLINE, POLICY_MODE_ALLOWLIST, POLICY_MODE_CLOUD})


def _utc_now() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _now_ns() -> int:
    return time.perf_counter_ns()


def _elapsed_ms(start_ns: int) -> float:
    return round((time.perf_counter_ns() - start_ns) / 1_000_000.0, 3)


def _normalize_program_id(value: Any) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip()
    return normalized or None


def _normalize_project_id(value: Any) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip()
    return normalized or None


def _normalize_policy_mode(value: Any) -> str:
    normalized = str(value or POLICY_MODE_OFFLINE).strip().lower()
    if not normalized:
        normalized = POLICY_MODE_OFFLINE
    if normalized not in _POLICY_MODES:
        supported = ", ".join(sorted(_POLICY_MODES))
        raise ValueError(f"policy mode must be one of: {supported}")
    return normalized


def _normalize_endpoint(value: Any) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip()
    return normalized or None


def _is_remote_endpoint(endpoint: str) -> bool:
    parsed = urlparse(endpoint)
    return parsed.scheme.lower() in {"http", "https"} and bool(parsed.netloc)


def _endpoint_matches_allowlist(endpoint: str, allowed_endpoints: frozenset[str]) -> bool:
    normalized_endpoint = endpoint.strip()
    if normalized_endpoint in allowed_endpoints:
        return True

    endpoint_lower = normalized_endpoint.lower()
    parsed_endpoint = urlparse(normalized_endpoint)
    endpoint_host = (parsed_endpoint.hostname or "").lower()
    endpoint_origin = ""
    if parsed_endpoint.scheme and parsed_endpoint.netloc:
        endpoint_origin = f"{parsed_endpoint.scheme.lower()}://{parsed_endpoint.netloc.lower()}"

    for allowed in allowed_endpoints:
        candidate = allowed.strip()
        if not candidate:
            continue
        if candidate == normalized_endpoint:
            return True

        candidate_lower = candidate.lower()
        if candidate_lower == endpoint_lower:
            return True

        parsed_candidate = urlparse(candidate)
        if parsed_candidate.scheme and parsed_candidate.netloc:
            candidate_origin = f"{parsed_candidate.scheme.lower()}://{parsed_candidate.netloc.lower()}"
            if endpoint_origin == candidate_origin:
                return True
            if endpoint_lower.startswith(candidate_origin.rstrip("/") + "/"):
                return True
            continue

        if "://" not in candidate and "/" not in candidate and endpoint_host:
            if candidate_lower.startswith("*."):
                if endpoint_host.endswith(candidate_lower[1:]):
                    return True
            elif endpoint_host == candidate_lower:
                return True

    return False


def _coerce_endpoints(raw: Any, *, field_name: str) -> set[str]:
    if raw is None:
        return set()
    if not isinstance(raw, list):
        raise ValueError(f"{field_name} must be a JSON array")
    normalized = {
        endpoint
        for endpoint in (_normalize_endpoint(item) for item in raw)
        if endpoint is not None
    }
    return normalized


def _normalize_capability(value: str) -> str:
    return value.strip().upper()


def _capability_granted(granted_capabilities: frozenset[str], required_capability: str) -> bool:
    required = _normalize_capability(required_capability)
    for granted_raw in granted_capabilities:
        granted = _normalize_capability(granted_raw)
        if not granted:
            continue
        if granted in {"*", "ADMIN"}:
            return True
        if granted == required:
            return True
        if granted.endswith(".*"):
            prefix = granted[:-1]
            if required.startswith(prefix):
                return True
    return False


def _normalize_provenance_entry(raw: Any) -> dict[str, str] | None:
    if isinstance(raw, Mapping):
        receipt_id = str(raw.get("receipt_id") or raw.get("id") or "").strip()
        if not receipt_id:
            return None
        entry: dict[str, str] = {"receipt_id": receipt_id}

        previous_receipt_id = str(raw.get("previous_receipt_id") or raw.get("previous") or "").strip()
        if previous_receipt_id:
            entry["previous_receipt_id"] = previous_receipt_id

        receipt_hash = str(raw.get("hash") or raw.get("receipt_hash") or "").strip()
        if receipt_hash:
            entry["hash"] = receipt_hash

        timestamp_utc = str(raw.get("timestamp_utc") or raw.get("timestamp") or "").strip()
        if timestamp_utc:
            entry["timestamp_utc"] = timestamp_utc

        return entry

    if raw is None:
        return None

    receipt_id = str(raw).strip()
    if not receipt_id:
        return None
    return {"receipt_id": receipt_id}


def _append_provenance_entries(target: list[dict[str, str]], raw_chain: Any) -> None:
    if isinstance(raw_chain, list):
        for item in raw_chain:
            entry = _normalize_provenance_entry(item)
            if entry is not None:
                target.append(entry)
        return

    if isinstance(raw_chain, Mapping):
        nested_chain = raw_chain.get("chain")
        if isinstance(nested_chain, list):
            _append_provenance_entries(target, nested_chain)
        entry = _normalize_provenance_entry(raw_chain)
        if entry is not None:
            target.append(entry)
        return

    entry = _normalize_provenance_entry(raw_chain)
    if entry is not None:
        target.append(entry)


def _dedupe_provenance_chain(entries: list[dict[str, str]]) -> list[dict[str, str]]:
    deduped: list[dict[str, str]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for entry in entries:
        key = (
            entry.get("receipt_id", ""),
            entry.get("previous_receipt_id", ""),
            entry.get("hash", ""),
            entry.get("timestamp_utc", ""),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(dict(entry))
    return deduped


def _extract_provenance_chain(
    raw: Mapping[str, Any],
    *,
    artifact: Mapping[str, Any] | None,
    receipt_id: str,
) -> tuple[Mapping[str, str], ...]:
    entries: list[dict[str, str]] = []
    _append_provenance_entries(entries, raw.get("provenance_chain"))
    _append_provenance_entries(entries, raw.get("provenance"))

    if artifact is not None:
        _append_provenance_entries(entries, artifact.get("provenance_chain"))
        _append_provenance_entries(entries, artifact.get("provenance"))

    deduped = _dedupe_provenance_chain(entries)
    if not deduped:
        deduped = [{"receipt_id": receipt_id}]

    tail_receipt_id = deduped[-1].get("receipt_id", "")
    if tail_receipt_id != receipt_id:
        link: dict[str, str] = {"receipt_id": receipt_id}
        if tail_receipt_id:
            link["previous_receipt_id"] = tail_receipt_id
        deduped.append(link)

    return tuple(dict(entry) for entry in deduped)


def _validate_provenance_chain(
    provenance_chain: tuple[Mapping[str, str], ...],
    *,
    expected_head_receipt_id: str,
) -> None:
    if not provenance_chain:
        raise ValueError("provenance_chain cannot be empty")

    seen_receipt_ids: set[str] = set()
    previous_receipt_id: str | None = None

    for idx, entry in enumerate(provenance_chain):
        receipt_id = str(entry.get("receipt_id") or "").strip()
        if not receipt_id:
            raise ValueError("provenance_chain entry missing required receipt_id")

        if receipt_id in seen_receipt_ids:
            raise ValueError(f"provenance_chain contains duplicate receipt_id '{receipt_id}'")
        seen_receipt_ids.add(receipt_id)

        parent = str(entry.get("previous_receipt_id") or "").strip()
        if idx > 0 and parent and parent != previous_receipt_id:
            raise ValueError(
                "provenance_chain continuity broken: "
                f"entry '{receipt_id}' points to '{parent}' instead of '{previous_receipt_id}'"
            )

        previous_receipt_id = receipt_id

    if previous_receipt_id != expected_head_receipt_id:
        raise ValueError(
            "provenance head mismatch: "
            f"expected '{expected_head_receipt_id}', found '{previous_receipt_id}'"
        )


class AccessDeniedError(PermissionError):
    """Raised when the active access context cannot perform an operation."""


@dataclass(frozen=True)
class AccessContext:
    """Principal + capabilities used for sync/read policy checks."""

    principal: str
    capabilities: frozenset[str]
    allowed_program_ids: frozenset[str] | None = None

    @classmethod
    def system(cls) -> "AccessContext":
        return cls(
            principal=DEFAULT_SYSTEM_PRINCIPAL,
            capabilities=frozenset(DEFAULT_SYSTEM_CAPABILITIES),
            allowed_program_ids=None,
        )

    @classmethod
    def from_values(
        cls,
        *,
        principal: str | None = None,
        capabilities: set[str] | None = None,
        allowed_program_ids: set[str] | None = None,
    ) -> "AccessContext":
        resolved_principal = str(principal or DEFAULT_SYSTEM_PRINCIPAL).strip() or DEFAULT_SYSTEM_PRINCIPAL

        if capabilities is None:
            resolved_capabilities = set(DEFAULT_SYSTEM_CAPABILITIES)
        else:
            resolved_capabilities = {
                normalized
                for normalized in (_normalize_capability(value) for value in capabilities)
                if normalized
            }

        resolved_program_ids: frozenset[str] | None = None
        if allowed_program_ids is not None:
            normalized_program_ids = {
                normalized
                for normalized in (_normalize_program_id(value) for value in allowed_program_ids)
                if normalized
            }
            resolved_program_ids = frozenset(normalized_program_ids)

        return cls(
            principal=resolved_principal,
            capabilities=frozenset(resolved_capabilities),
            allowed_program_ids=resolved_program_ids,
        )


@dataclass(frozen=True)
class AuditEvent:
    """Single structured access-control/provenance audit event."""

    event_type: str
    severity: str
    principal: str
    action: str
    outcome: str
    proposal_id: str | None = None
    program_id: str | None = None
    project_id: str | None = None
    required_capability: str | None = None
    destination: str | None = None
    policy_mode: str | None = None
    reason: str | None = None
    timestamp_utc: str = field(default_factory=_utc_now)

    def to_json(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": 1,
            "kind": "corpus_access_audit",
            "timestamp_utc": self.timestamp_utc,
            "event_type": self.event_type,
            "severity": self.severity,
            "principal": self.principal,
            "action": self.action,
            "outcome": self.outcome,
        }
        if self.proposal_id is not None:
            payload["proposal_id"] = self.proposal_id
        if self.program_id is not None:
            payload["program_id"] = self.program_id
        if self.project_id is not None:
            payload["project_id"] = self.project_id
        if self.required_capability is not None:
            payload["required_capability"] = self.required_capability
        if self.destination is not None:
            payload["destination"] = self.destination
        if self.policy_mode is not None:
            payload["policy_mode"] = self.policy_mode
        if self.reason is not None:
            payload["reason"] = self.reason
        return payload


class AuditLogger:
    """Append-only structured audit logger."""

    def __init__(self, path: Path | None = None):
        self._path = path
        self._events: list[AuditEvent] = []

    @property
    def events(self) -> tuple[AuditEvent, ...]:
        return tuple(self._events)

    def log(self, event: AuditEvent) -> None:
        self._events.append(event)
        if self._path is None:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event.to_json(), sort_keys=True) + "\n")


@dataclass(frozen=True)
class EndpointPolicyRule:
    """Single policy mode and endpoint allowlist rule."""

    mode: str = POLICY_MODE_OFFLINE
    allowed_endpoints: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        object.__setattr__(self, "mode", _normalize_policy_mode(self.mode))
        object.__setattr__(
            self,
            "allowed_endpoints",
            frozenset(
                endpoint
                for endpoint in (_normalize_endpoint(item) for item in self.allowed_endpoints)
                if endpoint is not None
            ),
        )

    @classmethod
    def from_values(
        cls,
        *,
        mode: str | None = None,
        allowed_endpoints: set[str] | None = None,
    ) -> "EndpointPolicyRule":
        normalized_endpoints = {
            endpoint
            for endpoint in (_normalize_endpoint(item) for item in (allowed_endpoints or set()))
            if endpoint is not None
        }
        return cls(
            mode=_normalize_policy_mode(mode),
            allowed_endpoints=frozenset(normalized_endpoints),
        )


@dataclass(frozen=True)
class EndpointPolicyConfig:
    """Default + per-project endpoint policy rules."""

    default_rule: EndpointPolicyRule = field(default_factory=EndpointPolicyRule)
    project_rules: Mapping[str, EndpointPolicyRule] = field(default_factory=dict)

    def __post_init__(self) -> None:
        normalized: dict[str, EndpointPolicyRule] = {}
        for raw_project_id, rule in self.project_rules.items():
            project_id = _normalize_project_id(raw_project_id)
            if project_id is None:
                continue
            if not isinstance(rule, EndpointPolicyRule):
                raise ValueError("project policy rules must be EndpointPolicyRule values")
            normalized[project_id] = rule
        object.__setattr__(self, "project_rules", dict(sorted(normalized.items())))

    @classmethod
    def from_values(
        cls,
        *,
        default_mode: str | None = None,
        default_allowed_endpoints: set[str] | None = None,
        project_modes: Mapping[str, str] | None = None,
        project_allowed_endpoints: Mapping[str, set[str]] | None = None,
    ) -> "EndpointPolicyConfig":
        default_rule = EndpointPolicyRule.from_values(
            mode=default_mode,
            allowed_endpoints=default_allowed_endpoints,
        )

        normalized_modes: dict[str, str] = {}
        for raw_project_id, raw_mode in (project_modes or {}).items():
            project_id = _normalize_project_id(raw_project_id)
            if project_id is None:
                continue
            normalized_modes[project_id] = _normalize_policy_mode(raw_mode)

        normalized_allowed: dict[str, set[str]] = {}
        for raw_project_id, raw_endpoints in (project_allowed_endpoints or {}).items():
            project_id = _normalize_project_id(raw_project_id)
            if project_id is None:
                continue
            endpoints = {
                endpoint
                for endpoint in (_normalize_endpoint(item) for item in raw_endpoints)
                if endpoint is not None
            }
            normalized_allowed[project_id] = endpoints

        project_rules: dict[str, EndpointPolicyRule] = {}
        for project_id in sorted(set(normalized_modes) | set(normalized_allowed)):
            mode = normalized_modes.get(project_id, default_rule.mode)
            allowed_endpoints = normalized_allowed.get(project_id, set(default_rule.allowed_endpoints))
            project_rules[project_id] = EndpointPolicyRule.from_values(
                mode=mode,
                allowed_endpoints=allowed_endpoints,
            )

        return cls(default_rule=default_rule, project_rules=project_rules)

    @classmethod
    def from_json(cls, raw: Mapping[str, Any]) -> "EndpointPolicyConfig":
        if not isinstance(raw, Mapping):
            raise ValueError("policy config must be a JSON object")

        default_mode = raw.get("default_mode")
        default_allowed = _coerce_endpoints(raw.get("allowed_endpoints"), field_name="allowed_endpoints")

        project_modes: dict[str, str] = {}
        project_allowed_endpoints: dict[str, set[str]] = {}
        projects_raw = raw.get("projects")
        if projects_raw is not None:
            if not isinstance(projects_raw, Mapping):
                raise ValueError("policy config field 'projects' must be a JSON object")
            for raw_project_id, raw_rule in projects_raw.items():
                project_id = _normalize_project_id(raw_project_id)
                if project_id is None:
                    continue
                if not isinstance(raw_rule, Mapping):
                    raise ValueError(f"policy config for project '{project_id}' must be a JSON object")

                if "mode" in raw_rule:
                    project_modes[project_id] = str(raw_rule.get("mode"))
                if "allowed_endpoints" in raw_rule:
                    project_allowed_endpoints[project_id] = _coerce_endpoints(
                        raw_rule.get("allowed_endpoints"),
                        field_name=f"projects.{project_id}.allowed_endpoints",
                    )

        return cls.from_values(
            default_mode=default_mode,
            default_allowed_endpoints=default_allowed,
            project_modes=project_modes,
            project_allowed_endpoints=project_allowed_endpoints,
        )

    @classmethod
    def from_path(cls, path: Path) -> "EndpointPolicyConfig":
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, Mapping):
            raise ValueError("policy config file must contain a JSON object")
        return cls.from_json(raw)

    def resolve(self, *, project_id: str | None, program_id: str | None = None) -> EndpointPolicyRule:
        resolved_project_id = _normalize_project_id(project_id)
        if resolved_project_id is not None and resolved_project_id in self.project_rules:
            return self.project_rules[resolved_project_id]

        resolved_program_id = _normalize_program_id(program_id)
        if resolved_program_id is not None and resolved_program_id in self.project_rules:
            return self.project_rules[resolved_program_id]

        return self.default_rule


class EndpointPolicyEnforcer:
    """Runtime destination enforcement for sync/read worker paths."""

    def __init__(
        self,
        *,
        context: AccessContext,
        destination: str,
        policy_config: EndpointPolicyConfig | None = None,
        audit_logger: AuditLogger | None = None,
    ):
        normalized_destination = _normalize_endpoint(destination)
        if normalized_destination is None:
            raise ValueError("destination cannot be empty")
        self._context = context
        self._destination = normalized_destination
        self._policy_config = policy_config or EndpointPolicyConfig()
        self._audit_logger = audit_logger or AuditLogger()

    def authorize_sync(
        self,
        *,
        proposal_id: str,
        project_id: str | None,
        program_id: str | None,
    ) -> None:
        self._authorize(
            action="SYNC",
            proposal_id=proposal_id,
            project_id=project_id,
            program_id=program_id,
        )

    def authorize_read(
        self,
        *,
        proposal_id: str,
        project_id: str | None,
        program_id: str | None,
    ) -> None:
        self._authorize(
            action="READ",
            proposal_id=proposal_id,
            project_id=project_id,
            program_id=program_id,
        )

    def _authorize(
        self,
        *,
        action: str,
        proposal_id: str,
        project_id: str | None,
        program_id: str | None,
    ) -> None:
        resolved_project_id = _normalize_project_id(project_id)
        resolved_program_id = _normalize_program_id(program_id)
        scope_id = resolved_project_id or resolved_program_id or "default"
        rule = self._policy_config.resolve(
            project_id=resolved_project_id,
            program_id=resolved_program_id,
        )

        violation_reason: str | None = None
        if rule.mode == POLICY_MODE_OFFLINE and _is_remote_endpoint(self._destination):
            violation_reason = (
                f"policy mode '{POLICY_MODE_OFFLINE}' blocks destination '{self._destination}' "
                f"for project '{scope_id}'"
            )
        elif rule.mode == POLICY_MODE_ALLOWLIST and not _endpoint_matches_allowlist(
            self._destination,
            rule.allowed_endpoints,
        ):
            violation_reason = (
                f"policy mode '{POLICY_MODE_ALLOWLIST}' blocks destination '{self._destination}' "
                f"for project '{scope_id}': destination is not allowlisted"
            )

        if violation_reason is None:
            return

        self._audit_logger.log(
            AuditEvent(
                event_type="EGRESS_BLOCKED",
                severity="WARNING",
                principal=self._context.principal,
                action=action,
                outcome="DENY",
                proposal_id=proposal_id,
                program_id=resolved_program_id,
                project_id=resolved_project_id,
                destination=self._destination,
                policy_mode=rule.mode,
                reason=violation_reason,
            )
        )
        raise AccessDeniedError(violation_reason)


class AccessPolicy:
    """Capability + scope policy enforcement with audit logging."""

    def __init__(self, *, context: AccessContext, audit_logger: AuditLogger | None = None):
        self._context = context
        self._audit_logger = audit_logger or AuditLogger()

    @property
    def audit_logger(self) -> AuditLogger:
        return self._audit_logger

    def authorize_sync(self, *, proposal_id: str, program_id: str | None) -> None:
        self._authorize(
            action="SYNC",
            required_capability=SYNC_WRITE_CAPABILITY,
            proposal_id=proposal_id,
            program_id=program_id,
        )

    def authorize_read(self, *, proposal_id: str, program_id: str | None) -> None:
        self._authorize(
            action="READ",
            required_capability=READ_CAPABILITY,
            proposal_id=proposal_id,
            program_id=program_id,
        )

    def authorize_read_capability(self, *, proposal_id: str) -> None:
        self._check_capability(
            action="READ",
            required_capability=READ_CAPABILITY,
            proposal_id=proposal_id,
            program_id=None,
        )

    def authorize_read_scope(self, *, proposal_id: str, program_id: str | None) -> None:
        self._check_program_scope(
            action="READ",
            required_capability=READ_CAPABILITY,
            proposal_id=proposal_id,
            program_id=program_id,
        )
        self._emit(
            event_type="ACCESS_GRANTED",
            severity="INFO",
            action="READ",
            outcome="ALLOW",
            proposal_id=proposal_id,
            program_id=program_id,
            required_capability=READ_CAPABILITY,
        )

    def audit_read_miss(self, *, proposal_id: str) -> None:
        self._emit(
            event_type="CORPUS_READ_MISS",
            severity="INFO",
            action="READ",
            outcome="ALLOW",
            proposal_id=proposal_id,
            reason="artifact not found",
        )

    def audit_provenance_violation(
        self,
        *,
        action: str,
        proposal_id: str,
        program_id: str | None,
        reason: str,
    ) -> None:
        self._emit(
            event_type="PROVENANCE_CHAIN_INVALID",
            severity="WARNING",
            action=action,
            outcome="DENY",
            proposal_id=proposal_id,
            program_id=program_id,
            reason=reason,
        )

    def _authorize(
        self,
        *,
        action: str,
        required_capability: str,
        proposal_id: str,
        program_id: str | None,
    ) -> None:
        self._check_capability(
            action=action,
            required_capability=required_capability,
            proposal_id=proposal_id,
            program_id=program_id,
        )
        self._check_program_scope(
            action=action,
            required_capability=required_capability,
            proposal_id=proposal_id,
            program_id=program_id,
        )
        self._emit(
            event_type="ACCESS_GRANTED",
            severity="INFO",
            action=action,
            outcome="ALLOW",
            proposal_id=proposal_id,
            program_id=program_id,
            required_capability=required_capability,
        )

    def _check_capability(
        self,
        *,
        action: str,
        required_capability: str,
        proposal_id: str,
        program_id: str | None,
    ) -> None:
        if not _capability_granted(self._context.capabilities, required_capability):
            reason = (
                f"principal '{self._context.principal}' lacks capability '{required_capability}' "
                f"for action '{action}'"
            )
            self._emit(
                event_type="CAPABILITY_DENIED",
                severity="WARNING",
                action=action,
                outcome="DENY",
                proposal_id=proposal_id,
                program_id=program_id,
                required_capability=required_capability,
                reason=reason,
            )
            raise AccessDeniedError(reason)

    def _check_program_scope(
        self,
        *,
        action: str,
        required_capability: str,
        proposal_id: str,
        program_id: str | None,
    ) -> None:
        allowed_program_ids = self._context.allowed_program_ids
        if program_id is not None and allowed_program_ids is not None and program_id not in allowed_program_ids:
            reason = (
                f"principal '{self._context.principal}' cannot access program '{program_id}' "
                f"for action '{action}'"
            )
            self._emit(
                event_type="ACCESS_DENIED",
                severity="WARNING",
                action=action,
                outcome="DENY",
                proposal_id=proposal_id,
                program_id=program_id,
                required_capability=required_capability,
                reason=reason,
            )
            raise AccessDeniedError(reason)

    def _emit(
        self,
        *,
        event_type: str,
        severity: str,
        action: str,
        outcome: str,
        proposal_id: str | None = None,
        program_id: str | None = None,
        required_capability: str | None = None,
        reason: str | None = None,
    ) -> None:
        self._audit_logger.log(
            AuditEvent(
                event_type=event_type,
                severity=severity,
                principal=self._context.principal,
                action=action,
                outcome=outcome,
                proposal_id=proposal_id,
                program_id=program_id,
                required_capability=required_capability,
                reason=reason,
            )
        )


@dataclass(frozen=True)
class ProposalArtifact:
    """Proposal payload from local store."""

    proposal_id: str
    state: str
    receipt_id: str
    provenance_chain: tuple[Mapping[str, str], ...]
    project_id: str | None = None
    program_id: str | None = None
    artifact: Mapping[str, Any] | None = None
    updated_at_utc: str | None = None

    @classmethod
    def from_json(cls, raw: Mapping[str, Any]) -> "ProposalArtifact":
        proposal_id = str(raw.get("proposal_id") or raw.get("id") or "").strip()
        if not proposal_id:
            raise ValueError("proposal missing required proposal_id/id")

        state = str(raw.get("state") or raw.get("status") or "").strip().upper()
        if not state:
            state = "PROPOSED"

        receipt_id = str(raw.get("receipt_id") or "").strip()
        if not receipt_id:
            receipt_id = f"receipt:{proposal_id}"

        project_id = _normalize_project_id(raw.get("project_id") or raw.get("project"))
        program_id = _normalize_program_id(raw.get("program_id"))

        artifact_raw = raw.get("artifact")
        artifact: Mapping[str, Any] | None = None
        if isinstance(artifact_raw, Mapping):
            artifact = artifact_raw

        updated_at_raw = raw.get("updated_at_utc") or raw.get("updated_at")
        updated_at_utc = str(updated_at_raw).strip() if updated_at_raw is not None else None
        if updated_at_utc == "":
            updated_at_utc = None

        provenance_chain = _extract_provenance_chain(raw, artifact=artifact, receipt_id=receipt_id)

        return cls(
            proposal_id=proposal_id,
            state=state,
            receipt_id=receipt_id,
            provenance_chain=provenance_chain,
            project_id=project_id,
            program_id=program_id,
            artifact=artifact,
            updated_at_utc=updated_at_utc,
        )

    def to_backend_json(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "proposal_id": self.proposal_id,
            "state": self.state,
            "receipt_id": self.receipt_id,
            "synced_at_utc": _utc_now(),
            "provenance_chain": [dict(item) for item in self.provenance_chain],
            "provenance_receipt_ids": [
                str(item.get("receipt_id") or "")
                for item in self.provenance_chain
                if str(item.get("receipt_id") or "").strip()
            ],
            "provenance_head_receipt_id": self.receipt_id,
        }
        if self.project_id is not None:
            payload["project_id"] = self.project_id
        if self.program_id is not None:
            payload["program_id"] = self.program_id
        if self.updated_at_utc is not None:
            payload["updated_at_utc"] = self.updated_at_utc
        if self.artifact is not None:
            payload["artifact"] = dict(self.artifact)
        return payload


def load_local_proposals(local_store_path: Path) -> list[ProposalArtifact]:
    doc = json.loads(local_store_path.read_text(encoding="utf-8"))
    if not isinstance(doc, dict):
        raise ValueError("local store must be an object with a 'proposals' array")
    proposals_raw = doc.get("proposals")
    if not isinstance(proposals_raw, list):
        raise ValueError("local store missing required 'proposals' array")
    return [ProposalArtifact.from_json(item) for item in proposals_raw if isinstance(item, Mapping)]


@dataclass
class SyncCheckpoint:
    """Persistent resumable sync state."""

    synced_proposal_ids: set[str]
    updated_at_utc: str

    @classmethod
    def empty(cls) -> "SyncCheckpoint":
        return cls(synced_proposal_ids=set(), updated_at_utc=_utc_now())

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "kind": "corpus_sync_checkpoint",
            "synced_proposal_ids": sorted(self.synced_proposal_ids),
            "updated_at_utc": self.updated_at_utc,
        }

    @classmethod
    def from_json(cls, raw: Mapping[str, Any]) -> "SyncCheckpoint":
        ids = raw.get("synced_proposal_ids")
        if not isinstance(ids, list):
            ids = []
        synced = {str(item).strip() for item in ids if str(item).strip()}
        updated_at_utc = str(raw.get("updated_at_utc") or "").strip() or _utc_now()
        return cls(synced_proposal_ids=synced, updated_at_utc=updated_at_utc)


class SyncStateStore:
    """Checkpoint file manager."""

    def __init__(self, path: Path):
        self._path = path

    def load(self) -> SyncCheckpoint:
        if not self._path.exists():
            return SyncCheckpoint.empty()
        raw = json.loads(self._path.read_text(encoding="utf-8"))
        if not isinstance(raw, Mapping):
            raise ValueError("sync state file must be an object")
        return SyncCheckpoint.from_json(raw)

    def save(self, checkpoint: SyncCheckpoint) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(self._path.suffix + ".tmp")
        tmp.write_text(json.dumps(checkpoint.to_json(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
        tmp.replace(self._path)


class SharedCorpusBackend(Protocol):
    """Minimal backend API used by the sync worker."""

    def has(self, proposal_id: str) -> bool:
        ...

    def upsert(self, proposal: ProposalArtifact) -> None:
        ...

    def get(self, proposal_id: str) -> Mapping[str, Any] | None:
        ...


class JsonFileCorpusBackend:
    """Local JSON-backed shared corpus backend adapter."""

    def __init__(self, path: Path):
        self._path = path
        self._loaded = False
        self._doc: dict[str, Any] = {}

    def has(self, proposal_id: str) -> bool:
        self._ensure_loaded()
        artifacts = self._doc.get("artifacts", {})
        if not isinstance(artifacts, dict):
            return False
        return proposal_id in artifacts

    def upsert(self, proposal: ProposalArtifact) -> None:
        self._ensure_loaded()
        artifacts = self._doc.setdefault("artifacts", {})
        if not isinstance(artifacts, dict):
            raise ValueError("backend artifacts store must be an object")
        artifacts[proposal.proposal_id] = proposal.to_backend_json()
        self._flush()

    def get(self, proposal_id: str) -> Mapping[str, Any] | None:
        self._ensure_loaded()
        artifacts = self._doc.get("artifacts", {})
        if not isinstance(artifacts, dict):
            return None
        entry = artifacts.get(proposal_id)
        if not isinstance(entry, Mapping):
            return None
        return dict(entry)

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        if not self._path.exists():
            self._doc = {
                "schema_version": 1,
                "kind": "shared_corpus_backend",
                "artifacts": {},
            }
            self._loaded = True
            return

        raw = json.loads(self._path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("backend store file must be a JSON object")
        artifacts = raw.get("artifacts")
        if artifacts is None:
            raw["artifacts"] = {}
        elif not isinstance(artifacts, dict):
            raise ValueError("backend store 'artifacts' must be a JSON object")
        self._doc = raw
        self._loaded = True

    def _flush(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(self._path.suffix + ".tmp")
        tmp.write_text(json.dumps(self._doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        tmp.replace(self._path)


@dataclass(frozen=True)
class SyncError:
    proposal_id: str
    error: str

    def to_json(self) -> dict[str, str]:
        return {"proposal_id": self.proposal_id, "error": self.error}


@dataclass(frozen=True)
class SyncTelemetry:
    job_id: str
    started_at_utc: str
    completed_at_utc: str
    resumed_from_checkpoint: bool
    scanned_total: int
    approved_total: int
    skipped_non_approved: int
    synced_count: int
    already_synced_count: int
    error_count: int
    latency_ms: float
    errors: tuple[SyncError, ...] = ()

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "kind": "corpus_sync_run",
            "job_id": self.job_id,
            "started_at_utc": self.started_at_utc,
            "completed_at_utc": self.completed_at_utc,
            "resumed_from_checkpoint": self.resumed_from_checkpoint,
            "scanned_total": self.scanned_total,
            "approved_total": self.approved_total,
            "skipped_non_approved": self.skipped_non_approved,
            "synced_count": self.synced_count,
            "already_synced_count": self.already_synced_count,
            "error_count": self.error_count,
            "latency_ms": self.latency_ms,
            "errors": [item.to_json() for item in self.errors],
        }


class CorpusSyncWorker:
    """Approved-only sync with resumable idempotent checkpointing."""

    def __init__(
        self,
        *,
        backend: SharedCorpusBackend,
        state_store: SyncStateStore,
        approved_states: set[str] | None = None,
        access_policy: AccessPolicy | None = None,
        endpoint_policy_enforcer: EndpointPolicyEnforcer | None = None,
    ):
        self._backend = backend
        self._state_store = state_store
        self._access_policy = access_policy or AccessPolicy(context=AccessContext.system())
        self._endpoint_policy_enforcer = endpoint_policy_enforcer
        normalized = approved_states or {"APPROVED"}
        self._approved_states = {item.strip().upper() for item in normalized if item.strip()}
        if not self._approved_states:
            raise ValueError("approved_states cannot be empty")

    def sync(self, proposals: list[ProposalArtifact], *, job_id: str | None = None) -> SyncTelemetry:
        start_ns = _now_ns()
        started_at_utc = _utc_now()
        resolved_job_id = job_id or f"corpus-sync-{datetime.now(tz=timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"

        approved = [proposal for proposal in proposals if proposal.state in self._approved_states]
        skipped_non_approved = len(proposals) - len(approved)

        preflight_id = resolved_job_id
        preflight_project_id: str | None = None
        preflight_program_id: str | None = None
        if approved:
            preflight_id = approved[0].proposal_id
            preflight_project_id = approved[0].project_id
            preflight_program_id = approved[0].program_id
        try:
            self._access_policy.authorize_sync(
                proposal_id=preflight_id,
                program_id=preflight_program_id,
            )
            if self._endpoint_policy_enforcer is not None:
                self._endpoint_policy_enforcer.authorize_sync(
                    proposal_id=preflight_id,
                    project_id=preflight_project_id,
                    program_id=preflight_program_id,
                )
        except AccessDeniedError as exc:
            completed_at_utc = _utc_now()
            errors = (SyncError(proposal_id=preflight_id, error=str(exc)),)
            return SyncTelemetry(
                job_id=resolved_job_id,
                started_at_utc=started_at_utc,
                completed_at_utc=completed_at_utc,
                resumed_from_checkpoint=False,
                scanned_total=len(proposals),
                approved_total=len(approved),
                skipped_non_approved=skipped_non_approved,
                synced_count=0,
                already_synced_count=0,
                error_count=len(errors),
                latency_ms=_elapsed_ms(start_ns),
                errors=errors,
            )

        checkpoint = self._state_store.load()
        synced_ids = set(checkpoint.synced_proposal_ids)
        resumed_from_checkpoint = bool(synced_ids)

        synced_count = 0
        already_synced_count = 0
        errors: list[SyncError] = []

        # Stable ordering keeps retries deterministic.
        ordered = sorted(approved, key=lambda item: (item.updated_at_utc or "", item.proposal_id))
        for proposal in ordered:
            try:
                self._access_policy.authorize_sync(
                    proposal_id=proposal.proposal_id,
                    program_id=proposal.program_id,
                )
                if self._endpoint_policy_enforcer is not None:
                    self._endpoint_policy_enforcer.authorize_sync(
                        proposal_id=proposal.proposal_id,
                        project_id=proposal.project_id,
                        program_id=proposal.program_id,
                    )
            except AccessDeniedError as exc:
                errors.append(SyncError(proposal_id=proposal.proposal_id, error=str(exc)))
                continue

            try:
                _validate_provenance_chain(
                    proposal.provenance_chain,
                    expected_head_receipt_id=proposal.receipt_id,
                )
            except ValueError as exc:
                self._access_policy.audit_provenance_violation(
                    action="SYNC",
                    proposal_id=proposal.proposal_id,
                    program_id=proposal.program_id,
                    reason=str(exc),
                )
                errors.append(SyncError(proposal_id=proposal.proposal_id, error=str(exc)))
                continue

            if proposal.proposal_id in synced_ids or self._backend.has(proposal.proposal_id):
                already_synced_count += 1
                if proposal.proposal_id not in synced_ids:
                    synced_ids.add(proposal.proposal_id)
                    self._state_store.save(
                        SyncCheckpoint(synced_proposal_ids=synced_ids, updated_at_utc=_utc_now())
                    )
                continue

            try:
                self._backend.upsert(proposal)
                synced_ids.add(proposal.proposal_id)
                synced_count += 1
                self._state_store.save(
                    SyncCheckpoint(synced_proposal_ids=synced_ids, updated_at_utc=_utc_now())
                )
            except Exception as exc:
                errors.append(SyncError(proposal_id=proposal.proposal_id, error=str(exc)))

        completed_at_utc = _utc_now()
        telemetry = SyncTelemetry(
            job_id=resolved_job_id,
            started_at_utc=started_at_utc,
            completed_at_utc=completed_at_utc,
            resumed_from_checkpoint=resumed_from_checkpoint,
            scanned_total=len(proposals),
            approved_total=len(approved),
            skipped_non_approved=skipped_non_approved,
            synced_count=synced_count,
            already_synced_count=already_synced_count,
            error_count=len(errors),
            latency_ms=_elapsed_ms(start_ns),
            errors=tuple(errors),
        )
        return telemetry


def append_sync_telemetry(telemetry_path: Path | None, telemetry: SyncTelemetry) -> None:
    if telemetry_path is None:
        return
    telemetry_path.parent.mkdir(parents=True, exist_ok=True)
    with telemetry_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(telemetry.to_json(), sort_keys=True) + "\n")


def read_synced_artifact(
    *,
    backend: SharedCorpusBackend,
    proposal_id: str,
    access_policy: AccessPolicy | None = None,
    endpoint_policy_enforcer: EndpointPolicyEnforcer | None = None,
    project_id: str | None = None,
) -> Mapping[str, Any] | None:
    normalized_proposal_id = str(proposal_id).strip()
    if not normalized_proposal_id:
        raise ValueError("proposal_id cannot be empty")

    resolved_policy = access_policy or AccessPolicy(context=AccessContext.system())
    resolved_policy.authorize_read_capability(proposal_id=normalized_proposal_id)

    if endpoint_policy_enforcer is not None:
        endpoint_policy_enforcer.authorize_read(
            proposal_id=normalized_proposal_id,
            project_id=project_id,
            program_id=None,
        )

    artifact = backend.get(normalized_proposal_id)
    artifact_project_id: str | None = None
    program_id: str | None = None
    if artifact is not None:
        artifact_project_id = _normalize_project_id(artifact.get("project_id"))
        program_id = _normalize_program_id(artifact.get("program_id"))
        if endpoint_policy_enforcer is not None:
            endpoint_policy_enforcer.authorize_read(
                proposal_id=normalized_proposal_id,
                project_id=artifact_project_id or project_id,
                program_id=program_id,
            )

    resolved_policy.authorize_read_scope(
        proposal_id=normalized_proposal_id,
        program_id=program_id,
    )

    if artifact is None:
        resolved_policy.audit_read_miss(proposal_id=normalized_proposal_id)
        return None

    receipt_id = str(artifact.get("receipt_id") or "").strip()
    if not receipt_id:
        reason = "synced artifact missing required receipt_id"
        resolved_policy.audit_provenance_violation(
            action="READ",
            proposal_id=normalized_proposal_id,
            program_id=program_id,
            reason=reason,
        )
        raise ValueError(reason)

    raw_chain = artifact.get("provenance_chain")
    if not isinstance(raw_chain, list):
        reason = "synced artifact missing required provenance_chain"
        resolved_policy.audit_provenance_violation(
            action="READ",
            proposal_id=normalized_proposal_id,
            program_id=program_id,
            reason=reason,
        )
        raise ValueError(reason)

    extracted_chain: list[dict[str, str]] = []
    _append_provenance_entries(extracted_chain, raw_chain)
    deduped_chain = tuple(_dedupe_provenance_chain(extracted_chain))

    try:
        _validate_provenance_chain(deduped_chain, expected_head_receipt_id=receipt_id)
    except ValueError as exc:
        resolved_policy.audit_provenance_violation(
            action="READ",
            proposal_id=normalized_proposal_id,
            program_id=program_id,
            reason=str(exc),
        )
        raise

    return dict(artifact)


def _resolve_backend_destination(backend_store_path: Path, backend_endpoint: str | None) -> str:
    if backend_endpoint is not None:
        normalized = _normalize_endpoint(backend_endpoint)
        if normalized is None:
            raise ValueError("backend endpoint cannot be empty")
        return normalized
    return backend_store_path.expanduser().resolve().as_uri()


def run_sync_job(
    *,
    local_store_path: Path,
    backend_store_path: Path,
    state_path: Path,
    telemetry_path: Path | None = None,
    approved_states: set[str] | None = None,
    job_id: str | None = None,
    access_context: AccessContext | None = None,
    audit_path: Path | None = None,
    policy_config: EndpointPolicyConfig | None = None,
    backend_endpoint: str | None = None,
) -> SyncTelemetry:
    proposals = load_local_proposals(local_store_path)
    backend = JsonFileCorpusBackend(backend_store_path)
    state_store = SyncStateStore(state_path)
    resolved_context = access_context or AccessContext.system()
    audit_logger = AuditLogger(audit_path)
    access_policy = AccessPolicy(
        context=resolved_context,
        audit_logger=audit_logger,
    )
    endpoint_policy_enforcer = EndpointPolicyEnforcer(
        context=resolved_context,
        destination=_resolve_backend_destination(backend_store_path, backend_endpoint),
        policy_config=policy_config,
        audit_logger=audit_logger,
    )
    worker = CorpusSyncWorker(
        backend=backend,
        state_store=state_store,
        approved_states=approved_states,
        access_policy=access_policy,
        endpoint_policy_enforcer=endpoint_policy_enforcer,
    )
    telemetry = worker.sync(proposals, job_id=job_id)
    append_sync_telemetry(telemetry_path, telemetry)
    return telemetry


def run_read_job(
    *,
    backend_store_path: Path,
    proposal_id: str,
    access_context: AccessContext | None = None,
    audit_path: Path | None = None,
    project_id: str | None = None,
    policy_config: EndpointPolicyConfig | None = None,
    backend_endpoint: str | None = None,
) -> Mapping[str, Any] | None:
    backend = JsonFileCorpusBackend(backend_store_path)
    resolved_context = access_context or AccessContext.system()
    audit_logger = AuditLogger(audit_path)
    access_policy = AccessPolicy(
        context=resolved_context,
        audit_logger=audit_logger,
    )
    endpoint_policy_enforcer = EndpointPolicyEnforcer(
        context=resolved_context,
        destination=_resolve_backend_destination(backend_store_path, backend_endpoint),
        policy_config=policy_config,
        audit_logger=audit_logger,
    )
    return read_synced_artifact(
        backend=backend,
        proposal_id=proposal_id,
        access_policy=access_policy,
        endpoint_policy_enforcer=endpoint_policy_enforcer,
        project_id=project_id,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Sync approved proposals to shared corpus backend")
    parser.add_argument("--local-store", type=Path, required=True, help="Path to local proposal store JSON")
    parser.add_argument("--backend-store", type=Path, required=True, help="Path to shared corpus backend JSON")
    parser.add_argument("--state-path", type=Path, required=True, help="Path to resumable sync checkpoint JSON")
    parser.add_argument(
        "--telemetry-path",
        type=Path,
        default=None,
        help="Optional JSONL output path for sync telemetry events",
    )
    parser.add_argument(
        "--audit-path",
        type=Path,
        default=None,
        help="Optional JSONL output path for access/provenance audit events",
    )
    parser.add_argument(
        "--approved-state",
        action="append",
        default=None,
        help="Approved proposal state value(s). Repeatable. Defaults to APPROVED.",
    )
    parser.add_argument(
        "--job-id",
        type=str,
        default=None,
        help="Optional deterministic sync job id",
    )
    parser.add_argument(
        "--principal",
        type=str,
        default=None,
        help="Principal identifier used for access checks (defaults to system principal)",
    )
    parser.add_argument(
        "--capability",
        action="append",
        default=None,
        help="Capability grant(s) for the principal. Repeatable.",
    )
    parser.add_argument(
        "--allow-program-id",
        action="append",
        default=None,
        help="Optional allowlist of program_id values. Repeatable.",
    )
    parser.add_argument(
        "--policy-config",
        type=Path,
        default=None,
        help=(
            "Optional JSON policy config path with default_mode/allowed_endpoints and "
            "per-project overrides."
        ),
    )
    parser.add_argument(
        "--policy-mode",
        type=str,
        default=None,
        choices=sorted(_POLICY_MODES),
        help="Optional default policy mode override: offline, allowlist, or cloud.",
    )
    parser.add_argument(
        "--allow-endpoint",
        action="append",
        default=None,
        help="Optional default endpoint allowlist entries. Repeatable.",
    )
    parser.add_argument(
        "--backend-endpoint",
        type=str,
        default=None,
        help="Optional explicit destination endpoint used for policy enforcement.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    approved_states = None
    if args.approved_state:
        approved_states = {str(item).strip().upper() for item in args.approved_state if str(item).strip()}

    capabilities = None
    if args.capability is not None:
        capabilities = {str(item) for item in args.capability if str(item).strip()}

    allowed_program_ids = None
    if args.allow_program_id is not None:
        allowed_program_ids = {str(item) for item in args.allow_program_id if str(item).strip()}

    policy_config = EndpointPolicyConfig()
    if args.policy_config is not None:
        policy_config = EndpointPolicyConfig.from_path(args.policy_config)

    if args.policy_mode is not None or args.allow_endpoint is not None:
        default_mode = args.policy_mode or policy_config.default_rule.mode
        if args.allow_endpoint is None:
            default_allowed_endpoints = set(policy_config.default_rule.allowed_endpoints)
        else:
            default_allowed_endpoints = {
                endpoint
                for endpoint in (_normalize_endpoint(item) for item in args.allow_endpoint)
                if endpoint is not None
            }
        policy_config = EndpointPolicyConfig(
            default_rule=EndpointPolicyRule.from_values(
                mode=default_mode,
                allowed_endpoints=default_allowed_endpoints,
            ),
            project_rules=policy_config.project_rules,
        )

    access_context = AccessContext.from_values(
        principal=args.principal,
        capabilities=capabilities,
        allowed_program_ids=allowed_program_ids,
    )

    telemetry = run_sync_job(
        local_store_path=args.local_store,
        backend_store_path=args.backend_store,
        state_path=args.state_path,
        telemetry_path=args.telemetry_path,
        approved_states=approved_states,
        job_id=args.job_id,
        access_context=access_context,
        audit_path=args.audit_path,
        policy_config=policy_config,
        backend_endpoint=args.backend_endpoint,
    )
    print(json.dumps(telemetry.to_json(), indent=2, sort_keys=True))
    return 0 if telemetry.error_count == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
