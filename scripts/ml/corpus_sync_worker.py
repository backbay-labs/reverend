#!/usr/bin/env python3
"""E7-S1: approved-only corpus sync worker.

This module syncs approved proposals from a local store into a shared corpus
backend representation. The worker is:
1) Approved-only: non-approved proposals are skipped.
2) Idempotent: already-synced proposals are detected and not duplicated.
3) Resumable: successful proposal ids are checkpointed after each write.
4) Observable: each run emits counts, errors, and latency telemetry.
"""

from __future__ import annotations

import argparse
import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Protocol


def _utc_now() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _now_ns() -> int:
    return time.perf_counter_ns()


def _elapsed_ms(start_ns: int) -> float:
    return round((time.perf_counter_ns() - start_ns) / 1_000_000.0, 3)


@dataclass(frozen=True)
class ProposalArtifact:
    """Proposal payload from local store."""

    proposal_id: str
    state: str
    receipt_id: str
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

        program_id_raw = raw.get("program_id")
        program_id = str(program_id_raw).strip() if program_id_raw is not None else None
        if program_id == "":
            program_id = None

        artifact_raw = raw.get("artifact")
        artifact: Mapping[str, Any] | None = None
        if isinstance(artifact_raw, Mapping):
            artifact = artifact_raw

        updated_at_raw = raw.get("updated_at_utc") or raw.get("updated_at")
        updated_at_utc = str(updated_at_raw).strip() if updated_at_raw is not None else None
        if updated_at_utc == "":
            updated_at_utc = None

        return cls(
            proposal_id=proposal_id,
            state=state,
            receipt_id=receipt_id,
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
        }
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
    ):
        self._backend = backend
        self._state_store = state_store
        normalized = approved_states or {"APPROVED"}
        self._approved_states = {item.strip().upper() for item in normalized if item.strip()}
        if not self._approved_states:
            raise ValueError("approved_states cannot be empty")

    def sync(self, proposals: list[ProposalArtifact], *, job_id: str | None = None) -> SyncTelemetry:
        start_ns = _now_ns()
        started_at_utc = _utc_now()
        resolved_job_id = job_id or f"corpus-sync-{datetime.now(tz=timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"

        checkpoint = self._state_store.load()
        synced_ids = set(checkpoint.synced_proposal_ids)
        resumed_from_checkpoint = bool(synced_ids)

        approved = [proposal for proposal in proposals if proposal.state in self._approved_states]
        skipped_non_approved = len(proposals) - len(approved)

        synced_count = 0
        already_synced_count = 0
        errors: list[SyncError] = []

        # Stable ordering keeps retries deterministic.
        ordered = sorted(approved, key=lambda item: (item.updated_at_utc or "", item.proposal_id))
        for proposal in ordered:
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


def run_sync_job(
    *,
    local_store_path: Path,
    backend_store_path: Path,
    state_path: Path,
    telemetry_path: Path | None = None,
    approved_states: set[str] | None = None,
    job_id: str | None = None,
) -> SyncTelemetry:
    proposals = load_local_proposals(local_store_path)
    backend = JsonFileCorpusBackend(backend_store_path)
    state_store = SyncStateStore(state_path)
    worker = CorpusSyncWorker(
        backend=backend,
        state_store=state_store,
        approved_states=approved_states,
    )
    telemetry = worker.sync(proposals, job_id=job_id)
    append_sync_telemetry(telemetry_path, telemetry)
    return telemetry


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
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    approved_states = None
    if args.approved_state:
        approved_states = {str(item).strip().upper() for item in args.approved_state if str(item).strip()}
    telemetry = run_sync_job(
        local_store_path=args.local_store,
        backend_store_path=args.backend_store,
        state_path=args.state_path,
        telemetry_path=args.telemetry_path,
        approved_states=approved_states,
        job_id=args.job_id,
    )
    print(json.dumps(telemetry.to_json(), indent=2, sort_keys=True))
    return 0 if telemetry.error_count == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
