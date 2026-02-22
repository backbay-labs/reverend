#!/usr/bin/env python3
"""Deterministic staged candidate generation for sharded retrieval."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable, Mapping


@dataclass(frozen=True)
class StageContribution:
    """Per-stage candidate contribution summary."""

    stage: str
    enabled: bool
    input_count: int
    output_count: int
    contribution_count: int

    def to_json(self) -> dict[str, int | bool | str]:
        return {
            "stage": self.stage,
            "enabled": self.enabled,
            "input_count": self.input_count,
            "output_count": self.output_count,
            "contribution_count": self.contribution_count,
        }


@dataclass(frozen=True)
class ShardedRetrievalConfig:
    """Deterministic staged candidate generation configuration."""

    enable_symbolic_stage: bool = True
    enable_lexical_stage: bool = True
    enable_embedding_stage: bool = True
    lexical_min_score: float = 0.0


def build_candidates(
    *,
    shard_candidates: Mapping[str, Iterable[str]],
    symbolic_filter: Callable[[str], bool] | None,
    lexical_score: Callable[[str], float],
    embedding_rank: Callable[[list[str]], list[str]] | None,
    top_k: int,
    config: ShardedRetrievalConfig | None = None,
) -> tuple[list[str], tuple[StageContribution, ...], str, bool]:
    """Build deterministic candidates using symbolic, lexical, then embedding stages."""

    resolved = config or ShardedRetrievalConfig()
    all_candidates: list[str] = sorted(
        {
            candidate_id
            for shard in sorted(shard_candidates)
            for candidate_id in shard_candidates[shard]
        }
    )

    stage_metrics: list[StageContribution] = []

    symbolic_input = len(all_candidates)
    if resolved.enable_symbolic_stage and symbolic_filter is not None:
        symbolic_output = [candidate for candidate in all_candidates if symbolic_filter(candidate)]
    else:
        symbolic_output = list(all_candidates)
    stage_metrics.append(
        StageContribution(
            stage="symbolic",
            enabled=resolved.enable_symbolic_stage,
            input_count=symbolic_input,
            output_count=len(symbolic_output),
            contribution_count=max(0, symbolic_input - len(symbolic_output)),
        )
    )

    lexical_input = len(symbolic_output)
    if resolved.enable_lexical_stage:
        lexical_ranked = sorted(
            ((lexical_score(candidate), candidate) for candidate in symbolic_output),
            key=lambda item: (-item[0], item[1]),
        )
        lexical_output = [candidate for score, candidate in lexical_ranked if score >= resolved.lexical_min_score]
        if not lexical_output:
            lexical_output = [candidate for _, candidate in lexical_ranked]
    else:
        lexical_output = list(symbolic_output)
    stage_metrics.append(
        StageContribution(
            stage="lexical",
            enabled=resolved.enable_lexical_stage,
            input_count=lexical_input,
            output_count=len(lexical_output),
            contribution_count=max(0, lexical_input - len(lexical_output)),
        )
    )

    embedding_input = len(lexical_output)
    embedding_backend_status = "available"
    embedding_fallback_applied = False
    if not resolved.enable_embedding_stage:
        embedding_backend_status = "disabled"
        embedding_fallback_applied = True
        ranked = lexical_output
    else:
        try:
            if embedding_rank is None:
                raise RuntimeError("embedding backend unavailable")
            ranked = embedding_rank(list(lexical_output))
            if not ranked:
                ranked = lexical_output
                embedding_fallback_applied = True
        except Exception:
            ranked = lexical_output
            embedding_backend_status = "unavailable"
            embedding_fallback_applied = True

    final_candidates = ranked[: min(top_k, len(ranked))]
    stage_metrics.append(
        StageContribution(
            stage="embedding",
            enabled=resolved.enable_embedding_stage,
            input_count=embedding_input,
            output_count=len(final_candidates),
            contribution_count=max(0, embedding_input - len(final_candidates)),
        )
    )
    return final_candidates, tuple(stage_metrics), embedding_backend_status, embedding_fallback_applied
