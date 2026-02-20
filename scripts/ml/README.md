# ML-301 Local Embedding Baseline

This directory contains a deterministic local baseline for:
- Embedding/index build over a corpus slice.
- Top-k similarity retrieval adapter.
- Runtime and index build stats recording.

## Build Index

```bash
python3 scripts/ml/local_embedding_pipeline.py build \
  --corpus scripts/ml/fixtures/toy_similarity_corpus_slice.json \
  --output-dir /tmp/ml301-index \
  --vector-dimension 128
```

Artifacts:
- `/tmp/ml301-index/index.json`
- `/tmp/ml301-index/features.jsonl`
- `/tmp/ml301-index/stats.json`

## Query Top-k

```bash
python3 scripts/ml/local_embedding_pipeline.py search \
  --index-dir /tmp/ml301-index \
  --mode intent \
  --query "elf section table parser" \
  --top-k 3
```

Search/panel paths apply an evidence-weighted reranker by default.

Use baseline-only ordering when reranking is unavailable or intentionally disabled:

```bash
python3 scripts/ml/local_embedding_pipeline.py search \
  --index-dir /tmp/ml301-index \
  --mode intent \
  --query "socket connect host" \
  --top-k 3 \
  --disable-reranker
```

Similar-function query from a known function id:

```bash
python3 scripts/ml/local_embedding_pipeline.py search \
  --index-dir /tmp/ml301-index \
  --mode similar-function \
  --function-id "fn.elf.parse_headers" \
  --top-k 3
```

Append latency telemetry for each query interaction:

```bash
python3 scripts/ml/local_embedding_pipeline.py search \
  --index-dir /tmp/ml301-index \
  --mode intent \
  --query "socket connect host" \
  --top-k 3 \
  --telemetry-path /tmp/ml301-search-latency.jsonl
```

## Render Search Panel Payload

```bash
python3 scripts/ml/local_embedding_pipeline.py panel \
  --index-dir /tmp/ml301-index \
  --mode intent \
  --query "pe import resolver" \
  --top-k 5 \
  --telemetry-path /tmp/ml301-search-latency.jsonl
```

Panel/search results include ranked hits plus provenance and evidence references.

## Evaluate Slice

```bash
python3 scripts/ml/local_embedding_pipeline.py evaluate \
  --index-dir /tmp/ml301-index \
  --queries scripts/ml/fixtures/toy_similarity_queries_slice.json \
  --top-k 3 \
  --output /tmp/ml301-metrics.json
```

`evaluate` emits reranked metrics plus a baseline comparison block (`mrr_delta`,
`recall@1_delta`, `recall_at_top_k_delta`, and per-query ordering deltas). The
metrics payload always includes `recall@1` plus `recall@{top_k}`.

When reranking is enabled, retrieval first gathers `top_k * multiplier`
candidates before reranking and truncation, which allows `recall@{top_k}` to
improve against stock baseline ordering:

```bash
python3 scripts/ml/local_embedding_pipeline.py evaluate \
  --index-dir /tmp/ml301-index \
  --queries scripts/ml/fixtures/toy_similarity_queries_slice.json \
  --top-k 10 \
  --rerank-candidate-multiplier 4
```

Add `--disable-reranker` to evaluate baseline only.

## Benchmark MVP Gates (Recall/Latency)

```bash
python3 scripts/ml/local_embedding_pipeline.py benchmark-mvp \
  --target-corpus-size 100000 \
  --output eval/artifacts/mvp-gates/runs/smoke-$(date -u +%Y%m%dT%H%M%SZ).json
```

This emits a deterministic artifact containing:
- `recall_at_10_delta_vs_stock`
- `search_latency_p95_ms`
- `receipt_completeness`
- `rollback_success_rate`

By default, the command exits non-zero if any gate fails. Add
`--no-fail-on-gate-fail` to force a zero exit status.

## Generate Type Suggestions (Confidence + Quarantine Policy)

```bash
python3 scripts/ml/local_embedding_pipeline.py suggest-types \
  --input scripts/ml/fixtures/toy_type_suggestions_slice.json \
  --auto-apply-threshold 0.90 \
  --suggest-threshold 0.50 \
  --output /tmp/ml301-type-suggestions.json \
  --telemetry-path /tmp/ml301-type-suggestion-metrics.jsonl
```

Suggestion reports include:
- Confidence score and confidence component breakdown
- Evidence summary and evidence references
- Policy action (`AUTO_APPLY`, `SUGGEST`, `QUARANTINED`)
- Suggestion quality metrics (accuracy, precision, quarantine rates) for CI artifacts

## Run Deterministic Triage Mission Graph (ML-327)

```bash
python3 scripts/ml/local_embedding_pipeline.py triage-mission \
  --corpus scripts/ml/fixtures/toy_similarity_corpus_slice.json \
  --mission-id triage-smoke \
  --output /tmp/ml327-triage-summary.json \
  --report-dir /tmp/ml327-triage-artifacts
```

Mission artifacts include:
- Deterministic stage-graph execution trace
- Triage map nodes and explicit ranked hotspot rows for UI consumers
- `entrypoints`, `hotspots`, and `unknowns` rows
- Evidence links with source-context URIs on all emitted triage findings

`--report-dir` exports:
- `triage-summary.json` (machine-readable summary artifact)
- `triage-panel.json` (in-plugin panel payload for map + ranked hotspots)
- `triage-report.md` (versionable report with navigable evidence/source links)
- `triage-artifacts.json` (artifact manifest)

Render only the UI panel payload:

```bash
python3 scripts/ml/local_embedding_pipeline.py triage-panel \
  --corpus scripts/ml/fixtures/toy_similarity_corpus_slice.json \
  --mission-id triage-smoke \
  --output /tmp/ml327-triage-panel.json
```

## Sync Approved Proposals to Shared Corpus Backend

```bash
python3 scripts/ml/corpus_sync_worker.py \
  --local-store /tmp/local-proposals.json \
  --backend-store /tmp/shared-corpus-backend.json \
  --state-path /tmp/corpus-sync-checkpoint.json \
  --telemetry-path /tmp/corpus-sync-telemetry.jsonl
```

Local store input is a JSON object with a `proposals` array. The worker:
- Syncs only proposals with state `APPROVED` by default
- Checkpoints each successful proposal for resumable retries
- Skips already-synced proposals for idempotent re-runs
- Emits per-run telemetry (`counts`, `errors`, `latency_ms`)

## Pull Cross-Binary Reuse into Local Proposal Store

```bash
python3 scripts/ml/local_embedding_pipeline.py pullback-reuse \
  --index-dir /tmp/ml301-index \
  --backend-store /tmp/shared-corpus-backend.json \
  --local-store /tmp/local-proposals.json \
  --function-id fn.pe.parse_imports \
  --top-k 3 \
  --program-id program:local
```

`pullback-reuse`:
- Queries shared-corpus artifacts for cross-binary matches against local session functions
- Extracts reusable names/types/annotations from matched artifacts
- Inserts local proposals in `PROPOSED` state with receipt and provenance chain links
- Leaves accept/reject decisions in the existing local review flow (`PROPOSED` -> `APPROVED` / `REJECTED`)
