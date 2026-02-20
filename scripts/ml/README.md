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
