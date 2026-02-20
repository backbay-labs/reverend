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
  --query "elf section table parser" \
  --top-k 3
```

## Evaluate Slice

```bash
python3 scripts/ml/local_embedding_pipeline.py evaluate \
  --index-dir /tmp/ml301-index \
  --queries scripts/ml/fixtures/toy_similarity_queries_slice.json \
  --top-k 3 \
  --output /tmp/ml301-metrics.json
```
