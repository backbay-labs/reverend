from __future__ import annotations

import io
import importlib.util
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "local_embedding_pipeline.py"
SPEC = importlib.util.spec_from_file_location("ml301_local_embedding_pipeline", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"failed to load module spec from {MODULE_PATH}")
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

BaselineSimilarityAdapter = MODULE.BaselineSimilarityAdapter
EmbeddingIndex = MODULE.EmbeddingIndex
FunctionRecord = MODULE.FunctionRecord
LocalEmbeddingPipeline = MODULE.LocalEmbeddingPipeline
SemanticSearchQueryService = MODULE.SemanticSearchQueryService
evaluate_queries = MODULE.evaluate_queries


class LocalEmbeddingPipelineTest(unittest.TestCase):
    def setUp(self) -> None:
        self.pipeline = LocalEmbeddingPipeline(vector_dimension=64)
        self.records = [
            FunctionRecord.from_json(
                {
                    "id": "fn.elf.parse_headers",
                    "name": "parse_elf_headers",
                    "text": "parse elf header and section table entries",
                }
            ),
            FunctionRecord.from_json(
                {
                    "id": "fn.net.open_socket",
                    "name": "open_socket",
                    "text": "initialize socket and connect to host endpoint",
                }
            ),
            FunctionRecord.from_json(
                {
                    "id": "fn.pe.parse_imports",
                    "name": "parse_pe_imports",
                    "text": "parse pe import table and imported symbol names",
                }
            ),
        ]

    def test_top_k_is_deterministic_across_runs(self) -> None:
        index_a = self.pipeline.build_index(self.records)
        adapter_a = BaselineSimilarityAdapter(self.pipeline, index_a)
        top_a = [item.function_id for item in adapter_a.top_k("elf section parser", top_k=3)]

        index_b = self.pipeline.build_index(self.records)
        adapter_b = BaselineSimilarityAdapter(self.pipeline, index_b)
        top_b = [item.function_id for item in adapter_b.top_k("elf section parser", top_k=3)]

        self.assertEqual(top_a, top_b)

    def test_tie_breaks_by_function_id(self) -> None:
        tied_records = [
            FunctionRecord(function_id="fn.b", name="same", text="identical function text"),
            FunctionRecord(function_id="fn.a", name="same", text="identical function text"),
        ]
        index = self.pipeline.build_index(tied_records)
        adapter = BaselineSimilarityAdapter(self.pipeline, index)
        top = [item.function_id for item in adapter.top_k("identical function text", top_k=2)]
        self.assertEqual(top, ["fn.a", "fn.b"])

    def test_stats_and_features_are_recorded(self) -> None:
        index = self.pipeline.build_index(self.records)
        with tempfile.TemporaryDirectory() as tmpdir:
            index_dir = Path(tmpdir)
            index.save(index_dir)

            stats = json.loads((index_dir / "stats.json").read_text(encoding="utf-8"))
            self.assertEqual(stats["schema_version"], 1)
            self.assertEqual(stats["corpus_size"], len(self.records))
            self.assertEqual(stats["vector_dimension"], 64)
            self.assertGreaterEqual(stats["pipeline_runtime_ms"], 0.0)
            self.assertGreaterEqual(stats["index_build_runtime_ms"], 0.0)
            self.assertGreaterEqual(stats["embedding_runtime_ms"], 0.0)

            features_lines = (index_dir / "features.jsonl").read_text(encoding="utf-8").strip().splitlines()
            self.assertEqual(len(features_lines), len(self.records))

            loaded = EmbeddingIndex.load(index_dir)
            adapter = BaselineSimilarityAdapter(self.pipeline, loaded)
            hits = adapter.top_k("socket host connect", top_k=2)
            self.assertEqual(len(hits), 2)

    def test_evaluate_queries_returns_metrics(self) -> None:
        index = self.pipeline.build_index(self.records)
        adapter = BaselineSimilarityAdapter(self.pipeline, index)

        with tempfile.TemporaryDirectory() as tmpdir:
            queries_path = Path(tmpdir) / "queries.json"
            queries_path.write_text(
                json.dumps(
                    {
                        "queries": [
                            {
                                "text": "elf section table parser",
                                "ground_truth_id": "fn.elf.parse_headers",
                            },
                            {
                                "text": "connect socket host",
                                "ground_truth_id": "fn.net.open_socket",
                            },
                        ]
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
            metrics = evaluate_queries(adapter, queries_path, top_k=3)
            self.assertEqual(metrics["queries"], 2)
            self.assertIn("recall@1", metrics)
            self.assertIn("mrr", metrics)
            self.assertEqual(len(metrics["results"]), 2)

    def test_function_record_defaults_provenance_and_evidence_refs(self) -> None:
        record = FunctionRecord.from_json(
            {
                "id": "fn.default.metadata",
                "name": "default_metadata",
                "text": "function with baseline provenance and evidence defaults",
            }
        )
        provenance = record.provenance_map()
        self.assertEqual(provenance["source"], "local_corpus")
        self.assertEqual(provenance["record_id"], "fn.default.metadata")
        self.assertEqual(len(record.evidence_refs), 1)
        self.assertEqual(record.evidence_refs[0].kind, "TEXT_FEATURE")

    def test_semantic_search_supports_intent_and_similar_function_queries(self) -> None:
        index = self.pipeline.build_index(self.records)
        adapter = BaselineSimilarityAdapter(self.pipeline, index)
        service = SemanticSearchQueryService(adapter=adapter, index=index)

        intent_doc = service.search_intent("socket host connect", top_k=2).to_json()
        self.assertEqual(intent_doc["query"]["mode"], "intent")
        self.assertEqual(intent_doc["query"]["top_k"], 2)
        self.assertGreaterEqual(intent_doc["metrics"]["latency_ms"], 0.0)
        self.assertEqual(len(intent_doc["results"]), 2)
        self.assertIn("provenance", intent_doc["results"][0])
        self.assertIn("evidence_refs", intent_doc["results"][0])
        self.assertGreaterEqual(len(intent_doc["results"][0]["evidence_refs"]), 1)

        similar_doc = service.search_similar_function("fn.net.open_socket", top_k=2).to_json()
        self.assertEqual(similar_doc["query"]["mode"], "similar-function")
        self.assertEqual(similar_doc["query"]["seed_function_id"], "fn.net.open_socket")
        self.assertGreaterEqual(similar_doc["metrics"]["latency_ms"], 0.0)
        self.assertTrue(
            all(item["function_id"] != "fn.net.open_socket" for item in similar_doc["results"])
        )

    def test_panel_output_includes_ranked_results_and_latency_telemetry(self) -> None:
        index = self.pipeline.build_index(self.records)
        with tempfile.TemporaryDirectory() as tmpdir:
            index_dir = Path(tmpdir) / "index"
            telemetry_path = Path(tmpdir) / "latency.jsonl"
            index.save(index_dir)

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = MODULE.main(
                    [
                        "panel",
                        "--index-dir",
                        str(index_dir),
                        "--mode",
                        "intent",
                        "--query",
                        "elf section parser",
                        "--top-k",
                        "3",
                        "--telemetry-path",
                        str(telemetry_path),
                    ]
                )
            self.assertEqual(exit_code, 0)

            panel = json.loads(stdout.getvalue())
            self.assertEqual(panel["panel"]["id"], "semantic-search")
            self.assertEqual(panel["panel"]["query_mode"], "intent")
            self.assertGreaterEqual(panel["metrics"]["latency_ms"], 0.0)
            self.assertGreaterEqual(len(panel["results"]), 1)
            self.assertIn("provenance", panel["results"][0])
            self.assertIn("evidence_refs", panel["results"][0])

            events = telemetry_path.read_text(encoding="utf-8").strip().splitlines()
            self.assertEqual(len(events), 1)
            telemetry_event = json.loads(events[0])
            self.assertEqual(telemetry_event["kind"], "semantic_search_latency")
            self.assertEqual(telemetry_event["mode"], "intent")
            self.assertGreaterEqual(telemetry_event["latency_ms"], 0.0)


if __name__ == "__main__":
    unittest.main()
