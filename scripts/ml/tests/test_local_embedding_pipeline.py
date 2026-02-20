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

SYNC_MODULE_PATH = Path(__file__).resolve().parents[1] / "corpus_sync_worker.py"
SYNC_SPEC = importlib.util.spec_from_file_location("e7_corpus_sync_worker_for_pullback", SYNC_MODULE_PATH)
if SYNC_SPEC is None or SYNC_SPEC.loader is None:
    raise RuntimeError(f"failed to load module spec from {SYNC_MODULE_PATH}")
SYNC_MODULE = importlib.util.module_from_spec(SYNC_SPEC)
sys.modules[SYNC_SPEC.name] = SYNC_MODULE
SYNC_SPEC.loader.exec_module(SYNC_MODULE)

BaselineSimilarityAdapter = MODULE.BaselineSimilarityAdapter
DeterministicTriageFeatureExtractor = MODULE.DeterministicTriageFeatureExtractor
DeterministicTriageMission = MODULE.DeterministicTriageMission
EmbeddingIndex = MODULE.EmbeddingIndex
EvidenceWeightedReranker = MODULE.EvidenceWeightedReranker
FunctionRecord = MODULE.FunctionRecord
LocalEmbeddingPipeline = MODULE.LocalEmbeddingPipeline
SemanticSearchQueryService = MODULE.SemanticSearchQueryService
TypeSuggestionGenerator = MODULE.TypeSuggestionGenerator
TypeSuggestionPolicy = MODULE.TypeSuggestionPolicy
evaluate_queries = MODULE.evaluate_queries
generate_type_suggestion_report = MODULE.generate_type_suggestion_report
render_triage_panel = MODULE.render_triage_panel
run_sync_job = SYNC_MODULE.run_sync_job


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
            self.assertIn("recall@3", metrics)
            self.assertIn("mrr", metrics)
            self.assertEqual(len(metrics["results"]), 2)

    def test_evidence_weighted_reranker_improves_eval_slice(self) -> None:
        corpus_path = MODULE_PATH.parent / "fixtures" / "toy_similarity_corpus_slice.json"
        queries_path = MODULE_PATH.parent / "fixtures" / "toy_similarity_queries_slice.json"

        pipeline = LocalEmbeddingPipeline(vector_dimension=128)
        corpus_records = MODULE.load_corpus(corpus_path)
        index = pipeline.build_index(corpus_records)
        adapter = BaselineSimilarityAdapter(pipeline, index)

        baseline = evaluate_queries(adapter, queries_path, top_k=3)
        reranked = evaluate_queries(
            adapter,
            queries_path,
            top_k=3,
            index=index,
            reranker=EvidenceWeightedReranker(),
        )

        self.assertGreater(reranked["mrr"], baseline["mrr"])
        self.assertGreater(reranked["recall@1"], baseline["recall@1"])
        comparison = MODULE.compare_eval_ordering(baseline, reranked, top_k=3)
        self.assertTrue(comparison["improves_against_baseline"])
        self.assertGreater(comparison["ordering_improved_queries"], 0)

    def test_reranker_oversampling_can_improve_recall_at_top_k(self) -> None:
        records: list[FunctionRecord] = [
            FunctionRecord.from_json(
                {
                    "id": "fn.target.parse_imports",
                    "name": "parse_imports",
                    "text": "parse pe import directory entries",
                    "provenance": {
                        "source": "test",
                        "receipt_id": "receipt:test:target",
                        "record_id": "fn.target.parse_imports",
                    },
                    "evidence_refs": [
                        {
                            "kind": "CALLSITE",
                            "description": "callsite evidence iat thunk import resolver",
                            "uri": "local-index://evidence/fn.target.parse_imports/callsite",
                            "confidence": 0.99,
                        },
                        {
                            "kind": "XREF",
                            "description": "xref evidence links iat thunk references",
                            "uri": "local-index://evidence/fn.target.parse_imports/xref",
                            "confidence": 0.95,
                        },
                    ],
                }
            )
        ]
        for index in range(24):
            records.append(
                FunctionRecord.from_json(
                    {
                        "id": f"fn.aa.noise.{index:02d}",
                        "name": f"noise_{index:02d}",
                        "text": "auxiliary routine buffer state machine checksum handler",
                    }
                )
            )
        for index in range(12):
            records.append(
                FunctionRecord.from_json(
                    {
                        "id": f"fn.zz.noise.{index:02d}",
                        "name": f"noise_tail_{index:02d}",
                        "text": "auxiliary routine buffer state machine checksum handler",
                    }
                )
            )

        pipeline = LocalEmbeddingPipeline(vector_dimension=1024)
        index = pipeline.build_index(records)
        adapter = BaselineSimilarityAdapter(pipeline, index)

        with tempfile.TemporaryDirectory() as tmpdir:
            queries_path = Path(tmpdir) / "queries.json"
            queries_path.write_text(
                json.dumps(
                    {
                        "queries": [
                            {
                                "text": "callsite evidence iat thunk",
                                "ground_truth_id": "fn.target.parse_imports",
                            }
                        ]
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )

            baseline = evaluate_queries(adapter, queries_path, top_k=10)
            reranked = evaluate_queries(
                adapter,
                queries_path,
                top_k=10,
                index=index,
                reranker=EvidenceWeightedReranker(),
                rerank_candidate_multiplier=4,
            )

            self.assertEqual(baseline["recall@10"], 0.0)
            self.assertEqual(reranked["recall@10"], 1.0)

    def test_similar_function_query_uses_oversampled_candidates_for_rerank(self) -> None:
        records: list[FunctionRecord] = [
            FunctionRecord.from_json(
                {
                    "id": "fn.seed.resolve",
                    "name": "resolve_symbols",
                    "text": "resolve import symbol thunk table",
                }
            ),
            FunctionRecord.from_json(
                {
                    "id": "fn.zz.target.resolve",
                    "name": "target_candidate",
                    "text": "resolve import symbol thunk table",
                    "provenance": {
                        "source": "test",
                        "receipt_id": "receipt:test:target",
                        "record_id": "fn.zz.target.resolve",
                    },
                    "evidence_refs": [
                        {
                            "kind": "CALLSITE",
                            "description": "iat thunk resolver callsite evidence",
                            "uri": "local-index://evidence/fn.zz.target.resolve/callsite",
                            "confidence": 0.99,
                        },
                        {
                            "kind": "XREF",
                            "description": "xref links to import thunk table",
                            "uri": "local-index://evidence/fn.zz.target.resolve/xref",
                            "confidence": 0.97,
                        },
                    ],
                }
            ),
        ]
        for index in range(10):
            records.append(
                FunctionRecord.from_json(
                    {
                        "id": f"fn.aa.noise.{index:02d}",
                        "name": f"noise_{index:02d}",
                        "text": "resolve import symbol thunk table",
                    }
                )
            )

        pipeline = LocalEmbeddingPipeline(vector_dimension=64)
        index = pipeline.build_index(records)
        adapter = BaselineSimilarityAdapter(pipeline, index)

        baseline_service = SemanticSearchQueryService(adapter=adapter, index=index)
        reranked_service = SemanticSearchQueryService(
            adapter=adapter,
            index=index,
            reranker=EvidenceWeightedReranker(),
            rerank_candidate_multiplier=4,
        )

        baseline_ids = [
            item["function_id"]
            for item in baseline_service.search_similar_function("fn.seed.resolve", top_k=3).to_json()[
                "results"
            ]
        ]
        reranked_ids = [
            item["function_id"]
            for item in reranked_service.search_similar_function("fn.seed.resolve", top_k=3).to_json()[
                "results"
            ]
        ]

        self.assertNotIn("fn.zz.target.resolve", baseline_ids)
        self.assertEqual(reranked_ids[0], "fn.zz.target.resolve")

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

    def test_semantic_search_falls_back_on_reranker_failure(self) -> None:
        class ExplodingReranker:
            def rerank(self, **_: object) -> list[object]:
                raise RuntimeError("reranker unavailable")

        index = self.pipeline.build_index(self.records)
        adapter = BaselineSimilarityAdapter(self.pipeline, index)
        baseline_service = SemanticSearchQueryService(adapter=adapter, index=index)
        fallback_service = SemanticSearchQueryService(
            adapter=adapter,
            index=index,
            reranker=ExplodingReranker(),
        )

        baseline_doc = baseline_service.search_intent("socket host connect", top_k=2).to_json()
        fallback_doc = fallback_service.search_intent("socket host connect", top_k=2).to_json()
        baseline_ids = [item["function_id"] for item in baseline_doc["results"]]
        fallback_ids = [item["function_id"] for item in fallback_doc["results"]]
        self.assertEqual(fallback_ids, baseline_ids)

    def test_evaluate_command_can_disable_reranker(self) -> None:
        corpus_path = MODULE_PATH.parent / "fixtures" / "toy_similarity_corpus_slice.json"
        queries_path = MODULE_PATH.parent / "fixtures" / "toy_similarity_queries_slice.json"

        corpus_records = MODULE.load_corpus(corpus_path)
        index = self.pipeline.build_index(corpus_records)
        with tempfile.TemporaryDirectory() as tmpdir:
            index_dir = Path(tmpdir) / "index"
            index.save(index_dir)

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = MODULE.main(
                    [
                        "evaluate",
                        "--index-dir",
                        str(index_dir),
                        "--queries",
                        str(queries_path),
                        "--top-k",
                        "3",
                        "--disable-reranker",
                    ]
                )
            self.assertEqual(exit_code, 0)
            metrics = json.loads(stdout.getvalue())
            self.assertEqual(metrics["reranker"]["enabled"], False)
            self.assertEqual(metrics["reranker"]["status"], "disabled")
            self.assertNotIn("comparison", metrics)

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

    def test_benchmark_mvp_outputs_gate_metrics(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            report_path = Path(tmpdir) / "benchmark.json"
            exit_code = MODULE.main(
                [
                    "benchmark-mvp",
                    "--target-corpus-size",
                    "2000",
                    "--recall-query-count",
                    "8",
                    "--latency-sample-count",
                    "40",
                    "--output",
                    str(report_path),
                    "--run-id",
                    "test-run",
                    "--commit-sha",
                    "abc123",
                ]
            )
            self.assertEqual(exit_code, 0)
            report = json.loads(report_path.read_text(encoding="utf-8"))

            self.assertEqual(report["kind"], "semantic_search_mvp_benchmark")
            self.assertEqual(report["run_id"], "test-run")
            self.assertEqual(report["commit_sha"], "abc123")
            self.assertEqual(report["status"], "passed")
            self.assertEqual(report["corpus"]["actual_size"], 2000)

            metrics = report["metrics"]
            self.assertGreaterEqual(metrics["recall_at_10_delta_vs_stock"], 0.10)
            self.assertLessEqual(metrics["search_latency_p95_ms"], 300.0)
            self.assertEqual(metrics["receipt_completeness"], 1.0)
            self.assertEqual(metrics["rollback_success_rate"], 1.0)

    def test_type_suggestion_generator_emits_confidence_and_evidence_summary(self) -> None:
        policy = TypeSuggestionPolicy(auto_apply_threshold=0.9, suggest_threshold=0.5)
        generator = TypeSuggestionGenerator(policy=policy)
        suggestions = generator.generate(
            [
                {
                    "target_id": "fn.net.open_socket:param.addr",
                    "target_scope": "PARAMETER",
                    "suggested_type": "struct sockaddr_in *",
                    "model_confidence": 0.84,
                    "consensus_ratio": 0.8,
                    "pattern_match_score": 1.0,
                    "evidence_refs": [
                        {
                            "kind": "CALLSITE",
                            "description": "12 callsites pass AF_INET constants",
                            "uri": "local-index://evidence/fn.net.open_socket/callsite",
                            "confidence": 0.9,
                        },
                        {
                            "kind": "STRUCT_LAYOUT",
                            "description": "offset layout matches sockaddr_in",
                            "uri": "local-index://evidence/fn.net.open_socket/layout",
                            "confidence": 0.88,
                        },
                    ],
                }
            ]
        )
        self.assertEqual(len(suggestions), 1)
        suggestion = suggestions[0]
        self.assertGreaterEqual(suggestion.confidence, 0.0)
        self.assertLessEqual(suggestion.confidence, 1.0)
        self.assertIn("evidence refs", suggestion.evidence_summary)
        self.assertEqual(suggestion.policy_action, "SUGGEST")

    def test_low_confidence_type_suggestions_are_quarantined_by_policy(self) -> None:
        policy = TypeSuggestionPolicy(auto_apply_threshold=0.95, suggest_threshold=0.7)
        generator = TypeSuggestionGenerator(policy=policy)
        suggestions = generator.generate(
            [
                {
                    "target_id": "fn.crypto.sha256_update:local.ctx",
                    "target_scope": "VARIABLE",
                    "suggested_type": "AES_CTX *",
                    "model_confidence": 0.2,
                    "consensus_ratio": 0.1,
                    "pattern_match_score": 0.0,
                    "evidence_refs": [],
                }
            ]
        )
        self.assertEqual(len(suggestions), 1)
        self.assertEqual(suggestions[0].policy_action, "QUARANTINED")
        self.assertTrue(suggestions[0].quarantined)

    def test_type_suggestion_quality_metrics_are_reported(self) -> None:
        policy = TypeSuggestionPolicy(auto_apply_threshold=0.9, suggest_threshold=0.5)
        report = generate_type_suggestion_report(
            [
                {
                    "target_id": "fn.net.open_socket:param.addr",
                    "target_scope": "PARAMETER",
                    "suggested_type": "struct sockaddr_in *",
                    "ground_truth_type": "struct sockaddr_in *",
                    "model_confidence": 0.86,
                    "consensus_ratio": 0.9,
                    "pattern_match_score": 1.0,
                    "evidence_refs": [
                        {
                            "kind": "CALLSITE",
                            "description": "socket callsite argument typing",
                            "uri": "local-index://evidence/fn.net.open_socket/callsite",
                            "confidence": 0.9,
                        }
                    ],
                },
                {
                    "target_id": "fn.pe.parse_imports:local.desc",
                    "target_scope": "VARIABLE",
                    "suggested_type": "IMAGE_IMPORT_DESCRIPTOR *",
                    "ground_truth_type": "IMAGE_IMPORT_DESCRIPTOR *",
                    "model_confidence": 0.83,
                    "consensus_ratio": 0.7,
                    "pattern_match_score": 1.0,
                    "evidence_refs": [
                        {
                            "kind": "STRUCT_LAYOUT",
                            "description": "descriptor offsets match PE import descriptor",
                            "uri": "local-index://evidence/fn.pe.parse_imports/layout",
                            "confidence": 0.87,
                        }
                    ],
                },
                {
                    "target_id": "fn.crypto.sha256_update:local.ctx",
                    "target_scope": "VARIABLE",
                    "suggested_type": "AES_CTX *",
                    "ground_truth_type": "SHA256_CTX *",
                    "model_confidence": 0.2,
                    "consensus_ratio": 0.1,
                    "pattern_match_score": 0.0,
                    "evidence_refs": [],
                },
            ],
            policy=policy,
        )

        metrics = report["metrics"]
        self.assertEqual(metrics["total_suggestions"], 3)
        self.assertEqual(metrics["evaluated_with_ground_truth"], 3)
        self.assertIn("overall_accuracy", metrics)
        self.assertIn("accepted_precision", metrics)
        self.assertIn("incorrect_quarantine_recall", metrics)
        self.assertEqual(metrics["quarantined_count"], 1)
        self.assertGreater(metrics["overall_accuracy"], 0.0)

    def test_suggest_types_cli_writes_report_and_telemetry(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = Path(tmpdir) / "type_suggestions.json"
            output_path = Path(tmpdir) / "type_suggestion_report.json"
            telemetry_path = Path(tmpdir) / "type_suggestion_metrics.jsonl"
            input_path.write_text(
                json.dumps(
                    {
                        "suggestions": [
                            {
                                "target_id": "fn.net.open_socket:param.addr",
                                "target_scope": "PARAMETER",
                                "suggested_type": "struct sockaddr_in *",
                                "ground_truth_type": "struct sockaddr_in *",
                                "model_confidence": 0.84,
                                "consensus_ratio": 0.8,
                                "pattern_match_score": 1.0,
                                "evidence_refs": [
                                    {
                                        "kind": "CALLSITE",
                                        "description": "socket callsites",
                                        "uri": "local-index://evidence/fn.net.open_socket/callsite",
                                        "confidence": 0.9,
                                    }
                                ],
                            }
                        ]
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = MODULE.main(
                    [
                        "suggest-types",
                        "--input",
                        str(input_path),
                        "--output",
                        str(output_path),
                        "--telemetry-path",
                        str(telemetry_path),
                    ]
                )
            self.assertEqual(exit_code, 0)
            report = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(report["kind"], "type_suggestion_report")
            self.assertIn("metrics", report)
            self.assertEqual(report["metrics"]["total_suggestions"], 1)

            events = telemetry_path.read_text(encoding="utf-8").strip().splitlines()
            self.assertEqual(len(events), 1)
            telemetry_event = json.loads(events[0])
            self.assertEqual(telemetry_event["kind"], "type_suggestion_quality")
            self.assertEqual(telemetry_event["total_suggestions"], 1)

    def test_pullback_reuse_inserts_proposals_with_receipts(self) -> None:
        records = [
            FunctionRecord.from_json(
                {
                    "id": "fn.local.parse_imports",
                    "name": "parse_pe_imports",
                    "text": "parse pe import table and resolve imported function names",
                }
            )
        ]
        index = self.pipeline.build_index(records)

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            index_dir = tmp / "index"
            backend_store = tmp / "shared_backend.json"
            local_store = tmp / "local_store.json"
            index.save(index_dir)

            backend_store.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "kind": "shared_corpus_backend",
                        "artifacts": {
                            "remote-1": {
                                "proposal_id": "remote-1",
                                "state": "APPROVED",
                                "receipt_id": "receipt:remote:1",
                                "program_id": "program:remote",
                                "artifact": {
                                    "function_name": "parse_pe_imports",
                                    "function_text": "parse pe import table and resolve imported symbol names",
                                    "reusable_artifacts": [
                                        {
                                            "kind": "NAME",
                                            "target_scope": "FUNCTION",
                                            "value": "resolve_import_thunks",
                                            "confidence": 0.95,
                                        },
                                        {
                                            "kind": "TYPE",
                                            "target_scope": "VARIABLE",
                                            "target_id": "fn.local.parse_imports:local.desc",
                                            "value": "IMAGE_IMPORT_DESCRIPTOR *",
                                            "confidence": 0.9,
                                        },
                                        {
                                            "kind": "ANNOTATION",
                                            "target_scope": "FUNCTION",
                                            "value": "Resolves PE imports and thunk targets.",
                                            "confidence": 0.88,
                                        },
                                    ],
                                },
                            }
                        },
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = MODULE.main(
                    [
                        "pullback-reuse",
                        "--index-dir",
                        str(index_dir),
                        "--backend-store",
                        str(backend_store),
                        "--local-store",
                        str(local_store),
                        "--function-id",
                        "fn.local.parse_imports",
                        "--top-k",
                        "2",
                        "--program-id",
                        "program:local",
                    ]
                )
            self.assertEqual(exit_code, 0)

            report = json.loads(stdout.getvalue())
            self.assertEqual(report["kind"], "cross_binary_pullback_report")
            self.assertEqual(report["metrics"]["inserted_count"], 3)
            self.assertEqual(report["metrics"]["matches"], 1)

            local_doc = json.loads(local_store.read_text(encoding="utf-8"))
            proposals = local_doc["proposals"]
            self.assertEqual(len(proposals), 3)
            self.assertTrue(all(item["state"] == "PROPOSED" for item in proposals))
            self.assertTrue(all(item["receipt_id"].startswith("receipt:pullback:") for item in proposals))
            self.assertTrue(all(len(item["provenance_chain"]) >= 2 for item in proposals))
            self.assertTrue(
                all(item["artifact"]["kind"] == "cross_binary_reuse_proposal" for item in proposals)
            )
            self.assertTrue(all(item["program_id"] == "program:local" for item in proposals))

    def test_pullback_proposals_work_with_accepted_rejected_sync_flow(self) -> None:
        records = [
            FunctionRecord.from_json(
                {
                    "id": "fn.local.parse_imports",
                    "name": "parse_pe_imports",
                    "text": "parse pe import table and resolve imported function names",
                }
            )
        ]
        index = self.pipeline.build_index(records)

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            index_dir = tmp / "index"
            source_backend = tmp / "source_backend.json"
            local_store = tmp / "local_store.json"
            sync_backend = tmp / "sync_backend.json"
            state_path = tmp / "state.json"
            index.save(index_dir)

            source_backend.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "kind": "shared_corpus_backend",
                        "artifacts": {
                            "remote-1": {
                                "proposal_id": "remote-1",
                                "state": "APPROVED",
                                "receipt_id": "receipt:remote:1",
                                "artifact": {
                                    "function_name": "parse_pe_imports",
                                    "reusable_artifacts": [
                                        {
                                            "kind": "NAME",
                                            "target_scope": "FUNCTION",
                                            "value": "resolve_import_thunks",
                                        },
                                        {
                                            "kind": "ANNOTATION",
                                            "target_scope": "FUNCTION",
                                            "value": "Resolves imported functions.",
                                        },
                                    ],
                                },
                            }
                        },
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )

            exit_code = MODULE.main(
                [
                    "pullback-reuse",
                    "--index-dir",
                    str(index_dir),
                    "--backend-store",
                    str(source_backend),
                    "--local-store",
                    str(local_store),
                    "--function-id",
                    "fn.local.parse_imports",
                ]
            )
            self.assertEqual(exit_code, 0)

            local_doc = json.loads(local_store.read_text(encoding="utf-8"))
            proposals = local_doc["proposals"]
            self.assertEqual(len(proposals), 2)
            proposals[0]["state"] = "APPROVED"
            proposals[1]["state"] = "REJECTED"
            local_store.write_text(json.dumps(local_doc, indent=2) + "\n", encoding="utf-8")

            telemetry = run_sync_job(
                local_store_path=local_store,
                backend_store_path=sync_backend,
                state_path=state_path,
                job_id="pullback-review-flow",
            )

            synced = json.loads(sync_backend.read_text(encoding="utf-8"))
            self.assertEqual(telemetry.scanned_total, 2)
            self.assertEqual(telemetry.approved_total, 1)
            self.assertEqual(telemetry.synced_count, 1)
            self.assertEqual(len(synced["artifacts"]), 1)

    def test_proposal_review_and_query_support_approve_reject_and_bulk(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            local_store = Path(tmpdir) / "local_store.json"
            local_store.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "kind": "local_proposal_store",
                        "proposals": [
                            {"proposal_id": "p-1", "state": "PROPOSED", "receipt_id": "receipt:p-1"},
                            {"proposal_id": "p-2", "state": "PROPOSED", "receipt_id": "receipt:p-2"},
                            {"proposal_id": "p-3", "state": "PROPOSED", "receipt_id": "receipt:p-3"},
                        ],
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = MODULE.main(
                    [
                        "proposal-review",
                        "--local-store",
                        str(local_store),
                        "--action",
                        "approve",
                        "--proposal-id",
                        "p-1",
                        "--reviewer-id",
                        "user:analyst",
                    ]
                )
            self.assertEqual(exit_code, 0)
            approve_report = json.loads(stdout.getvalue())
            self.assertEqual(approve_report["kind"], "proposal_review_report")
            self.assertEqual(approve_report["metrics"]["reviewed_total"], 1)
            self.assertFalse(approve_report["bulk"])

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = MODULE.main(
                    [
                        "proposal-review",
                        "--local-store",
                        str(local_store),
                        "--action",
                        "reject",
                        "--rationale",
                        "bulk cleanup",
                    ]
                )
            self.assertEqual(exit_code, 0)
            reject_report = json.loads(stdout.getvalue())
            self.assertEqual(reject_report["metrics"]["reviewed_total"], 2)
            self.assertEqual(reject_report["metrics"]["skipped_total"], 1)
            self.assertTrue(reject_report["bulk"])

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = MODULE.main(
                    [
                        "proposal-query",
                        "--local-store",
                        str(local_store),
                        "--state",
                        "REJECTED",
                    ]
                )
            self.assertEqual(exit_code, 0)
            query_report = json.loads(stdout.getvalue())
            self.assertEqual(query_report["kind"], "proposal_query_report")
            self.assertEqual(query_report["metrics"]["matched_total"], 2)
            self.assertEqual(query_report["metrics"]["state_counts"]["APPROVED"], 1)
            self.assertEqual(query_report["metrics"]["state_counts"]["REJECTED"], 2)

            local_doc = json.loads(local_store.read_text(encoding="utf-8"))
            by_id = {item["proposal_id"]: item for item in local_doc["proposals"]}
            self.assertEqual(by_id["p-1"]["state"], "APPROVED")
            self.assertEqual(by_id["p-2"]["state"], "REJECTED")
            self.assertEqual(by_id["p-3"]["state"], "REJECTED")
            self.assertTrue(all(len(item["lifecycle_transitions"]) >= 2 for item in by_id.values()))

    def test_proposal_apply_requires_approved_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            local_store = Path(tmpdir) / "local_store.json"
            local_store.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "kind": "local_proposal_store",
                        "proposals": [
                            {"proposal_id": "p-approved", "state": "APPROVED", "receipt_id": "receipt:p-approved"},
                            {"proposal_id": "p-proposed", "state": "PROPOSED", "receipt_id": "receipt:p-proposed"},
                        ],
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = MODULE.main(
                    [
                        "proposal-apply",
                        "--local-store",
                        str(local_store),
                        "--proposal-id",
                        "p-approved",
                        "--proposal-id",
                        "p-proposed",
                    ]
                )
            self.assertEqual(exit_code, 1)
            error_report = json.loads(stdout.getvalue())
            self.assertEqual(error_report["kind"], "proposal_apply_error")
            self.assertIn("only APPROVED proposals can enter apply workflow", error_report["error"])

            local_doc = json.loads(local_store.read_text(encoding="utf-8"))
            by_id = {item["proposal_id"]: item for item in local_doc["proposals"]}
            self.assertEqual(by_id["p-approved"]["state"], "APPROVED")
            self.assertEqual(by_id["p-proposed"]["state"], "PROPOSED")

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = MODULE.main(
                    [
                        "proposal-apply",
                        "--local-store",
                        str(local_store),
                        "--actor-id",
                        "worker:apply",
                    ]
                )
            self.assertEqual(exit_code, 0)
            apply_report = json.loads(stdout.getvalue())
            self.assertEqual(apply_report["kind"], "proposal_apply_report")
            self.assertEqual(apply_report["metrics"]["applied_total"], 1)
            self.assertEqual(apply_report["applied_proposal_ids"], ["p-approved"])
            self.assertTrue(apply_report["apply_receipt_id"].startswith("receipt:apply:"))
            self.assertEqual(apply_report["transaction"]["phase"], "apply")
            self.assertEqual(apply_report["transaction"]["scope"], "single")
            self.assertEqual(apply_report["receipt_links"][0]["link_type"], "APPLIES_PROPOSAL")
            self.assertEqual(apply_report["receipt_links"][0]["receipt_id"], "receipt:p-approved")

            local_doc = json.loads(local_store.read_text(encoding="utf-8"))
            by_id = {item["proposal_id"]: item for item in local_doc["proposals"]}
            self.assertEqual(by_id["p-approved"]["state"], "APPLIED")
            self.assertEqual(by_id["p-proposed"]["state"], "PROPOSED")
            self.assertEqual(len(local_doc["apply_transactions"]), 1)
            tx = local_doc["apply_transactions"][0]
            self.assertEqual(tx["status"], "applied")
            self.assertEqual(tx["apply_receipt_id"], apply_report["apply_receipt_id"])
            self.assertEqual(tx["receipt_links"][0]["link_type"], "APPLIES_PROPOSAL")
            self.assertEqual(tx["state_before"]["p-approved"]["state"], "APPROVED")
            self.assertEqual(tx["state_after"]["p-approved"]["state"], "APPLIED")

    def test_proposal_rollback_restores_pre_apply_state_for_single_change(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            local_store = Path(tmpdir) / "local_store.json"
            local_store.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "kind": "local_proposal_store",
                        "proposals": [
                            {"proposal_id": "p-1", "state": "APPROVED", "receipt_id": "receipt:p-1"},
                        ],
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                apply_exit = MODULE.main(
                    [
                        "proposal-apply",
                        "--local-store",
                        str(local_store),
                        "--proposal-id",
                        "p-1",
                        "--actor-id",
                        "worker:apply",
                    ]
                )
            self.assertEqual(apply_exit, 0)
            apply_report = json.loads(stdout.getvalue())
            apply_receipt_id = apply_report["apply_receipt_id"]

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                rollback_exit = MODULE.main(
                    [
                        "proposal-rollback",
                        "--local-store",
                        str(local_store),
                        "--apply-receipt-id",
                        apply_receipt_id,
                        "--actor-id",
                        "worker:rollback",
                    ]
                )
            self.assertEqual(rollback_exit, 0)
            rollback_report = json.loads(stdout.getvalue())
            self.assertEqual(rollback_report["kind"], "proposal_rollback_report")
            self.assertEqual(rollback_report["metrics"]["rolled_back_total"], 1)
            self.assertEqual(rollback_report["metrics"]["restored_total"], 1)
            self.assertEqual(rollback_report["restored_proposal_ids"], ["p-1"])
            self.assertEqual(rollback_report["rolled_back_apply_receipt_ids"], [apply_receipt_id])

            local_doc = json.loads(local_store.read_text(encoding="utf-8"))
            proposal = local_doc["proposals"][0]
            self.assertEqual(proposal["state"], "APPROVED")
            rollback_events = [event for event in proposal["apply_events"] if event["action"] == "ROLLBACK"]
            self.assertEqual(len(rollback_events), 1)
            rollback_event = rollback_events[0]
            self.assertEqual(rollback_event["receipt_links"][0]["link_type"], "ROLLS_BACK_APPLY")
            self.assertEqual(rollback_event["receipt_links"][0]["receipt_id"], apply_receipt_id)

            tx = local_doc["apply_transactions"][0]
            self.assertEqual(tx["status"], "rolled_back")
            self.assertEqual(tx["rollback_receipt_id"], rollback_report["rollback_receipt_ids"][0])
            self.assertEqual(tx["rollback_receipt_links"][0]["link_type"], "ROLLS_BACK_APPLY")
            self.assertEqual(tx["rollback_receipt_links"][0]["receipt_id"], apply_receipt_id)

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                rollback_exit = MODULE.main(
                    [
                        "proposal-rollback",
                        "--local-store",
                        str(local_store),
                        "--apply-receipt-id",
                        apply_receipt_id,
                    ]
                )
            self.assertEqual(rollback_exit, 0)
            second_report = json.loads(stdout.getvalue())
            self.assertEqual(second_report["metrics"]["rolled_back_total"], 0)
            self.assertEqual(second_report["metrics"]["already_rolled_back_total"], 1)
            self.assertEqual(second_report["rollback_receipt_ids"], rollback_report["rollback_receipt_ids"])

    def test_proposal_rollback_restores_pre_apply_state_for_batch_change(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            local_store = Path(tmpdir) / "local_store.json"
            local_store.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "kind": "local_proposal_store",
                        "proposals": [
                            {"proposal_id": "p-1", "state": "APPROVED", "receipt_id": "receipt:p-1"},
                            {"proposal_id": "p-2", "state": "APPROVED", "receipt_id": "receipt:p-2"},
                            {"proposal_id": "p-3", "state": "PROPOSED", "receipt_id": "receipt:p-3"},
                        ],
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                apply_exit = MODULE.main(
                    [
                        "proposal-apply",
                        "--local-store",
                        str(local_store),
                        "--actor-id",
                        "worker:apply",
                    ]
                )
            self.assertEqual(apply_exit, 0)
            apply_report = json.loads(stdout.getvalue())
            self.assertEqual(apply_report["transaction"]["scope"], "batch")
            self.assertEqual(apply_report["applied_proposal_ids"], ["p-1", "p-2"])

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                rollback_exit = MODULE.main(
                    [
                        "proposal-rollback",
                        "--local-store",
                        str(local_store),
                        "--apply-receipt-id",
                        apply_report["apply_receipt_id"],
                    ]
                )
            self.assertEqual(rollback_exit, 0)
            rollback_report = json.loads(stdout.getvalue())
            self.assertEqual(rollback_report["metrics"]["rolled_back_total"], 1)
            self.assertEqual(rollback_report["metrics"]["restored_total"], 2)
            self.assertEqual(
                rollback_report["restored_proposal_ids"],
                list(reversed(apply_report["applied_proposal_ids"])),
            )

            local_doc = json.loads(local_store.read_text(encoding="utf-8"))
            by_id = {item["proposal_id"]: item for item in local_doc["proposals"]}
            self.assertEqual(by_id["p-1"]["state"], "APPROVED")
            self.assertEqual(by_id["p-2"]["state"], "APPROVED")
            self.assertEqual(by_id["p-3"]["state"], "PROPOSED")

    @staticmethod
    def _triage_fixture_records() -> list[FunctionRecord]:
        return [
            FunctionRecord.from_json(
                {
                    "id": "fn.main.dispatch",
                    "name": "main_dispatch",
                    "text": "bootstrap main dispatch parses config and opens socket network session",
                    "evidence_refs": [
                        {
                            "kind": "CALLSITE",
                            "description": "main dispatcher calls parser and network connectors",
                            "uri": "local-index://evidence/fn.main.dispatch/callsite",
                            "confidence": 0.92,
                        },
                        {
                            "kind": "XREF",
                            "description": "xref from entry thunk into dispatch loop",
                            "uri": "local-index://evidence/fn.main.dispatch/xref",
                            "confidence": 0.88,
                        },
                    ],
                }
            ),
            FunctionRecord.from_json(
                {
                    "id": "fn.crypto.decrypt",
                    "name": "decrypt_payload",
                    "text": "aes key schedule decrypt routine for encrypted packet payload",
                    "evidence_refs": [
                        {
                            "kind": "CONSTANT",
                            "description": "AES S-box constants detected",
                            "uri": "local-index://evidence/fn.crypto.decrypt/constant",
                            "confidence": 0.95,
                        }
                    ],
                }
            ),
            FunctionRecord.from_json(
                {
                    "id": "fn.helper.unknown",
                    "name": "FUN_00401090",
                    "text": "opaque unknown state machine over unresolved buffer",
                }
            ),
        ]

    def test_triage_mission_uses_fixed_stage_graph_order(self) -> None:
        mission = DeterministicTriageMission()
        report = mission.run(self._triage_fixture_records(), mission_id="triage:test").to_json()

        stages = [stage["stage"] for stage in report["execution"]["stage_graph"]]
        self.assertEqual(
            stages,
            [
                "extract_features",
                "select_entrypoints",
                "rank_hotspots",
                "select_unknowns",
                "build_summary",
            ],
        )
        transitions = [stage["next_stage"] for stage in report["execution"]["stage_graph"]]
        self.assertEqual(
            transitions,
            [
                "select_entrypoints",
                "rank_hotspots",
                "select_unknowns",
                "build_summary",
                None,
            ],
        )

    def test_triage_mission_emits_entrypoints_hotspots_unknowns_with_evidence_refs(self) -> None:
        mission = DeterministicTriageMission()
        report = mission.run(self._triage_fixture_records()).to_json()

        self.assertGreaterEqual(report["counts"]["entrypoints"], 1)
        self.assertGreaterEqual(report["counts"]["hotspots"], 1)
        self.assertGreaterEqual(report["counts"]["unknowns"], 1)

        entrypoint_ids = {row["function_id"] for row in report["entrypoints"]}
        hotspot_ids = {row["function_id"] for row in report["hotspots"]}
        unknown_ids = {row["function_id"] for row in report["unknowns"]}
        self.assertIn("fn.main.dispatch", entrypoint_ids)
        self.assertIn("fn.crypto.decrypt", hotspot_ids)
        self.assertIn("fn.helper.unknown", unknown_ids)

        self.assertTrue(all(len(row["evidence_refs"]) >= 1 for row in report["entrypoints"]))
        self.assertTrue(all(len(row["evidence_refs"]) >= 1 for row in report["hotspots"]))
        self.assertTrue(all(len(row["evidence_refs"]) >= 1 for row in report["unknowns"]))
        self.assertTrue(all(row["source_context_uri"].startswith("local-index://function/") for row in report["hotspots"]))
        self.assertTrue(all(len(row["evidence_links"]) >= 1 for row in report["hotspots"]))
        self.assertEqual(
            [row["rank"] for row in report["ranked_hotspots"]],
            list(range(1, len(report["ranked_hotspots"]) + 1)),
        )
        self.assertEqual(len(report["triage_map"]["nodes"]), report["execution"]["feature_count"])
        map_ids = {row["function_id"] for row in report["triage_map"]["nodes"]}
        self.assertIn("fn.main.dispatch", map_ids)
        self.assertIn("fn.crypto.decrypt", map_ids)
        self.assertIn("fn.helper.unknown", map_ids)

    def test_triage_feature_extractor_is_order_invariant_for_evidence_refs(self) -> None:
        extractor = DeterministicTriageFeatureExtractor()
        evidence_a = {
            "evidence_ref_id": "evr:a",
            "kind": "CALLSITE",
            "description": "entrypoint thunk callsite",
            "uri": "local-index://evidence/fn.test/a",
            "confidence": 0.9,
        }
        evidence_b = {
            "evidence_ref_id": "evr:b",
            "kind": "XREF",
            "description": "entry xref",
            "uri": "local-index://evidence/fn.test/b",
            "confidence": 0.8,
        }
        record_a = FunctionRecord.from_json(
            {
                "id": "fn.test",
                "name": "main_dispatch",
                "text": "bootstrap entry dispatcher",
                "evidence_refs": [evidence_a, evidence_b],
            }
        )
        record_b = FunctionRecord.from_json(
            {
                "id": "fn.test",
                "name": "main_dispatch",
                "text": "bootstrap entry dispatcher",
                "evidence_refs": [evidence_b, evidence_a],
            }
        )

        extracted_a = extractor.extract(record_a)
        extracted_b = extractor.extract(record_b)
        self.assertEqual(extracted_a, extracted_b)
        self.assertEqual(
            [ref.evidence_ref_id for ref in extracted_a.evidence_refs],
            ["evr:a", "evr:b"],
        )

    def test_triage_mission_output_is_order_invariant_for_input_records(self) -> None:
        mission = DeterministicTriageMission()
        records = self._triage_fixture_records()
        report_a = mission.run(records).to_json()
        report_b = mission.run(list(reversed(records))).to_json()

        report_a.pop("generated_at_utc", None)
        report_b.pop("generated_at_utc", None)
        self.assertEqual(report_a, report_b)

    def test_triage_panel_payload_includes_triage_map_and_ranked_hotspots(self) -> None:
        mission = DeterministicTriageMission()
        report = mission.run(self._triage_fixture_records()).to_json()
        panel = render_triage_panel(report)

        self.assertEqual(panel["kind"], "triage_mission_panel")
        self.assertEqual(panel["panel"]["id"], "triage-mission")
        self.assertGreaterEqual(panel["panel"]["map_node_count"], 3)
        self.assertGreaterEqual(panel["panel"]["hotspot_count"], 1)
        self.assertIn("triage_map", panel)
        self.assertGreaterEqual(len(panel["triage_map"]["nodes"]), 3)
        self.assertGreaterEqual(len(panel["ranked_hotspots"]), 1)

    def test_triage_mission_cli_persists_summary_artifact_and_exports_report_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            corpus_path = tmp / "triage_corpus.json"
            output_path = tmp / "triage_summary.json"
            report_dir = tmp / "triage_artifacts"
            corpus_path.write_text(
                json.dumps(
                    {
                        "functions": [
                            {
                                "id": "fn.main.dispatch",
                                "name": "main_dispatch",
                                "text": "bootstrap main dispatch parses config and opens socket network session",
                                "evidence_refs": [
                                    {
                                        "kind": "CALLSITE",
                                        "description": "main dispatcher calls parser and network connectors",
                                        "uri": "local-index://evidence/fn.main.dispatch/callsite",
                                        "confidence": 0.92,
                                    }
                                ],
                            },
                            {
                                "id": "fn.crypto.decrypt",
                                "name": "decrypt_payload",
                                "text": "aes key schedule decrypt routine for encrypted packet payload",
                            },
                            {
                                "id": "fn.helper.unknown",
                                "name": "FUN_00401090",
                                "text": "opaque unknown state machine over unresolved buffer",
                            },
                        ]
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )

            exit_code = MODULE.main(
                [
                    "triage-mission",
                    "--corpus",
                    str(corpus_path),
                    "--output",
                    str(output_path),
                    "--mission-id",
                    "triage:test",
                    "--report-dir",
                    str(report_dir),
                ]
            )
            self.assertEqual(exit_code, 0)
            summary = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(summary["kind"], "triage_mission_summary")
            self.assertEqual(summary["mission_id"], "triage:test")
            self.assertEqual(len(summary["execution"]["stage_graph"]), 5)
            self.assertGreaterEqual(summary["counts"]["entrypoints"], 1)
            self.assertGreaterEqual(len(summary["ranked_hotspots"]), 1)
            self.assertGreaterEqual(len(summary["triage_map"]["nodes"]), 1)

            panel = json.loads((report_dir / "triage-panel.json").read_text(encoding="utf-8"))
            self.assertEqual(panel["kind"], "triage_mission_panel")
            self.assertGreaterEqual(panel["panel"]["map_node_count"], 1)
            self.assertGreaterEqual(len(panel["ranked_hotspots"]), 1)

            markdown = (report_dir / "triage-report.md").read_text(encoding="utf-8")
            self.assertIn("## Ranked Hotspots", markdown)
            self.assertIn("local-index://evidence/fn.main.dispatch/callsite", markdown)
            self.assertIn("local-index://function/fn.main.dispatch", markdown)

            manifest = json.loads((report_dir / "triage-artifacts.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["kind"], "triage_mission_artifacts")
            self.assertEqual(manifest["mission_id"], "triage:test")

    def test_triage_panel_cli_emits_ui_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            corpus_path = tmp / "triage_corpus.json"
            panel_path = tmp / "triage_panel.json"
            corpus_path.write_text(
                json.dumps(
                    {
                        "functions": [
                            {
                                "id": "fn.main.dispatch",
                                "name": "main_dispatch",
                                "text": "bootstrap main dispatch parses config and opens socket network session",
                            },
                            {
                                "id": "fn.crypto.decrypt",
                                "name": "decrypt_payload",
                                "text": "aes key schedule decrypt routine for encrypted packet payload",
                            },
                            {
                                "id": "fn.helper.unknown",
                                "name": "FUN_00401090",
                                "text": "opaque unknown state machine over unresolved buffer",
                            },
                        ]
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )

            exit_code = MODULE.main(
                [
                    "triage-panel",
                    "--corpus",
                    str(corpus_path),
                    "--output",
                    str(panel_path),
                    "--mission-id",
                    "triage:test",
                ]
            )
            self.assertEqual(exit_code, 0)
            panel = json.loads(panel_path.read_text(encoding="utf-8"))
            self.assertEqual(panel["kind"], "triage_mission_panel")
            self.assertEqual(panel["panel"]["mission_id"], "triage:test")
            self.assertGreaterEqual(panel["panel"]["map_node_count"], 3)
            self.assertGreaterEqual(len(panel["ranked_hotspots"]), 1)

    def test_triage_benchmark_fixture_is_versioned(self) -> None:
        benchmark_path = MODULE_PATH.parent / "fixtures" / "triage_benchmark_v2026_02_1.json"
        benchmark = MODULE.load_triage_benchmark(benchmark_path)

        self.assertEqual(benchmark["kind"], "triage_scoring_benchmark")
        self.assertEqual(benchmark["benchmark_id"], "triage-curated")
        self.assertEqual(benchmark["benchmark_version"], "2026.02.1")
        self.assertEqual(len(benchmark["cases"]), 12)
        self.assertIn("macro_f1", benchmark["target_thresholds"])

    def test_triage_calibrate_cli_reports_before_after_improvement(self) -> None:
        benchmark_path = MODULE_PATH.parent / "fixtures" / "triage_benchmark_v2026_02_1.json"
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "triage_calibration.json"
            exit_code = MODULE.main(
                [
                    "triage-calibrate",
                    "--benchmark",
                    str(benchmark_path),
                    "--output",
                    str(output_path),
                    "--commit-sha",
                    "abc123",
                ]
            )
            self.assertEqual(exit_code, 0)

            report = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(report["kind"], "triage_scoring_calibration")
            self.assertEqual(report["status"], "passed")
            self.assertEqual(report["commit_sha"], "abc123")
            self.assertEqual(report["benchmark"]["benchmark_version"], "2026.02.1")
            self.assertLess(report["baseline"]["targets_passed"], report["candidate"]["targets_passed"])
            self.assertGreater(
                report["candidate"]["metrics"]["macro_f1"],
                report["baseline"]["metrics"]["macro_f1"],
            )
            self.assertEqual(
                report["candidate"]["thresholds"]["entrypoint"],
                MODULE.DEFAULT_TRIAGE_ENTRYPOINT_THRESHOLD,
            )
            self.assertEqual(
                report["candidate"]["thresholds"]["hotspot"],
                MODULE.DEFAULT_TRIAGE_HOTSPOT_THRESHOLD,
            )
            self.assertEqual(
                report["candidate"]["thresholds"]["unknown"],
                MODULE.DEFAULT_TRIAGE_UNKNOWN_THRESHOLD,
            )
            self.assertTrue(all(check["passed"] for check in report["candidate"]["checks"].values()))


if __name__ == "__main__":
    unittest.main()
