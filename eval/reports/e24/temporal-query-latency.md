# E24 Temporal Query Latency Budget Report

Date: 2026-02-23
Scope: `QueryService` temporal API over unified evidence graph.

## Representative fixture volumes
- Temporal events: 5,000 (`latency-0` .. `latency-4999`)
- Window query result cap: 256
- Interval-join result cap: 2,048
- Lineage depth: 128

## Budget enforcement
Budgets are measured in `LiveQueryServiceImplTemporalQueryTest#testTemporalLatencyBudgetsAcrossRepresentativeVolumes`
using deterministic fixtures and p95 over 12 iterations.

- `queryTemporalWindow`: p95 budget <= 150 ms
- `queryTemporalIntervalJoin`: p95 budget <= 500 ms
- `queryTemporalLineage`: p95 budget <= 100 ms

These thresholds are intentionally bounded and checked in CI as regression guards.
