# No-Direct-Agent-Write Invariant Report

- Generated: `2026-02-21T06:29:42.980592+00:00`
- Invariant: `NO_DIRECT_AGENT_WRITE`
- Status: `PASS`
- Checks: `3/3` passed

| Check ID | Path | Status | Details |
|---|---|---|---|
| `direct_sync_write_capability_denied` | `direct` | `PASS` | Unauthorized agent write attempt was denied before canonical state mutation. |
| `indirect_sync_scope_denied` | `indirect` | `PASS` | Scoped token blocked indirect write path despite write capability grant. |
| `indirect_sync_preflight_bypass_denied` | `indirect` | `PASS` | Preflight guard denied no-approved-proposal bypass attempt before state writes. |
