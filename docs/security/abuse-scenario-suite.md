# Adversarial Abuse Scenario Suite

> Executable abuse-scenario suite run against current controls.
>
> **Primary scope**: E8-S2 security signoff story (Issue 1702, reopened)
> **Spec under test**: `docs/research/agent-runtime-security-spec.md` (v1, 2026-02-19)
> **Compliance reference**: `docs/research/legal-compliance-playbook.md` (v1.0, 2026-02-19)
> **Executed**: 2026-02-21 (UTC)
> **Executable harness**: `python3 scripts/security/run_abuse_scenario_suite.py`
> **Evidence bundle**: `docs/security/evidence/abuse-scenario-suite-1702/README.md`
> **Machine-readable outcomes**: `docs/security/evidence/abuse-scenario-suite-1702/scenario-outcomes.json`
> **Prior comparable rerun**: R1-S6 signoff story (Issue 1806, 2026-02-21)

---

## Executable Scenario Run (E8-S2 Reopen)

All scenarios below are executable and were run in this workcell. Commands are
listed exactly for reproducibility. Logs and checksum-verified artifacts are in
`docs/security/evidence/abuse-scenario-suite-1702/`.

| ID | Abuse scenario | Executable command | Expected controls | Observed outcome | Evidence link | Remediation note if failed |
|---|---|---|---|---|---|---|
| S1 | Direct or indirect agent write attempt to canonical corpus state | `python3 scripts/tests/no_direct_agent_write_invariant.py --output-dir docs/security/evidence/abuse-scenario-suite-1702/no-direct-agent-write` | Capability checks deny unauthorized sync writes; denied operations emit `corpus_access_audit` + `corpus_violation_incident` records | **PASS** (`3/3` invariant checks passed; denied paths left backend/state unwritten) | `docs/security/evidence/abuse-scenario-suite-1702/scenario-01-no-direct-agent-write.log` and `docs/security/evidence/abuse-scenario-suite-1702/no-direct-agent-write/no-direct-agent-write-invariant.json` | Fix or restore fail-closed authorization in `scripts/ml/corpus_sync_worker.py` (`WRITE.CORPUS_SYNC` precheck + deny/audit on violation). |
| S2 | Egress policy bypass by targeting non-allowlisted cloud endpoint | `python3 -m unittest -v scripts/ml/tests/test_corpus_sync_worker.py -k allowlist_mode_blocks_non_approved_destination` | `allowlist` mode blocks non-approved destinations and emits deterministic `EGRESS_BLOCKED` incident remediation | **PASS** (`test_allowlist_mode_blocks_non_approved_destination ... ok`) | `docs/security/evidence/abuse-scenario-suite-1702/scenario-02-allowlist-egress.log` | Re-enable endpoint allowlist matching and `EGRESS_BLOCKED` incident emission in `scripts/ml/corpus_sync_worker.py`. |
| S3 | Project-level policy override bypass (`offline` project tries remote sync) | `python3 -m unittest -v scripts/ml/tests/test_corpus_sync_worker.py -k sync_policy_modes_are_configurable_per_project` | Per-project policy modes override defaults; offline project is denied while cloud project proceeds | **PASS** (`test_sync_policy_modes_are_configurable_per_project ... ok`) | `docs/security/evidence/abuse-scenario-suite-1702/scenario-03-policy-mode-scope.log` | Repair project policy resolution in `EndpointPolicyConfig`/`EndpointPolicyRule` to enforce offline deny semantics. |
| S4 | Provenance-chain tampering to bypass read-side trust checks | `python3 -m unittest -v scripts/ml/tests/test_corpus_sync_worker.py -k read_rejects_incomplete_provenance_chain` | Read path rejects malformed chain continuity and emits `PROVENANCE_CHAIN_INVALID` denial audit | **PASS** (`test_read_rejects_incomplete_provenance_chain ... ok`) | `docs/security/evidence/abuse-scenario-suite-1702/scenario-04-provenance-chain.log` | Reinstate provenance continuity validation in `_validate_provenance_chain(...)` and deny malformed artifacts. |
| S5 | Receipt-history tampering (mutate historic record) | `python3 -m unittest -v scripts/ml/tests/test_receipt_store.py -k verify_integrity_detects_tampering` | Hash-chain integrity check detects mutation and blocks further appends | **PASS** (`test_verify_integrity_detects_tampering ... ok`) | `docs/security/evidence/abuse-scenario-suite-1702/scenario-05-receipt-tamper.log` | Restore canonical hash verification and append-time integrity guard in `scripts/ml/receipt_store.py`. |

### Run Summary

- Executed scenarios: `5`
- Passed: `5`
- Failed: `0`
- Open remediation items from this run: `0`
- Additional documented scenarios (legacy tabletop appendix): `8`
- Total scenarios documented in this file: `13` (`5` executable + `8` tabletop)

## Legacy Tabletop Appendix (E8-S2, 2026-02-20)

### Methodology

Each scenario is evaluated against the architectural controls defined in the
security spec. For each scenario we assess:

1. **Attack viability** — Can the attack be mounted against the designed architecture?
2. **Mitigation coverage** — Do the specified controls address the attack?
3. **Residual risk** — What risk remains after mitigations are applied?
4. **Finding** — Remediated, accepted, or requires action.

Since the agent runtime is in design phase (pre-implementation), scenarios are
executed as structured tabletop exercises against the specification. Each
scenario maps to a threat from the STRIDE analysis (Section 7 of the spec).

---

## Scenario 1: Prompt Injection via Crafted ELF Symbol Names

**Threat ID**: T1
**STRIDE**: Tampering, Elevation of Privilege
**Spec reference**: Section 6.1

### Attack Description

A malware author embeds natural-language instructions in ELF symbol names
(`.symtab`/`.dynsym`). When an analyst invokes "explain function" via the agent,
the crafted symbol name is included in the LLM prompt as indirect injection,
potentially causing the model to mischaracterize malicious code as benign.

### Preconditions

- Agent has READ.DECOMPILE + READ.DISASM capabilities
- MCP server constructs prompts from binary-derived content
- Analyst trusts agent output without independent verification

### Attack Steps Evaluated

| Step | Description | Mitigation in Spec | Coverage |
|------|-------------|-------------------|----------|
| 1 | Malicious ELF loaded into Ghidra | N/A (normal workflow) | N/A |
| 2 | Auto-analysis populates function names from .symtab | N/A (Ghidra behavior) | N/A |
| 3 | Analyst invokes "explain function" via agent | Capability token scopes the request | Partial |
| 4 | MCP server constructs prompt including function name | Input sanitization: truncate to 128 chars, strip NL sequences | **Yes** |
| 5 | Crafted symbol name acts as indirect prompt injection | Structured prompts with XML/JSON delimiters; system prompt marks binary content as untrusted | **Yes** |
| 6 | LLM output mischaracterizes function | Dual-model verification; adversarial content detector (Flesch-Kincaid heuristic) | **Yes** |
| 7 | Analyst trusts incorrect assessment | Human-in-the-loop for anomalous names; auto-flagging of suspicious symbols | **Yes** |

### Outcome

**Finding: REMEDIATED (defense-in-depth)**

The spec provides four layers of defense: (1) input sanitization truncating
symbol names and stripping natural-language patterns, (2) structured prompt
boundaries separating untrusted data from instructions, (3) dual-model
verification detecting influenced output, and (4) human-in-the-loop flagging
for anomalous symbol names.

**Residual risk**: MEDIUM. No complete defense against indirect prompt injection
exists in the literature. The defense-in-depth approach reduces but cannot
eliminate the risk that a sufficiently crafted injection evades all four layers.
This is an inherent limitation of LLM-based systems processing adversary-
controlled input.

**Acceptance**: Residual risk formally accepted. The multi-layer mitigation
reduces practical exploitability to a level consistent with industry norms
(OWASP Top 10 for LLM Applications 2025, LLM01: Prompt Injection).

---

## Scenario 2: Model Hallucination Causing Incorrect Type Application

**Threat ID**: T9
**STRIDE**: Tampering (unintentional)
**Spec reference**: Section 6.2

### Attack Description

An agent suggests applying `struct sockaddr_in` to a data structure that is
actually a custom protocol buffer. The suggestion is auto-accepted due to high
single-dimension confidence. Subsequent analysis tools misinterpret fields,
causing a real vulnerability to be missed.

### Preconditions

- Agent has WRITE.RETYPE capability (Analyst or Engineer profile)
- Single-score confidence threshold used for auto-suggest
- Analyst configured to accept suggestions above threshold

### Attack Steps Evaluated

| Step | Description | Mitigation in Spec | Coverage |
|------|-------------|-------------------|----------|
| 1 | Agent analyzes function with network strings | N/A (normal workflow) | N/A |
| 2 | Model suggests sockaddr_in (0.87 confidence) | Confidence decomposition: semantic + structural | **Yes** |
| 3 | Suggestion auto-applied above threshold | Structural validation: verify layout matches memory access patterns | **Yes** |
| 4 | Struct layout mismatches actual data | Receipt-linked Ghidra transactions enable one-click undo | **Yes** |
| 5 | Downstream analysis misidentifies boundaries | Consensus requirement: two models must agree on types | **Yes** |

### Outcome

**Finding: REMEDIATED**

The spec addresses this through: (1) decomposed confidence scoring (semantic
vs. structural), preventing high semantic confidence alone from triggering
auto-application, (2) structural validation checking memory access patterns
against proposed types, (3) dual-model consensus for type suggestions, and
(4) full reversibility via receipt-linked transactions.

**Residual risk**: MEDIUM. Hallucination is inherent to all LLMs. The
structural validation check is the strongest mitigation — if memory access
patterns are ambiguous (e.g., the function only reads the first 4 bytes),
validation may not catch the mismatch. Dual-model consensus reduces but
does not eliminate correlated hallucination.

**Acceptance**: Residual risk formally accepted. Controls match OWASP
recommendations for LLM output validation (LLM02: Insecure Output Handling).

---

## Scenario 3: Exfiltration of Proprietary Binary Content via Cloud API

**Threat ID**: T3
**STRIDE**: Information Disclosure
**Spec reference**: Section 6.3

### Attack Description

An analyst uses a cloud LLM to batch-analyze all functions in a proprietary
firmware image. Over a session, the entire decompiled codebase is transmitted
to the cloud API provider, effectively exfiltrating proprietary IP.

### Preconditions

- Cloud API configured (not air-gapped mode)
- Analyst has access to proprietary/confidential binary
- Batch analysis enabled without content budget

### Attack Steps Evaluated

| Step | Description | Mitigation in Spec | Coverage |
|------|-------------|-------------------|----------|
| 1 | Analyst opens proprietary firmware | Data classification labels (T1-T4 tiers) | **Yes** |
| 2 | Agent configured with cloud API | Offline-first default; per-project cloud opt-in | **Yes** |
| 3 | Analyst runs batch analyze | Batch requires Engineer/Admin profile + audit alert | **Yes** |
| 4 | Agent iterates through all functions | Egress monitor: detects sequential iteration pattern | **Yes** |
| 5 | Decompiled code sent to cloud API | Content budget: alert on >500KB cumulative | **Yes** |
| 6 | API provider logs contain source | Content redaction: strip paths, addresses, annotations | **Partial** |
| 7 | Complete firmware effectively exfiltrated | Data classification blocks cloud for T3/T4 projects | **Yes** |

### Outcome

**Finding: REMEDIATED (with accepted residual)**

The spec provides comprehensive controls: (1) data classification system
blocking cloud APIs for confidential/restricted projects, (2) offline-first
default requiring explicit opt-in, (3) role-based batch restrictions,
(4) egress monitoring with sequential iteration detection, (5) cumulative
content budget alerting, and (6) content redaction.

**Residual risk**: MEDIUM. When cloud use is legitimately opted-in for T2
(internal) data, the model provider necessarily receives decompiled code.
Content redaction strips metadata but the functional logic remains. This is
inherent to cloud LLM usage and is disclosed in the per-project opt-in
confirmation dialog.

**Acceptance**: Residual risk formally accepted for T1-T2 data with
informed analyst consent. T3-T4 data is blocked from cloud APIs by policy,
reducing risk to LOW for sensitive content.

**Implementation note (SEC-417, 2026-02-20)**: `scripts/ml/corpus_sync_worker.py`
now enforces per-project `offline` / `allowlist` / `cloud` policy modes in both
sync and read runtime paths. Non-allowlisted destinations emit deterministic
`EGRESS_BLOCKED` audit events and the worker denies the operation.

**Implementation note (SEC-509, 2026-02-20)**: runtime permission checks now
log explicit `actor` + `timestamp_utc` + `target` fields on
`corpus_access_audit` events. Every denied policy/capability/provenance event
emits a paired `corpus_violation_incident` record with `policy_context` and a
deterministic `remediation_action`. Audit JSONL is queryable via
`query_audit_log_records(...)` for compliance review.

---

## Scenario 4: Supply Chain Attack via Malicious Plugin

**Threat ID**: T10
**STRIDE**: Tampering, Elevation of Privilege
**Spec reference**: Section 6.4

### Attack Description

An attacker publishes a Ghidra plugin with genuine functionality plus a
time-delayed backdoor. After activation, the plugin exfiltrates analysis
data via DNS TXT queries or subtly alters decompiler output to hide
vulnerabilities.

### Preconditions

- Plugin ecosystem allows third-party installation
- No capability manifest or signing requirement
- Plugin has full Ghidra API access

### Attack Steps Evaluated

| Step | Description | Mitigation in Spec | Coverage |
|------|-------------|-------------------|----------|
| 1 | Attacker publishes plugin | Plugin provenance verification (developer key signing) | **Yes** |
| 2 | Plugin provides genuine functionality | Org-approved plugin list; security review before approval | **Yes** |
| 3 | Hidden code activates after 7 days | Behavioral monitoring: API call pattern analysis | **Yes** |
| 4 | Plugin reads all function names/strings | Capability manifest: undeclared API access blocked | **Yes** |
| 5 | Data exfiltrated via DNS TXT queries | Network monitoring for plugins; DNS exfiltration detection | **Yes** |
| 6 | Alternative: plugin alters decompiler output | Sandboxed execution via restricted classloader (Section 8) | **Yes** |

### Outcome

**Finding: REMEDIATED**

The spec provides layered supply chain defenses: (1) plugin signing
with provenance verification, (2) capability manifest requiring
declaration of all API/network/filesystem access, (3) organizational
approved-list requirement with security review, (4) sandboxed execution
via restricted classloader or process isolation, (5) behavioral monitoring
for anomalous API patterns, and (6) DNS exfiltration detection.

**Residual risk**: MEDIUM. Supply chain attacks are inherently difficult
to prevent completely. A sophisticated attacker with a long-term presence
in the approved-list review process could potentially bypass controls.
The manifest + sandbox combination significantly limits blast radius.

**Acceptance**: Residual risk formally accepted. The phased implementation
plan (Section 8.5) correctly prioritizes plugin manifest/signing as a
longer-term effort requiring ecosystem coordination.

---

## Scenario 5: DoS via Expensive Agent-Triggered Analysis

**Threat ID**: T7
**STRIDE**: Denial of Service
**Spec reference**: Section 6.5

### Attack Description

An agent's investigation loop triggers symbolic execution on a function
with exponential path space. The symbolic execution engine exhausts memory
and CPU, crashing the Ghidra process and losing unsaved analysis.

### Preconditions

- Agent has EXECUTE.EXTERNAL capability (to invoke angr)
- No resource limits on external tool invocations
- No pre-screening of function complexity

### Attack Steps Evaluated

| Step | Description | Mitigation in Spec | Coverage |
|------|-------------|-------------------|----------|
| 1 | Agent analyzes complex function | N/A (normal workflow) | N/A |
| 2 | Agent invokes symbolic execution | Timeout: 30s default, 5min max per tool call | **Yes** |
| 3 | Function has 2^47 paths | Pre-screening: cyclomatic complexity check | **Yes** |
| 4 | angr allocates memory exponentially | Resource limits: cgroup 1GB RAM for first attempt | **Yes** |
| 5 | Workstation runs out of memory | Staged allocation: strict limits first, analyst approval for more | **Yes** |
| 6 | Ghidra killed by OOM | Agent loop iteration cap (50 calls); Ghidra auto-save | **Yes** |

### Outcome

**Finding: REMEDIATED**

The spec provides robust DoS prevention: (1) hard timeouts on all
operations (30s-10min depending on type), (2) pre-screening via
cyclomatic complexity before expensive analysis, (3) cgroup resource
limits preventing system-level impact, (4) staged resource allocation
requiring analyst approval for escalation, (5) iteration caps on
agent loops, and (6) Ghidra auto-save preventing data loss.

**Residual risk**: LOW. Hard resource limits (cgroups, timeouts) are
OS-enforced and cannot be bypassed by application-level bugs. The
remaining risk is that the Ghidra process itself (not the sandboxed
tool) encounters resource pressure, which auto-save mitigates.

**Acceptance**: Residual risk formally accepted.

---

## Scenario 6: Capability Escalation via Prompt Injection

**Threat ID**: T11
**STRIDE**: Elevation of Privilege
**Spec reference**: Sections 2, 6.1, 7 (T11)

### Attack Description

A prompt injection attack (via crafted binary content or a compromised
MCP server response) attempts to cause the LLM to invoke privileged tools
(WRITE.PATCH, EXECUTE.SCRIPT) that the current capability token does not
authorize.

### Preconditions

- Agent operates with Annotator profile (limited capabilities)
- LLM susceptible to prompt injection
- Capability enforcement relies on LLM self-restraint

### Attack Steps Evaluated

| Step | Description | Mitigation in Spec | Coverage |
|------|-------------|-------------------|----------|
| 1 | Injected prompt instructs "patch bytes at 0x401000" | N/A (attack payload) | N/A |
| 2 | LLM generates tool call: modify_bytes(addr=0x401000) | N/A (LLM is susceptible) | N/A |
| 3 | Tool call reaches MCP server | CapabilityGuard checks token before execution | **Yes** |
| 4 | MCP server validates capability token | Token lacks WRITE.PATCH; SecurityException thrown | **Yes** |
| 5 | Ghidra API wrapper validates capability | guardedStartTransaction rejects unauthorized write | **Yes** |
| 6 | Receipt builder rejects mutation | No matching capability in active token | **Yes** |

### Outcome

**Finding: REMEDIATED**

The spec explicitly states that capability enforcement is orthogonal to
prompt content — it operates at the API/tool handler level, not the LLM
level. The CapabilityGuard (Section 2.4) intercepts all Ghidra API calls
and validates the capability token before execution. Even if the LLM is
fully compromised by prompt injection and generates arbitrary tool calls,
the enforcement layer rejects unauthorized operations.

Three independent enforcement points exist: (1) MCP server tool handler,
(2) Ghidra Plugin API wrapper, and (3) receipt builder.

**Residual risk**: LOW. The enforcement is not dependent on LLM behavior.
The only remaining risk is an implementation bug in the CapabilityGuard
itself, which is a standard authorization code review concern.

**Acceptance**: Residual risk formally accepted.

---

## Scenario 7: MITM on Cloud API Connection

**Threat ID**: T2
**STRIDE**: Tampering, Spoofing
**Spec reference**: Sections 3, 7 (T2)

### Attack Description

A network adversary intercepts the connection between the MCP server and
the cloud model API, modifying responses to inject misleading analysis
(e.g., renaming a malicious function to appear benign).

### Preconditions

- Cloud API in use (not air-gapped)
- Attacker has network position (MITM)
- TLS verification disabled or vulnerable

### Attack Steps Evaluated

| Step | Description | Mitigation in Spec | Coverage |
|------|-------------|-------------------|----------|
| 1 | Attacker intercepts API traffic | TLS with certificate verification (mandatory) | **Yes** |
| 2 | Attacker modifies model response | TLS integrity; optional certificate pinning | **Yes** |
| 3 | Modified response applied to analysis | mTLS to organizational proxy for enterprise | **Yes** |
| 4 | Analyst receives falsified analysis | Receipt chain records response hash for audit | **Yes** |

### Outcome

**Finding: REMEDIATED**

TLS with certificate verification is mandatory (Section 3.2,
`tls_verify: true`). Enterprise deployments add mTLS to the
organizational proxy. Certificate pinning is available as an
additional option for high-security deployments.

**Residual risk**: LOW. Standard TLS effectively mitigates network
MITM attacks. Residual risk is limited to TLS implementation
vulnerabilities (rare, well-monitored) or CA compromise (very rare,
detectable via CT logs).

**Acceptance**: Residual risk formally accepted.

---

## Scenario 8: API Key Theft from Configuration

**Threat ID**: T4
**STRIDE**: Information Disclosure
**Spec reference**: Section 4

### Attack Description

An attacker (or careless workflow) exposes API keys through plaintext
configuration files, log output, error messages, or version control.

### Preconditions

- API keys stored in plaintext config
- Logging does not redact credentials
- Config files checked into version control

### Attack Steps Evaluated

| Step | Description | Mitigation in Spec | Coverage |
|------|-------------|-------------------|----------|
| 1 | Keys in plaintext config | OS keychain storage (macOS/Windows/Linux) | **Yes** |
| 2 | Keys in log output | Pattern-based log redaction (sk-..., Bearer ...) | **Yes** |
| 3 | Keys in error messages | Exception handler sanitization | **Yes** |
| 4 | Keys in version control | .gitignore + pre-commit hook scanning | **Yes** |
| 5 | Keys in receipts | Receipt stores prompt hashes, never raw prompts | **Yes** |
| 6 | Keys in memory (long-lived) | char[] storage with zeroing (Java best practice) | **Yes** |

### Outcome

**Finding: REMEDIATED**

The spec provides comprehensive secrets hygiene: OS keychain as primary
storage, organizational proxy eliminating direct key handling, log
redaction, exception sanitization, VCS scanning, and in-memory
protection.

**Residual risk**: LOW. OS keychain + organizational proxy eliminates
most exposure vectors. The organizational proxy model (Section 4.3)
is the strongest control — analysts never see raw API keys.

**Acceptance**: Residual risk formally accepted.

---

## Scenario 9: Receipt Chain Tampering

**Threat ID**: T8
**STRIDE**: Repudiation, Tampering
**Spec reference**: Sections 7, 8.4

### Attack Description

An attacker with access to the receipt store modifies or deletes receipts
to hide unauthorized analysis changes, breaking the audit trail.

### Preconditions

- Attacker has write access to receipt store
- No hash chain integrity verification
- Receipts stored in mutable storage

### Attack Steps Evaluated

| Step | Description | Mitigation in Spec | Coverage |
|------|-------------|-------------------|----------|
| 1 | Attacker modifies a receipt | Hash-chain integrity: each receipt includes hash of previous | **Yes** |
| 2 | Attacker deletes a receipt | Append-only storage prevents deletion | **Yes** |
| 3 | Attacker inserts a forged receipt | Chain verification detects inconsistency | **Yes** |
| 4 | Tampering goes undetected | Periodic chain validation + separate audit log | **Yes** |

### Outcome

**Finding: REMEDIATED**

Hash-chain integrity (each receipt includes hash of its predecessor)
makes tampering detectable. Append-only storage prevents deletion.
Periodic validation and a separate audit log provide defense-in-depth.

**Residual risk**: LOW. Hash chain makes post-hoc tampering detectable
(requires rewriting entire chain from modification point). Separate
audit log provides an independent record.

**Acceptance**: Residual risk formally accepted.

---

## Scenario 10: Compromised Model Weights

**Threat ID**: T5
**STRIDE**: Tampering
**Spec reference**: Section 7 (T5)

### Attack Description

Model weights are compromised at the source (model provider or weight
distribution channel) to produce systematically biased analysis — e.g.,
never flagging certain vulnerability patterns.

### Preconditions

- Supply chain compromise of model weights
- No weight verification mechanism
- No cross-checking of model output

### Attack Steps Evaluated

| Step | Description | Mitigation in Spec | Coverage |
|------|-------------|-------------------|----------|
| 1 | Compromised weights distributed | Weight hash verification (SHA-256 manifest) | **Yes** |
| 2 | Biased model deployed | Model provenance tracking | **Yes** |
| 3 | Subtle bias in analysis output | Dual-model cross-checking | **Partial** |
| 4 | Bias goes undetected | Periodic evaluation against known benchmarks | **Yes** |

### Outcome

**Finding: ACCEPTED (with mitigations)**

Weight hash verification prevents tampering during distribution, and
provenance tracking maintains chain of custody. However, if the
compromise occurs at the model provider before hashes are published,
verification cannot detect it. Dual-model cross-checking reduces
impact but correlated bias (if both models are biased in the same
direction) remains a theoretical risk.

**Residual risk**: MEDIUM. Subtle bias in model weights is the
hardest attack to detect in the entire threat model. Periodic
benchmark evaluation is the best available control but may not
catch targeted biases for specific vulnerability patterns.

**Acceptance**: Residual risk formally accepted. This is a known
limitation of LLM-dependent systems. Benchmark evaluation provides
the best available detection.

---

## Scenario 11: Agent-Generated Script with Injected Code

**Threat ID**: T12
**STRIDE**: Elevation of Privilege, Tampering
**Spec reference**: Section 7 (T12)

### Attack Description

A prompt injection causes the agent to generate a Ghidra script containing
malicious code (e.g., exfiltration, persistence). If executed, this achieves
arbitrary code execution on the analyst's workstation.

### Preconditions

- Agent has EXECUTE.SCRIPT capability
- Script generation not subject to human review
- Prompt injection successful

### Attack Steps Evaluated

| Step | Description | Mitigation in Spec | Coverage |
|------|-------------|-------------------|----------|
| 1 | Prompt injection causes malicious script generation | Input sanitization (Section 6.1 mitigations) | **Yes** |
| 2 | Script submitted for execution | Script generation disabled by default | **Yes** |
| 3 | Script executes without review | Mandatory human review for all generated scripts | **Yes** |
| 4 | Malicious code runs on workstation | Script sandbox (custom GhidraScript subclass) | **Yes** |

### Outcome

**Finding: REMEDIATED**

Multiple gates prevent execution: (1) EXECUTE.SCRIPT capability
required (not in Observer/Annotator profiles), (2) script generation
disabled by default, (3) mandatory human review for all generated
scripts, and (4) script sandbox enforcing capability checks.

**Residual risk**: LOW. Three independent gates must all fail for
this attack to succeed.

**Acceptance**: Residual risk formally accepted.

---

## Scenario 12: Rogue MCP Server

**Threat ID**: T6
**STRIDE**: Spoofing, Elevation of Privilege, Information Disclosure
**Spec reference**: Sections 5.6, 7 (T6)

### Attack Description

A malicious MCP server masquerades as a legitimate tool provider. Once
connected, it exfiltrates analysis data, escalates privileges, or injects
misleading responses.

### Preconditions

- MCP server ecosystem allows arbitrary server connections
- No manifest or capability enforcement
- Server runs with full host access

### Attack Steps Evaluated

| Step | Description | Mitigation in Spec | Coverage |
|------|-------------|-------------------|----------|
| 1 | Rogue server installed | Manifest declaration required on first use | **Yes** |
| 2 | Server requests excessive capabilities | Capability consent: analyst approves each capability | **Yes** |
| 3 | Server attempts undeclared access | Runtime enforcement: undeclared access blocked + logged | **Yes** |
| 4 | Server updated with new capabilities | Update verification: manifest diff shown for re-approval | **Yes** |
| 5 | Server attempts network exfiltration | Sandbox: allow-listed endpoints only | **Yes** |

### Outcome

**Finding: REMEDIATED**

The MCP server sandboxing requirements (Section 5.6) provide five
controls: manifest declaration, capability consent, runtime enforcement,
least-privilege default, and update verification. Combined with
process-level isolation (Section 5.1-5.4), a rogue server is contained
to its declared capabilities.

**Residual risk**: LOW. Sandbox + manifest enforcement contains rogue
servers effectively.

**Acceptance**: Residual risk formally accepted.

---

## Scenario 13: DNS/Timing Side-Channel Information Leakage

**Threat ID**: T13
**STRIDE**: Information Disclosure
**Spec reference**: Section 7 (T13)

### Attack Description

A compromised component leaks binary metadata through DNS queries
(encoding data in subdomain labels) or timing side channels (observable
differences in processing time revealing structural properties).

### Preconditions

- Component has DNS access
- Attacker has network visibility
- No DNS monitoring

### Attack Steps Evaluated

| Step | Description | Mitigation in Spec | Coverage |
|------|-------------|-------------------|----------|
| 1 | Component encodes data in DNS queries | DNS query monitoring | **Yes** |
| 2 | Timing differences reveal binary structure | Network namespace isolation | **Yes** |
| 3 | Attacker correlates observations | Encrypted DNS (DoH/DoT) | **Yes** |

### Outcome

**Finding: REMEDIATED**

DNS monitoring detects exfiltration attempts. Network namespace
isolation (Section 8.3) limits side-channel observability. Encrypted
DNS prevents passive interception.

**Residual risk**: LOW. Side channels yield limited data and require
sophisticated attackers with sustained network visibility.

**Acceptance**: Residual risk formally accepted.

---

## Summary of Findings

| Scenario | Threat ID | Finding | Residual Risk | Disposition |
|----------|-----------|---------|---------------|-------------|
| 1. Prompt injection via symbols | T1 | Remediated | Medium | Accepted |
| 2. Hallucination incorrect types | T9 | Remediated | Medium | Accepted |
| 3. Cloud API data exfiltration | T3 | Remediated | Medium | Accepted |
| 4. Malicious plugin supply chain | T10 | Remediated | Medium | Accepted |
| 5. DoS via expensive analysis | T7 | Remediated | Low | Accepted |
| 6. Capability escalation via injection | T11 | Remediated | Low | Accepted |
| 7. MITM on cloud API | T2 | Remediated | Low | Accepted |
| 8. API key theft | T4 | Remediated | Low | Accepted |
| 9. Receipt chain tampering | T8 | Remediated | Low | Accepted |
| 10. Compromised model weights | T5 | Accepted | Medium | Accepted |
| 11. Agent-generated malicious script | T12 | Remediated | Low | Accepted |
| 12. Rogue MCP server | T6 | Remediated | Low | Accepted |
| 13. DNS/timing side channels | T13 | Remediated | Low | Accepted |

**Critical findings requiring remediation**: None. All 13 threat scenarios
have architectural mitigations specified. No unaddressed attack vectors
identified.

**Findings with MEDIUM residual risk** (5 of 13): `T1`, `T3`, `T5`, `T9`,
and `T10`. These represent inherent limitations of LLM-based systems
(prompt injection, hallucination, cloud data exposure, and model/plugin
supply chain) where defense-in-depth reduces but cannot eliminate risk.
All are formally accepted with documented justification.

---

## Cross-Reference: OWASP Top 10 for LLM Applications 2025

| OWASP LLM Risk | Covered By Scenario | Mitigation Status |
|----------------|--------------------|--------------------|
| LLM01: Prompt Injection | Scenarios 1, 6 | Remediated (defense-in-depth) |
| LLM02: Insecure Output Handling | Scenario 2 | Remediated |
| LLM03: Training Data Poisoning | Scenario 10 | Accepted (medium residual) |
| LLM04: Model Denial of Service | Scenario 5 | Remediated |
| LLM05: Supply Chain Vulnerabilities | Scenarios 4, 10 | Remediated / Accepted |
| LLM06: Sensitive Information Disclosure | Scenarios 3, 8, 13 | Remediated |
| LLM07: Insecure Plugin Design | Scenarios 4, 12 | Remediated |
| LLM08: Excessive Agency | Scenario 6 | Remediated |
| LLM09: Overreliance | Scenario 2 | Remediated |
| LLM10: Model Theft | N/A (not applicable to this architecture) | N/A |

## Cross-Reference: OWASP Top 10 for Agentic Applications 2026

| OWASP Agentic Risk | Covered By Scenario | Mitigation Status |
|--------------------|--------------------|--------------------|
| Excessive Agency & Autonomy | Scenarios 5, 6 | Remediated |
| Trust Boundary Violations | Scenarios 1, 12 | Remediated |
| Inadequate Sandboxing | Scenarios 4, 5, 12 | Remediated |
| Uncontrolled Escalation | Scenario 6 | Remediated |
| Insecure Tool Integration | Scenarios 4, 12 | Remediated |
| Insufficient Audit & Logging | Scenario 9 | Remediated |
| Data Leakage Through Agents | Scenarios 3, 13 | Remediated |
| Prompt Injection in Agentic Contexts | Scenarios 1, 6, 11 | Remediated |
| Multi-Agent Trust Issues | Scenario 12 | Remediated |
| Lack of Human Oversight | Scenarios 2, 11 | Remediated |

---

> **Document version**: 1.3
> **Classification**: Internal — Security Review
> **Next review**: Next security signoff reopen or control-surface change
