# AegisFlow Architecture

## 1. Design principles

1. **Investigation is the product.** Engines are first-class typed components, not
   playbook boxes. The orchestrator composes them; the analyst consumes the package.
2. **Connectors are swappable.** Every external product sits behind an abstract base class
   with a deterministic `mock` implementation. The platform is fully runnable offline and
   testable in CI without secrets.
3. **Durable by default.** Long-running investigations run as Temporal workflows so a
   sandbox detonation that takes 8 minutes survives a pod restart.
4. **Zero Trust + multi-tenant from line one.** Every request carries an authenticated
   principal *and* a tenant; Postgres Row-Level Security enforces isolation at the DB.
5. **Never execute LLM output.** The copilot produces text and *recommendations*; humans
   (or signed playbooks) act. See AI Security in [SECURITY.md](SECURITY.md).

## 2. Component map

```
backend/app
├── core/            config, structured logging, OIDC/JWT, RBAC+ABAC, tenancy, OTel
├── schemas/         Pydantic v2 contracts (Alert, IOC, Investigation, ...)
├── db/              SQLAlchemy 2.x models, session, RLS helpers
├── ingestion/       SIEM normalizers + artifact parsers → common Alert schema
│   └── parsers/         .eml, Windows/Sysmon event (.xml/.json), .csv/.txt
│                        (stdlib-only, XXE-hardened) → Alert → investigate
├── agents/          autonomous investigation core:
│   ├── planner.py       dynamic, deterministic action planner (budgeted)
│   ├── loop.py          plan → act → observe → re-plan → finalize
│   ├── tools.py         state-folding tools (delegate analytic work to specialists)
│   ├── memory.py        long-term case memory (tenant-isolated recall)
│   ├── state.py         working memory of one investigation
│   └── specialists/     typed, independently-callable specialist agents
│       ├── base.py          SpecialistAgent, AgentRegistry, AgentOrchestrator
│       └── agents.py        ThreatIntel/EdrHunt/Detection/Mitre/Risk/Memory/…
├── engines/
│   ├── detection/         Sigma-inspired rule DSL + engine, built-in ATT&CK-mapped
│   │                      rule pack, tenant-scoped custom rules (author via API)
│   ├── ioc_extraction/    deterministic IOC parser (defang-aware, validated)
│   ├── threat_intel/      connector base + aggregator (verdict fusion)
│   ├── risk_scoring/      weighted, explainable score → Critical/High/Med/Low
│   ├── timeline/          event fusion → ordered timeline
│   ├── mitre/             technique tagging
│   ├── sandbox|edr|email|graph|ticketing|copilot/   connector interfaces + mocks
├── orchestrator/    InvestigationOrchestrator: composes engines into a package
└── api/             FastAPI v1 surface; every route authz-guarded
```

## 3. Investigation lifecycle

```
ingest(alert) ─▶ normalize ─▶ persist(Investigation: status=RUNNING)
  ─▶ extract IOCs
  ─▶ enrich IOCs (threat-intel aggregator, concurrent, rate-limited, cached)
  ─▶ detonate attachments/urls (sandbox)        [async, Temporal child]
  ─▶ hunt IOCs in EDR + email gateway
  ─▶ collect evidence (immutable, hashed)
  ─▶ build timeline + IOC graph (Neo4j)
  ─▶ score risk + map MITRE ATT&CK
  ─▶ copilot: exec summary + analyst narrative   [guarded]
  ─▶ recommend containment playbook
  ─▶ open ticket(s)                              [ServiceNow / Jira]
  ─▶ persist(Investigation: status=COMPLETE, package=...)
```

The lifecycle above is not a hardcoded pipeline: it is what the **autonomous agent
loop** (`app/agents/`) converges to on a typical phishing alert. The planner re-plans
after every batch of tool executions, so evidence discovered mid-investigation changes
what happens next — e.g. IOCs dropped by a sandbox detonation are enriched and hunted in
EDR in later iterations, exactly like an analyst pivoting. Properties:

- **Deterministic control flow.** Action selection is rule-driven and auditable; LLM
  judgement is confined to the narrative (copilot) layer. Prompt injection in evidence
  can never steer which tools run.
- **Budgeted.** Hard caps on iterations, tool calls and wall-clock time bound worst-case
  cost per investigation.
- **Explainable.** Every plan decision, tool execution (with duration and outcome) and
  finalization step is recorded as an `AgentTraceStep` in the package — a complete
  audit trail of *why* the agent did what it did.
- **Resilient.** A failing connector is recorded in the trace and the investigation
  completes on partial evidence.
- **Long-term memory.** Completed cases are remembered (IOC keys + techniques); new
  investigations recall tenant-scoped similar past cases (`related_investigations`)
  with the shared indicators shown, so recurring campaigns surface instantly.

In local/dev the orchestrator runs in-process (`run_investigation`). In production the
same engine calls are wrapped as Temporal **activities** so each step is retried,
timed-out, and durably checkpointed (`orchestrator/temporal_workflow.py`).

### Durability, streaming & scale path

- **Per-tool Temporal activities**: `InvestigationState` JSON-round-trips, so the
  durable workflow checkpoints after every tool call — a worker crash resumes from
  the last completed activity. The deterministic planner runs inside the workflow
  (replay-safe by construction).
- **Dispatch** (`orchestrator/dispatch.py`): `AEGIS_DISPATCH=inline` runs supervised,
  semaphore-bounded asyncio tasks (429 at capacity); `temporal` starts the durable
  workflow. Both persist a QUEUED placeholder up front and a FAILED package on crash.
- **Async ingestion**: `POST /alerts/ingest?mode=async` → 202 + id; poll
  `GET /investigations/{id}`.
- **Kafka** (`ingestion/kafka_consumer.py`): at-least-once (commit after dispatch),
  poison messages to a DLQ with the error in a header, dispatcher backpressure.
- **Durable stores** (`AEGIS_PERSISTENCE=postgres`): case memory, approvals and
  tenant detection rules persist to RLS-protected tables (alembic 0002).

### AI model routing

`engines/copilot/router.py` routes each generation: task tiers (`fast` for exec
summaries → e.g. Haiku, `deep` for analyst reports → e.g. Sonnet), a
preference-ordered provider chain (`anthropic` cloud / `ollama` local &
air-gapped), a per-provider circuit breaker, and a deterministic grounded
fallback so the pipeline never blocks on an LLM. Prompt fencing and output
validation stay in `guards.py` regardless of provider.

### Human approval workflow

Recommendations are never auto-executed. When an investigation completes with an
actionable verdict, every playbook step that `requires_approval` becomes an
`ApprovalRequest` (`engines/approvals/`) with a strict, audited state machine:

```
PENDING ──approve──▶ APPROVED ──mark executed──▶ EXECUTED
   │──reject──▶ REJECTED          │──(72h TTL)──▶ EXPIRED
```

- **Four-eyes**: the requester can never decide their own request.
- **RBAC**: deciding/executing requires `investigation:act` (tier3 / incident
  responder); reading requires `investigation:read`.
- **Audit**: every transition logs actor, tenant, request id and note.
- API: `GET /api/v1/approvals`, `POST /api/v1/approvals/{id}/decision`,
  `POST /api/v1/approvals/{id}/executed`. The package carries `approval_ids`.

### Offline knowledge base

`engines/offline_cache/` bundles seed datasets so ATT&CK/CVE/Sigma lookups work
**fully air-gapped** out of the box, with best-effort online refresh:

- **ATT&CK** (`attack.json`, 30+ techniques), **CVE** (`cve.json`, known
  high-impact vulns with CVSS), **Sigma** (`sigma.json`, a rule pack).
- Each dataset loads its bundled seed unless a refreshed copy exists in
  `AEGIS_OFFLINE_CACHE_DIR`; `refresh()` pulls upstream (MITRE/NVD/SigmaHQ) when
  online and never blocks offline use.
- API: `GET /offline/status`, `/offline/attack/{id}`, `/offline/cve/{id}`,
  `/offline/sigma` (converted to the DetectionRule DSL — importable into a
  tenant's rules), `POST /offline/refresh/{dataset}` (detection:write).

### Observability

- **Metrics** (`core/metrics.py`): a zero-dependency, thread-safe registry
  (labelled counters + histograms) rendered in Prometheus text format at
  `GET /metrics` — always available, no client library, air-gap-capable. The
  agent loop records `aegis_investigations_total{verdict}`,
  `aegis_investigation_duration_seconds`, `aegis_tool_calls_total{tool,ok}`,
  `aegis_detections_fired_total`; the API records `aegis_agent_runs_total{agent}`
  and `aegis_alerts_ingested_total{mode}`.
- **Tracing** (`core/observability.py`): `span(name, **attrs)` emits OpenTelemetry
  spans when the SDK is installed and degrades to a no-op otherwise, so the loop
  (`investigation.finalize`, `agent.tool`) is instrumented unconditionally.

### Semantic memory & natural-language search

`engines/semantic/` embeds every completed case and searches them in natural
language ("credential phishing against finance"). Complements — does not replace
— the exact IOC-overlap recall in `agents/memory.py`:

- **Offline-first embedder**: the default `HashingEmbedder` needs no model and no
  network — signed feature-hashing over word + char-trigram tokens, deterministic
  (blake2b), fully air-gap-capable and hermetic for tests. `AEGIS_EMBEDDER=ollama`
  swaps in a local embedding model (e.g. `nomic-embed-text`) behind the same
  interface.
- **Vector store**: tenant-partitioned in-memory cosine search by default;
  ChromaDB (already in the stack) drops in behind the `VectorStore` interface.
- **Index-on-finalize**: the loop indexes each case after `memory.remember`
  (failure never breaks a case). `POST /api/v1/search/cases` runs NL search
  (RBAC: `investigation:read`), tenant-isolated.

### Knowledge graph (write + query)

The investigation loop writes a tenant-isolated entity graph (`alert`/`host`/
`user`/IOC nodes). `engines/graph/` now also **queries** it, with one interface
implemented for both the offline in-memory back end and Neo4j (Cypher):

- `neighbors(node, depth)` — N-hop subgraph for the Attack-Graph view
- `campaign(node)` — alerts + entities that reuse an indicator (infrastructure-
  reuse / campaign detection)
- `path(src, dst)` — shortest relationship path (attack-path reconstruction)

Exposed at `GET /api/v1/graph/{neighbors,campaign,path}` (RBAC:
`investigation:read`), every query tenant-gated. The graph is a process-wide
singleton so API reads see the loop's writes. Depth is hard-capped (6) so a
query can't traverse the whole graph.

### Planning layer (Task Graph + Priority Scheduler)

An opt-in evolution of the batch planner toward autonomous execution
(`agents/planning/`, `AEGIS_INVESTIGATION_STRATEGY=taskgraph`):

- **PlanningEngine** lifts the deterministic `Planner`'s proposed actions into
  explicit, deduplicated, dependency-linked **Tasks** (control flow stays
  auditable — the rule-based planner still decides *what* is appropriate).
- **TaskGraph** tracks nodes + dependency edges, dedups by (tool, params) against
  *active* work (a completed task may re-run when new evidence re-proposes it —
  e.g. re-enriching sandbox-dropped IOCs), and reports progress.
- **PriorityScheduler** runs ready tasks concurrently highest-priority-first,
  retries transient failures (bounded), re-expands as evidence unlocks new tasks,
  and stops on convergence or budget. It reuses `run_tool` + the specialist
  agents and feeds the same `finalize()`.
- The execution graph ships on the package (`plan_graph`) and renders as the
  investigation's **Plan** tab. The default `batch` strategy is unchanged, so
  existing behavior and tests are preserved (parity test enforces identical
  verdicts).

### Consensus + confidence engine

`agents/consensus.py` makes the final verdict a **weighted vote of independent
evidence sources** — never a single agent's call. Threat intel, EDR (on-host),
sandbox, detection rules and ATT&CK each cast a weighted vote *only when they
have evidence* (they abstain otherwise), so a conclusion resting on one weak
source is inherently low-confidence — "reject unsupported conclusions" falls out
of the math, and a lone voter's confidence is explicitly penalized.

The result (`package.consensus`) is fully explainable per the Explainable-AI
contract: the votes, the verdict + confidence, inter-source **agreement**, ranked
**alternative hypotheses**, and the **supporting / rejected** observations plus a
reasoning chain. It replaces the old single-function verdict heuristic and is
authoritative (`overall_verdict = consensus.verdict`); the reflection loop's
"unverified single-source" follow-ups feed it stronger evidence before it
decides. Surfaced as the Consensus panel in the investigation overview.

### Reflection loop (self-review)

`agents/reflection.py` gives every investigation a senior-analyst self-review.
After collection converges the engine (stateless, deterministic — auditable like
the planner) asks: was work left undone, was an obvious pivot missed, does a
conclusion rest on a single unconfirmed source, do sources contradict?

- Findings are categorized **coverage / gap / unverified / contradiction**.
- `suggest(state)` returns follow-up actions the **PriorityScheduler** re-opens as
  a task wave (e.g. hunt suspicious IOCs the planner skipped, or independently
  verify a single-source malicious verdict in EDR); it re-drains and reflects
  again until nothing new is proposed (confidence stabilizes) or the
  reflection-round budget trips.
- `review(state)` records the **residual** findings on every package
  (`reflections`) — what an analyst should still scrutinize — for both the
  batch and taskgraph strategies. Surfaced in the investigation overview.

### Specialist-agent framework

Every analytic capability is a `SpecialistAgent` (`app/agents/specialists/`): a
typed, stateless, **independently callable** unit with a uniform `run(payload,
tenant) -> AgentResult` contract and discovery metadata. Agents:
`ioc_extraction`, `threat_intel`, `detection`, `edr_hunt`, `sandbox`, `email`,
`mitre`, `risk`, `memory`.

- **Single source of truth**: the autonomous loop's state-folding tools delegate
  their analytic step to the matching agent — there is exactly one implementation
  per capability, and test-injected engines (e.g. a broken EDR) flow through
  unchanged.
- **Independently callable**: `GET /api/v1/agents` lists the catalog;
  `POST /api/v1/agents/{name}/run` invokes any single agent (RBAC: `agent:run`).
  Useful for ad-hoc analysis and external orchestration without a full case.
- **Generation & analytic agents** (`generation.py`): `sigma_generator`,
  `yara_generator`, `root_cause`, `attack_path`, `business_impact`. Deliberately
  **deterministic and grounded** in the case's own evidence — an LLM-invented
  detection rule is a liability, not an asset. `root_cause` (kill-chain origin)
  and `business_impact` (blast radius / asset class / cost band) are also wired
  into every investigation package at finalize.
- **Auditable by design**: agents are stateless and take `tenant` explicitly;
  action *selection* stays in the deterministic planner, so LLM/agent output can
  never steer which agents run.

### Detection engineering & threat hunting

- **Rule DSL** (`engines/detection/`): strictly-typed, Sigma-inspired conditions
  (`all`/`any`/`none` matchers with equals/contains/regex/... modifiers). Regexes are
  validated and compiled at load time; a malformed rule can never enter the engine, and
  one rule failing can never suppress another (per-rule isolation).
- **Built-in pack**: curated rules (encoded PowerShell, LOLBins, run-key/schtask
  persistence, LSASS dumping, ransomware staging, phishing lures, anomalous sign-ins),
  each with ATT&CK mapping, references and documented false positives.
- **Tenant custom rules**: `PUT /api/v1/detections/rules` (RBAC: `detection:write`);
  `POST /api/v1/detections/evaluate` dry-runs a raw alert with zero side effects —
  the detection engineer's author→test loop.
- **In the agent loop**: `run_detections` executes in the first planner batch; matches
  land in the package (`detections`), their ATT&CK techniques merge into the MITRE
  mapping, and severity feeds risk.
- **Threat hunting**: `POST /api/v1/hunts` (RBAC: `hunt:run`) pivots on free text or
  explicit indicators — TI enrichment + EDR hunt + long-term case-memory recall in one
  call, tenant-isolated.

## 4. Data stores

| Store      | Purpose                                   | Isolation                     |
| ---------- | ----------------------------------------- | ----------------------------- |
| PostgreSQL | alerts, investigations, IOCs, evidence    | Row-Level Security per tenant |
| Neo4j      | entity relationship graph                 | `tenant` property + label gate|
| ChromaDB   | RAG over historical incidents (copilot)   | per-tenant collection         |
| Redis      | enrichment cache, rate-limit buckets      | key-prefixed per tenant       |

## 4a. Deployment & hardening

- **CI** (`.github/workflows/ci.yml`) gates every PR on ruff (app + tests), a
  bandit security scan (`-ll`, medium+), the full pytest suite with coverage, and
  the frontend typecheck + build.
- **Helm** (`infra/helm/aegisflow`) packages the API with the same non-root /
  read-only-rootfs / drop-ALL-caps posture as the raw manifests, an HPA
  (3→30), and Prometheus scrape annotations for `/metrics`.
- **Endpoint hardening**: every Phase 2–8 route is RBAC- and tenant-gated; the
  agent-invocation payload is capped at 1 MiB, artifact upload at 10 MiB, and
  untrusted XML is DTD/entity-rejected (XXE/billion-laughs). A concurrency test
  drives 40 simultaneous investigations through the bounded dispatcher toward
  the 10k-concurrent target.

## 5. Scaling model

- Stateless API + workers scale horizontally behind the gateway.
- Kafka decouples ingestion spikes (100k+ alerts/day) from processing.
- Temporal task queues shard investigation work; sandbox detonation is its own queue
  with low concurrency to respect vendor rate limits.
- Threat-intel results are cached (Redis, TTL by IOC type) and deduplicated so a noisy
  campaign hitting the same IOC 10k times costs one upstream call.

## 6. Why these choices

- **Pydantic v2 + SQLAlchemy 2.x** give typed, validated contracts end-to-end (defense
  against injection/IDOR begins at the schema boundary).
- **Temporal over Celery** for investigations because correctness under partial failure is
  a security property here, not just reliability.
- **Connector ABCs** keep vendor churn out of the core and make the security boundary
  (egress, SSRF guards, credential scope) uniform and auditable.
