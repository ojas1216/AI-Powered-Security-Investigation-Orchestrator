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
├── ingestion/       SIEM normalizers → common Alert schema
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
