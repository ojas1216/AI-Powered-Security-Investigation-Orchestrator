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
├── engines/
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

In local/dev the orchestrator runs in-process (`run_investigation`). In production the
same engine calls are wrapped as Temporal **activities** so each step is retried,
timed-out, and durably checkpointed (`orchestrator/temporal_workflow.py`).

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
