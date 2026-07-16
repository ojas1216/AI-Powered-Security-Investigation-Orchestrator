# AegisFlow — AI-Powered Security Investigation Orchestrator

> Turn a single alert, IOC, email, or ticket into a complete investigation package — automatically.

AegisFlow eliminates SOC tool sprawl and analyst swivel-chair. Given one signal, it
investigates across SIEM / EDR / Email / Threat-Intel / Sandbox / Cloud, correlates the
evidence, builds a timeline + IOC graph, scores risk, maps MITRE ATT&CK, drafts the
report, and opens the ticket — driving MTTR from hours to minutes.

This repository is a **production-grade reference implementation**. The core investigation
pipeline (ingestion → IOC extraction → threat-intel correlation → risk scoring → timeline →
report) is fully implemented and unit-tested. External products are integrated behind clean,
swappable connector interfaces that ship with deterministic **mock** implementations, so the
whole platform runs end-to-end with zero third-party API keys, and lights up real data the
moment you drop credentials into Vault / env.

---

## Why this is not a SOAR / workflow tool

| SOAR                                   | AegisFlow                                              |
| -------------------------------------- | ----------------------------------------------------- |
| You build & maintain playbooks         | Investigation is the product; playbooks are *output*  |
| Drag-and-drop boxes, brittle wiring    | Typed engines + durable Temporal workflows            |
| Automates clicks                       | Automates *reasoning* + evidence assembly             |
| Analyst still pivots between tools      | Analyst gets one investigation package                |

---

## Architecture at a glance

```
            ┌─────────────┐   webhook / API / syslog / Kafka
   Alerts ─▶│ Ingestion   │──▶ normalize ─▶ common Alert schema
            └─────────────┘
                   │
                   ▼
          ┌───────────────────────────────────────────────┐
          │           Investigation Orchestrator           │  (Temporal-durable)
          │                                                │
          │  IOC Extraction ─▶ Threat-Intel Correlation ─▶ │
          │  Sandbox ─▶ EDR ─▶ Email ─▶ Evidence ─▶        │
          │  Timeline ─▶ Graph(Neo4j) ─▶ Risk Scoring ─▶   │
          │  MITRE map ─▶ AI Copilot report ─▶ Ticketing   │
          └───────────────────────────────────────────────┘
                   │
                   ▼
       Investigation Package  ──▶  Analyst UI / ServiceNow / Jira
```

Full detail in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Security posture in
[docs/SECURITY.md](docs/SECURITY.md) and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

---

## Tech stack

- **Backend:** Python 3.13, FastAPI, SQLAlchemy 2.x, Pydantic v2, Temporal
- **Frontend:** React, TypeScript, Vite, TailwindCSS
- **Data:** PostgreSQL (RLS multi-tenant), Neo4j (graph), ChromaDB (RAG), Redis (cache/rate-limit)
- **Streaming:** Apache Kafka
- **AuthN/Z:** Keycloak (OIDC / OAuth 2.1), RBAC + ABAC
- **Secrets:** HashiCorp Vault + External Secrets Operator
- **Observability:** OpenTelemetry, Prometheus, Grafana, Loki
- **Infra:** Docker (distroless, non-root), Kubernetes, Terraform
- **DevSecOps:** Semgrep, Trivy, Grype, Gitleaks, Checkov, Syft

---

## One-click launch (Windows)

Double-click **`AegisFlow.exe`** in the project root. It starts the backend + the
SOC console and opens your browser to the UI; on first run it auto-installs any
missing dependencies. Log in with the dev-mode button (tenant `acme`, role
`tier3_analyst`). See [installer/README.md](installer/README.md). Rebuild with
`.\installer\build.ps1`.

## Quickstart (local, no external keys required)

```bash
# 1. Backend
cd backend
python -m venv .venv && . .venv/Scripts/activate   # PowerShell: .venv\Scripts\Activate.ps1
pip install -e ".[dev]"
cp ../.env.example .env
uvicorn app.main:app --reload

# 2. Run a real investigation against the bundled mock connectors
curl -X POST localhost:8000/api/v1/alerts/ingest \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: acme" \
  -d @backend/seed/sample_phishing_alert.json

# 3. Tests
pytest -q
```

Full stack (Postgres, Neo4j, Redis, Kafka, Keycloak, Temporal, observability):

```bash
docker compose up -d
```

---

## What's implemented vs. interface-only

**Fully implemented & tested:** IOC extraction (RFC-aware, defang-aware), threat-intel
verdict aggregation, risk scoring algorithm, alert normalizers (Splunk/Sentinel/Elastic),
timeline builder, MITRE mapping, copilot prompt-injection guards, RBAC/ABAC policy engine,
multi-tenant context + Postgres RLS, the FastAPI surface, and the orchestrator that wires it
all together.

**Connector interfaces with runnable mock implementations** (swap in real creds to go live):
VirusTotal, AbuseIPDB, GreyNoise, OpenCTI, MISP, OTX, Joe/Falcon/CAPE/Any.Run sandboxes,
CrowdStrike/SentinelOne/Defender/Wazuh EDR, M365/Workspace/Mimecast/Proofpoint email,
ServiceNow, Jira, Ollama.

See [docs/STATUS.md](docs/STATUS.md) for the module-by-module matrix.

---

## License

Apache-2.0 — see [LICENSE](LICENSE).
