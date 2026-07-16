# Module Implementation Status

Legend: ✅ implemented & tested · 🔌 interface + runnable mock (swap creds for live) · 🧱 scaffold

| # | Module                          | Status | Notes                                                |
|---|---------------------------------|--------|------------------------------------------------------|
| 1 | Alert Ingestion Engine          | ✅/🔌  | Webhook+API done; Splunk/Sentinel/Elastic normalizers ✅; Kafka/syslog 🔌 |
| 2 | IOC Extraction Engine           | ✅     | Full, RFC + defang aware, unit-tested                |
| 3 | Threat-Intel Correlation        | ✅     | Aggregator + verdict fusion; VT/AbuseIPDB/GreyNoise/OTX/OpenCTI/MISP/DShield/CIRCL/ThreatFox connectors + respx tests ✅ |
| 3a| IOC Dossier Engine              | ✅     | Full TI dossier per IOC (classify→enrich→DNS/WHOIS/hosting→confidence→MITRE→attribution→campaign→relationships→impact); ThreatFox primary source (offline cache + online API); `/intel/dossier`; failure-isolated; tested ✅ |
| 4 | Sandbox Automation              | ✅/🔌  | Base + mock + CAPEv2 live connector (submit/poll/report) + respx tests ✅; Joe/Falcon/Any.Run 🔌 |
| 5 | EDR Investigation               | 🔌     | Base + mock telemetry; CRWD/S1/Defender/Wazuh 🔌     |
| 6 | Email Investigation             | 🔌     | Base + mock; M365/Workspace/Mimecast/Proofpoint 🔌   |
| 7 | Evidence Collection             | ✅     | Immutable, content-hashed store                      |
| 8 | Timeline Engine                 | ✅     | Event fusion + ordering, tested                      |
| 9 | Graph Engine (Neo4j)            | 🔌     | Client + schema; mock in-memory graph for offline    |
| 10| Risk Scoring Engine             | ✅     | Weighted, explainable, unit-tested                   |
| 11| Ticket Automation               | 🔌     | ServiceNow + Jira interfaces + mock                  |
| 12| AI SOC Copilot                  | ✅/🔌  | Guards + prompts ✅; Ollama client 🔌                |
| 13| Playbook Recommendation         | ✅     | MITRE-driven rule engine                             |
| 14| Multi-Tenant Architecture       | ✅     | TenantContext + Postgres RLS (verified) + ABAC       |

Auth (OIDC/JWT via Keycloak, verified end-to-end) ✅ · RBAC+ABAC ✅ · Config/logging/OTel ✅ · CI/CD security ✅ · Docker/K8s/TF 🧱→🔌

See [AUTH.md](AUTH.md) for the Keycloak realm, demo users, and the verified auth matrix.

**Full `docker compose up` verified end-to-end** (distroless API + Keycloak + Postgres):
real OIDC token → ingest → persisted to Postgres; ABAC denies a tier3 analyst on a
crown-jewel (FIN-host) investigation (403) while soc_manager is allowed (200); a raw
unfiltered count as the non-superuser app role shows the acme rows and 0 for globex.
Datastores are internal-only by default and published ports are overridable
(`AEGIS_API_PORT`, `AEGIS_KEYCLOAK_PORT`, `AEGIS_WEB_PORT`) to avoid host clashes.

**Persistence:** `AEGIS_PERSISTENCE=memory` (default, self-contained) or `postgres`
(SQLAlchemy + Row-Level Security). RLS tenant isolation is verified at the database
layer by `tests/integration/test_rls.py` and reproducible via `docker compose up`
(the `migrate` service applies the schema; the API connects as the non-superuser
`aegis_app` role so RLS is enforced).
