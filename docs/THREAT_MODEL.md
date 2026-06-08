# AegisFlow Threat Model (STRIDE summary)

Scope: the SaaS/MSSP deployment, internet-exposed API gateway, multi-tenant.

| Threat (STRIDE)        | Vector                                    | Control                                                   |
| ---------------------- | ----------------------------------------- | --------------------------------------------------------- |
| Spoofing               | Forged tokens, tenant impersonation       | OIDC RS256 + JWKS validation; tenant from signed claim    |
| Tampering              | IOC/evidence mutation                     | Immutable evidence (content hash), audit log, RLS         |
| Repudiation            | "I didn't run that containment"           | Signed playbook + approval, full audit trail              |
| Information disclosure | Cross-tenant data leak (IDOR)             | Postgres RLS + ABAC tenant gate on every object           |
| DoS                    | Alert-flood / enrichment amplification    | Kafka buffer, per-tenant rate limits, enrichment cache    |
| Elevation of privilege | Analyst → admin, SSRF → internal          | RBAC least-privilege, SSRF allow-list, network policies   |

## Highest-risk flows
1. **Server-side enrichment of attacker-controlled IOCs** → SSRF / pivot into internal
   network. Mitigated by `core/ssrf.py` (block RFC1918/link-local/metadata IPs, scheme +
   host allow-list) and egress-only network policy.
2. **LLM over attacker-authored email content** → prompt injection to exfiltrate other
   tenants' context or emit malicious recommendations. Mitigated by guard layer, data/instruction
   separation, tenant-scoped RAG, no tool execution, output schema validation.
3. **Multi-tenant data plane** → IDOR. Defense in depth: ABAC + RLS + tenant-prefixed cache
   + Neo4j label gating.

## Trust boundaries
- Internet ↔ API gateway (WAF, rate limit, mTLS upstream)
- API ↔ connectors (egress allow-list, scoped credentials per tenant)
- API ↔ LLM (treated as untrusted compute; outputs validated)
- Tenant ↔ Tenant (RLS, ABAC — assumed always hostile to each other)
