# Contributing to AegisFlow

## Dev setup
```bash
cd backend && python -m venv .venv && . .venv/Scripts/activate
pip install -e ".[dev]"
pre-commit install
pytest -q
```

## Ground rules
- All new endpoints declare an RBAC `Permission` and are tenant-scoped.
- New connectors implement the relevant `*Connector` ABC **and** ship a mock so the
  suite stays hermetic.
- Never log secrets; never fetch user-supplied URLs without the SSRF guard.
- The copilot must never gain the ability to execute actions.
- CI (lint, types, tests, Semgrep, Trivy, Gitleaks, Checkov) must pass; the
  security workflow fails the build on Critical findings.

## Adding a threat-intel source
1. Implement `ThreatIntelConnector` in `app/engines/threat_intel/connectors/`.
2. Add its host to the SSRF allow-list in `app/core/ssrf.py`.
3. Register it in `build_aggregator()`.
4. Add a unit test (mock the HTTP with `respx`).
