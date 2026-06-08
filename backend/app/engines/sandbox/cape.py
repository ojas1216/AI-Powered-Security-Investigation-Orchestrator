"""CAPEv2 sandbox connector (live).

Submits a sample (URL or file bytes) to a self-hosted CAPE instance, polls until the
analysis is reported, then maps the report to our SandboxReport schema (malscore,
signatures, process tree, dropped IOCs, persistence/registry changes).

Self-hosted: base URL + token from trusted config (not routed through the public
SSRF allow-list; CAPE is typically on an internal network). Detonation is long-running
and idempotent per task id, which is why the production path wraps this as a Temporal
activity with a generous timeout.
"""
from __future__ import annotations

import asyncio

import httpx

from app.core.config import settings
from app.core.exceptions import ConnectorError
from app.core.logging import get_logger
from app.engines.sandbox.base import ProcessNode, SandboxConnector, SandboxReport
from app.schemas.common import IOCType
from app.schemas.ioc import IOC

log = get_logger("sandbox.cape")


def _build_tree(node: dict) -> ProcessNode:
    return ProcessNode(
        pid=int(node.get("pid", 0) or 0),
        name=node.get("process_name") or node.get("name") or "unknown",
        cmdline=node.get("command_line") or node.get("environ", {}).get("CommandLine", ""),
        children=[_build_tree(c) for c in node.get("children", [])],
    )


class CAPESandbox(SandboxConnector):
    name = "cape"

    def __init__(self, url: str | None = None, token: str | None = None,
                 poll_interval: float = 5.0, max_polls: int = 60) -> None:
        self._url = (url or settings.cape_url).rstrip("/")
        self._token = token or settings.cape_token
        self._poll_interval = poll_interval
        self._max_polls = max_polls

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Token {self._token}"} if self._token else {}

    async def detonate(self, *, filename: str, content: bytes | None = None,
                       url: str | None = None) -> SandboxReport:
        if not self._url:
            raise ConnectorError("CAPE URL not configured")
        async with httpx.AsyncClient(
            timeout=30.0, verify=settings.internal_tls_verify, headers=self._headers()
        ) as client:
            task_id = await self._submit(client, filename, content, url)
            if task_id is None:
                # Nothing submittable (no bytes/url); return a non-blocking unknown.
                log.warning("cape_nothing_to_submit", filename=filename)
                return SandboxReport(sample_ref=filename, malscore=0.0, verdict="unknown")
            await self._await_report(client, task_id)
            report = await self._fetch_report(client, task_id)
        return self._map_report(filename, report)

    async def _submit(self, client, filename, content, url) -> int | None:
        if url:
            resp = await client.post(f"{self._url}/apiv2/tasks/create/url/", data={"url": url})
        elif content is not None:
            resp = await client.post(
                f"{self._url}/apiv2/tasks/create/file/",
                files={"file": (filename, content)},
            )
        else:
            return None
        resp.raise_for_status()
        data = resp.json().get("data", resp.json())
        ids = data.get("task_ids") or ([data["task_id"]] if "task_id" in data else [])
        if not ids:
            raise ConnectorError("CAPE submission returned no task id")
        return int(ids[0])

    async def _await_report(self, client, task_id: int) -> None:
        for _ in range(self._max_polls):
            resp = await client.get(f"{self._url}/apiv2/tasks/status/{task_id}/")
            resp.raise_for_status()
            status = resp.json().get("data")
            if status in ("reported", "completed"):
                return
            if status in ("failed_analysis", "failed_processing"):
                raise ConnectorError(f"CAPE analysis failed: {status}")
            await asyncio.sleep(self._poll_interval)
        raise ConnectorError("CAPE analysis timed out")

    async def _fetch_report(self, client, task_id: int) -> dict:
        resp = await client.get(f"{self._url}/apiv2/tasks/get/report/{task_id}/")
        resp.raise_for_status()
        body = resp.json()
        # CAPE may wrap the report under varying keys depending on version.
        return body.get("data", body)

    def _map_report(self, filename: str, report: dict) -> SandboxReport:
        malscore_raw = float(report.get("malscore", 0) or 0)
        malscore = max(0.0, min(1.0, malscore_raw / 10.0))  # CAPE malscore is 0-10
        signatures = [
            s.get("description") or s.get("name", "")
            for s in report.get("signatures", [])
        ]
        # Dropped network IOCs.
        dropped: list[IOC] = []
        for dom in report.get("network", {}).get("domains", []):
            value = dom.get("domain") if isinstance(dom, dict) else dom
            if value:
                dropped.append(IOC(type=IOCType.DOMAIN, value=value, context="cape-network"))
        for h in report.get("dropped", []):
            sha = h.get("sha256") if isinstance(h, dict) else None
            if sha:
                dropped.append(IOC(type=IOCType.SHA256, value=sha, context="cape-dropped"))

        roots = report.get("behavior", {}).get("processtree", [])
        tree = _build_tree(roots[0]) if roots else None

        persistence = [
            s for s in signatures if "persist" in s.lower() or "run key" in s.lower()
        ]
        verdict = "malicious" if malscore >= 0.6 else "suspicious" if malscore >= 0.3 else "benign"
        return SandboxReport(
            sample_ref=str(report.get("target", {}).get("file", {}).get("sha256", filename)),
            malscore=round(malscore, 3),
            verdict=verdict,
            signatures=signatures,
            dropped_iocs=dropped,
            process_tree=tree,
            persistence=persistence,
        )
