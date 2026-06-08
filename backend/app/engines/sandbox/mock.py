"""Deterministic mock sandbox so the pipeline produces a real detonation report
offline. Filenames hinting at malware yield a high malscore + persistence."""
from __future__ import annotations

import hashlib

from app.core.config import settings
from app.engines.sandbox.base import ProcessNode, SandboxConnector, SandboxReport
from app.schemas.common import IOCType
from app.schemas.ioc import IOC

_BAD_HINTS = ("invoice", "payment", ".lnk", ".scr", ".hta", "macro", "enable")


class MockSandbox(SandboxConnector):
    name = "mock-sandbox"

    async def detonate(self, *, filename: str, content: bytes | None = None,
                       url: str | None = None) -> SandboxReport:
        sample = filename or url or "sample"
        digest = hashlib.sha256(sample.lower().encode()).hexdigest()
        looks_bad = any(h in sample.lower() for h in _BAD_HINTS)
        malscore = 0.92 if looks_bad else 0.2

        if not looks_bad:
            return SandboxReport(sample_ref=digest, malscore=malscore, verdict="benign")

        tree = ProcessNode(
            pid=1000, name="winword.exe", cmdline=f"winword.exe {filename}",
            children=[
                ProcessNode(pid=1040, name="powershell.exe",
                            cmdline="powershell.exe -enc aQB3AHIA...",
                            children=[
                                ProcessNode(pid=1080, name="rundll32.exe",
                                            cmdline="rundll32.exe payload.dll,Start"),
                            ]),
            ],
        )
        return SandboxReport(
            sample_ref=digest,
            malscore=malscore,
            verdict="malicious",
            signatures=[
                "Spawns PowerShell with encoded command",
                "Creates Run key for persistence",
                "Beacons to external host over HTTPS",
            ],
            dropped_iocs=[
                IOC(type=IOCType.DOMAIN, value="malware-c2.net", context="sandbox-c2"),
                IOC(type=IOCType.SHA256,
                    value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    context="dropped-payload"),
            ],
            process_tree=tree,
            persistence=["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater"],
            registry_changes=["HKCU\\...\\Run\\Updater = %APPDATA%\\updater.exe"],
        )


def build_sandbox() -> SandboxConnector:
    if settings.use_mock_connectors:
        return MockSandbox()
    # Live connectors (JoeSandbox/Falcon/CAPE/AnyRun) register here.
    return MockSandbox()
