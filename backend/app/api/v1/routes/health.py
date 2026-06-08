"""Liveness/readiness — unauthenticated, no tenant data."""
from __future__ import annotations

from fastapi import APIRouter

from app import __version__
from app.core.config import settings

router = APIRouter()


@router.get("/healthz")
async def healthz() -> dict:
    return {"status": "ok", "version": __version__}


@router.get("/readyz")
async def readyz() -> dict:
    return {
        "status": "ready",
        "env": settings.env,
        "connector_mode": settings.connector_mode.value,
    }
