from fastapi import APIRouter

from app.api.v1.routes import (
    alerts,
    copilot,
    detections,
    health,
    hunts,
    investigations,
    iocs,
)

api_router = APIRouter()
api_router.include_router(health.router, tags=["health"])
api_router.include_router(alerts.router, prefix="/alerts", tags=["alerts"])
api_router.include_router(
    investigations.router, prefix="/investigations", tags=["investigations"]
)
api_router.include_router(iocs.router, prefix="/iocs", tags=["iocs"])
api_router.include_router(copilot.router, prefix="/copilot", tags=["copilot"])
api_router.include_router(detections.router, prefix="/detections", tags=["detections"])
api_router.include_router(hunts.router, prefix="/hunts", tags=["hunts"])
