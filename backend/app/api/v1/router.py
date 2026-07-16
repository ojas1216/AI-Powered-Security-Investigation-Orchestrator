from fastapi import APIRouter

from app.api.v1.routes import (
    agents,
    alerts,
    approvals,
    auth,
    copilot,
    detections,
    graph,
    health,
    hunts,
    investigations,
    iocs,
)

api_router = APIRouter()
api_router.include_router(health.router, tags=["health"])
api_router.include_router(auth.router, prefix="/auth", tags=["auth"])
api_router.include_router(alerts.router, prefix="/alerts", tags=["alerts"])
api_router.include_router(
    investigations.router, prefix="/investigations", tags=["investigations"]
)
api_router.include_router(iocs.router, prefix="/iocs", tags=["iocs"])
api_router.include_router(copilot.router, prefix="/copilot", tags=["copilot"])
api_router.include_router(detections.router, prefix="/detections", tags=["detections"])
api_router.include_router(hunts.router, prefix="/hunts", tags=["hunts"])
api_router.include_router(approvals.router, prefix="/approvals", tags=["approvals"])
api_router.include_router(agents.router, prefix="/agents", tags=["agents"])
api_router.include_router(graph.router, prefix="/graph", tags=["graph"])
