from fastapi import APIRouter

from app.api.v1.routes import (
    agents,
    alerts,
    approvals,
    auth,
    campaigns,
    copilot,
    detections,
    fingerprints,
    graph,
    health,
    hunts,
    investigations,
    iocs,
    offline,
    search,
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
api_router.include_router(search.router, prefix="/search", tags=["search"])
api_router.include_router(offline.router, prefix="/offline", tags=["offline"])
api_router.include_router(fingerprints.router, prefix="/fingerprints",
                          tags=["fingerprints"])
api_router.include_router(campaigns.router, prefix="/campaigns", tags=["campaigns"])
