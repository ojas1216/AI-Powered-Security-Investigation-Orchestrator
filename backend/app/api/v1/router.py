from fastapi import APIRouter

from app.api.v1.routes import alerts, copilot, health, investigations, iocs

api_router = APIRouter()
api_router.include_router(health.router, tags=["health"])
api_router.include_router(alerts.router, prefix="/alerts", tags=["alerts"])
api_router.include_router(
    investigations.router, prefix="/investigations", tags=["investigations"]
)
api_router.include_router(iocs.router, prefix="/iocs", tags=["iocs"])
api_router.include_router(copilot.router, prefix="/copilot", tags=["copilot"])
