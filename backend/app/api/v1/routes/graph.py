"""Knowledge-graph query API.

Pivot the tenant-isolated entity graph the investigation loop builds: expand a
node's neighborhood (Attack-Graph view), detect campaigns (alerts + entities
that reuse an indicator), and reconstruct attack paths between two entities.
All reads are tenant-gated by the graph back end.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.api.deps import require
from app.core.authz import Permission
from app.core.security import Principal
from app.engines.graph import build_graph, node_type
from app.engines.graph.client import GraphResult

router = APIRouter()
_graph = build_graph()


class GraphNode(BaseModel):
    key: str
    type: str


class GraphEdge(BaseModel):
    src: str
    rel: str
    dst: str


class Subgraph(BaseModel):
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)


class CampaignResponse(BaseModel):
    seed: str
    alerts: list[str] = Field(default_factory=list)
    related_entities: list[str] = Field(default_factory=list)
    subgraph: Subgraph


def _to_subgraph(result: GraphResult) -> Subgraph:
    return Subgraph(
        nodes=[GraphNode(key=n, type=node_type(n)) for n in result.nodes],
        edges=[GraphEdge(src=e.src, rel=e.rel, dst=e.dst) for e in result.edges],
    )


@router.get("/neighbors", response_model=Subgraph)
async def neighbors(
    node: str = Query(min_length=1, max_length=2100),
    depth: int = Query(default=1, ge=1, le=6),
    principal: Principal = Depends(require(Permission.INVESTIGATION_READ)),
) -> Subgraph:
    return _to_subgraph(_graph.neighbors(principal.tenant, node, depth=depth))


@router.get("/campaign", response_model=CampaignResponse)
async def campaign(
    node: str = Query(min_length=1, max_length=2100),
    depth: int = Query(default=2, ge=1, le=6),
    principal: Principal = Depends(require(Permission.INVESTIGATION_READ)),
) -> CampaignResponse:
    result = _graph.campaign(principal.tenant, node, depth=depth)
    return CampaignResponse(
        seed=result.seed, alerts=result.alerts,
        related_entities=result.related_entities,
        subgraph=_to_subgraph(result.subgraph),
    )


@router.get("/path", response_model=list[GraphEdge])
async def path(
    src: str = Query(min_length=1, max_length=2100),
    dst: str = Query(min_length=1, max_length=2100),
    max_depth: int = Query(default=6, ge=1, le=6),
    principal: Principal = Depends(require(Permission.INVESTIGATION_READ)),
) -> list[GraphEdge]:
    edges = _graph.path(principal.tenant, src, dst, max_depth=max_depth)
    if not edges:
        raise HTTPException(status_code=404, detail="no path between the entities")
    return [GraphEdge(src=e.src, rel=e.rel, dst=e.dst) for e in edges]
