"""IOC relationship graph.

In the full stack this writes to Neo4j; every node/edge carries a `tenant`
property and queries are tenant-gated. Offline we use an in-memory graph so the
investigation package still includes a relationship map. Both share one interface.
"""
from __future__ import annotations

import abc
from dataclasses import dataclass, field

from app.core.config import settings
from app.core.logging import get_logger

log = get_logger("graph")


@dataclass
class GraphTriple:
    src: str  # "type:value"
    rel: str
    dst: str


@dataclass
class GraphResult:
    nodes: list[str] = field(default_factory=list)
    edges: list[GraphTriple] = field(default_factory=list)


class GraphClient(abc.ABC):
    @abc.abstractmethod
    def upsert(self, tenant: str, triples: list[GraphTriple]) -> GraphResult: ...


class InMemoryGraph(GraphClient):
    def __init__(self) -> None:
        self._store: dict[str, GraphResult] = {}

    def upsert(self, tenant: str, triples: list[GraphTriple]) -> GraphResult:
        res = self._store.setdefault(tenant, GraphResult())
        nodes = set(res.nodes)
        for t in triples:
            nodes.add(t.src)
            nodes.add(t.dst)
            res.edges.append(t)
        res.nodes = sorted(nodes)
        return res


class Neo4jGraph(GraphClient):  # pragma: no cover - requires live Neo4j
    """Tenant-isolated Neo4j writer. MERGE is idempotent; tenant gates every node."""

    def __init__(self, uri: str, user: str, password: str) -> None:
        from neo4j import GraphDatabase

        self._driver = GraphDatabase.driver(uri, auth=(user, password))

    def upsert(self, tenant: str, triples: list[GraphTriple]) -> GraphResult:
        cypher = (
            "UNWIND $triples AS t "
            "MERGE (a:Entity {key: t.src, tenant: $tenant}) "
            "MERGE (b:Entity {key: t.dst, tenant: $tenant}) "
            "MERGE (a)-[r:REL {type: t.rel, tenant: $tenant}]->(b)"
        )
        with self._driver.session() as session:
            session.run(
                cypher,
                tenant=tenant,
                triples=[{"src": t.src, "dst": t.dst, "rel": t.rel} for t in triples],
            )
        nodes = sorted({t.src for t in triples} | {t.dst for t in triples})
        return GraphResult(nodes=nodes, edges=triples)


def build_graph() -> GraphClient:
    if settings.use_mock_connectors:
        return InMemoryGraph()
    try:
        return Neo4jGraph(settings.neo4j_uri, settings.neo4j_user, settings.neo4j_password)
    except Exception as exc:  # pragma: no cover
        log.warning("neo4j_unavailable_fallback_memory", error=str(exc))
        return InMemoryGraph()
