"""IOC / entity relationship graph — write + query.

In the full stack this is Neo4j; every node/edge carries a `tenant` property and
every query is tenant-gated. Offline we use an in-memory graph so the whole
platform (and its tests) run without Neo4j. Both back ends implement one
interface: `upsert` plus three analytic queries used for pivoting and
attack-path reconstruction —

- `neighbors(node, depth)`  → the subgraph within N hops (Attack-Graph view)
- `campaign(node)`          → alerts sharing this entity + everything they touch
                              (campaign / infrastructure-reuse detection)
- `path(src, dst)`          → a shortest relationship path (attack-path recon)

Adjacency is treated as **undirected** for traversal: an analyst pivoting from an
IOC to the hosts/alerts it appears on does not care about edge direction.
"""
from __future__ import annotations

import abc
from collections import deque
from dataclasses import dataclass, field

from app.core.config import settings
from app.core.logging import get_logger

log = get_logger("graph")

_MAX_DEPTH = 6  # hard cap so a pathological query can't traverse the whole graph


@dataclass(frozen=True)
class GraphTriple:
    src: str  # "type:value"
    rel: str
    dst: str


@dataclass
class GraphResult:
    nodes: list[str] = field(default_factory=list)
    edges: list[GraphTriple] = field(default_factory=list)


@dataclass
class CampaignResult:
    """Entities and alerts that co-occur with a seed indicator."""

    seed: str
    alerts: list[str] = field(default_factory=list)
    related_entities: list[str] = field(default_factory=list)
    subgraph: GraphResult = field(default_factory=GraphResult)


def node_type(key: str) -> str:
    """The type prefix of a node key ('domain:evil.com' -> 'domain')."""
    return key.split(":", 1)[0] if ":" in key else "entity"


class GraphClient(abc.ABC):
    @abc.abstractmethod
    def upsert(self, tenant: str, triples: list[GraphTriple]) -> GraphResult: ...

    @abc.abstractmethod
    def neighbors(self, tenant: str, node: str, depth: int = 1) -> GraphResult: ...

    @abc.abstractmethod
    def path(self, tenant: str, src: str, dst: str,
             max_depth: int = _MAX_DEPTH) -> list[GraphTriple]: ...

    @abc.abstractmethod
    def campaign(self, tenant: str, node: str, depth: int = 2) -> CampaignResult: ...


def _clamp_depth(depth: int) -> int:
    return max(1, min(int(depth), _MAX_DEPTH))


class InMemoryGraph(GraphClient):
    def __init__(self) -> None:
        self._store: dict[str, GraphResult] = {}

    def upsert(self, tenant: str, triples: list[GraphTriple]) -> GraphResult:
        res = self._store.setdefault(tenant, GraphResult())
        nodes = set(res.nodes)
        existing = set(res.edges)
        for t in triples:
            nodes.add(t.src)
            nodes.add(t.dst)
            if t not in existing:  # idempotent, mirrors Neo4j MERGE
                res.edges.append(t)
                existing.add(t)
        res.nodes = sorted(nodes)
        return res

    # -- traversal helpers ---------------------------------------------------

    def _adjacency(self, tenant: str) -> dict[str, list[GraphTriple]]:
        adj: dict[str, list[GraphTriple]] = {}
        for t in self._store.get(tenant, GraphResult()).edges:
            adj.setdefault(t.src, []).append(t)
            adj.setdefault(t.dst, []).append(t)  # undirected
        return adj

    def neighbors(self, tenant: str, node: str, depth: int = 1) -> GraphResult:
        depth = _clamp_depth(depth)
        adj = self._adjacency(tenant)
        if node not in adj:
            return GraphResult()
        seen_nodes = {node}
        seen_edges: set[GraphTriple] = set()
        frontier = {node}
        for _ in range(depth):
            nxt: set[str] = set()
            for n in frontier:
                for edge in adj.get(n, []):
                    seen_edges.add(edge)
                    for end in (edge.src, edge.dst):
                        if end not in seen_nodes:
                            seen_nodes.add(end)
                            nxt.add(end)
            frontier = nxt
            if not frontier:
                break
        return GraphResult(nodes=sorted(seen_nodes),
                           edges=sorted(seen_edges, key=lambda e: (e.src, e.dst, e.rel)))

    def path(self, tenant: str, src: str, dst: str,
             max_depth: int = _MAX_DEPTH) -> list[GraphTriple]:
        max_depth = _clamp_depth(max_depth)
        adj = self._adjacency(tenant)
        if src not in adj or dst not in adj:
            return []
        # BFS shortest path, tracking the edge used to reach each node.
        prev: dict[str, tuple[str, GraphTriple]] = {}
        visited = {src}
        queue: deque[tuple[str, int]] = deque([(src, 0)])
        while queue:
            cur, d = queue.popleft()
            if cur == dst:
                return _reconstruct(prev, src, dst)
            if d >= max_depth:
                continue
            for edge in adj.get(cur, []):
                other = edge.dst if edge.src == cur else edge.src
                if other not in visited:
                    visited.add(other)
                    prev[other] = (cur, edge)
                    queue.append((other, d + 1))
        return []

    def campaign(self, tenant: str, node: str, depth: int = 2) -> CampaignResult:
        sub = self.neighbors(tenant, node, depth=depth)
        alerts = sorted(n for n in sub.nodes if node_type(n) == "alert")
        related = sorted(
            n for n in sub.nodes if n != node and node_type(n) != "alert")
        return CampaignResult(seed=node, alerts=alerts,
                              related_entities=related, subgraph=sub)


def _reconstruct(prev: dict[str, tuple[str, GraphTriple]], src: str,
                 dst: str) -> list[GraphTriple]:
    edges: list[GraphTriple] = []
    cur = dst
    while cur != src:
        parent, edge = prev[cur]
        edges.append(edge)
        cur = parent
    edges.reverse()
    return edges


class Neo4jGraph(GraphClient):  # pragma: no cover - requires live Neo4j
    """Tenant-isolated Neo4j back end. MERGE is idempotent; tenant gates every node."""

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
                cypher, tenant=tenant,
                triples=[{"src": t.src, "dst": t.dst, "rel": t.rel} for t in triples])
        nodes = sorted({t.src for t in triples} | {t.dst for t in triples})
        return GraphResult(nodes=nodes, edges=triples)

    def neighbors(self, tenant: str, node: str, depth: int = 1) -> GraphResult:
        depth = _clamp_depth(depth)
        cypher = (
            f"MATCH p=(a:Entity {{key:$node, tenant:$tenant}})-[*1..{depth}]-"
            "(b:Entity {tenant:$tenant}) "
            "UNWIND relationships(p) AS r "
            "RETURN startNode(r).key AS src, r.type AS rel, endNode(r).key AS dst"
        )
        return self._collect(cypher, tenant=tenant, node=node)

    def path(self, tenant: str, src: str, dst: str,
             max_depth: int = _MAX_DEPTH) -> list[GraphTriple]:
        max_depth = _clamp_depth(max_depth)
        cypher = (
            "MATCH p=shortestPath("
            "(a:Entity {key:$src, tenant:$tenant})-"
            f"[*..{max_depth}]-(b:Entity {{key:$dst, tenant:$tenant}})) "
            "UNWIND relationships(p) AS r "
            "RETURN startNode(r).key AS src, r.type AS rel, endNode(r).key AS dst"
        )
        with self._driver.session() as session:
            rows = session.run(cypher, tenant=tenant, src=src, dst=dst)
            return [GraphTriple(r["src"], r["rel"], r["dst"]) for r in rows]

    def campaign(self, tenant: str, node: str, depth: int = 2) -> CampaignResult:
        sub = self.neighbors(tenant, node, depth=depth)
        alerts = sorted(n for n in sub.nodes if node_type(n) == "alert")
        related = sorted(n for n in sub.nodes if n != node and node_type(n) != "alert")
        return CampaignResult(seed=node, alerts=alerts,
                              related_entities=related, subgraph=sub)

    def _collect(self, cypher: str, **params) -> GraphResult:
        edges: set[GraphTriple] = set()
        nodes: set[str] = set()
        with self._driver.session() as session:
            for r in session.run(cypher, **params):
                edges.add(GraphTriple(r["src"], r["rel"], r["dst"]))
                nodes.update((r["src"], r["dst"]))
        return GraphResult(nodes=sorted(nodes),
                           edges=sorted(edges, key=lambda e: (e.src, e.dst, e.rel)))


_graph: GraphClient | None = None


def build_graph() -> GraphClient:
    """Process-wide graph singleton so the loop's writes and API reads share one
    store (essential for the in-memory back end)."""
    global _graph
    if _graph is not None:
        return _graph
    if settings.use_mock_connectors:
        _graph = InMemoryGraph()
    else:
        try:
            _graph = Neo4jGraph(settings.neo4j_uri, settings.neo4j_user,
                                settings.neo4j_password)
        except Exception as exc:  # pragma: no cover
            log.warning("neo4j_unavailable_fallback_memory", error=str(exc))
            _graph = InMemoryGraph()
    return _graph
