import { useMemo } from "react";
import {
  Background,
  Controls,
  MiniMap,
  ReactFlow,
  type Edge,
  type Node,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import type { InvestigationPackage } from "@/types/api";

const VERDICT_COLOR: Record<string, string> = {
  malicious: "#ef4444",
  suspicious: "#f97316",
  benign: "#10b981",
  unknown: "#64748b",
};

function nodeStyle(bg: string, border: string) {
  return {
    background: bg,
    color: "#e2e8f0",
    border: `1px solid ${border}`,
    borderRadius: 8,
    fontSize: 11,
    padding: "6px 10px",
    width: 170,
  } as const;
}

/** Builds an entity-relationship graph from one investigation's package:
 *  alert ⇄ IOCs ⇄ affected hosts/users. Pure function of real API data. */
export function AttackGraph({ pkg, height = 560 }: { pkg: InvestigationPackage; height?: number }) {
  const { nodes, edges } = useMemo(() => {
    const nodes: Node[] = [];
    const edges: Edge[] = [];
    const alertId = `alert:${pkg.alert.source_alert_id}`;

    nodes.push({
      id: alertId,
      position: { x: 0, y: 0 },
      data: { label: `🚨 ${pkg.alert.title.slice(0, 40)}` },
      style: nodeStyle("#1e1b4b", "#6366f1"),
    });

    const iocs = pkg.iocs.slice(0, 14);
    iocs.forEach((e, i) => {
      const id = `ioc:${e.ioc.type}:${e.ioc.value}`;
      const angle = (i / Math.max(iocs.length, 1)) * Math.PI - Math.PI / 2;
      nodes.push({
        id,
        position: { x: 380, y: i * 70 - iocs.length * 35 },
        data: { label: `${e.ioc.type}\n${e.ioc.value.slice(0, 22)}` },
        style: nodeStyle("#111827", VERDICT_COLOR[e.verdict]),
      });
      edges.push({ id: `${alertId}-${id}`, source: alertId, target: id, animated: e.verdict === "malicious" });
      void angle;
    });

    pkg.affected_hosts.forEach((h, i) => {
      const id = `host:${h}`;
      nodes.push({
        id,
        position: { x: 760, y: i * 70 },
        data: { label: `🖥️ ${h}` },
        style: nodeStyle("#0f1626", "#3b82f6"),
      });
      const firstMal = iocs.find((e) => e.verdict === "malicious");
      if (firstMal) {
        edges.push({
          id: `host-${id}`,
          source: `ioc:${firstMal.ioc.type}:${firstMal.ioc.value}`,
          target: id,
          label: "observed on",
        });
      }
    });

    pkg.affected_users.forEach((u, i) => {
      const id = `user:${u}`;
      nodes.push({
        id,
        position: { x: 760, y: pkg.affected_hosts.length * 70 + i * 60 + 40 },
        data: { label: `👤 ${u}` },
        style: nodeStyle("#0f1626", "#f59e0b"),
      });
      edges.push({ id: `user-${id}`, source: alertId, target: id, label: "recipient" });
    });

    return { nodes, edges };
  }, [pkg]);

  return (
    <div style={{ height }} className="overflow-hidden rounded-lg border border-border">
      <ReactFlow nodes={nodes} edges={edges} fitView minZoom={0.2} proOptions={{ hideAttribution: true }}>
        <Background color="#1f2937" gap={20} />
        <Controls className="!border-border" />
        <MiniMap
          pannable
          zoomable
          nodeColor="#1f2937"
          maskColor="rgba(11,16,32,0.7)"
          style={{ background: "#0f1626", border: "1px solid #1f2937" }}
        />
      </ReactFlow>
    </div>
  );
}
