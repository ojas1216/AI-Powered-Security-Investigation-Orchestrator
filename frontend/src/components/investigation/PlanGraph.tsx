/**
 * Execution graph — the dependency-aware task plan the scheduler ran, with each
 * task's status, priority, retries, dependencies and outcome. Only present when
 * the investigation used the taskgraph strategy.
 */
import { CheckCircle2, Circle, RefreshCw, XCircle } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { EmptyState } from "@/components/common/states";
import type { PlanNode } from "@/types/api";

const statusTone: Record<PlanNode["status"], "low" | "critical" | "medium" | "neutral"> = {
  done: "low",
  failed: "critical",
  running: "medium",
  pending: "neutral",
  skipped: "neutral",
};

function StatusIcon({ status }: { status: PlanNode["status"] }) {
  if (status === "done") return <CheckCircle2 className="h-4 w-4 text-low" />;
  if (status === "failed") return <XCircle className="h-4 w-4 text-critical" />;
  if (status === "running") return <RefreshCw className="h-4 w-4 animate-spin text-medium" />;
  return <Circle className="h-4 w-4 text-fg-subtle" />;
}

export function PlanGraph({ nodes }: { nodes: PlanNode[] }) {
  if (!nodes.length) {
    return (
      <EmptyState
        title="No execution graph"
        description="This investigation used the batch strategy (no task graph). Enable AEGIS_INVESTIGATION_STRATEGY=taskgraph to record one."
      />
    );
  }
  const done = nodes.filter((n) => n.status === "done").length;
  return (
    <div>
      <div className="mb-3 flex items-center gap-2 text-sm text-fg-subtle">
        <span>
          {done}/{nodes.length} tasks complete
        </span>
        <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-[#172033]">
          <div
            className="h-full bg-accent"
            style={{ width: `${nodes.length ? (done / nodes.length) * 100 : 0}%` }}
          />
        </div>
      </div>
      <ol className="space-y-2">
        {nodes.map((n) => (
          <li key={n.id} className="rounded-md border border-border p-2.5">
            <div className="flex flex-wrap items-center gap-2">
              <StatusIcon status={n.status} />
              <span className="font-mono text-xs text-fg-subtle">{n.id}</span>
              <span className="text-sm font-medium text-fg">{n.tool}</span>
              <Badge tone={statusTone[n.status]}>{n.status}</Badge>
              <span className="text-xs text-fg-subtle">prio {n.priority}</span>
              {n.attempts > 1 && (
                <span className="text-xs text-medium">{n.attempts} attempts</span>
              )}
              {n.duration_ms > 0 && (
                <span className="text-xs text-fg-subtle">{n.duration_ms.toFixed(0)} ms</span>
              )}
              {n.depends_on.length > 0 && (
                <span className="text-xs text-fg-subtle">
                  ⇠ {n.depends_on.join(", ")}
                </span>
              )}
            </div>
            {n.reason && <p className="mt-1 pl-6 text-xs text-fg-subtle">{n.reason}</p>}
            {n.outcome && (
              <p className={`mt-1 pl-6 text-xs ${n.ok ? "text-fg" : "text-critical"}`}>
                → {n.outcome}
              </p>
            )}
          </li>
        ))}
      </ol>
    </div>
  );
}
