/**
 * Explainability trace: every decision the autonomous agent made, in order —
 * what it did, why, what it observed, and how long it took. This is the
 * audit-trail view auditors and senior analysts ask for.
 */
import { Bot, CheckCircle2, Flag, XCircle } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { EmptyState } from "@/components/common/states";
import type { AgentTraceStep } from "@/types/api";

const phaseTone: Record<AgentTraceStep["phase"], "info" | "medium" | "neutral" | "low"> = {
  plan: "medium",
  act: "info",
  observe: "neutral",
  finalize: "low",
};

export function AgentTrace({ steps }: { steps: AgentTraceStep[] }) {
  if (!steps.length) {
    return (
      <EmptyState
        title="No agent trace"
        description="This investigation predates the autonomous agent loop."
      />
    );
  }
  return (
    <ol className="relative ml-3 space-y-4 border-l border-border pl-6">
      {steps.map((s) => (
        <li key={s.step} className="relative">
          <span className="absolute -left-[31px] top-0.5 flex h-5 w-5 items-center justify-center rounded-full border border-border bg-surface">
            {s.phase === "finalize" ? (
              <Flag className="h-3 w-3 text-fg-subtle" />
            ) : s.ok ? (
              <CheckCircle2 className="h-3 w-3 text-low" />
            ) : (
              <XCircle className="h-3 w-3 text-critical" />
            )}
          </span>
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-xs text-fg-subtle">#{s.step}</span>
            <Badge tone={phaseTone[s.phase]}>{s.phase}</Badge>
            <span className="text-sm font-medium text-fg">{s.action}</span>
            {s.iteration > 0 && (
              <span className="text-xs text-fg-subtle">iteration {s.iteration}</span>
            )}
            {s.duration_ms > 0 && (
              <span className="text-xs text-fg-subtle">{s.duration_ms.toFixed(0)} ms</span>
            )}
          </div>
          <p className="mt-1 flex items-start gap-1.5 text-xs text-fg-subtle">
            <Bot className="mt-0.5 h-3 w-3 shrink-0" />
            {s.reason}
          </p>
          {s.outcome && (
            <p
              className={`mt-1 text-xs ${s.ok ? "text-fg" : "text-critical"}`}
            >
              → {s.outcome}
            </p>
          )}
        </li>
      ))}
    </ol>
  );
}
