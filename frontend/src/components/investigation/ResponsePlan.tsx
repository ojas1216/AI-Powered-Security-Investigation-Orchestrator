/**
 * Response plan — ranked, atomic response actions with estimated risk reduction,
 * business/operational impact, implementation difficulty and rollback. Disruptive
 * actions require approval (they flow through the approval workflow).
 */
import { ListChecks, Lock } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { ResponseAction, ResponsePlan as Plan } from "@/types/api";

const impactTone: Record<string, "critical" | "high" | "medium" | "low"> = {
  high: "high",
  medium: "medium",
  low: "low",
};

const categoryTone: Record<string, "critical" | "high" | "medium" | "info" | "neutral"> = {
  network: "info",
  endpoint: "high",
  identity: "medium",
  email: "info",
  escalation: "neutral",
};

export function ResponsePlan({ plan }: { plan: Plan }) {
  if (!plan.actions.length) return null;
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-sm">
          <ListChecks className="h-4 w-4 text-accent" />
          Recommended Response — {plan.actions.length} action(s)
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-2 pt-0">
        {plan.actions.map((a, i) => (
          <Row key={i} a={a} />
        ))}
      </CardContent>
    </Card>
  );
}

function Row({ a }: { a: ResponseAction }) {
  return (
    <div className="rounded-md border border-border p-2.5">
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone={categoryTone[a.category] ?? "neutral"}>{a.category}</Badge>
        <span className="text-sm font-medium text-fg">{a.action}</span>
        {a.requires_approval && (
          <span className="inline-flex items-center gap-1 text-xs text-medium">
            <Lock className="h-3 w-3" /> needs approval
          </span>
        )}
      </div>
      <div className="mt-1.5 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-fg-subtle">
        <span>
          risk ↓{" "}
          <span className="font-medium text-low">
            {Math.round(a.risk_reduction * 100)}%
          </span>
        </span>
        <span>
          business impact <Badge tone={impactTone[a.business_impact] ?? "low"}>{a.business_impact}</Badge>
        </span>
        <span>ops {a.operational_impact}</span>
        <span>difficulty {a.difficulty}</span>
      </div>
      {a.rollback && (
        <p className="mt-1 text-xs text-fg-subtle">Rollback: {a.rollback}</p>
      )}
    </div>
  );
}
