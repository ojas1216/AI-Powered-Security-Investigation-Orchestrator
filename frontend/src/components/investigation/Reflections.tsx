/**
 * Self-review — residual gaps, unverified conclusions and source contradictions
 * the reflection loop surfaced after all collection. This is what an analyst
 * should still scrutinize; an empty list means the investigation self-reviewed
 * clean.
 */
import { AlertTriangle, GitCompareArrows, HelpCircle, SearchX } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { ReflectionFinding } from "@/types/api";

const meta: Record<string, { tone: "critical" | "high" | "medium" | "neutral"; icon: typeof AlertTriangle }> = {
  contradiction: { tone: "critical", icon: GitCompareArrows },
  unverified: { tone: "high", icon: HelpCircle },
  gap: { tone: "medium", icon: SearchX },
  coverage: { tone: "medium", icon: AlertTriangle },
};

export function Reflections({ findings }: { findings: ReflectionFinding[] }) {
  if (!findings.length) return null;
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-sm">
          <HelpCircle className="h-4 w-4 text-high" />
          Self-review — {findings.length} residual finding{findings.length > 1 ? "s" : ""}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-2 pt-0">
        {findings.map((f, i) => {
          const m = meta[f.category] ?? { tone: "neutral" as const, icon: AlertTriangle };
          const Icon = m.icon;
          return (
            <div key={i} className="flex items-start gap-2 rounded-md border border-border p-2">
              <Icon className="mt-0.5 h-4 w-4 shrink-0 text-fg-subtle" />
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <Badge tone={m.tone}>{f.category}</Badge>
                  {f.action_recommended && (
                    <span className="text-xs text-fg-subtle">
                      recommended: {f.action_recommended}
                    </span>
                  )}
                </div>
                <p className="mt-1 text-xs text-fg-subtle">{f.detail}</p>
              </div>
            </div>
          );
        })}
      </CardContent>
    </Card>
  );
}
