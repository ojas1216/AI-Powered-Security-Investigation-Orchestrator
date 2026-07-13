/** Prior investigations recalled from the agent's long-term memory. */
import { Link } from "react-router-dom";
import { History } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { VerdictBadge } from "@/components/common/badges";
import type { RelatedCase } from "@/types/api";

export function RelatedCases({ cases }: { cases: RelatedCase[] }) {
  if (!cases.length) return null;
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-sm">
          <History className="h-4 w-4 text-info" />
          Seen before — {cases.length} related past investigation{cases.length > 1 ? "s" : ""}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-2 pt-0">
        {cases.map((c) => (
          <div
            key={c.investigation_id}
            className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-border p-2"
          >
            <div className="min-w-0">
              <Link
                to={`/investigations/${c.investigation_id}`}
                className="text-sm font-medium text-fg hover:text-info hover:underline"
              >
                {c.title}
              </Link>
              <p className="mt-0.5 break-all font-mono text-xs text-fg-subtle">
                shared: {c.shared_iocs.join(", ")}
                {c.shared_techniques.length > 0 && ` · ${c.shared_techniques.join(", ")}`}
              </p>
            </div>
            <div className="flex items-center gap-2">
              <Badge tone="info">{Math.round(c.similarity * 100)}% match</Badge>
              <VerdictBadge verdict={c.verdict} />
            </div>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}
