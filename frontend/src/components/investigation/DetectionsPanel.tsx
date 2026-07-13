/** Detection rules that fired on the originating alert, with match evidence. */
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState } from "@/components/common/states";
import { SeverityBadge } from "@/components/common/badges";
import type { DetectionMatch } from "@/types/api";

export function DetectionsPanel({ detections }: { detections: DetectionMatch[] }) {
  if (!detections.length) {
    return <EmptyState title="No detection rules fired" description="The alert did not match any built-in or custom rule." />;
  }
  return (
    <div className="space-y-3">
      {detections.map((d) => (
        <Card key={d.rule_id}>
          <CardHeader className="flex flex-row items-center justify-between gap-2 pb-2">
            <CardTitle className="text-sm">
              <span className="mr-2 font-mono text-xs text-fg-subtle">{d.rule_id}</span>
              {d.title}
            </CardTitle>
            <SeverityBadge severity={d.severity} />
          </CardHeader>
          <CardContent className="space-y-2 pt-0">
            {d.techniques.length > 0 && (
              <div className="flex flex-wrap gap-1.5">
                {d.techniques.map((t) => (
                  <Badge key={t.technique_id} tone="medium">
                    {t.technique_id} · {t.name}
                  </Badge>
                ))}
              </div>
            )}
            {Object.entries(d.matched_fields).length > 0 && (
              <div className="rounded-md border border-border bg-[#0d1526] p-2">
                {Object.entries(d.matched_fields).map(([field, excerpt]) => (
                  <p key={field} className="break-all font-mono text-xs text-fg-subtle">
                    <span className="text-info">{field}</span>: {excerpt}
                  </p>
                ))}
              </div>
            )}
            {d.tags.length > 0 && (
              <div className="flex flex-wrap gap-1">
                {d.tags.map((tag) => (
                  <Badge key={tag}>{tag}</Badge>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      ))}
    </div>
  );
}
