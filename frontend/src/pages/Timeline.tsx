import { useMemo, useState } from "react";
import { useInvestigations } from "@/hooks/useInvestigations";
import { PageHeader } from "@/components/common/PageHeader";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { TimelineView } from "@/components/investigation/TimelineView";
import { LoadingState, EmptyState } from "@/components/common/states";
import type { TimelineEvent } from "@/types/api";

export function TimelinePage() {
  const { data, isLoading } = useInvestigations();
  const [source, setSource] = useState<string>("all");

  const { events, sources } = useMemo(() => {
    const all: TimelineEvent[] = [];
    const srcSet = new Set<string>();
    for (const inv of data ?? []) {
      for (const ev of inv.timeline) {
        all.push(ev);
        if (ev.source) srcSet.add(ev.source);
      }
    }
    all.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
    return { events: all, sources: ["all", ...srcSet] };
  }, [data]);

  const filtered = source === "all" ? events : events.filter((e) => e.source === source);

  return (
    <div>
      <PageHeader title="Timeline" description="Unified attack chronology across investigations" />
      <div className="mb-4 flex gap-1">
        {sources.map((s) => (
          <Button key={s} size="sm" variant={source === s ? "primary" : "ghost"} onClick={() => setSource(s)}>
            {s}
          </Button>
        ))}
      </div>
      {isLoading ? (
        <LoadingState />
      ) : filtered.length === 0 ? (
        <EmptyState title="No timeline events" />
      ) : (
        <Card>
          <CardContent className="pt-4">
            <TimelineView events={filtered} />
          </CardContent>
        </Card>
      )}
    </div>
  );
}
