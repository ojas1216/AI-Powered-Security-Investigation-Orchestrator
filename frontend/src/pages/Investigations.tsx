import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Search } from "lucide-react";
import { useInvestigations } from "@/hooks/useInvestigations";
import { PageHeader } from "@/components/common/PageHeader";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { SeverityBadge, VerdictBadge } from "@/components/common/badges";
import { LoadingState, ErrorState, EmptyState } from "@/components/common/states";
import type { Verdict } from "@/types/api";

const FILTERS: (Verdict | "all")[] = ["all", "malicious", "suspicious", "benign", "unknown"];

export function InvestigationsPage() {
  const navigate = useNavigate();
  const { data, isLoading, isError, refetch } = useInvestigations();
  const [q, setQ] = useState("");
  const [filter, setFilter] = useState<Verdict | "all">("all");

  const rows = useMemo(() => {
    let list = data ?? [];
    if (filter !== "all") list = list.filter((i) => i.overall_verdict === filter);
    const term = q.trim().toLowerCase();
    if (term)
      list = list.filter(
        (i) =>
          i.alert.title.toLowerCase().includes(term) ||
          i.investigation_id.includes(term) ||
          i.iocs.some((e) => e.ioc.value.toLowerCase().includes(term)),
      );
    return list;
  }, [data, q, filter]);

  return (
    <div>
      <PageHeader title="Investigations" description="Automated investigation packages" />

      <div className="mb-4 flex flex-wrap items-center gap-2">
        <div className="relative max-w-sm flex-1">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
          <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search title, id, IOC…" className="pl-9" />
        </div>
        <div className="flex gap-1">
          {FILTERS.map((f) => (
            <Button key={f} size="sm" variant={filter === f ? "primary" : "ghost"} onClick={() => setFilter(f)}>
              {f}
            </Button>
          ))}
        </div>
      </div>

      {isLoading ? (
        <LoadingState />
      ) : isError ? (
        <ErrorState message="Failed to load investigations." onRetry={refetch} />
      ) : rows.length === 0 ? (
        <EmptyState title="No investigations" description="Adjust filters or ingest an alert." />
      ) : (
        <div className="grid gap-3">
          {rows.map((inv) => (
            <Card
              key={inv.investigation_id}
              onClick={() => navigate(`/investigations/${inv.investigation_id}`)}
              className="cursor-pointer p-4 transition-colors hover:border-[#2a3650]"
            >
              <div className="flex flex-wrap items-center gap-3">
                <VerdictBadge verdict={inv.overall_verdict} />
                {inv.risk && <SeverityBadge severity={inv.risk.severity} />}
                <span className="min-w-0 flex-1 truncate font-medium text-fg">{inv.alert.title}</span>
                <span className="text-sm font-semibold text-fg">{inv.risk?.score ?? "—"}</span>
              </div>
              <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-fg-subtle">
                <span className="font-mono">{inv.investigation_id.slice(0, 8)}</span>
                <span>{inv.iocs.length} IOCs</span>
                <span>{inv.mitre.length} techniques</span>
                <span>{inv.affected_hosts.length} hosts</span>
                <span>{new Date(inv.created_at).toLocaleString()}</span>
              </div>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
