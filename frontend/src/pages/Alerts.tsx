import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Loader2, Plus, Search } from "lucide-react";
import { useInvestigations, useIngestAlert } from "@/hooks/useInvestigations";
import { useAuthStore } from "@/stores/auth";
import { SAMPLE_ALERTS } from "@/lib/sampleAlerts";
import { PageHeader } from "@/components/common/PageHeader";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { SeverityBadge, VerdictBadge } from "@/components/common/badges";
import { LoadingState, ErrorState, EmptyState } from "@/components/common/states";

export function AlertsPage() {
  const navigate = useNavigate();
  const { data, isLoading, isError, refetch } = useInvestigations();
  const ingest = useIngestAlert();
  const canIngest = useAuthStore((s) => s.can("alert:ingest"));
  const [q, setQ] = useState("");

  const rows = useMemo(() => {
    const list = (data ?? []).map((inv) => ({ inv, a: inv.alert }));
    const term = q.trim().toLowerCase();
    return term
      ? list.filter(
          ({ a }) =>
            a.title.toLowerCase().includes(term) ||
            a.source.includes(term) ||
            a.source_alert_id.toLowerCase().includes(term),
        )
      : list;
  }, [data, q]);

  return (
    <div>
      <PageHeader
        title="Alerts"
        description="Inbound detections normalized into the common schema"
        actions={
          canIngest &&
          SAMPLE_ALERTS.map((s) => (
            <Button
              key={s.id}
              variant="secondary"
              size="sm"
              disabled={ingest.isPending}
              onClick={() =>
                ingest.mutate(s.payload, {
                  onSuccess: (pkg) => navigate(`/investigations/${pkg.investigation_id}`),
                })
              }
            >
              {ingest.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />}
              {s.label}
            </Button>
          ))
        }
      />

      <div className="mb-4 flex items-center gap-2">
        <div className="relative max-w-sm flex-1">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
          <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Filter alerts…" className="pl-9" />
        </div>
      </div>

      {isLoading ? (
        <LoadingState />
      ) : isError ? (
        <ErrorState message="Failed to load alerts." onRetry={refetch} />
      ) : rows.length === 0 ? (
        <EmptyState
          title="No alerts"
          description={canIngest ? "Ingest a sample alert above to exercise the pipeline." : "No alerts match your filter."}
        />
      ) : (
        <Card className="overflow-hidden">
          <table className="w-full text-sm">
            <thead className="border-b border-border text-left text-xs uppercase text-fg-subtle">
              <tr>
                <th className="px-4 py-2.5 font-medium">Alert</th>
                <th className="px-4 py-2.5 font-medium">Source</th>
                <th className="px-4 py-2.5 font-medium">Severity</th>
                <th className="px-4 py-2.5 font-medium">Verdict</th>
                <th className="px-4 py-2.5 font-medium">Entities</th>
                <th className="px-4 py-2.5 font-medium">Time</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {rows.map(({ inv, a }) => (
                <tr
                  key={inv.investigation_id}
                  onClick={() => navigate(`/investigations/${inv.investigation_id}`)}
                  className="cursor-pointer hover:bg-[#141d31]"
                >
                  <td className="max-w-xs px-4 py-3">
                    <div className="truncate font-medium text-fg">{a.title}</div>
                    <div className="font-mono text-xs text-muted">{a.source_alert_id}</div>
                  </td>
                  <td className="px-4 py-3 text-fg-subtle">{a.source}</td>
                  <td className="px-4 py-3"><SeverityBadge severity={a.severity} /></td>
                  <td className="px-4 py-3"><VerdictBadge verdict={inv.overall_verdict} /></td>
                  <td className="px-4 py-3 text-xs text-fg-subtle">
                    {[...a.hosts, ...a.users].slice(0, 2).join(", ") || "—"}
                  </td>
                  <td className="px-4 py-3 text-xs text-muted">{new Date(a.created_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}
    </div>
  );
}
