import { FileJson, FileText, Printer } from "lucide-react";
import { useInvestigations } from "@/hooks/useInvestigations";
import { exportHtml, exportJson, exportPdf } from "@/lib/export";
import { PageHeader } from "@/components/common/PageHeader";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { VerdictBadge } from "@/components/common/badges";
import { LoadingState, EmptyState } from "@/components/common/states";

export function ReportsPage() {
  const { data, isLoading } = useInvestigations();

  return (
    <div>
      <PageHeader
        title="Reports"
        description="Executive, technical, and machine-readable exports per investigation"
      />
      {isLoading ? (
        <LoadingState />
      ) : (data ?? []).length === 0 ? (
        <EmptyState title="No reports" description="Reports are generated from completed investigations." />
      ) : (
        <div className="grid gap-3">
          {(data ?? []).map((inv) => (
            <Card key={inv.investigation_id} className="flex flex-wrap items-center gap-3 p-4">
              <VerdictBadge verdict={inv.overall_verdict} />
              <div className="min-w-0 flex-1">
                <div className="truncate text-sm font-medium text-fg">{inv.alert.title}</div>
                <div className="text-xs text-muted">
                  {inv.investigation_id.slice(0, 8)} · risk {inv.risk?.score ?? "—"} · {inv.iocs.length} IOCs
                </div>
              </div>
              <div className="flex gap-2">
                <Button variant="secondary" size="sm" onClick={() => exportPdf(inv)}>
                  <Printer className="h-4 w-4" /> PDF
                </Button>
                <Button variant="secondary" size="sm" onClick={() => exportHtml(inv)}>
                  <FileText className="h-4 w-4" /> HTML
                </Button>
                <Button variant="secondary" size="sm" onClick={() => exportJson(inv)}>
                  <FileJson className="h-4 w-4" /> JSON
                </Button>
              </div>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
