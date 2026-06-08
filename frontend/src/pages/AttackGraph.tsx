import { useState } from "react";
import { useInvestigations } from "@/hooks/useInvestigations";
import { PageHeader } from "@/components/common/PageHeader";
import { AttackGraph } from "@/components/graph/AttackGraph";
import { LoadingState, EmptyState } from "@/components/common/states";

export function AttackGraphPage() {
  const { data, isLoading } = useInvestigations();
  const [selected, setSelected] = useState<string>("");
  const invId = selected || data?.[0]?.investigation_id || "";
  const pkg = (data ?? []).find((i) => i.investigation_id === invId);

  return (
    <div>
      <PageHeader
        title="Attack Graph"
        description="Entity-relationship view: alerts ⇄ IOCs ⇄ hosts ⇄ users"
        actions={
          <select
            value={invId}
            onChange={(e) => setSelected(e.target.value)}
            className="h-9 max-w-xs rounded-md border border-border bg-surface-2 px-3 text-sm text-fg focus-ring"
          >
            {(data ?? []).map((inv) => (
              <option key={inv.investigation_id} value={inv.investigation_id}>
                {inv.alert.title.slice(0, 50)}
              </option>
            ))}
          </select>
        }
      />
      {isLoading ? (
        <LoadingState />
      ) : !pkg ? (
        <EmptyState title="No investigation selected" description="Ingest an alert to build a graph." />
      ) : (
        <AttackGraph pkg={pkg} height={620} />
      )}
    </div>
  );
}
