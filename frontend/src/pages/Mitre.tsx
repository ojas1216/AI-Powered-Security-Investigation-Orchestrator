import { useMemo } from "react";
import { useInvestigations } from "@/hooks/useInvestigations";
import { PageHeader } from "@/components/common/PageHeader";
import { Card, CardContent } from "@/components/ui/card";
import { StatCard } from "@/components/common/StatCard";
import { MitreMatrix } from "@/components/mitre/MitreMatrix";
import { LoadingState, EmptyState } from "@/components/common/states";
import type { MitreTechnique } from "@/types/api";

export function MitrePage() {
  const { data, isLoading } = useInvestigations();

  const { techniques, tacticCount } = useMemo(() => {
    const map = new Map<string, MitreTechnique>();
    const tactics = new Set<string>();
    for (const inv of data ?? []) {
      for (const t of inv.mitre) {
        map.set(t.technique_id, t);
        tactics.add(t.tactic);
      }
    }
    return { techniques: [...map.values()], tacticCount: tactics.size };
  }, [data]);

  return (
    <div>
      <PageHeader title="MITRE ATT&CK" description="Coverage observed across all investigations" />
      <div className="mb-4 grid grid-cols-3 gap-4">
        <StatCard label="Techniques Observed" value={techniques.length} />
        <StatCard label="Tactics Covered" value={tacticCount} hint="of 14 enterprise tactics" />
        <StatCard label="Investigations" value={(data ?? []).length} />
      </div>
      {isLoading ? (
        <LoadingState />
      ) : techniques.length === 0 ? (
        <EmptyState title="No techniques mapped yet" description="Run an investigation to populate the matrix." />
      ) : (
        <Card>
          <CardContent className="pt-4">
            <MitreMatrix techniques={techniques} />
          </CardContent>
        </Card>
      )}
    </div>
  );
}
