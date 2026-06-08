import { Activity, CircleCheck, CircleX } from "lucide-react";
import { useHealth } from "@/hooks/useHealth";
import { useAuditStore } from "@/stores/audit";
import { ROLE_PERMISSIONS } from "@/lib/rbac";
import { PageHeader } from "@/components/common/PageHeader";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { StatCard } from "@/components/common/StatCard";
import { EmptyState } from "@/components/common/states";

export function AdministrationPage() {
  const { data: health, isError } = useHealth();
  const audit = useAuditStore((s) => s.entries);

  return (
    <div>
      <PageHeader title="Administration" description="System health, RBAC, and audit" />

      <div className="mb-4 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard
          label="API Status"
          value={isError ? "offline" : (health?.status ?? "…")}
          tone={isError ? "critical" : "low"}
          icon={isError ? <CircleX className="h-4 w-4" /> : <CircleCheck className="h-4 w-4" />}
        />
        <StatCard label="Environment" value={health?.env ?? "—"} icon={<Activity className="h-4 w-4" />} />
        <StatCard label="Connector Mode" value={health?.connector_mode ?? "—"} />
        <StatCard label="Client Audit Events" value={audit.length} />
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>RBAC Matrix</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-sm">
            {Object.entries(ROLE_PERMISSIONS).map(([role, perms]) => (
              <div key={role} className="rounded-md border border-border p-2.5">
                <div className="font-medium text-fg">{role}</div>
                <div className="mt-1 flex flex-wrap gap-1">
                  {perms.map((p) => (
                    <span key={p} className="rounded bg-[#172033] px-1.5 py-0.5 text-[11px] text-fg-subtle">
                      {p}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Audit Log (client session)</CardTitle>
          </CardHeader>
          <CardContent>
            {audit.length === 0 ? (
              <EmptyState title="No audit events yet" description="Authoritative audit is server-side; this mirrors session actions." />
            ) : (
              <div className="max-h-96 space-y-1.5 overflow-y-auto">
                {audit.map((e) => (
                  <div key={e.id} className="flex items-center gap-2 text-xs">
                    <span className="text-muted">{new Date(e.ts).toLocaleTimeString()}</span>
                    <span className="font-medium text-fg">{e.actor}</span>
                    <span className="text-fg-subtle">{e.action}</span>
                    {e.target && <span className="truncate text-muted">{e.target}</span>}
                    <span className={`ml-auto ${e.result === "success" ? "text-low" : "text-critical"}`}>{e.result}</span>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      <p className="mt-4 text-xs text-muted">
        User, tenant, connector, and license management activate when the corresponding admin
        endpoints are added to the backend. No mock administrative data is shown.
      </p>
    </div>
  );
}
