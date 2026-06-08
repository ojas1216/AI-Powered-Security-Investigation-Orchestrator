import { useMemo } from "react";
import { useNavigate } from "react-router-dom";
import {
  Activity,
  AlertOctagon,
  Crosshair,
  Microscope,
  ServerCrash,
  ShieldAlert,
  Timer,
} from "lucide-react";
import {
  Bar,
  BarChart,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { useInvestigations } from "@/hooks/useInvestigations";
import { computeMetrics, formatDuration } from "@/lib/metrics";
import { PageHeader } from "@/components/common/PageHeader";
import { StatCard } from "@/components/common/StatCard";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { LoadingState, ErrorState, EmptyState } from "@/components/common/states";
import { VerdictBadge } from "@/components/common/badges";

const SEV_COLOR: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#f59e0b",
  low: "#10b981",
  info: "#3b82f6",
};

export function DashboardPage() {
  const navigate = useNavigate();
  const { data, isLoading, isError, refetch } = useInvestigations();
  const metrics = useMemo(() => (data ? computeMetrics(data) : null), [data]);

  if (isLoading) return <LoadingState label="Loading SOC dashboard…" />;
  if (isError || !metrics) return <ErrorState message="Failed to load dashboard data." onRetry={refetch} />;

  return (
    <div>
      <PageHeader title="Security Operations Dashboard" description="Live view across all investigations" />

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard label="Open Investigations" value={metrics.open} icon={<Microscope className="h-4 w-4" />} />
        <StatCard label="Malicious Verdicts" value={metrics.malicious} tone="critical" icon={<AlertOctagon className="h-4 w-4" />} />
        <StatCard label="Investigations Today" value={metrics.today} icon={<Activity className="h-4 w-4" />} />
        <StatCard label="Threat Intel Hits" value={metrics.tiHits} tone="high" icon={<ShieldAlert className="h-4 w-4" />} />
        <StatCard label="Affected Assets" value={metrics.affectedAssets} icon={<ServerCrash className="h-4 w-4" />} />
        <StatCard label="Affected Users" value={metrics.affectedUsers} icon={<Crosshair className="h-4 w-4" />} />
        <StatCard label="MITRE Coverage" value={metrics.mitreCoverage} hint="unique techniques" icon={<Crosshair className="h-4 w-4" />} />
        <StatCard label="Mean Time To Respond" value={formatDuration(metrics.mttrSeconds)} tone="low" icon={<Timer className="h-4 w-4" />} />
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Incident Volume (by hour)</CardTitle>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={metrics.volumeByHour}>
                <XAxis dataKey="hour" stroke="#64748b" fontSize={10} interval={3} tickLine={false} />
                <YAxis stroke="#64748b" fontSize={10} allowDecimals={false} tickLine={false} axisLine={false} />
                <Tooltip
                  contentStyle={{ background: "#111827", border: "1px solid #1f2937", borderRadius: 8, fontSize: 12 }}
                  cursor={{ fill: "#172033" }}
                />
                <Bar dataKey="count" fill="#3b82f6" radius={[3, 3, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Risk Distribution</CardTitle>
          </CardHeader>
          <CardContent>
            {metrics.severityDist.length === 0 ? (
              <p className="py-10 text-center text-sm text-fg-subtle">No scored investigations.</p>
            ) : (
              <ResponsiveContainer width="100%" height={220}>
                <PieChart>
                  <Pie data={metrics.severityDist} dataKey="value" nameKey="name" innerRadius={50} outerRadius={80} paddingAngle={2}>
                    {metrics.severityDist.map((d) => (
                      <Cell key={d.name} fill={SEV_COLOR[d.name]} stroke="#0b1020" />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ background: "#111827", border: "1px solid #1f2937", borderRadius: 8, fontSize: 12 }} />
                </PieChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>
      </div>

      <Card className="mt-4">
        <CardHeader>
          <CardTitle>Recent Activity</CardTitle>
        </CardHeader>
        <CardContent>
          {data && data.length === 0 ? (
            <EmptyState title="No investigations yet" description="Ingest an alert from the Alerts page to start." />
          ) : (
            <ul className="divide-y divide-border">
              {data!.slice(0, 8).map((inv) => (
                <li
                  key={inv.investigation_id}
                  onClick={() => navigate(`/investigations/${inv.investigation_id}`)}
                  className="flex cursor-pointer items-center gap-3 py-2.5 hover:opacity-80"
                >
                  <VerdictBadge verdict={inv.overall_verdict} />
                  <span className="min-w-0 flex-1 truncate text-sm text-fg">{inv.alert.title}</span>
                  <span className="text-xs text-fg-subtle">risk {inv.risk?.score ?? "—"}</span>
                  <span className="hidden text-xs text-muted sm:block">
                    {new Date(inv.created_at).toLocaleTimeString()}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
