/**
 * Executive Intelligence — board-level view aggregated across investigations:
 * business risk, campaigns, financial exposure, top threat-actor types,
 * departments affected, compliance impact, MTTR, AI time saved, false-positive
 * rate and risk trend. Backed by GET /executive/summary.
 */
import { useQuery } from "@tanstack/react-query";
import {
  AlertTriangle,
  Boxes,
  Clock,
  DollarSign,
  Gauge,
  ShieldCheck,
  Sparkles,
  TrendingUp,
} from "lucide-react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { executiveSummary } from "@/services/platform";
import { PageHeader } from "@/components/common/PageHeader";
import { StatCard } from "@/components/common/StatCard";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { LoadingState, ErrorState } from "@/components/common/states";
import { ActorBadge } from "@/components/investigation/ActorBadge";

const riskTone: Record<string, "critical" | "high" | "low" | "info"> = {
  critical: "critical",
  high: "high",
  medium: "high",
  low: "low",
};

export function ExecutivePage() {
  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ["executive"],
    queryFn: () => executiveSummary(30),
    refetchInterval: 30_000,
  });

  if (isLoading) return <LoadingState label="Aggregating executive intelligence…" />;
  if (isError || !data)
    return <ErrorState message="Could not load the executive summary." onRetry={refetch} />;

  const fp = Math.round(data.false_positive_rate * 100);
  return (
    <div>
      <PageHeader
        title="Executive Intelligence"
        description={`SOC posture over the last ${data.window_days} days`}
      />

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard
          label="Business Risk"
          value={data.business_risk.toUpperCase()}
          tone={riskTone[data.business_risk] ?? "default"}
          icon={<Gauge className="h-4 w-4" />}
          hint={`avg risk ${data.average_risk_score}/100`}
        />
        <StatCard
          label="Financial Exposure"
          value={data.financial_exposure_band}
          tone="high"
          icon={<DollarSign className="h-4 w-4" />}
          hint={`${data.high_impact_incidents} high-impact incidents`}
        />
        <StatCard
          label="Active Campaigns"
          value={data.active_campaigns}
          icon={<Boxes className="h-4 w-4" />}
        />
        <StatCard
          label="Investigations"
          value={data.investigation_volume}
          icon={<TrendingUp className="h-4 w-4" />}
          hint={`${data.malicious_count} malicious · ${data.suspicious_count} suspicious`}
        />
        <StatCard
          label="AI Time Saved"
          value={`${data.ai_time_saved_hours} h`}
          tone="low"
          icon={<Sparkles className="h-4 w-4" />}
          hint={`${data.analyst_productivity_multiplier}× analyst productivity`}
        />
        <StatCard
          label="Estimated MTTR"
          value={`${data.estimated_mttr_minutes} min`}
          tone="low"
          icon={<Clock className="h-4 w-4" />}
        />
        <StatCard
          label="False Positive Rate"
          value={`${fp}%`}
          tone={fp > 40 ? "high" : "info"}
          icon={<AlertTriangle className="h-4 w-4" />}
        />
        <StatCard
          label="Compliance Flags"
          value={data.compliance_impact.length}
          tone={data.compliance_impact.length ? "critical" : "low"}
          icon={<ShieldCheck className="h-4 w-4" />}
        />
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Risk Trend</CardTitle>
          </CardHeader>
          <CardContent>
            {data.risk_trend.length ? (
              <ResponsiveContainer width="100%" height={220}>
                <AreaChart data={data.risk_trend}>
                  <defs>
                    <linearGradient id="risk" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.5} />
                      <stop offset="95%" stopColor="#f59e0b" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis dataKey="period" stroke="#64748b" fontSize={11} />
                  <YAxis domain={[0, 100]} stroke="#64748b" fontSize={11} />
                  <Tooltip
                    contentStyle={{ background: "#0d1526", border: "1px solid #1e293b" }}
                  />
                  <Area
                    type="monotone"
                    dataKey="avg_risk"
                    stroke="#f59e0b"
                    fill="url(#risk)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <p className="p-8 text-center text-sm text-fg-subtle">No trend data yet.</p>
            )}
          </CardContent>
        </Card>

        <div className="space-y-4">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm">Top Threat Actors</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 pt-0">
              {data.top_threat_actors.length ? (
                data.top_threat_actors.map((a) => (
                  <div key={a.actor_type} className="flex items-center justify-between">
                    <ActorBadge
                      attribution={{ actor_type: a.actor_type, confidence: 0, rationale: [], signals: [] }}
                    />
                    <span className="text-sm text-fg-subtle">{a.count}</span>
                  </div>
                ))
              ) : (
                <p className="text-xs text-fg-subtle">No attributed actors.</p>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm">Departments Affected</CardTitle>
            </CardHeader>
            <CardContent className="space-y-1.5 pt-0">
              {data.departments_affected.length ? (
                data.departments_affected.map((d) => (
                  <div key={d.department} className="flex items-center justify-between text-sm">
                    <span className="text-fg-subtle">{d.department}</span>
                    <span className="text-fg">{d.incidents}</span>
                  </div>
                ))
              ) : (
                <p className="text-xs text-fg-subtle">None recorded.</p>
              )}
            </CardContent>
          </Card>
        </div>
      </div>

      {data.compliance_impact.length > 0 && (
        <Card className="mt-4">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Compliance Impact</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-wrap gap-2 pt-0">
            {data.compliance_impact.map((c) => (
              <Badge key={c} tone="critical">
                {c}
              </Badge>
            ))}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
