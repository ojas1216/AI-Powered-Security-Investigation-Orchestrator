/**
 * Campaigns — incidents clustered into campaigns by shared attacker DNA, each
 * with a threat-actor-type attribution. Backed by GET /campaigns.
 */
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Boxes, Users } from "lucide-react";
import { listCampaigns } from "@/services/platform";
import { PageHeader } from "@/components/common/PageHeader";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { EmptyState, ErrorState, LoadingState } from "@/components/common/states";
import { VerdictBadge } from "@/components/common/badges";
import { ActorBadge } from "@/components/investigation/ActorBadge";

export function CampaignsPage() {
  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ["campaigns"],
    queryFn: listCampaigns,
    refetchInterval: 30_000,
  });

  if (isLoading) return <LoadingState label="Correlating campaigns…" />;
  if (isError) return <ErrorState message="Could not load campaigns." onRetry={refetch} />;

  return (
    <div>
      <PageHeader
        title="Campaigns"
        description="Incidents correlated by shared infrastructure and TTPs, with threat-actor-type attribution."
      />
      {!data?.length ? (
        <EmptyState
          icon={<Boxes className="h-8 w-8" />}
          title="No campaigns detected"
          description="Campaigns appear once two or more incidents share attacker DNA."
        />
      ) : (
        <div className="space-y-3">
          {data.map((c) => (
            <Card key={c.campaign_id}>
              <CardHeader className="flex flex-row flex-wrap items-center justify-between gap-2 pb-2">
                <CardTitle className="flex items-center gap-2 text-sm">
                  <Boxes className="h-4 w-4 text-accent" />
                  <span className="font-mono text-xs text-fg-subtle">{c.campaign_id}</span>
                  <Badge tone="neutral">{c.size} incidents</Badge>
                  <VerdictBadge verdict={c.verdict} />
                </CardTitle>
                <ActorBadge attribution={c.attribution} />
              </CardHeader>
              <CardContent className="space-y-2 pt-0 text-xs text-fg-subtle">
                {c.shared_infrastructure.length > 0 && (
                  <div>
                    <span className="font-semibold uppercase">Shared infrastructure: </span>
                    <span className="font-mono">{c.shared_infrastructure.join(", ")}</span>
                  </div>
                )}
                {c.shared_techniques.length > 0 && (
                  <div>
                    <span className="font-semibold uppercase">Techniques: </span>
                    {c.shared_techniques.join(", ")}
                  </div>
                )}
                {c.victims.length > 0 && (
                  <div className="flex items-center gap-1">
                    <Users className="h-3 w-3" /> {c.victims.length} victim(s):{" "}
                    {c.victims.slice(0, 5).join(", ")}
                  </div>
                )}
                {c.first_seen && c.last_seen && (
                  <div>
                    {new Date(c.first_seen).toLocaleString()} →{" "}
                    {new Date(c.last_seen).toLocaleString()}
                  </div>
                )}
                <div className="flex flex-wrap gap-1.5 pt-1">
                  {c.members.map((m) => (
                    <Link
                      key={m}
                      to={`/investigations/${m}`}
                      className="rounded bg-[#172033] px-1.5 py-0.5 font-mono text-[11px] text-info hover:underline"
                    >
                      {m.slice(0, 8)}
                    </Link>
                  ))}
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
