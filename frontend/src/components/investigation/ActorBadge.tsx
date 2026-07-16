/** Threat-actor-type attribution badge (type only, never a named group). */
import { UserCog } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import type { Attribution } from "@/types/api";

const tone: Record<string, "critical" | "high" | "medium" | "neutral"> = {
  ransomware: "critical",
  apt: "critical",
  botnet: "high",
  crimeware: "high",
  insider: "medium",
  hacktivist: "medium",
  unattributed: "neutral",
};

export function ActorBadge({ attribution }: { attribution: Attribution }) {
  const t = tone[attribution.actor_type] ?? "neutral";
  return (
    <span
      className="inline-flex items-center gap-1.5"
      title={attribution.rationale.join(" · ")}
    >
      <UserCog className="h-3.5 w-3.5 text-fg-subtle" />
      <Badge tone={t}>{attribution.actor_type}</Badge>
      {attribution.confidence > 0 && (
        <span className="text-xs text-fg-subtle">
          {Math.round(attribution.confidence * 100)}%
        </span>
      )}
    </span>
  );
}
