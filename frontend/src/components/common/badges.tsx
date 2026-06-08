import { Badge } from "@/components/ui/badge";
import type { Severity, Verdict } from "@/types/api";

const sevTone: Record<Severity, "critical" | "high" | "medium" | "low" | "info"> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  info: "info",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <Badge tone={sevTone[severity]}>{severity.toUpperCase()}</Badge>;
}

const verdictTone: Record<Verdict, "critical" | "high" | "low" | "neutral"> = {
  malicious: "critical",
  suspicious: "high",
  benign: "low",
  unknown: "neutral",
};

export function VerdictBadge({ verdict }: { verdict: Verdict }) {
  return <Badge tone={verdictTone[verdict]}>{verdict}</Badge>;
}
