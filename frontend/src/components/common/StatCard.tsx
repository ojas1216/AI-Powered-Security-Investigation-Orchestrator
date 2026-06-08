import type { ReactNode } from "react";
import { cn } from "@/lib/cn";
import { Card } from "@/components/ui/card";

export function StatCard({
  label,
  value,
  icon,
  hint,
  tone = "default",
}: {
  label: string;
  value: ReactNode;
  icon?: ReactNode;
  hint?: string;
  tone?: "default" | "critical" | "high" | "low" | "info";
}) {
  const toneColor = {
    default: "text-fg",
    critical: "text-critical",
    high: "text-high",
    low: "text-low",
    info: "text-info",
  }[tone];
  return (
    <Card className="p-4">
      <div className="flex items-center justify-between">
        <span className="text-xs font-medium uppercase tracking-wide text-fg-subtle">{label}</span>
        {icon && <span className="text-fg-subtle">{icon}</span>}
      </div>
      <div className={cn("mt-2 text-2xl font-semibold", toneColor)}>{value}</div>
      {hint && <div className="mt-1 text-xs text-fg-subtle">{hint}</div>}
    </Card>
  );
}
