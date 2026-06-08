import type { RiskBreakdown } from "@/types/api";
import { cn } from "@/lib/cn";

const sevColor: Record<string, string> = {
  critical: "text-critical",
  high: "text-high",
  medium: "text-medium",
  low: "text-low",
  info: "text-info",
};
const sevStroke: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#f59e0b",
  low: "#10b981",
  info: "#3b82f6",
};

/** Radial gauge for an investigation risk score (0-100). */
export function RiskMeter({ risk, size = 132 }: { risk: RiskBreakdown; size?: number }) {
  const r = size / 2 - 10;
  const c = 2 * Math.PI * r;
  const pct = Math.max(0, Math.min(100, risk.score)) / 100;
  const stroke = sevStroke[risk.severity] ?? "#3b82f6";
  return (
    <div className="relative inline-flex items-center justify-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="#1f2937" strokeWidth={10} />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke={stroke}
          strokeWidth={10}
          strokeLinecap="round"
          strokeDasharray={c}
          strokeDashoffset={c * (1 - pct)}
        />
      </svg>
      <div className="absolute flex flex-col items-center">
        <span className={cn("text-2xl font-bold", sevColor[risk.severity])}>
          {Math.round(risk.score)}
        </span>
        <span className="text-[10px] uppercase tracking-wide text-fg-subtle">
          {risk.severity}
        </span>
      </div>
    </div>
  );
}
