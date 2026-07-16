/**
 * Predictive attack path — the attacker's likely next moves from the
 * reconstructed kill chain, each with a probability and a preventative control.
 */
import { Radar, ShieldPlus } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { AttackPrediction } from "@/types/api";

export function Prediction({ prediction }: { prediction: AttackPrediction }) {
  if (!prediction.predictions.length) return null;
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-sm">
          <Radar className="h-4 w-4 text-high" />
          Predicted Next Moves
          <span className="text-xs text-fg-subtle">
            currently at &ldquo;{prediction.current_stage}&rdquo;
          </span>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-2 pt-0">
        {prediction.predictions.map((p) => (
          <div key={p.tactic} className="rounded-md border border-border p-2">
            <div className="flex items-center gap-2">
              <div className="h-1.5 w-16 overflow-hidden rounded-full bg-[#172033]">
                <div className="h-full bg-high" style={{ width: `${p.probability * 100}%` }} />
              </div>
              <span className="text-xs font-medium text-fg">
                {Math.round(p.probability * 100)}%
              </span>
              <span className="text-sm text-fg">{p.tactic}</span>
              <span className="font-mono text-xs text-fg-subtle">{p.technique_id}</span>
              <span className="text-xs text-fg-subtle">{p.name}</span>
            </div>
            <p className="mt-1 flex items-start gap-1.5 pl-1 text-xs text-low">
              <ShieldPlus className="mt-0.5 h-3 w-3 shrink-0" />
              {p.preventative_action}
            </p>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}
