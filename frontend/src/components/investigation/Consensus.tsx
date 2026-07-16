/**
 * Consensus decision — the explainable, multi-voter verdict. No single agent
 * decides: independent evidence sources vote, and the panel shows the confidence,
 * inter-source agreement, each vote, ranked alternative hypotheses, and the
 * supporting / rejected observations behind the conclusion.
 */
import { Scale } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { VerdictBadge } from "@/components/common/badges";
import type { ConsensusResult } from "@/types/api";

export function Consensus({ consensus }: { consensus: ConsensusResult }) {
  const pct = (n: number) => `${Math.round(n * 100)}%`;
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="flex flex-wrap items-center gap-2 text-sm">
          <Scale className="h-4 w-4 text-info" />
          Consensus Decision
          <VerdictBadge verdict={consensus.verdict} />
          <span className="text-xs text-fg-subtle">
            {pct(consensus.confidence)} confidence · {pct(consensus.agreement)} agreement ·{" "}
            {consensus.votes.length} voters
          </span>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4 pt-0">
        {/* Votes */}
        <div className="overflow-x-auto rounded-lg border border-border">
          <table className="w-full text-sm">
            <thead className="border-b border-border text-left text-xs uppercase text-fg-subtle">
              <tr>
                <th className="px-3 py-2 font-medium">Source</th>
                <th className="px-3 py-2 font-medium">Vote</th>
                <th className="px-3 py-2 font-medium">Malice</th>
                <th className="px-3 py-2 font-medium">Weight</th>
                <th className="px-3 py-2 font-medium">Rationale</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {consensus.votes.map((v) => (
                <tr key={v.voter}>
                  <td className="px-3 py-2 font-medium text-fg">{v.voter}</td>
                  <td className="px-3 py-2"><VerdictBadge verdict={v.verdict} /></td>
                  <td className="px-3 py-2 text-fg-subtle">{pct(v.malice)}</td>
                  <td className="px-3 py-2 text-fg-subtle">{v.weight.toFixed(2)}</td>
                  <td className="px-3 py-2 text-fg-subtle">{v.rationale}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Alternative hypotheses */}
        {consensus.hypotheses.length > 0 && (
          <div>
            <div className="mb-1.5 text-xs font-semibold uppercase text-fg-subtle">
              Alternative hypotheses
            </div>
            <div className="flex flex-wrap gap-2">
              {consensus.hypotheses.map((h) => (
                <span
                  key={h.verdict}
                  className="inline-flex items-center gap-1.5 rounded-md border border-border px-2 py-1 text-xs"
                  title={h.rationale}
                >
                  <VerdictBadge verdict={h.verdict} />
                  {pct(h.probability)}
                </span>
              ))}
            </div>
          </div>
        )}

        <div className="grid gap-3 md:grid-cols-2">
          {consensus.supporting.length > 0 && (
            <Observations title="Supporting" tone="low" items={consensus.supporting} />
          )}
          {consensus.rejected.length > 0 && (
            <Observations title="Rejected / caveats" tone="high" items={consensus.rejected} />
          )}
        </div>

        {/* Reasoning chain */}
        <div>
          <div className="mb-1.5 text-xs font-semibold uppercase text-fg-subtle">
            Reasoning chain
          </div>
          <ol className="space-y-1">
            {consensus.reasoning.map((step, i) => (
              <li key={i} className="flex gap-2 text-xs text-fg-subtle">
                <span className="font-mono text-fg-subtle">{i + 1}.</span>
                {step}
              </li>
            ))}
          </ol>
        </div>
      </CardContent>
    </Card>
  );
}

function Observations({
  title,
  tone,
  items,
}: {
  title: string;
  tone: "low" | "high";
  items: string[];
}) {
  return (
    <div>
      <div className="mb-1.5 flex items-center gap-1.5">
        <Badge tone={tone}>{title}</Badge>
      </div>
      <ul className="space-y-1">
        {items.map((it, i) => (
          <li key={i} className="text-xs text-fg-subtle">
            • {it}
          </li>
        ))}
      </ul>
    </div>
  );
}
