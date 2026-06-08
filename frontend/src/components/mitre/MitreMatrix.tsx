import type { MitreTechnique } from "@/types/api";
import { cn } from "@/lib/cn";

/** ATT&CK Enterprise tactics in kill-chain order. */
const TACTICS: { id: string; name: string }[] = [
  { id: "reconnaissance", name: "Reconnaissance" },
  { id: "resource-development", name: "Resource Dev" },
  { id: "initial-access", name: "Initial Access" },
  { id: "execution", name: "Execution" },
  { id: "persistence", name: "Persistence" },
  { id: "privilege-escalation", name: "Priv Esc" },
  { id: "defense-evasion", name: "Defense Evasion" },
  { id: "credential-access", name: "Credential Access" },
  { id: "discovery", name: "Discovery" },
  { id: "lateral-movement", name: "Lateral Movement" },
  { id: "collection", name: "Collection" },
  { id: "command-and-control", name: "Command & Control" },
  { id: "exfiltration", name: "Exfiltration" },
  { id: "impact", name: "Impact" },
];

/** Heatmap matrix highlighting tactics/techniques observed across the supplied
 *  techniques (from one or many investigations). */
export function MitreMatrix({ techniques }: { techniques: MitreTechnique[] }) {
  const byTactic = new Map<string, MitreTechnique[]>();
  for (const t of techniques) {
    const list = byTactic.get(t.tactic) ?? [];
    list.push(t);
    byTactic.set(t.tactic, list);
  }

  return (
    <div className="overflow-x-auto">
      <div className="flex min-w-max gap-2">
        {TACTICS.map((tac) => {
          const hits = byTactic.get(tac.id) ?? [];
          return (
            <div key={tac.id} className="w-40 shrink-0">
              <div
                className={cn(
                  "mb-2 rounded-md border px-2 py-1.5 text-center text-xs font-semibold",
                  hits.length
                    ? "border-critical/40 bg-critical/10 text-critical"
                    : "border-border bg-surface-2 text-fg-subtle",
                )}
              >
                {tac.name}
                {hits.length > 0 && <span className="ml-1 opacity-70">({hits.length})</span>}
              </div>
              <div className="space-y-1.5">
                {hits.map((t) => (
                  <div
                    key={t.technique_id}
                    className="rounded-md border border-high/30 bg-high/10 px-2 py-1.5 text-xs"
                    title={`${t.technique_id} — ${t.name}`}
                  >
                    <div className="font-mono text-[11px] text-high">{t.technique_id}</div>
                    <div className="truncate text-fg-subtle">{t.name}</div>
                  </div>
                ))}
                {hits.length === 0 && <div className="h-2" />}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
