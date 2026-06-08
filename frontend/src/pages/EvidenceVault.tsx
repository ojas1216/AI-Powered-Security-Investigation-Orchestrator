import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Search, ShieldCheck } from "lucide-react";
import { useInvestigations } from "@/hooks/useInvestigations";
import { PageHeader } from "@/components/common/PageHeader";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { CopyButton } from "@/components/common/CopyButton";
import { LoadingState, EmptyState } from "@/components/common/states";
import type { Evidence } from "@/types/api";

export function EvidenceVaultPage() {
  const { data, isLoading } = useInvestigations();
  const [q, setQ] = useState("");

  const items = useMemo(() => {
    const rows: (Evidence & { investigationId: string })[] = [];
    for (const inv of data ?? []) {
      for (const ev of inv.evidence) rows.push({ ...ev, investigationId: inv.investigation_id });
    }
    const term = q.trim().toLowerCase();
    return term
      ? rows.filter((r) => r.label.toLowerCase().includes(term) || r.kind.includes(term) || r.sha256.includes(term))
      : rows;
  }, [data, q]);

  return (
    <div>
      <PageHeader
        title="Evidence Vault"
        description="Immutable, content-hashed artifacts with chain-of-custody metadata"
      />
      <div className="mb-4 flex items-center gap-2 text-xs text-fg-subtle">
        <ShieldCheck className="h-4 w-4 text-low" />
        Every artifact is SHA-256 content-addressed; the hash is its tamper-evidence and storage key.
      </div>
      <div className="relative mb-4 max-w-sm">
        <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
        <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search evidence…" className="pl-9" />
      </div>

      {isLoading ? (
        <LoadingState />
      ) : items.length === 0 ? (
        <EmptyState title="No evidence" description="Evidence is collected automatically during investigations." />
      ) : (
        <Card className="overflow-hidden">
          <table className="w-full text-sm">
            <thead className="border-b border-border text-left text-xs uppercase text-fg-subtle">
              <tr>
                <th className="px-4 py-2.5 font-medium">Kind</th>
                <th className="px-4 py-2.5 font-medium">Label</th>
                <th className="px-4 py-2.5 font-medium">SHA-256</th>
                <th className="px-4 py-2.5 font-medium">Investigation</th>
                <th className="px-4 py-2.5 font-medium">Collected</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {items.map((ev, i) => (
                <tr key={`${ev.sha256}-${i}`}>
                  <td className="px-4 py-3"><span className="rounded bg-[#172033] px-1.5 py-0.5 text-xs">{ev.kind}</span></td>
                  <td className="px-4 py-3 text-fg">{ev.label}</td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-1.5">
                      <code className="font-mono text-[11px] text-fg-subtle">{ev.sha256.slice(0, 20)}…</code>
                      <CopyButton value={ev.sha256} />
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <Link to={`/investigations/${ev.investigationId}`} className="text-xs text-accent hover:underline">
                      {ev.investigationId.slice(0, 8)}
                    </Link>
                  </td>
                  <td className="px-4 py-3 text-xs text-muted">{new Date(ev.collected_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}
    </div>
  );
}
