import type { EnrichedIOC } from "@/types/api";
import { VerdictBadge } from "@/components/common/badges";
import { CopyButton } from "@/components/common/CopyButton";
import { Badge } from "@/components/ui/badge";
import { EmptyState } from "@/components/common/states";

export function IocTable({ iocs }: { iocs: EnrichedIOC[] }) {
  if (iocs.length === 0) {
    return <EmptyState title="No indicators" description="No IOCs were extracted for this item." />;
  }
  return (
    <div className="overflow-x-auto rounded-lg border border-border">
      <table className="w-full text-sm">
        <thead className="border-b border-border text-left text-xs uppercase text-fg-subtle">
          <tr>
            <th className="px-4 py-2.5 font-medium">Type</th>
            <th className="px-4 py-2.5 font-medium">Indicator</th>
            <th className="px-4 py-2.5 font-medium">Verdict</th>
            <th className="px-4 py-2.5 font-medium">Confidence</th>
            <th className="px-4 py-2.5 font-medium">Sources</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-border">
          {iocs.map((e, i) => (
            <tr key={`${e.ioc.type}:${e.ioc.value}:${i}`} className="align-top">
              <td className="px-4 py-3">
                <Badge>{e.ioc.type}</Badge>
              </td>
              <td className="px-4 py-3">
                <div className="flex items-center gap-1.5">
                  <span className="break-all font-mono text-xs text-fg">{e.ioc.value}</span>
                  <CopyButton value={e.ioc.value} />
                </div>
                {e.ioc.context && <div className="text-[11px] text-muted">{e.ioc.context}</div>}
              </td>
              <td className="px-4 py-3">
                <VerdictBadge verdict={e.verdict} />
              </td>
              <td className="px-4 py-3">
                <div className="flex items-center gap-2">
                  <div className="h-1.5 w-16 overflow-hidden rounded-full bg-[#172033]">
                    <div
                      className="h-full rounded-full bg-accent"
                      style={{ width: `${Math.round(e.confidence * 100)}%` }}
                    />
                  </div>
                  <span className="text-xs text-fg-subtle">{Math.round(e.confidence * 100)}%</span>
                </div>
              </td>
              <td className="px-4 py-3">
                <div className="flex flex-wrap gap-1">
                  {e.sources.map((s, j) => (
                    <span
                      key={j}
                      title={s.detail ?? ""}
                      className="rounded bg-[#172033] px-1.5 py-0.5 text-[11px] text-fg-subtle"
                    >
                      {s.source}
                    </span>
                  ))}
                  {e.sources.length === 0 && <span className="text-xs text-muted">—</span>}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
