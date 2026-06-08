import type { TimelineEvent } from "@/types/api";
import { EmptyState } from "@/components/common/states";

const SOURCE_COLOR: Record<string, string> = {
  email: "#3b82f6",
  sandbox: "#f97316",
  edr: "#ef4444",
  ti: "#a855f7",
};

export function TimelineView({ events }: { events: TimelineEvent[] }) {
  if (events.length === 0) {
    return <EmptyState title="No timeline events" description="The investigation produced no ordered events." />;
  }
  return (
    <ol className="relative ml-3 border-l border-border">
      {events.map((ev, i) => (
        <li key={i} className="mb-5 ml-5">
          <span
            className="absolute -left-[6px] mt-1.5 h-3 w-3 rounded-full border-2 border-bg"
            style={{ background: SOURCE_COLOR[ev.source ?? ""] ?? "#64748b" }}
          />
          <div className="flex flex-wrap items-baseline gap-2">
            <time className="font-mono text-xs text-fg-subtle">
              {new Date(ev.timestamp).toLocaleString()}
            </time>
            {ev.source && (
              <span className="rounded bg-[#172033] px-1.5 py-0.5 text-[10px] uppercase text-fg-subtle">
                {ev.source}
              </span>
            )}
          </div>
          <p className="mt-0.5 text-sm font-medium text-fg">{ev.action}</p>
          {ev.detail && <p className="text-xs text-fg-subtle">{ev.detail}</p>}
          {ev.actor && <p className="text-[11px] text-muted">actor: {ev.actor}</p>}
        </li>
      ))}
    </ol>
  );
}
