import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { CornerDownLeft, Search, ShieldAlert } from "lucide-react";
import { NAV, type NavItem } from "@/lib/nav";
import { useUIStore } from "@/stores/ui";
import { cn } from "@/lib/cn";

type Item =
  | { kind: "lookup"; label: string; query: string }
  | { kind: "nav"; nav: NavItem };

export function CommandPalette() {
  const open = useUIStore((s) => s.commandOpen);
  const setOpen = useUIStore((s) => s.setCommandOpen);
  const navigate = useNavigate();
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);

  const items = useMemo<Item[]>(() => {
    const q = query.trim();
    const lower = q.toLowerCase();
    const navMatches = NAV.filter((i) => !lower || i.label.toLowerCase().includes(lower));
    const list: Item[] = navMatches.map((nav) => ({ kind: "nav", nav }));
    // When the user typed something, offer an IOC/threat-intel lookup as the top action.
    if (q) {
      list.unshift({ kind: "lookup", label: `Full IOC report for "${q}"`, query: q });
    }
    return list;
  }, [query]);

  useEffect(() => {
    if (open) {
      setQuery("");
      setActive(0);
    }
  }, [open]);

  if (!open) return null;

  const choose = (item: Item) => {
    setOpen(false);
    if (item.kind === "lookup") {
      navigate(`/ioc-report?q=${encodeURIComponent(item.query)}`);
    } else {
      navigate(item.nav.to);
    }
  };

  return (
    <div
      className="fixed inset-0 z-[100] flex items-start justify-center bg-black/60 pt-[15vh]"
      onClick={() => setOpen(false)}
    >
      <div
        className="w-full max-w-lg overflow-hidden rounded-xl border border-border bg-surface shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center gap-2 border-b border-border px-4">
          <Search className="h-4 w-4 text-fg-subtle" />
          <input
            autoFocus
            value={query}
            placeholder="Jump to a page, or type an IOC (IP, domain, hash, URL) to look up…"
            onChange={(e) => {
              setQuery(e.target.value);
              setActive(0);
            }}
            onKeyDown={(e) => {
              if (e.key === "ArrowDown") setActive((a) => Math.min(a + 1, items.length - 1));
              if (e.key === "ArrowUp") setActive((a) => Math.max(a - 1, 0));
              if (e.key === "Enter" && items[active]) choose(items[active]);
              if (e.key === "Escape") setOpen(false);
            }}
            className="h-12 flex-1 bg-transparent text-sm text-fg outline-none placeholder:text-muted"
          />
        </div>
        <ul className="max-h-80 overflow-y-auto p-2">
          {items.length === 0 && (
            <li className="px-3 py-6 text-center text-sm text-fg-subtle">No matches.</li>
          )}
          {items.map((item, i) => {
            const isLookup = item.kind === "lookup";
            const Icon = isLookup ? ShieldAlert : item.nav.icon;
            return (
              <li key={isLookup ? "lookup" : item.nav.to}>
                <button
                  onMouseEnter={() => setActive(i)}
                  onClick={() => choose(item)}
                  className={cn(
                    "flex w-full items-center gap-3 rounded-md px-3 py-2 text-sm",
                    i === active ? "bg-accent/15 text-accent" : "text-fg-subtle",
                  )}
                >
                  <Icon className={cn("h-4 w-4", isLookup && "text-high")} />
                  <span className="truncate">{isLookup ? item.label : item.nav.label}</span>
                  {i === active && <CornerDownLeft className="ml-auto h-3.5 w-3.5" />}
                </button>
              </li>
            );
          })}
        </ul>
      </div>
    </div>
  );
}
