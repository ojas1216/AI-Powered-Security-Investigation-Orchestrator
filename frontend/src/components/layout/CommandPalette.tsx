import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Search, CornerDownLeft } from "lucide-react";
import { NAV } from "@/lib/nav";
import { useUIStore } from "@/stores/ui";
import { cn } from "@/lib/cn";

export function CommandPalette() {
  const open = useUIStore((s) => s.commandOpen);
  const setOpen = useUIStore((s) => s.setCommandOpen);
  const navigate = useNavigate();
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);

  const results = useMemo(() => {
    const q = query.trim().toLowerCase();
    return NAV.filter((i) => !q || i.label.toLowerCase().includes(q));
  }, [query]);

  useEffect(() => {
    if (open) {
      setQuery("");
      setActive(0);
    }
  }, [open]);

  if (!open) return null;

  const go = (to: string) => {
    setOpen(false);
    navigate(to);
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
            placeholder="Jump to…"
            onChange={(e) => {
              setQuery(e.target.value);
              setActive(0);
            }}
            onKeyDown={(e) => {
              if (e.key === "ArrowDown") setActive((a) => Math.min(a + 1, results.length - 1));
              if (e.key === "ArrowUp") setActive((a) => Math.max(a - 1, 0));
              if (e.key === "Enter" && results[active]) go(results[active].to);
              if (e.key === "Escape") setOpen(false);
            }}
            className="h-12 flex-1 bg-transparent text-sm text-fg outline-none placeholder:text-muted"
          />
        </div>
        <ul className="max-h-80 overflow-y-auto p-2">
          {results.length === 0 && (
            <li className="px-3 py-6 text-center text-sm text-fg-subtle">No matches.</li>
          )}
          {results.map((item, i) => (
            <li key={item.to}>
              <button
                onMouseEnter={() => setActive(i)}
                onClick={() => go(item.to)}
                className={cn(
                  "flex w-full items-center gap-3 rounded-md px-3 py-2 text-sm",
                  i === active ? "bg-accent/15 text-accent" : "text-fg-subtle",
                )}
              >
                <item.icon className="h-4 w-4" />
                <span>{item.label}</span>
                {i === active && <CornerDownLeft className="ml-auto h-3.5 w-3.5" />}
              </button>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
