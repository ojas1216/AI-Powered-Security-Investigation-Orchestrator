import { useNavigate } from "react-router-dom";
import { Search, LogOut, CircleDot } from "lucide-react";
import { Kbd } from "@/components/ui/misc";
import { useUIStore } from "@/stores/ui";
import { useAuthStore } from "@/stores/auth";
import { useHealth } from "@/hooks/useHealth";
import { NotificationCenter } from "./NotificationCenter";
import { cn } from "@/lib/cn";

export function Topbar() {
  const navigate = useNavigate();
  const setCommandOpen = useUIStore((s) => s.setCommandOpen);
  const user = useAuthStore((s) => s.user);
  const clear = useAuthStore((s) => s.clear);
  const { data: health, isError } = useHealth();

  return (
    <header className="flex h-14 shrink-0 items-center gap-4 border-b border-border bg-surface-2 px-4">
      <button
        onClick={() => setCommandOpen(true)}
        className="flex h-9 flex-1 max-w-md items-center gap-2 rounded-md border border-border bg-surface-2 px-3 text-sm text-muted hover:border-[#2a3650] focus-ring"
      >
        <Search className="h-4 w-4" />
        <span>Search investigations, IOCs, hosts…</span>
        <span className="ml-auto flex items-center gap-1">
          <Kbd>⌘</Kbd>
          <Kbd>K</Kbd>
        </span>
      </button>

      <div className="ml-auto flex items-center gap-4">
        <div className="hidden items-center gap-1.5 text-xs text-fg-subtle md:flex" title="API health">
          <CircleDot className={cn("h-3.5 w-3.5", isError ? "text-critical" : "text-low")} />
          <span>{isError ? "API offline" : `API ${health?.status ?? "…"}`}</span>
          {health?.connector_mode && (
            <span className="rounded bg-[#172033] px-1.5 py-0.5">{health.connector_mode}</span>
          )}
        </div>

        <NotificationCenter />

        <div className="flex items-center gap-2 border-l border-border pl-4">
          <div className="hidden text-right sm:block">
            <div className="text-xs font-medium text-fg">{user?.username}</div>
            <div className="text-[11px] text-fg-subtle">
              {user?.tenant} · {user?.roles[0] ?? "—"}
            </div>
          </div>
          <button
            onClick={() => {
              clear();
              navigate("/login", { replace: true });
            }}
            title="Sign out"
            className="rounded-md p-2 text-fg-subtle hover:bg-[#172033] hover:text-fg focus-ring"
          >
            <LogOut className="h-4 w-4" />
          </button>
        </div>
      </div>
    </header>
  );
}
