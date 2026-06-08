import { NavLink } from "react-router-dom";
import { ShieldHalf, PanelLeftClose, PanelLeft } from "lucide-react";
import { cn } from "@/lib/cn";
import { NAV } from "@/lib/nav";
import { config } from "@/lib/config";
import { useUIStore } from "@/stores/ui";
import { useAuthStore } from "@/stores/auth";
import { hasPermission } from "@/lib/rbac";

export function Sidebar() {
  const collapsed = useUIStore((s) => s.sidebarCollapsed);
  const toggle = useUIStore((s) => s.toggleSidebar);
  const roles = useAuthStore((s) => s.user?.roles ?? []);

  return (
    <aside
      className={cn(
        "flex h-screen shrink-0 flex-col border-r border-border bg-surface-2 transition-all",
        collapsed ? "w-16" : "w-60",
      )}
    >
      <div className="flex h-14 items-center gap-2 border-b border-border px-4">
        <ShieldHalf className="h-6 w-6 shrink-0 text-accent" />
        {!collapsed && (
          <span className="truncate text-sm font-semibold tracking-tight text-fg">
            {config.app.name}
          </span>
        )}
      </div>

      <nav className="flex-1 space-y-0.5 overflow-y-auto p-2">
        {NAV.filter((i) => !i.perm || hasPermission(roles, i.perm)).map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            title={item.label}
            className={({ isActive }) =>
              cn(
                "flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors focus-ring",
                isActive
                  ? "bg-accent/15 text-accent"
                  : "text-fg-subtle hover:bg-[#172033] hover:text-fg",
                collapsed && "justify-center px-0",
              )
            }
          >
            <item.icon className="h-[18px] w-[18px] shrink-0" />
            {!collapsed && <span className="truncate">{item.label}</span>}
          </NavLink>
        ))}
      </nav>

      <button
        onClick={toggle}
        className="flex h-12 items-center gap-3 border-t border-border px-4 text-fg-subtle hover:text-fg focus-ring"
      >
        {collapsed ? <PanelLeft className="h-[18px] w-[18px]" /> : <PanelLeftClose className="h-[18px] w-[18px]" />}
        {!collapsed && <span className="text-xs">Collapse</span>}
      </button>
    </aside>
  );
}
