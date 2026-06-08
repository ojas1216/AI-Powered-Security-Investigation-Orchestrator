import { useState } from "react";
import { Bell, X } from "lucide-react";
import { cn } from "@/lib/cn";
import { useNotificationsStore } from "@/stores/notifications";

const levelColor = {
  info: "text-info",
  success: "text-low",
  warning: "text-medium",
  critical: "text-critical",
};

export function NotificationCenter() {
  const [open, setOpen] = useState(false);
  const items = useNotificationsStore((s) => s.items);
  const markAllRead = useNotificationsStore((s) => s.markAllRead);
  const remove = useNotificationsStore((s) => s.remove);
  const unread = items.filter((i) => !i.read).length;

  return (
    <div className="relative">
      <button
        onClick={() => {
          setOpen((o) => !o);
          if (!open) markAllRead();
        }}
        className="relative rounded-md p-2 text-fg-subtle hover:bg-[#172033] hover:text-fg focus-ring"
        title="Notifications"
      >
        <Bell className="h-4 w-4" />
        {unread > 0 && (
          <span className="absolute right-1 top-1 flex h-4 min-w-4 items-center justify-center rounded-full bg-critical px-1 text-[10px] font-bold text-white">
            {unread}
          </span>
        )}
      </button>

      {open && (
        <>
          <div className="fixed inset-0 z-40" onClick={() => setOpen(false)} />
          <div className="absolute right-0 z-50 mt-2 w-80 overflow-hidden rounded-lg border border-border bg-surface shadow-xl">
            <div className="flex items-center justify-between border-b border-border px-4 py-2.5">
              <span className="text-sm font-semibold text-fg">Notifications</span>
              <span className="text-xs text-fg-subtle">{items.length}</span>
            </div>
            <div className="max-h-96 overflow-y-auto">
              {items.length === 0 ? (
                <p className="p-6 text-center text-sm text-fg-subtle">No notifications.</p>
              ) : (
                items.map((n) => (
                  <div
                    key={n.id}
                    className="group flex items-start gap-2 border-b border-border px-4 py-3 last:border-0"
                  >
                    <span className={cn("mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full", levelColor[n.level], "bg-current")} />
                    <div className="min-w-0 flex-1">
                      <div className="text-sm font-medium text-fg">{n.title}</div>
                      {n.message && <div className="truncate text-xs text-fg-subtle">{n.message}</div>}
                      <div className="mt-0.5 text-[11px] text-muted">
                        {new Date(n.ts).toLocaleTimeString()}
                      </div>
                    </div>
                    <button
                      onClick={() => remove(n.id)}
                      className="opacity-0 transition-opacity group-hover:opacity-100"
                    >
                      <X className="h-3.5 w-3.5 text-fg-subtle hover:text-fg" />
                    </button>
                  </div>
                ))
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
