import { create } from "zustand";

export type NotificationLevel = "info" | "success" | "warning" | "critical";

export interface AppNotification {
  id: string;
  level: NotificationLevel;
  title: string;
  message?: string;
  ts: number;
  read: boolean;
}

interface NotificationsState {
  items: AppNotification[];
  push: (n: Omit<AppNotification, "id" | "ts" | "read">) => void;
  markAllRead: () => void;
  remove: (id: string) => void;
  clear: () => void;
}

export const useNotificationsStore = create<NotificationsState>((set) => ({
  items: [],
  push: (n) =>
    set((s) => ({
      items: [
        { ...n, id: crypto.randomUUID(), ts: Date.now(), read: false },
        ...s.items,
      ].slice(0, 100),
    })),
  markAllRead: () => set((s) => ({ items: s.items.map((i) => ({ ...i, read: true })) })),
  remove: (id) => set((s) => ({ items: s.items.filter((i) => i.id !== id) })),
  clear: () => set({ items: [] }),
}));
