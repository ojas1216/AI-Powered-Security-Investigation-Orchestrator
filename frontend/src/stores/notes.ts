import { create } from "zustand";

export interface AnalystNote {
  id: string;
  author: string;
  text: string;
  ts: number;
}

interface NotesState {
  byInvestigation: Record<string, AnalystNote[]>;
  add: (investigationId: string, author: string, text: string) => void;
  remove: (investigationId: string, id: string) => void;
}

/** Client-side analyst notes. (No backend notes endpoint exists yet; these live
 *  in-session. Wire to a future POST /investigations/{id}/notes when available.) */
export const useNotesStore = create<NotesState>((set) => ({
  byInvestigation: {},
  add: (investigationId, author, text) =>
    set((s) => ({
      byInvestigation: {
        ...s.byInvestigation,
        [investigationId]: [
          { id: crypto.randomUUID(), author, text, ts: Date.now() },
          ...(s.byInvestigation[investigationId] ?? []),
        ],
      },
    })),
  remove: (investigationId, id) =>
    set((s) => ({
      byInvestigation: {
        ...s.byInvestigation,
        [investigationId]: (s.byInvestigation[investigationId] ?? []).filter((n) => n.id !== id),
      },
    })),
}));
