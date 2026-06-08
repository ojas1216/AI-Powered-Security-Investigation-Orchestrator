import { useState } from "react";
import { Bot, Loader2, Send, User } from "lucide-react";
import { useInvestigations } from "@/hooks/useInvestigations";
import { askCopilot } from "@/services/copilot";
import { useAudit } from "@/hooks/useAudit";
import { PageHeader } from "@/components/common/PageHeader";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { EmptyState } from "@/components/common/states";

interface Msg {
  role: "user" | "assistant";
  text: string;
  grounded?: string[];
}

const SUGGESTED = [
  "Why is this malicious?",
  "Show affected hosts",
  "What ATT&CK techniques were observed?",
  "Explain the sandbox findings",
];

export function CopilotPage() {
  const { data } = useInvestigations();
  const audit = useAudit();
  const [selected, setSelected] = useState<string>("");
  const [msgs, setMsgs] = useState<Msg[]>([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);

  const invId = selected || data?.[0]?.investigation_id || "";

  async function send(q: string) {
    if (!invId || !q.trim()) return;
    setMsgs((m) => [...m, { role: "user", text: q }]);
    setInput("");
    setBusy(true);
    try {
      const a = await askCopilot(invId, q);
      setMsgs((m) => [...m, { role: "assistant", text: a.answer, grounded: a.grounded_on }]);
      audit("copilot.ask", invId);
    } catch {
      setMsgs((m) => [...m, { role: "assistant", text: "The copilot is unavailable right now." }]);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex h-[calc(100vh-7rem)] flex-col">
      <PageHeader
        title="AI Security Copilot"
        description="Grounded, guard-railed analysis — never executes actions"
        actions={
          <select
            value={invId}
            onChange={(e) => {
              setSelected(e.target.value);
              setMsgs([]);
            }}
            className="h-9 rounded-md border border-border bg-surface-2 px-3 text-sm text-fg focus-ring"
          >
            {(data ?? []).length === 0 && <option value="">No investigations</option>}
            {(data ?? []).map((inv) => (
              <option key={inv.investigation_id} value={inv.investigation_id}>
                {inv.alert.title.slice(0, 50)}
              </option>
            ))}
          </select>
        }
      />

      <Card className="flex min-h-0 flex-1 flex-col">
        <div className="flex-1 space-y-4 overflow-y-auto p-4">
          {msgs.length === 0 ? (
            <EmptyState
              icon={<Bot className="h-8 w-8" />}
              title="Ask about this investigation"
              description="Answers are grounded strictly in the selected investigation's evidence."
            />
          ) : (
            msgs.map((m, i) => (
              <div key={i} className={`flex gap-3 ${m.role === "user" ? "justify-end" : ""}`}>
                {m.role === "assistant" && <Bot className="mt-1 h-5 w-5 shrink-0 text-accent" />}
                <div
                  className={`max-w-[80%] rounded-lg px-3 py-2 text-sm ${
                    m.role === "user" ? "bg-accent text-accent-fg" : "bg-surface-2 text-fg"
                  }`}
                >
                  <p className="whitespace-pre-wrap">{m.text}</p>
                  {m.grounded && m.grounded.length > 0 && (
                    <div className="mt-2 flex flex-wrap gap-1 border-t border-border pt-2">
                      {m.grounded.map((g, j) => (
                        <span key={j} className="rounded bg-[#0b1020] px-1.5 py-0.5 text-[10px] text-fg-subtle">
                          {g}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
                {m.role === "user" && <User className="mt-1 h-5 w-5 shrink-0 text-fg-subtle" />}
              </div>
            ))
          )}
        </div>

        <div className="border-t border-border p-3">
          <div className="mb-2 flex flex-wrap gap-1.5">
            {SUGGESTED.map((s) => (
              <button
                key={s}
                onClick={() => send(s)}
                disabled={busy || !invId}
                className="rounded-full border border-border px-2.5 py-1 text-xs text-fg-subtle hover:bg-[#172033] hover:text-fg disabled:opacity-50"
              >
                {s}
              </button>
            ))}
          </div>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              send(input);
            }}
            className="flex items-center gap-2"
          >
            <Input
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Ask the copilot…"
              disabled={busy || !invId}
            />
            <Button type="submit" size="icon" disabled={busy || !invId || !input.trim()}>
              {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />}
            </Button>
          </form>
        </div>
      </Card>
    </div>
  );
}
