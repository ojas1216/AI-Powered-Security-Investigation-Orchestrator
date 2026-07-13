/**
 * Approval queue: containment actions raised by the autonomous agent await a
 * human decision here. Deciding/executing needs `investigation:act`; the API
 * enforces it independently — buttons are gated for UX only.
 */
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { CheckCircle2, ClipboardCheck, ShieldAlert, XCircle } from "lucide-react";
import { PageHeader } from "@/components/common/PageHeader";
import { EmptyState, ErrorState, LoadingState } from "@/components/common/states";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useApprovals, useDecideApproval, useMarkExecuted } from "@/hooks/useApprovals";
import { useAuthStore } from "@/stores/auth";
import type { ApprovalRequest, ApprovalStatus } from "@/types/api";

const statusTone: Record<ApprovalStatus, "medium" | "low" | "critical" | "info" | "neutral"> = {
  pending: "medium",
  approved: "info",
  rejected: "critical",
  executed: "low",
  expired: "neutral",
};

const TABS: { value: ApprovalStatus | "all"; label: string }[] = [
  { value: "pending", label: "Pending" },
  { value: "approved", label: "Approved" },
  { value: "all", label: "All" },
];

export function ApprovalsPage() {
  const [tab, setTab] = useState<string>("pending");
  const status = tab === "all" ? undefined : (tab as ApprovalStatus);
  const { data, isLoading, isError, refetch } = useApprovals(status);
  const canAct = useAuthStore((s) => s.can("investigation:act"));

  return (
    <div>
      <PageHeader
        title="Approvals"
        description="Human sign-off for agent-recommended containment actions — nothing executes without a decision here."
      />
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          {TABS.map((t) => (
            <TabsTrigger key={t.value} value={t.value}>
              {t.label}
            </TabsTrigger>
          ))}
        </TabsList>
        {TABS.map((t) => (
          <TabsContent key={t.value} value={t.value}>
            {isLoading ? (
              <LoadingState label="Loading approvals…" />
            ) : isError ? (
              <ErrorState message="Could not load approvals." onRetry={refetch} />
            ) : !data?.length ? (
              <EmptyState
                icon={<ClipboardCheck className="h-8 w-8" />}
                title="Nothing waiting"
                description="Actionable investigations will queue containment steps here."
              />
            ) : (
              <div className="space-y-3">
                {data.map((req) => (
                  <ApprovalCard key={req.approval_id} req={req} canAct={canAct} />
                ))}
              </div>
            )}
          </TabsContent>
        ))}
      </Tabs>
    </div>
  );
}

function ApprovalCard({ req, canAct }: { req: ApprovalRequest; canAct: boolean }) {
  const [note, setNote] = useState("");
  const decide = useDecideApproval();
  const execute = useMarkExecuted();
  const busy = decide.isPending || execute.isPending;

  const expiresIn = useMemo(() => {
    const ms = new Date(req.expires_at).getTime() - Date.now();
    if (ms <= 0) return "expired";
    const hours = Math.floor(ms / 3_600_000);
    return hours >= 1 ? `${hours}h left` : `${Math.max(1, Math.floor(ms / 60_000))}m left`;
  }, [req.expires_at]);

  return (
    <Card>
      <CardContent className="space-y-3 pt-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <ShieldAlert className="h-4 w-4 text-high" />
            <span className="text-sm font-medium text-fg">{req.step.action}</span>
          </div>
          <div className="flex items-center gap-2">
            <Badge>{req.step.phase}</Badge>
            <Badge tone={statusTone[req.status]}>{req.status}</Badge>
            {req.status === "pending" && <Badge tone="neutral">{expiresIn}</Badge>}
          </div>
        </div>

        <p className="text-xs text-fg-subtle">{req.step.rationale}</p>
        <p className="text-xs text-fg-subtle">
          Investigation{" "}
          <Link
            to={`/investigations/${req.investigation_id}`}
            className="font-mono text-info hover:underline"
          >
            {req.investigation_id}
          </Link>{" "}
          · requested by {req.requested_by} ·{" "}
          {new Date(req.requested_at).toLocaleString()}
        </p>

        {req.decided_by && (
          <p className="text-xs text-fg-subtle">
            {req.status === "rejected" ? "Rejected" : "Approved"} by {req.decided_by}
            {req.decision_note ? ` — “${req.decision_note}”` : ""}
          </p>
        )}
        {req.executed_by && (
          <p className="text-xs text-fg-subtle">
            Executed by {req.executed_by}
            {req.execution_note ? ` — “${req.execution_note}”` : ""}
          </p>
        )}

        {canAct && req.status === "pending" && (
          <div className="flex flex-wrap items-center gap-2 border-t border-border pt-3">
            <Input
              value={note}
              onChange={(e) => setNote(e.target.value)}
              placeholder="Decision note (recorded in the audit trail)"
              className="max-w-md flex-1"
            />
            <Button
              size="sm"
              disabled={busy}
              onClick={() => decide.mutate({ id: req.approval_id, approve: true, note })}
            >
              <CheckCircle2 className="mr-1 h-4 w-4" /> Approve
            </Button>
            <Button
              size="sm"
              variant="secondary"
              disabled={busy}
              onClick={() => decide.mutate({ id: req.approval_id, approve: false, note })}
            >
              <XCircle className="mr-1 h-4 w-4" /> Reject
            </Button>
          </div>
        )}
        {canAct && req.status === "approved" && (
          <div className="flex flex-wrap items-center gap-2 border-t border-border pt-3">
            <Input
              value={note}
              onChange={(e) => setNote(e.target.value)}
              placeholder="Execution note (what was done, where)"
              className="max-w-md flex-1"
            />
            <Button
              size="sm"
              disabled={busy}
              onClick={() => execute.mutate({ id: req.approval_id, note })}
            >
              <ClipboardCheck className="mr-1 h-4 w-4" /> Mark executed
            </Button>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
