import { useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { ArrowLeft, FileJson, FileText, GitBranch, Printer, ShieldCheck, Ticket, TrendingUp, Trash2 } from "lucide-react";
import { useInvestigation } from "@/hooks/useInvestigations";
import { useAuthStore } from "@/stores/auth";
import { useNotesStore } from "@/stores/notes";
import { exportHtml, exportJson, exportPdf } from "@/lib/export";
import { PageHeader } from "@/components/common/PageHeader";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { LoadingState, ErrorState, EmptyState } from "@/components/common/states";
import { SeverityBadge, VerdictBadge } from "@/components/common/badges";
import { RiskMeter } from "@/components/common/RiskMeter";
import { CopyButton } from "@/components/common/CopyButton";
import { IocTable } from "@/components/investigation/IocTable";
import { TimelineView } from "@/components/investigation/TimelineView";
import { AttackGraph } from "@/components/graph/AttackGraph";
import { MitreMatrix } from "@/components/mitre/MitreMatrix";
import { AgentTrace } from "@/components/investigation/AgentTrace";
import { PlanGraph } from "@/components/investigation/PlanGraph";
import { Reflections } from "@/components/investigation/Reflections";
import { Consensus } from "@/components/investigation/Consensus";
import { IncidentDna } from "@/components/investigation/IncidentDna";
import { ActorBadge } from "@/components/investigation/ActorBadge";
import { DetectionsPanel } from "@/components/investigation/DetectionsPanel";
import { RelatedCases } from "@/components/investigation/RelatedCases";
import { runAgent } from "@/services/platform";
import type { InvestigationPackage } from "@/types/api";

export function InvestigationDetailPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { data: pkg, isLoading, isError, refetch } = useInvestigation(id);
  const [tab, setTab] = useState("overview");

  if (isLoading) return <LoadingState label="Loading investigation…" />;
  if (isError || !pkg) return <ErrorState message="Investigation not found or access denied." onRetry={refetch} />;

  return (
    <div>
      <button onClick={() => navigate(-1)} className="mb-3 flex items-center gap-1 text-sm text-fg-subtle hover:text-fg">
        <ArrowLeft className="h-4 w-4" /> Back
      </button>
      <PageHeader
        title={pkg.alert.title}
        description={`${pkg.investigation_id} · tenant ${pkg.tenant}`}
        actions={
          <div className="flex items-center gap-2">
            <VerdictBadge verdict={pkg.overall_verdict} />
            {pkg.risk && <SeverityBadge severity={pkg.risk.severity} />}
            {pkg.attribution && pkg.attribution.actor_type !== "unattributed" && (
              <ActorBadge attribution={pkg.attribution} />
            )}
          </div>
        }
      />

      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          {["overview", "plan", "agent-trace", "detections", "timeline", "evidence", "threat-intel", "mitre", "graph", "notes", "reports"].map((t) => (
            <TabsTrigger key={t} value={t}>
              {t.replace("-", " ").replace(/\b\w/g, (c) => c.toUpperCase())}
            </TabsTrigger>
          ))}
        </TabsList>

        <TabsContent value="overview">
          <Overview pkg={pkg} />
        </TabsContent>
        <TabsContent value="plan">
          <Card>
            <CardHeader>
              <CardTitle>Execution Graph ({pkg.plan_graph?.length ?? 0} tasks)</CardTitle>
            </CardHeader>
            <CardContent>
              <PlanGraph nodes={pkg.plan_graph ?? []} />
            </CardContent>
          </Card>
        </TabsContent>
        <TabsContent value="agent-trace">
          <Card>
            <CardHeader>
              <CardTitle>Agent Reasoning Trace ({pkg.agent_trace?.length ?? 0} steps)</CardTitle>
            </CardHeader>
            <CardContent>
              <AgentTrace steps={pkg.agent_trace ?? []} />
            </CardContent>
          </Card>
        </TabsContent>
        <TabsContent value="detections">
          <div className="space-y-4">
            <RuleExport pkg={pkg} />
            <DetectionsPanel detections={pkg.detections ?? []} />
          </div>
        </TabsContent>
        <TabsContent value="timeline">
          <Card>
            <CardContent className="pt-4">
              <TimelineView events={pkg.timeline} />
            </CardContent>
          </Card>
        </TabsContent>
        <TabsContent value="evidence">
          <EvidenceTab pkg={pkg} />
        </TabsContent>
        <TabsContent value="threat-intel">
          <IocTable iocs={pkg.iocs} />
        </TabsContent>
        <TabsContent value="mitre">
          <Card>
            <CardHeader>
              <CardTitle>ATT&CK Coverage ({pkg.mitre.length})</CardTitle>
            </CardHeader>
            <CardContent>
              {pkg.mitre.length ? <MitreMatrix techniques={pkg.mitre} /> : <EmptyState title="No techniques mapped" />}
            </CardContent>
          </Card>
        </TabsContent>
        <TabsContent value="graph">
          <AttackGraph pkg={pkg} />
        </TabsContent>
        <TabsContent value="notes">
          <NotesTab pkg={pkg} />
        </TabsContent>
        <TabsContent value="reports">
          <ReportsTab pkg={pkg} />
        </TabsContent>
      </Tabs>
    </div>
  );
}

function Overview({ pkg }: { pkg: InvestigationPackage }) {
  const malicious = pkg.iocs.filter((e) => e.verdict === "malicious");
  return (
    <div className="grid gap-4 lg:grid-cols-3">
      {(pkg.related_investigations?.length ?? 0) > 0 && (
        <div className="lg:col-span-3">
          <RelatedCases cases={pkg.related_investigations} />
        </div>
      )}

      {pkg.consensus && (
        <div className="lg:col-span-3">
          <Consensus consensus={pkg.consensus} />
        </div>
      )}

      {pkg.incident_dna && (
        <div className="lg:col-span-3">
          <IncidentDna dna={pkg.incident_dna} matches={pkg.dna_matches ?? []} />
        </div>
      )}

      {(pkg.reflections?.length ?? 0) > 0 && (
        <div className="lg:col-span-3">
          <Reflections findings={pkg.reflections} />
        </div>
      )}

      {pkg.business_impact && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-sm">
              <TrendingUp className="h-4 w-4 text-high" /> Business Impact
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 pt-0">
            <div className="flex items-center gap-2">
              <SeverityBadge severity={pkg.business_impact.level} />
              <span className="text-sm text-fg">{pkg.business_impact.estimated_cost_band}</span>
            </div>
            <div className="text-xs text-fg-subtle">
              Blast radius: {pkg.business_impact.blast_radius_hosts} host(s),{" "}
              {pkg.business_impact.blast_radius_users} user(s)
            </div>
            <div className="flex flex-wrap gap-1">
              {pkg.business_impact.affected_asset_classes.map((c) => (
                <span key={c} className="rounded bg-[#172033] px-1.5 py-0.5 text-xs text-fg-subtle">{c}</span>
              ))}
            </div>
            <div className="text-xs text-fg-subtle">Downtime: {pkg.business_impact.downtime_risk}</div>
          </CardContent>
        </Card>
      )}

      {pkg.root_cause && (
        <Card className="lg:col-span-2">
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-sm">
              <GitBranch className="h-4 w-4 text-info" /> Root Cause
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 pt-0">
            <div className="text-sm text-fg">
              Initial vector: <span className="font-medium">{pkg.root_cause.initial_vector}</span>
            </div>
            {pkg.root_cause.kill_chain.length > 0 && (
              <div className="flex flex-wrap items-center gap-1 text-xs text-fg-subtle">
                {pkg.root_cause.kill_chain.map((t, i) => (
                  <span key={t} className="flex items-center gap-1">
                    <span className="rounded bg-[#172033] px-1.5 py-0.5">{t}</span>
                    {i < pkg.root_cause!.kill_chain.length - 1 && <span>→</span>}
                  </span>
                ))}
              </div>
            )}
            <p className="text-xs text-fg-subtle">{pkg.root_cause.narrative}</p>
          </CardContent>
        </Card>
      )}
      <Card className="flex flex-col items-center justify-center gap-3 p-6">
        {pkg.risk ? <RiskMeter risk={pkg.risk} /> : <span className="text-fg-subtle">No risk score</span>}
        {pkg.risk && (
          <ul className="w-full space-y-1 text-xs text-fg-subtle">
            {pkg.risk.rationale.map((r, i) => (
              <li key={i} className="flex gap-1.5">
                <ShieldCheck className="mt-0.5 h-3 w-3 shrink-0 text-low" /> {r}
              </li>
            ))}
          </ul>
        )}
      </Card>

      <Card className="lg:col-span-2">
        <CardHeader>
          <CardTitle>Executive Summary</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <p className="whitespace-pre-wrap text-sm text-fg-subtle">{pkg.executive_summary || "—"}</p>
          <div className="grid grid-cols-2 gap-3 text-sm">
            <Field label="Affected Hosts" value={pkg.affected_hosts.join(", ") || "none"} />
            <Field label="Affected Users" value={pkg.affected_users.join(", ") || "none"} />
          </div>
          {pkg.tickets.length > 0 && (
            <div className="flex flex-wrap gap-2">
              {pkg.tickets.map((t) => (
                <span key={t.ticket_id} className="inline-flex items-center gap-1 rounded bg-[#172033] px-2 py-1 text-xs text-fg-subtle">
                  <Ticket className="h-3 w-3" /> {t.system}:{t.ticket_id}
                </span>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      <Card className="lg:col-span-2">
        <CardHeader>
          <CardTitle>Key Malicious Indicators ({malicious.length})</CardTitle>
        </CardHeader>
        <CardContent>
          {malicious.length ? <IocTable iocs={malicious} /> : <EmptyState title="No malicious indicators" />}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Recommended Playbook</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
          {pkg.playbook.map((s, i) => (
            <div key={i} className="rounded-md border border-border p-2.5">
              <div className="text-xs font-semibold uppercase text-accent">{s.phase}</div>
              <div className="text-sm text-fg">{s.action}</div>
              <div className="text-xs text-fg-subtle">{s.rationale}</div>
            </div>
          ))}
          {pkg.playbook.length === 0 && <EmptyState title="No recommendations" />}
        </CardContent>
      </Card>
    </div>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="text-xs uppercase text-muted">{label}</div>
      <div className="text-fg">{value}</div>
    </div>
  );
}

function RuleExport({ pkg }: { pkg: InvestigationPackage }) {
  const [rule, setRule] = useState<{ kind: string; text: string } | null>(null);
  const [busy, setBusy] = useState("");

  async function gen(kind: "sigma" | "yara") {
    setBusy(kind);
    try {
      if (kind === "sigma") {
        const r = await runAgent("sigma_generator", {
          title: pkg.alert.title,
          iocs: pkg.iocs,
          detections: pkg.detections,
        });
        setRule({ kind: "Sigma", text: String(r.data.sigma ?? "") });
      } else {
        const hashes = pkg.iocs
          .filter((e) => ["sha256", "sha1", "md5"].includes(e.ioc.type))
          .map((e) => e.ioc.value);
        const r = await runAgent("yara_generator", {
          rule_name: pkg.alert.source_alert_id,
          hashes,
          strings: [],
        });
        setRule({ kind: "YARA", text: String(r.data.yara ?? "") });
      }
    } catch {
      setRule({ kind, text: "Generation failed." });
    } finally {
      setBusy("");
    }
  }

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between pb-2">
        <CardTitle className="text-sm">Generate detection from this case</CardTitle>
        <div className="flex gap-2">
          <Button size="sm" variant="secondary" disabled={!!busy} onClick={() => gen("sigma")}>
            {busy === "sigma" ? "…" : "Sigma"}
          </Button>
          <Button size="sm" variant="secondary" disabled={!!busy} onClick={() => gen("yara")}>
            {busy === "yara" ? "…" : "YARA"}
          </Button>
        </div>
      </CardHeader>
      {rule && (
        <CardContent className="pt-0">
          <div className="mb-1 flex items-center justify-between">
            <span className="text-xs text-fg-subtle">{rule.kind} rule</span>
            <CopyButton value={rule.text} />
          </div>
          <pre className="max-h-80 overflow-auto rounded-md border border-border bg-[#0d1526] p-3 text-xs text-fg-subtle">
            {rule.text}
          </pre>
        </CardContent>
      )}
    </Card>
  );
}

function EvidenceTab({ pkg }: { pkg: InvestigationPackage }) {
  if (pkg.evidence.length === 0) return <EmptyState title="No evidence collected" />;
  return (
    <Card className="overflow-hidden">
      <table className="w-full text-sm">
        <thead className="border-b border-border text-left text-xs uppercase text-fg-subtle">
          <tr>
            <th className="px-4 py-2.5 font-medium">Kind</th>
            <th className="px-4 py-2.5 font-medium">Label</th>
            <th className="px-4 py-2.5 font-medium">SHA-256 (chain of custody)</th>
            <th className="px-4 py-2.5 font-medium">Collected</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-border">
          {pkg.evidence.map((ev) => (
            <tr key={ev.sha256}>
              <td className="px-4 py-3"><span className="rounded bg-[#172033] px-1.5 py-0.5 text-xs">{ev.kind}</span></td>
              <td className="px-4 py-3 text-fg">{ev.label}</td>
              <td className="px-4 py-3">
                <div className="flex items-center gap-1.5">
                  <code className="font-mono text-[11px] text-fg-subtle">{ev.sha256.slice(0, 24)}…</code>
                  <CopyButton value={ev.sha256} />
                </div>
              </td>
              <td className="px-4 py-3 text-xs text-muted">{new Date(ev.collected_at).toLocaleString()}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </Card>
  );
}

function NotesTab({ pkg }: { pkg: InvestigationPackage }) {
  const username = useAuthStore((s) => s.user?.username ?? "analyst");
  const notes = useNotesStore((s) => s.byInvestigation[pkg.investigation_id] ?? []);
  const add = useNotesStore((s) => s.add);
  const remove = useNotesStore((s) => s.remove);
  const [text, setText] = useState("");
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Card>
        <CardHeader>
          <CardTitle>Add Note</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
          <Textarea rows={4} value={text} onChange={(e) => setText(e.target.value)} placeholder="Analyst observations…" />
          <Button
            size="sm"
            disabled={!text.trim()}
            onClick={() => {
              add(pkg.investigation_id, username, text.trim());
              setText("");
            }}
          >
            Add note
          </Button>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Notes ({notes.length})</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
          {notes.length === 0 && <EmptyState title="No notes yet" />}
          {notes.map((n) => (
            <div key={n.id} className="group rounded-md border border-border p-2.5">
              <div className="flex items-center justify-between text-xs text-muted">
                <span>{n.author} · {new Date(n.ts).toLocaleString()}</span>
                <button onClick={() => remove(pkg.investigation_id, n.id)} className="opacity-0 group-hover:opacity-100">
                  <Trash2 className="h-3.5 w-3.5 text-fg-subtle hover:text-critical" />
                </button>
              </div>
              <p className="mt-1 whitespace-pre-wrap text-sm text-fg">{n.text}</p>
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}

function ReportsTab({ pkg }: { pkg: InvestigationPackage }) {
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-2">
        <Button variant="secondary" size="sm" onClick={() => exportPdf(pkg)}>
          <Printer className="h-4 w-4" /> PDF
        </Button>
        <Button variant="secondary" size="sm" onClick={() => exportHtml(pkg)}>
          <FileText className="h-4 w-4" /> HTML
        </Button>
        <Button variant="secondary" size="sm" onClick={() => exportJson(pkg)}>
          <FileJson className="h-4 w-4" /> JSON
        </Button>
      </div>
      <Card>
        <CardHeader>
          <CardTitle>Analyst Report</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="whitespace-pre-wrap text-sm text-fg-subtle">{pkg.analyst_report || "—"}</p>
        </CardContent>
      </Card>
    </div>
  );
}
