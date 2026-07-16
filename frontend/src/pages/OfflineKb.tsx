/**
 * Offline knowledge base — ATT&CK technique + CVE lookup served from the
 * air-gapped bundled datasets. Backed by /offline/{status,attack,cve}.
 */
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Database, Loader2, Search } from "lucide-react";
import { lookupCve, lookupTechnique, offlineStatus } from "@/services/platform";
import { PageHeader } from "@/components/common/PageHeader";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import type { AttackTechnique, CveRecord } from "@/types/api";

export function OfflineKbPage() {
  const { data: status } = useQuery({ queryKey: ["offline-status"], queryFn: offlineStatus });
  const [cveId, setCveId] = useState("CVE-2021-44228");
  const [techId, setTechId] = useState("T1059.001");
  const [cve, setCve] = useState<CveRecord | null>(null);
  const [tech, setTech] = useState<AttackTechnique | null>(null);
  const [cveErr, setCveErr] = useState("");
  const [techErr, setTechErr] = useState("");
  const [busy, setBusy] = useState(false);

  async function doCve() {
    setBusy(true);
    setCveErr("");
    try {
      setCve(await lookupCve(cveId.trim()));
    } catch {
      setCve(null);
      setCveErr("Not in the offline CVE set.");
    } finally {
      setBusy(false);
    }
  }

  async function doTech() {
    setBusy(true);
    setTechErr("");
    try {
      setTech(await lookupTechnique(techId.trim()));
    } catch {
      setTech(null);
      setTechErr("Not in the offline ATT&CK set.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <PageHeader
        title="Offline Knowledge Base"
        description="ATT&CK, CVE and Sigma served locally — works fully air-gapped."
      />

      {status && (
        <div className="mb-5 flex flex-wrap gap-2">
          {status.map((d) => (
            <Badge key={d.name} tone="neutral">
              <Database className="mr-1 h-3 w-3" />
              {d.name}: {d.records} · {d.loaded_from}
            </Badge>
          ))}
        </div>
      )}

      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">CVE lookup</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 pt-0">
            <form
              onSubmit={(e) => {
                e.preventDefault();
                void doCve();
              }}
              className="flex gap-2"
            >
              <Input value={cveId} onChange={(e) => setCveId(e.target.value)}
                     placeholder="CVE-2021-44228" />
              <Button type="submit" size="sm" disabled={busy}>
                <Search className="h-4 w-4" />
              </Button>
            </form>
            {cveErr && <p className="text-sm text-critical">{cveErr}</p>}
            {cve && (
              <div className="space-y-2 rounded-md border border-border p-3">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-sm text-fg">{cve.cve_id}</span>
                  <Badge tone={cve.cvss >= 9 ? "critical" : cve.cvss >= 7 ? "high" : "medium"}>
                    CVSS {cve.cvss}
                  </Badge>
                </div>
                <p className="text-sm text-fg-subtle">{cve.summary}</p>
                {cve.cwe && <Badge tone="neutral">{cve.cwe}</Badge>}
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">ATT&CK technique lookup</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 pt-0">
            <form
              onSubmit={(e) => {
                e.preventDefault();
                void doTech();
              }}
              className="flex gap-2"
            >
              <Input value={techId} onChange={(e) => setTechId(e.target.value)}
                     placeholder="T1059.001" />
              <Button type="submit" size="sm" disabled={busy}>
                {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
              </Button>
            </form>
            {techErr && <p className="text-sm text-critical">{techErr}</p>}
            {tech && (
              <div className="space-y-1 rounded-md border border-border p-3">
                <span className="font-mono text-sm text-fg">{tech.technique_id}</span>
                <div className="text-sm text-fg">{tech.name}</div>
                <Badge tone="medium">{tech.tactic}</Badge>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
