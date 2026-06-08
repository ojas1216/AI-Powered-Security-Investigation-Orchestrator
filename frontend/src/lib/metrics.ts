import type { InvestigationPackage, Severity } from "@/types/api";

export interface DashboardMetrics {
  total: number;
  open: number;
  malicious: number;
  today: number;
  tiHits: number;
  affectedAssets: number;
  affectedUsers: number;
  mitreCoverage: number;
  severityDist: { name: Severity; value: number }[];
  verdictDist: { name: string; value: number }[];
  mttrSeconds: number | null;
  volumeByHour: { hour: string; count: number }[];
}

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export function computeMetrics(items: InvestigationPackage[]): DashboardMetrics {
  const startOfToday = new Date();
  startOfToday.setHours(0, 0, 0, 0);

  const hosts = new Set<string>();
  const users = new Set<string>();
  const techniques = new Set<string>();
  let tiHits = 0;
  let malicious = 0;
  let today = 0;
  const sev: Record<string, number> = {};
  const verdict: Record<string, number> = {};
  const mttrSamples: number[] = [];
  const hourBuckets: Record<string, number> = {};

  for (const inv of items) {
    inv.affected_hosts.forEach((h) => hosts.add(h));
    inv.affected_users.forEach((u) => users.add(u));
    inv.mitre.forEach((t) => techniques.add(t.technique_id));
    tiHits += inv.iocs.filter((e) => e.verdict === "malicious").length;
    if (inv.overall_verdict === "malicious") malicious++;
    verdict[inv.overall_verdict] = (verdict[inv.overall_verdict] ?? 0) + 1;
    if (inv.risk) sev[inv.risk.severity] = (sev[inv.risk.severity] ?? 0) + 1;
    if (new Date(inv.created_at) >= startOfToday) today++;
    if (inv.completed_at) {
      mttrSamples.push((new Date(inv.completed_at).getTime() - new Date(inv.created_at).getTime()) / 1000);
    }
    const h = new Date(inv.created_at);
    const key = `${String(h.getHours()).padStart(2, "0")}:00`;
    hourBuckets[key] = (hourBuckets[key] ?? 0) + 1;
  }

  const volumeByHour = Array.from({ length: 24 }, (_, i) => {
    const hour = `${String(i).padStart(2, "0")}:00`;
    return { hour, count: hourBuckets[hour] ?? 0 };
  });

  return {
    total: items.length,
    open: items.filter((i) => i.status === "running" || i.status === "queued").length,
    malicious,
    today,
    tiHits,
    affectedAssets: hosts.size,
    affectedUsers: users.size,
    mitreCoverage: techniques.size,
    severityDist: SEVERITIES.map((name) => ({ name, value: sev[name] ?? 0 })).filter((d) => d.value > 0),
    verdictDist: Object.entries(verdict).map(([name, value]) => ({ name, value })),
    mttrSeconds: mttrSamples.length
      ? mttrSamples.reduce((a, b) => a + b, 0) / mttrSamples.length
      : null,
    volumeByHour,
  };
}

export function formatDuration(seconds: number | null): string {
  if (seconds == null) return "—";
  if (seconds < 1) return `${Math.round(seconds * 1000)} ms`;
  if (seconds < 60) return `${seconds.toFixed(1)} s`;
  const m = Math.floor(seconds / 60);
  return `${m}m ${Math.round(seconds % 60)}s`;
}
