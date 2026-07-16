/**
 * Relationship graph for a dossier — a dependency-free hub-and-spoke SVG placing
 * the indicator at the center with edges to related IPs, domains, hashes, malware
 * families and correlated campaigns. Deterministic layout, theme-aware.
 */
import type { DossierRelationships } from "@/types/api";

interface Node {
  label: string;
  kind: string;
  color: string;
}

const KIND_COLOR: Record<string, string> = {
  ip: "#38bdf8",
  domain: "#a78bfa",
  hash: "#f472b6",
  malware: "#f87171",
  campaign: "#fbbf24",
};

export function DossierGraph({
  indicator,
  rel,
}: {
  indicator: string;
  rel: DossierRelationships;
}) {
  const nodes: Node[] = [
    ...rel.related_ips.map((v) => ({ label: v, kind: "ip", color: KIND_COLOR.ip })),
    ...rel.related_domains.map((v) => ({ label: v, kind: "domain", color: KIND_COLOR.domain })),
    ...rel.related_hashes.map((v) => ({ label: short(v), kind: "hash", color: KIND_COLOR.hash })),
    ...rel.threat_actors.map((v) => ({ label: v, kind: "malware", color: KIND_COLOR.malware })),
    ...rel.campaigns.map((v) => ({ label: short(v), kind: "campaign", color: KIND_COLOR.campaign })),
  ].slice(0, 18);

  if (!nodes.length) return null;

  const W = 640;
  const H = 340;
  const cx = W / 2;
  const cy = H / 2;
  const r = Math.min(W, H) / 2 - 70;

  return (
    <div className="overflow-x-auto">
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full" style={{ minWidth: 480 }}>
        {nodes.map((n, i) => {
          const a = (2 * Math.PI * i) / nodes.length - Math.PI / 2;
          const x = cx + r * Math.cos(a);
          const y = cy + r * Math.sin(a);
          return (
            <g key={i}>
              <line x1={cx} y1={cy} x2={x} y2={y} stroke="#233048" strokeWidth={1} />
              <circle cx={x} cy={y} r={5} fill={n.color} />
              <text
                x={x}
                y={y + (Math.sin(a) >= 0 ? 16 : -10)}
                textAnchor="middle"
                fontSize={10}
                fill="#94a3b8"
              >
                {truncate(n.label, 22)}
              </text>
            </g>
          );
        })}
        <circle cx={cx} cy={cy} r={9} fill="#22c55e" />
        <text x={cx} y={cy - 16} textAnchor="middle" fontSize={12} fill="#e2e8f0"
              fontWeight={600}>
          {truncate(indicator, 30)}
        </text>
      </svg>
      <div className="mt-1 flex flex-wrap gap-3 text-xs text-fg-subtle">
        {Object.entries(KIND_COLOR).map(([k, c]) => (
          <span key={k} className="inline-flex items-center gap-1">
            <span className="inline-block h-2 w-2 rounded-full" style={{ background: c }} />
            {k}
          </span>
        ))}
      </div>
    </div>
  );
}

function short(v: string): string {
  return v.length > 14 ? v.slice(0, 12) + "…" : v;
}
function truncate(v: string, n: number): string {
  return v.length > n ? v.slice(0, n - 1) + "…" : v;
}
