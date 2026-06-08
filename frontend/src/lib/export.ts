import type { InvestigationPackage } from "@/types/api";

function download(filename: string, content: string, type: string) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export function exportJson(pkg: InvestigationPackage) {
  download(`investigation-${pkg.investigation_id.slice(0, 8)}.json`, JSON.stringify(pkg, null, 2), "application/json");
}

const esc = (s: string) =>
  s.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]!);

/** Build a self-contained, sanitized HTML report (no external resources, no inline JS). */
export function buildReportHtml(pkg: InvestigationPackage): string {
  const iocRows = pkg.iocs
    .map(
      (e) =>
        `<tr><td>${esc(e.ioc.type)}</td><td>${esc(e.ioc.value)}</td><td>${esc(e.verdict)}</td><td>${Math.round(
          e.confidence * 100,
        )}%</td></tr>`,
    )
    .join("");
  const mitreRows = pkg.mitre.map((t) => `<li>${esc(t.technique_id)} — ${esc(t.name)} (${esc(t.tactic)})</li>`).join("");
  const steps = pkg.playbook.map((s) => `<li><b>${esc(s.phase)}</b>: ${esc(s.action)}</li>`).join("");
  return `<!doctype html><html><head><meta charset="utf-8"><title>Investigation ${esc(
    pkg.investigation_id,
  )}</title><style>
    body{font-family:Inter,Arial,sans-serif;max-width:820px;margin:32px auto;color:#111;padding:0 16px}
    h1{font-size:20px} h2{font-size:15px;border-bottom:1px solid #ddd;padding-bottom:4px;margin-top:24px}
    table{border-collapse:collapse;width:100%;font-size:12px} td,th{border:1px solid #ddd;padding:6px;text-align:left}
    .tag{display:inline-block;padding:2px 8px;border-radius:10px;background:#eee;font-size:12px}
  </style></head><body>
    <h1>AegisFlow Investigation Report</h1>
    <p><span class="tag">${esc(pkg.overall_verdict)}</span> Risk ${pkg.risk?.score ?? "n/a"} (${esc(
    pkg.risk?.severity ?? "n/a",
  )}) · ${esc(pkg.investigation_id)}</p>
    <h2>Alert</h2><p>${esc(pkg.alert.title)}</p>
    <h2>Executive Summary</h2><p>${esc(pkg.executive_summary)}</p>
    <h2>Analyst Report</h2><p>${esc(pkg.analyst_report)}</p>
    <h2>Indicators (${pkg.iocs.length})</h2>
    <table><tr><th>Type</th><th>Value</th><th>Verdict</th><th>Confidence</th></tr>${iocRows}</table>
    <h2>MITRE ATT&CK</h2><ul>${mitreRows}</ul>
    <h2>Affected</h2><p>Hosts: ${esc(pkg.affected_hosts.join(", ") || "none")}<br/>Users: ${esc(
    pkg.affected_users.join(", ") || "none",
  )}</p>
    <h2>Recommended Playbook</h2><ul>${steps}</ul>
  </body></html>`;
}

export function exportHtml(pkg: InvestigationPackage) {
  download(`investigation-${pkg.investigation_id.slice(0, 8)}.html`, buildReportHtml(pkg), "text/html");
}

/** Open a print dialog (the browser's "Save as PDF" produces the PDF export). */
export function exportPdf(pkg: InvestigationPackage) {
  const w = window.open("", "_blank", "noopener,noreferrer");
  if (!w) return;
  w.document.write(buildReportHtml(pkg));
  w.document.close();
  w.focus();
  setTimeout(() => w.print(), 300);
}
