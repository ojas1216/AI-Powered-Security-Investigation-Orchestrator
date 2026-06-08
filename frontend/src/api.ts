// Typed API client. Auth token + tenant are supplied by the host (Keycloak via
// the gateway in production). For the local dev console we read them from a
// short-lived in-memory session, never localStorage (XSS-resistant).
import type { InvestigationPackage } from "./types";

interface Session {
  token: string;
  tenant: string;
  roles: string;
}

let session: Session = { token: "dev", tenant: "acme", roles: "tier3_analyst" };

export function setSession(s: Partial<Session>) {
  session = { ...session, ...s };
}

function headers(): HeadersInit {
  return {
    "Content-Type": "application/json",
    Authorization: `Bearer ${session.token}`,
    "X-Tenant-ID": session.tenant,
    "X-Roles": session.roles,
  };
}

async function handle<T>(resp: Response): Promise<T> {
  if (!resp.ok) {
    const body = await resp.json().catch(() => ({}));
    throw new Error(body?.error?.message ?? `Request failed: ${resp.status}`);
  }
  return resp.json() as Promise<T>;
}

export async function listInvestigations(): Promise<InvestigationPackage[]> {
  return handle(await fetch("/api/v1/investigations", { headers: headers() }));
}

export async function ingestSampleAlert(): Promise<InvestigationPackage> {
  const sample = {
    source: "sentinel",
    properties: {
      incidentNumber: "INC-204815",
      title: "Phishing email reported by user — suspicious invoice link",
      description:
        "Body contains hxxps://evil[.]com/pay and Invoice_8841.lnk on WS-FIN-042",
      severity: "high",
      entities: [{ kind: "Host", hostName: "WS-FIN-042" }],
    },
    message_id: "phish-0001",
  };
  return handle(
    await fetch("/api/v1/alerts/ingest", {
      method: "POST",
      headers: headers(),
      body: JSON.stringify(sample),
    })
  );
}

export async function askCopilot(
  investigationId: string,
  question: string
): Promise<{ answer: string; grounded_on: string[] }> {
  return handle(
    await fetch("/api/v1/copilot/ask", {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({ investigation_id: investigationId, question }),
    })
  );
}
