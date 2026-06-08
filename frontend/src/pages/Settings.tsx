import { useAuthStore } from "@/stores/auth";
import { config } from "@/lib/config";
import { PageHeader } from "@/components/common/PageHeader";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between border-b border-border py-2 text-sm last:border-0">
      <span className="text-fg-subtle">{label}</span>
      <span className="font-mono text-xs text-fg">{value}</span>
    </div>
  );
}

export function SettingsPage() {
  const user = useAuthStore((s) => s.user);
  const mode = useAuthStore((s) => s.mode);

  return (
    <div>
      <PageHeader title="Settings" description="Session, connection, and appearance" />
      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Session</CardTitle>
          </CardHeader>
          <CardContent>
            <Row label="User" value={user?.username ?? "—"} />
            <Row label="Tenant" value={user?.tenant ?? "—"} />
            <Row label="Roles" value={user?.roles.join(", ") ?? "—"} />
            <Row label="Auth mode" value={mode ?? "—"} />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Connection</CardTitle>
          </CardHeader>
          <CardContent>
            <Row label="API base" value={config.apiBaseUrl} />
            <Row label="OIDC issuer" value={`${config.oidc.url}/realms/${config.oidc.realm}`} />
            <Row label="OIDC client" value={config.oidc.clientId} />
            <Row label="Version" value={config.app.version} />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Appearance</CardTitle>
          </CardHeader>
          <CardContent>
            <Row label="Theme" value="Dark (enterprise)" />
            <Row label="Font" value="Inter" />
            <p className="pt-3 text-xs text-muted">
              AegisFlow ships dark-mode-first for low-light SOC environments. Tokens are defined
              in <code className="text-fg-subtle">src/index.css</code> via the Tailwind v4 theme.
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Security</CardTitle>
          </CardHeader>
          <CardContent className="space-y-1.5 text-xs text-fg-subtle">
            <p>• Access tokens are held in memory only — never localStorage/sessionStorage.</p>
            <p>• Trusted Types + DOMPurify policy installed; CSP enforced by nginx in production.</p>
            <p>• Tenant is taken from the signed token; the API enforces RBAC + RLS independently.</p>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
