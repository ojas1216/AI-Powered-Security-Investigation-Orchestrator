import { useState, type FormEvent } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { ShieldHalf, Loader2 } from "lucide-react";
import { config } from "@/lib/config";
import { loginWithPassword } from "@/services/auth";
import { useAuthStore } from "@/stores/auth";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

export function LoginPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const setOidc = useAuthStore((s) => s.setOidcSession);
  const setDev = useAuthStore((s) => s.setDevSession);
  const [username, setUsername] = useState("analyst");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const dest = (location.state as { from?: string } | null)?.from ?? "/dashboard";

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      const t = await loginWithPassword(username, password);
      setOidc(t.accessToken, t.refreshToken, t.expiresIn);
      navigate(dest, { replace: true });
    } catch {
      setError("Sign-in failed. Check your credentials or Keycloak availability.");
    } finally {
      setBusy(false);
    }
  }

  function devLogin() {
    // Local-only: header-based principal honored when the API runs with
    // AEGIS_AUTH_DEV_BYPASS=true. Disabled in production builds.
    setDev("acme", ["tier3_analyst"]);
    navigate(dest, { replace: true });
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-bg p-6">
      <div className="w-full max-w-sm">
        <div className="mb-8 flex flex-col items-center text-center">
          <ShieldHalf className="h-10 w-10 text-accent" />
          <h1 className="mt-3 text-xl font-semibold text-fg">{config.app.name}</h1>
          <p className="mt-1 text-sm text-fg-subtle">{config.app.tagline}</p>
        </div>

        <form onSubmit={onSubmit} className="card space-y-4 p-6">
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-fg-subtle">Username</label>
            <Input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" />
          </div>
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-fg-subtle">Password</label>
            <Input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
              placeholder="••••••••"
            />
          </div>

          {error && <p className="text-sm text-critical">{error}</p>}

          <Button type="submit" disabled={busy} className="w-full">
            {busy && <Loader2 className="h-4 w-4 animate-spin" />}
            Sign in with Keycloak
          </Button>

          {config.devLoginEnabled && (
            <button
              type="button"
              onClick={devLogin}
              className="w-full text-center text-xs text-fg-subtle hover:text-fg"
            >
              Continue in dev mode (local API only)
            </button>
          )}
        </form>

        <p className="mt-4 text-center text-xs text-muted">
          Protected by OpenID Connect · OAuth 2.1 · MFA enforced in Keycloak
        </p>
      </div>
    </div>
  );
}
