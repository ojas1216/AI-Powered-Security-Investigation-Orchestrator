import { useCallback, useState, type FormEvent } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { ShieldHalf, Loader2 } from "lucide-react";
import { config } from "@/lib/config";
import {
  loginNative,
  loginWithGoogle,
  loginWithPassword,
  registerUser,
} from "@/services/auth";
import { useAuthStore } from "@/stores/auth";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { GoogleSignInButton } from "@/components/auth/GoogleSignInButton";

type Mode = "signin" | "register";

export function LoginPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const setSession = useAuthStore((s) => s.setOidcSession);
  const setDev = useAuthStore((s) => s.setDevSession);

  const [mode, setMode] = useState<Mode>("signin");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const dest = (location.state as { from?: string } | null)?.from ?? "/dashboard";

  function goToDest() {
    navigate(dest, { replace: true });
  }

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      // Prefer native accounts; email that looks like a Keycloak username still
      // works via the password grant if the native login 404/401s.
      const s =
        mode === "register"
          ? await registerUser(email, password, displayName)
          : await loginNative(email, password).catch(async (err) => {
              // Fall back to Keycloak password grant if configured and native
              // login rejected the credentials (e.g. an SSO-only user).
              if (config.oidc.url && err?.response?.status === 401) {
                const t = await loginWithPassword(email, password);
                return {
                  access_token: t.accessToken,
                  token_type: "bearer",
                  expires_in: t.expiresIn,
                  email,
                  display_name: email,
                  tenant: "",
                  roles: [],
                };
              }
              throw err;
            });
      setSession(s.access_token, null, s.expires_in);
      goToDest();
    } catch (err: unknown) {
      const status = (err as { response?: { status?: number } })?.response?.status;
      setError(
        mode === "register"
          ? status === 409
            ? "An account with this email already exists."
            : "Registration failed. Use a valid email and a password of 10+ characters."
          : "Sign-in failed. Check your email and password.",
      );
    } finally {
      setBusy(false);
    }
  }

  const onGoogle = useCallback(
    async (credential: string) => {
      setBusy(true);
      setError("");
      try {
        const s = await loginWithGoogle(credential);
        setSession(s.access_token, null, s.expires_in);
        goToDest();
      } catch {
        setError("Google sign-in was rejected. Is AEGIS_GOOGLE_CLIENT_ID configured?");
      } finally {
        setBusy(false);
      }
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [],
  );

  function devLogin() {
    setDev("acme", ["tier3_analyst"]);
    goToDest();
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-bg p-6">
      <div className="w-full max-w-sm">
        <div className="mb-8 flex flex-col items-center text-center">
          <ShieldHalf className="h-10 w-10 text-accent" />
          <h1 className="mt-3 text-xl font-semibold text-fg">{config.app.name}</h1>
          <p className="mt-1 text-sm text-fg-subtle">{config.app.tagline}</p>
        </div>

        <div className="card space-y-4 p-6">
          {/* Sign in / Register toggle */}
          <div className="grid grid-cols-2 gap-1 rounded-lg bg-[#0d1526] p-1 text-sm">
            {(["signin", "register"] as Mode[]).map((m) => (
              <button
                key={m}
                type="button"
                onClick={() => {
                  setMode(m);
                  setError("");
                }}
                className={
                  "rounded-md py-1.5 font-medium transition " +
                  (mode === m
                    ? "bg-accent text-white"
                    : "text-fg-subtle hover:text-fg")
                }
              >
                {m === "signin" ? "Sign in" : "Register"}
              </button>
            ))}
          </div>

          <form onSubmit={onSubmit} className="space-y-4">
            {mode === "register" && (
              <div className="space-y-1.5">
                <label className="text-xs font-medium text-fg-subtle">Name</label>
                <Input
                  value={displayName}
                  onChange={(e) => setDisplayName(e.target.value)}
                  autoComplete="name"
                  placeholder="Jane Analyst"
                />
              </div>
            )}
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-fg-subtle">Email</label>
              <Input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                autoComplete="email"
                placeholder="you@company.com"
                required
              />
            </div>
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-fg-subtle">Password</label>
              <Input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete={mode === "register" ? "new-password" : "current-password"}
                placeholder={mode === "register" ? "10+ characters" : "••••••••"}
                required
              />
            </div>

            {error && <p className="text-sm text-critical">{error}</p>}

            <Button type="submit" className="w-full" disabled={busy}>
              {busy && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              {mode === "register" ? "Create account" : "Sign in"}
            </Button>
          </form>

          {config.googleClientId && (
            <>
              <div className="flex items-center gap-3">
                <div className="h-px flex-1 bg-border" />
                <span className="text-xs text-fg-subtle">or</span>
                <div className="h-px flex-1 bg-border" />
              </div>
              <GoogleSignInButton onCredential={onGoogle} onError={setError} />
            </>
          )}

          {config.devLoginEnabled && (
            <button
              type="button"
              onClick={devLogin}
              className="w-full text-center text-xs text-fg-subtle hover:text-fg"
            >
              Continue in dev mode (local API only)
            </button>
          )}
        </div>

        <p className="mt-4 text-center text-xs text-muted">
          Native accounts · Google Sign-In · OpenID Connect (Keycloak SSO)
        </p>
      </div>
    </div>
  );
}
