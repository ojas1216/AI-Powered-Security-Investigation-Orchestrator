/**
 * "Sign in with Google" using Google Identity Services (GIS).
 *
 * The GIS script is loaded lazily and only when a client id is configured, so
 * the app has no hard dependency on Google. GIS returns a signed ID token
 * (credential) which we hand to the backend (/auth/google) for verification —
 * the browser never trusts it directly. If no client id is set, the button is
 * not rendered.
 */
import { useEffect, useRef } from "react";
import { config } from "@/lib/config";

const GIS_SRC = "https://accounts.google.com/gsi/client";

interface GoogleCredentialResponse {
  credential: string;
}

declare global {
  interface Window {
    google?: {
      accounts: {
        id: {
          initialize: (opts: {
            client_id: string;
            callback: (resp: GoogleCredentialResponse) => void;
          }) => void;
          renderButton: (parent: HTMLElement, opts: Record<string, unknown>) => void;
        };
      };
    };
  }
}

function loadGis(): Promise<void> {
  return new Promise((resolve, reject) => {
    if (window.google?.accounts?.id) return resolve();
    const existing = document.querySelector<HTMLScriptElement>(`script[src="${GIS_SRC}"]`);
    if (existing) {
      existing.addEventListener("load", () => resolve());
      existing.addEventListener("error", () => reject(new Error("gis load failed")));
      return;
    }
    const script = document.createElement("script");
    script.src = GIS_SRC;
    script.async = true;
    script.defer = true;
    script.onload = () => resolve();
    script.onerror = () => reject(new Error("gis load failed"));
    document.head.appendChild(script);
  });
}

export function GoogleSignInButton({
  onCredential,
  onError,
}: {
  onCredential: (credential: string) => void;
  onError?: (message: string) => void;
}) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!config.googleClientId) return;
    let cancelled = false;
    loadGis()
      .then(() => {
        if (cancelled || !ref.current || !window.google) return;
        window.google.accounts.id.initialize({
          client_id: config.googleClientId,
          callback: (resp) => onCredential(resp.credential),
        });
        window.google.accounts.id.renderButton(ref.current, {
          theme: "filled_black",
          size: "large",
          width: 320,
          text: "continue_with",
          shape: "rectangular",
        });
      })
      .catch(() => onError?.("Could not load Google Sign-In."));
    return () => {
      cancelled = true;
    };
  }, [onCredential, onError]);

  if (!config.googleClientId) return null;
  return <div ref={ref} className="flex justify-center" />;
}
