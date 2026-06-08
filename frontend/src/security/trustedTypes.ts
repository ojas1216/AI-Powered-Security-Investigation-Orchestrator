import DOMPurify from "dompurify";

/**
 * Install a Trusted Types "default" policy so that, under a strict CSP
 * (`require-trusted-types-for 'script'`), any string assigned to a DOM sink is
 * sanitized by DOMPurify rather than rejected. React itself does not use these
 * sinks for normal rendering, so this is defense-in-depth against an accidental
 * innerHTML path or a third-party dependency.
 */
export function installTrustedTypes(): void {
  const tt = (window as unknown as { trustedTypes?: TrustedTypePolicyFactory }).trustedTypes;
  if (!tt || typeof tt.createPolicy !== "function") return;
  try {
    tt.createPolicy("default", {
      createHTML: (input: string) => DOMPurify.sanitize(input, { RETURN_TRUSTED_TYPE: false }),
      createScript: () => {
        throw new Error("Trusted Types: script creation is not allowed");
      },
      createScriptURL: (input: string) => {
        // Only allow same-origin script URLs.
        const u = new URL(input, window.location.origin);
        if (u.origin !== window.location.origin) {
          throw new Error("Trusted Types: cross-origin script URL blocked");
        }
        return input;
      },
    });
  } catch {
    /* A 'default' policy may already exist (HMR/dev) — safe to ignore. */
  }
}
