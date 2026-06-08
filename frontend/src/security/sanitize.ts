import DOMPurify from "dompurify";

/**
 * Sanitize untrusted text for safe display. The API returns analyst/AI narratives
 * and IOC values that originate from attacker-controlled material (emails, sandbox
 * notes). We render them as TEXT (never via dangerouslySetInnerHTML); this helper is
 * used for the rare case where limited inline markup is desired.
 */
export function sanitizeHtml(dirty: string): string {
  return DOMPurify.sanitize(dirty, {
    ALLOWED_TAGS: ["b", "i", "em", "strong", "code", "br", "span"],
    ALLOWED_ATTR: [],
  });
}

/** Neutralize IOC values for display so they cannot be accidentally clicked/executed. */
export function defang(value: string): string {
  return value
    .replace(/^https?:\/\//i, (m) => m.replace("tp", "xp"))
    .replace(/\./g, "[.]")
    .replace(/@/g, "[at]");
}
