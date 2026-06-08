import type { ReactNode } from "react";
import { Inbox, AlertCircle } from "lucide-react";
import { Spinner } from "@/components/ui/misc";
import { Button } from "@/components/ui/button";

export function EmptyState({
  icon,
  title,
  description,
  action,
}: {
  icon?: ReactNode;
  title: string;
  description?: string;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 rounded-lg border border-dashed border-border p-10 text-center">
      <div className="text-fg-subtle">{icon ?? <Inbox className="h-8 w-8" />}</div>
      <h3 className="text-sm font-semibold text-fg">{title}</h3>
      {description && <p className="max-w-md text-sm text-fg-subtle">{description}</p>}
      {action}
    </div>
  );
}

export function ErrorState({
  message,
  onRetry,
}: {
  message: string;
  onRetry?: () => void;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 rounded-lg border border-critical/30 bg-critical/5 p-8 text-center">
      <AlertCircle className="h-8 w-8 text-critical" />
      <p className="text-sm text-fg">{message}</p>
      {onRetry && (
        <Button variant="secondary" size="sm" onClick={onRetry}>
          Retry
        </Button>
      )}
    </div>
  );
}

export function LoadingState({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-2 p-10 text-sm text-fg-subtle">
      <Spinner /> {label}
    </div>
  );
}
