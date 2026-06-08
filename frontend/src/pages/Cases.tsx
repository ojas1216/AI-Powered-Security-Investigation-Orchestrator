import { FolderKanban } from "lucide-react";
import { PageHeader } from "@/components/common/PageHeader";
import { EmptyState } from "@/components/common/states";

export function CasesPage() {
  return (
    <div>
      <PageHeader title="Cases" description="Group related investigations into incident cases" />
      <EmptyState
        icon={<FolderKanban className="h-8 w-8" />}
        title="Case management is not yet wired to a backend"
        description="The current API exposes investigations, not multi-investigation cases. This view activates once a /cases endpoint is available — no placeholder data is shown by design."
      />
    </div>
  );
}
