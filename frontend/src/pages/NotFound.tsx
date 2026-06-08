import { Link } from "react-router-dom";
import { Compass } from "lucide-react";

export function NotFoundPage() {
  return (
    <div className="flex flex-1 flex-col items-center justify-center gap-3 p-16 text-center">
      <Compass className="h-10 w-10 text-fg-subtle" />
      <h1 className="text-lg font-semibold text-fg">Page not found</h1>
      <p className="text-sm text-fg-subtle">The page you’re looking for doesn’t exist.</p>
      <Link to="/dashboard" className="text-sm text-accent hover:underline">
        Back to dashboard
      </Link>
    </div>
  );
}
