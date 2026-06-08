import { Component, type ErrorInfo, type ReactNode } from "react";
import { AlertTriangle } from "lucide-react";

interface Props {
  children: ReactNode;
}
interface State {
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    // In production this would forward to the observability backend (Loki/OTel).
    console.error("UI error boundary:", error, info.componentStack);
  }

  render() {
    if (this.state.error) {
      return (
        <div className="flex h-screen flex-col items-center justify-center gap-4 bg-bg p-6 text-center">
          <AlertTriangle className="h-10 w-10 text-critical" />
          <h1 className="text-lg font-semibold text-fg">Something went wrong</h1>
          <p className="max-w-md text-sm text-fg-subtle">
            The interface hit an unexpected error. Your session is safe; reload to continue.
          </p>
          <button
            onClick={() => window.location.reload()}
            className="rounded-md bg-accent px-4 py-2 text-sm font-medium text-accent-fg focus-ring"
          >
            Reload
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
