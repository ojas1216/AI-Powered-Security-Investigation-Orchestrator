import { useEffect } from "react";
import { BrowserRouter, useNavigate } from "react-router-dom";
import { QueryClientProvider } from "@tanstack/react-query";
import { queryClient } from "./queryClient";
import { AppRoutes } from "@/routing/AppRoutes";
import { ErrorBoundary } from "@/routing/ErrorBoundary";
import { AUTH_EXPIRED_EVENT } from "@/services/http";

/** Bridges the global "auth expired" event (fired by the axios interceptor) to
 *  router navigation, so a 401 anywhere bounces the user to /login. */
function AuthExpiryListener() {
  const navigate = useNavigate();
  useEffect(() => {
    const handler = () => navigate("/login", { replace: true });
    window.addEventListener(AUTH_EXPIRED_EVENT, handler);
    return () => window.removeEventListener(AUTH_EXPIRED_EVENT, handler);
  }, [navigate]);
  return null;
}

export function App() {
  return (
    <ErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <BrowserRouter>
          <AuthExpiryListener />
          <AppRoutes />
        </BrowserRouter>
      </QueryClientProvider>
    </ErrorBoundary>
  );
}
