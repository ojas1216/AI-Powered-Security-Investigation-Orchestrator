import { Navigate, Outlet, useLocation } from "react-router-dom";
import { useAuthStore } from "@/stores/auth";

/** Gate for authenticated areas. Unauthenticated users are sent to /login and
 *  returned to their target after sign-in. */
export function ProtectedRoute() {
  const authed = useAuthStore((s) => !!s.token && Date.now() < s.expiresAt);
  const location = useLocation();
  if (!authed) {
    return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  }
  return <Outlet />;
}
