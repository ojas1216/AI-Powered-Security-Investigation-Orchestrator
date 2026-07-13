import { Navigate, Route, Routes } from "react-router-dom";
import { ProtectedRoute } from "./ProtectedRoute";
import { RoleGuard } from "./RoleGuard";
import { AppShell } from "@/components/layout/AppShell";
import { LoginPage } from "@/pages/Login";
import { DashboardPage } from "@/pages/Dashboard";
import { AlertsPage } from "@/pages/Alerts";
import { InvestigationsPage } from "@/pages/Investigations";
import { InvestigationDetailPage } from "@/pages/InvestigationDetail";
import { CasesPage } from "@/pages/Cases";
import { ThreatIntelPage } from "@/pages/ThreatIntel";
import { IocReportPage } from "@/pages/IocReport";
import { EvidenceVaultPage } from "@/pages/EvidenceVault";
import { TimelinePage } from "@/pages/Timeline";
import { AttackGraphPage } from "@/pages/AttackGraph";
import { MitrePage } from "@/pages/Mitre";
import { ApprovalsPage } from "@/pages/Approvals";
import { ReportsPage } from "@/pages/Reports";
import { CopilotPage } from "@/pages/Copilot";
import { AdministrationPage } from "@/pages/Administration";
import { SettingsPage } from "@/pages/Settings";
import { NotFoundPage } from "@/pages/NotFound";

export function AppRoutes() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route element={<ProtectedRoute />}>
        <Route element={<AppShell />}>
          <Route index element={<Navigate to="/dashboard" replace />} />
          <Route path="/dashboard" element={<DashboardPage />} />
          <Route path="/alerts" element={<AlertsPage />} />
          <Route path="/investigations" element={<InvestigationsPage />} />
          <Route path="/investigations/:id" element={<InvestigationDetailPage />} />
          <Route path="/cases" element={<CasesPage />} />
          <Route path="/threat-intel" element={<ThreatIntelPage />} />
          <Route path="/ioc-report" element={<IocReportPage />} />
          <Route path="/evidence" element={<EvidenceVaultPage />} />
          <Route path="/timeline" element={<TimelinePage />} />
          <Route path="/graph" element={<AttackGraphPage />} />
          <Route path="/mitre" element={<MitrePage />} />
          <Route path="/approvals" element={<ApprovalsPage />} />
          <Route path="/reports" element={<ReportsPage />} />
          <Route path="/copilot" element={<CopilotPage />} />
          <Route
            path="/admin"
            element={
              <RoleGuard perm="admin:*">
                <AdministrationPage />
              </RoleGuard>
            }
          />
          <Route path="/settings" element={<SettingsPage />} />
          <Route path="*" element={<NotFoundPage />} />
        </Route>
      </Route>
    </Routes>
  );
}
