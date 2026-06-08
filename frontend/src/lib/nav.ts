import {
  LayoutDashboard,
  BellRing,
  Microscope,
  FolderKanban,
  ShieldAlert,
  Archive,
  Clock,
  Share2,
  Grid3x3,
  FileText,
  Bot,
  ShieldCheck,
  Settings,
  type LucideIcon,
} from "lucide-react";
import type { Permission } from "./rbac";

export interface NavItem {
  to: string;
  label: string;
  icon: LucideIcon;
  /** If set, the item is hidden unless the user holds this permission. */
  perm?: Permission;
}

export const NAV: NavItem[] = [
  { to: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { to: "/alerts", label: "Alerts", icon: BellRing },
  { to: "/investigations", label: "Investigations", icon: Microscope },
  { to: "/cases", label: "Cases", icon: FolderKanban },
  { to: "/threat-intel", label: "Threat Intelligence", icon: ShieldAlert },
  { to: "/evidence", label: "Evidence Vault", icon: Archive },
  { to: "/timeline", label: "Timeline", icon: Clock },
  { to: "/graph", label: "Attack Graph", icon: Share2 },
  { to: "/mitre", label: "MITRE ATT&CK", icon: Grid3x3 },
  { to: "/reports", label: "Reports", icon: FileText },
  { to: "/copilot", label: "AI Copilot", icon: Bot },
  { to: "/admin", label: "Administration", icon: ShieldCheck, perm: "admin:*" },
  { to: "/settings", label: "Settings", icon: Settings },
];
