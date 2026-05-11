import {
  AppWindow,
  ClipboardList,
  Cpu,
  FileKey,
  KeyRound,
  LayoutDashboard,
  LucideIcon,
  ServerCog,
  Settings,
  Shield,
  ShieldAlert,
  UserCog,
  Users,
} from "lucide-react";

export interface AdminNavSection {
  slug: string;
  label: string;
  url: string;
  icon: LucideIcon;
  elevated?: boolean;
}

export const ADMIN_NAV_SECTIONS: AdminNavSection[] = [
  { slug: "overview",          label: "Overview",              url: "/dashboard",                       icon: LayoutDashboard },
  { slug: "users",             label: "Users",                 url: "/dashboard/users",                 icon: Users },
  { slug: "roles",             label: "Roles",                 url: "/dashboard/roles",                 icon: UserCog },
  { slug: "models",            label: "Models",                url: "/dashboard/models",                icon: Cpu },
  { slug: "applications",      label: "Applications",          url: "/dashboard/applications",          icon: AppWindow },
{ slug: "security",          label: "Security",              url: "/dashboard/security",              icon: Shield },
  { slug: "audit_logs",        label: "Audit Logs",            url: "/dashboard/audit-logs",            icon: ClipboardList },
  { slug: "security_keys",     label: "Security Keys",         url: "/dashboard/security-keys",         icon: KeyRound },
  { slug: "secure_files",      label: "Secure Files",          url: "/dashboard/secure-files",          icon: FileKey },
  { slug: "settings",          label: "Settings",              url: "/dashboard/settings",              icon: Settings },
  { slug: "emergency_actions", label: "Emergency Actions",     url: "/dashboard/emergency-actions",     icon: ShieldAlert, elevated: true },
  { slug: "system_config",     label: "System Configuration",  url: "/dashboard/system-configuration",  icon: ServerCog,   elevated: true },
];
