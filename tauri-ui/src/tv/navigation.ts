import {
  Activity,
  Download,
  LayoutDashboard,
  MonitorPlay,
  ScrollText,
  ShieldAlert,
  type LucideIcon,
} from "lucide-react";

export type TvOverviewSectionId = "overview" | "bindings" | "startup" | "updates" | "operations";
export type TvDashboardView = "overview" | "logs" | "settings" | "profile" | "update";

export interface TvDashboardNavItem {
  to: string;
  label: string;
  icon: LucideIcon;
  title: string;
  description: string;
  view: TvDashboardView;
  focusSection?: TvOverviewSectionId;
}

export const TV_NAV_ITEMS: TvDashboardNavItem[] = [
  {
    to: "/tv-overview",
    label: "Overview",
    icon: LayoutDashboard,
    title: "TV Command Center",
    description: "Global health, binding pressure, and quick operator actions for the signage runtime.",
    view: "overview",
    focusSection: "overview",
  },
  {
    to: "/tv-bindings",
    label: "Bindings",
    icon: MonitorPlay,
    title: "Screen Bindings",
    description: "Monitor assignments, runtime states, and per-screen support actions.",
    view: "overview",
    focusSection: "bindings",
  },
  {
    to: "/tv-startup",
    label: "Startup",
    icon: ShieldAlert,
    title: "Startup Safety",
    description: "Preflight checks, reconciliation history, and crash-recovery diagnostics.",
    view: "overview",
    focusSection: "startup",
  },
  {
    to: "/tv-updates",
    label: "Updates",
    icon: Download,
    title: "Software Updates",
    description: "Check for new MonClub TV releases, download and install updates.",
    view: "update",
  },
  {
    to: "/tv-operations",
    label: "Operations",
    icon: Activity,
    title: "Operations & Retention",
    description: "Retention cleanup, monitor discovery, and long-running operational visibility.",
    view: "overview",
    focusSection: "operations",
  },
  {
    to: "/tv-logs",
    label: "Logs",
    icon: ScrollText,
    title: "Runtime Logs",
    description: "Live TV runtime logs for player launch, recovery, sync, and update diagnostics.",
    view: "logs",
  },
];

export const TV_NAV_ITEM = TV_NAV_ITEMS[0];
