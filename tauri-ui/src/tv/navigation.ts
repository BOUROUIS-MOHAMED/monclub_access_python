import {
  Activity,
  Download,
  LayoutDashboard,
  MonitorPlay,
  ShieldAlert,
  type LucideIcon,
} from "lucide-react";

export type TvOverviewSectionId = "overview" | "bindings" | "startup" | "updates" | "operations";

export interface TvDashboardNavItem {
  to: string;
  label: string;
  icon: LucideIcon;
  title: string;
  description: string;
  focusSection: TvOverviewSectionId;
}

export const TV_NAV_ITEMS: TvDashboardNavItem[] = [
  {
    to: "/tv-overview",
    label: "Overview",
    icon: LayoutDashboard,
    title: "TV Command Center",
    description: "Global health, binding pressure, and quick operator actions for the signage runtime.",
    focusSection: "overview",
  },
  {
    to: "/tv-bindings",
    label: "Bindings",
    icon: MonitorPlay,
    title: "Screen Bindings",
    description: "Monitor assignments, runtime states, and per-screen support actions.",
    focusSection: "bindings",
  },
  {
    to: "/tv-startup",
    label: "Startup",
    icon: ShieldAlert,
    title: "Startup Safety",
    description: "Preflight checks, reconciliation history, and crash-recovery diagnostics.",
    focusSection: "startup",
  },
  {
    to: "/tv-updates",
    label: "Updates",
    icon: Download,
    title: "Update Runtime",
    description: "Standalone MonClub TV release status, download progress, and install readiness.",
    focusSection: "updates",
  },
  {
    to: "/tv-operations",
    label: "Operations",
    icon: Activity,
    title: "Operations & Retention",
    description: "Retention cleanup, monitor discovery, and long-running operational visibility.",
    focusSection: "operations",
  },
];

export const TV_NAV_ITEM = TV_NAV_ITEMS[0];
