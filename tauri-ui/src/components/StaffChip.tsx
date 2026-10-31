import type { StaffBlock } from "@/api/types";
import { ApiError } from "@/api/client";
import { Avatar, Chip } from "@/components/ui/chip";
import { ActionButton, type ActionButtonProps } from "@/components/ui/action-button";
import { DropdownMenu, DropdownMenuContent, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { initialsOf } from "@/components/ui/tone";
import { ChevronDown, UserRoundX } from "lucide-react";

export function staffTime(value?: string | null) {
  return value?.match(/T(\d{2}:\d{2})/)?.[1] ?? "—";
}

export function staffPermissionHint(staff: StaffBlock | undefined, permission: string, label: string): string {
  if (!staff?.enabled) return "";
  if (staff.offline?.active) {
    if (!["DRIVER", "ALL_TURNSTILES"].includes(staff.offline.role)) return "Hors ligne : utilisez le PC pilote pour les modifications.";
    if (!staff.offline.unlocked) return "Déverrouillez le mode hors ligne pour utiliser cette action.";
    const actor = staff.allowedAgents.find((person) => person.id === staff.offline?.actAs?.id);
    if (!actor) return "Choisissez la personne au nom de laquelle agir.";
    if (actor.adminAgent || ["ACTIVE_MEMBERSHIP_MANAGEMENT", permission].every((p) => actor.permissions?.includes(p))) return "";
    return `${actor.name} n'a pas la permission « ${label} »`;
  }
  if (!staff.agent) return "Connectez-vous au tableau de bord pour utiliser cette action";
  if (staff.agent.adminAgent || ["ACTIVE_MEMBERSHIP_MANAGEMENT", permission].every((p) => staff.permissions.includes(p))) return "";
  return `${staff.agent.name} n'a pas la permission « ${label} »`;
}

export function StaffActionButton({ staff, permission, permissionLabel, disabled, ...props }: ActionButtonProps & {
  staff?: StaffBlock; permission: string; permissionLabel: string;
}) {
  const hint = staffPermissionHint(staff, permission, permissionLabel);
  if (!hint) return <ActionButton disabled={disabled} {...props} />;
  return <Tooltip><TooltipTrigger asChild><span tabIndex={0} className="inline-flex cursor-not-allowed"><ActionButton {...props} disabled /></span></TooltipTrigger><TooltipContent className="max-w-[310px]">{hint}</TooltipContent></Tooltip>;
}

export function staffError(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.code === "NO_AGENT") return "Connectez-vous au tableau de bord pour utiliser cette action.";
    if (error.code === "MISSING_PERMISSION") return "L'agent actuel n'a pas la permission d'utiliser cette action.";
    if (error.code === "OFFLINE") return String(error.payload?.error || "Internet requis pour cette action.");
    if (error.code === "OFFLINE_LOCKED") return "Internet indisponible – passez en mode hors ligne";
    if (error.code === "READER_OFFLINE") return "Hors ligne : utilisez le PC pilote pour les modifications.";
    if (error.code === "LIMIT_REACHED") return "Limite atteinte pour aujourd'hui. Utilisez le tableau de bord pour continuer. La porte s'ouvre toujours.";
    const body = error.payload;
    const message = body?.errorMsg || body?.message || body?.error;
    if (typeof message === "string") return message;
    return error.message;
  }
  return String(error);
}

export function staffResultUnknown(error: unknown): boolean {
  return !(error instanceof ApiError) || error.code === "OFFLINE" || error.status >= 500;
}

export default function StaffChip({ staff }: { staff?: StaffBlock }) {
  if (!staff?.enabled || staff.offline?.active) return null;
  const current = staff.agent;
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button type="button" className="inline-flex h-9 shrink-0 items-center gap-2 rounded-lg border border-grey/32 bg-card px-2.5 text-[13px] font-bold focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary">
          {current ? <Avatar initials={initialsOf(current.name)} tone="primary" size={32} className="h-6 w-6 text-[10px]" /> : <UserRoundX className="h-4 w-4 text-muted-foreground" />}
          {current ? `Agent : ${current.name}` : "Aucun agent"}
          {current && <span className="hidden font-normal text-muted-foreground xl:inline">· depuis {staffTime(current.since)}</span>}
          <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" />
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-[330px] max-w-[calc(100vw-2rem)] rounded-xl p-3">
        <div className="pb-2 text-[11px] font-bold tracking-wide text-muted-foreground">PERSONNEL AUTORISÉ SUR ACCESS</div>
        <div className="max-h-[300px] overflow-auto">
          {staff.allowedAgents.map((person) => <div key={person.id} className={`flex items-center gap-2.5 rounded-lg px-2 py-2 ${person.id === current?.id ? "bg-primary/8" : ""}`}>
            <Avatar initials={initialsOf(person.name)} tone="primary" />
            <div className="min-w-0 flex-1"><div className="truncate text-[13px] font-semibold">{person.name}</div><div className="text-[12px] text-muted-foreground">{person.adminAgent ? "Admin" : "Agent"}</div></div>
            {person.id === current?.id && <Chip tone="primary" size="sm">Actuel</Chip>}
          </div>)}
          {staff.allowedAgents.length === 0 && <div className="py-2 text-[13px] text-muted-foreground">Aucun membre du personnel autorisé.</div>}
        </div>
        <div className="mt-2 border-t border-dashed border-grey/24 pt-3 text-[12.5px] leading-relaxed text-muted-foreground">Pour changer d'agent, connectez-vous au tableau de bord.</div>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
