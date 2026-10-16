import { AlertCircle, CheckCircle2, ShieldAlert, Undo2 } from "lucide-react";
import type { UpdateLastResult, UpdateStatusResponse } from "@/api/types";

const REASONS: Record<string, string> = {
  crash: "the new version stopped right after it started",
  health_timeout: "the new version did not finish starting in time",
  interrupted: "the installation was interrupted (power cut or restart)",
  backup_failed: "the current version could not be backed up",
  setup_failed: "the installer failed",
  restore_failed: "the previous version could not be fully restored",
  same_version: "this version was already installed",
  user_rollback: "you went back to the previous version from the Update page",
  no_result: "the installer did not report a result",
};

function reasonText(reason: string | null | undefined): string {
  if (!reason) return "";
  if (reason.startsWith("setup_exit_")) return `the installer stopped (code ${reason.slice("setup_exit_".length)})`;
  return REASONS[reason] ?? reason;
}

function formatWhen(at: string | null | undefined): string {
  if (!at) return "";
  const d = new Date(at);
  return Number.isNaN(d.getTime()) ? "" : d.toLocaleString();
}

function LastResult({ result }: { result: UpdateLastResult }) {
  const when = formatWhen(result.at);
  if (result.result === "INSTALLED") {
    return (
      <div className="flex items-start gap-2 rounded-lg border border-emerald-500/30 bg-emerald-500/5 p-3 text-[12px]">
        <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-500" />
        <span className="text-foreground">
          Last update: {result.from || "?"} → {result.to || "?"} installed{when ? ` (${when})` : ""}.
        </span>
      </div>
    );
  }
  const rolledBack = result.result === "ROLLED_BACK";
  return (
    <div className="flex items-start gap-2 rounded-lg border border-amber-500/30 bg-amber-500/5 p-3 text-[12px]">
      {rolledBack ? <Undo2 className="h-4 w-4 shrink-0 text-amber-500" /> : <AlertCircle className="h-4 w-4 shrink-0 text-amber-500" />}
      <span className="text-foreground">
        Last update to {result.to || "?"} {rolledBack ? "was rolled back" : "did not install"}
        {result.reason ? `: ${reasonText(result.reason)}` : ""}. Version {result.installedNow || result.from || "?"} is running
        {when ? ` (${when})` : ""}.
      </span>
    </div>
  );
}

/** The installer's last result, a refused (unsigned / tampered) offer, the loop-guard
 *  warning and the last install error. */
export default function UpdateNotices({ status, installError }: { status: UpdateStatusResponse | null; installError: string | null }) {
  if (!status && !installError) return null;
  return (
    <div className="space-y-2">
      {status?.lastResult && <LastResult result={status.lastResult} />}
      {status?.verifyError && (
        <div className="flex items-start gap-2 rounded-lg border border-destructive/30 bg-destructive/5 p-3 text-[12px]">
          <ShieldAlert className="h-4 w-4 shrink-0 text-destructive" />
          <span className="text-foreground">
            Update {status.latestVersion ?? ""} refused: it is not a verified MonClub release ({status.verifyError}).
          </span>
        </div>
      )}
      {status?.updateAvailable && status.autoInstallBlocked && status.autoInstallBlockedReason?.startsWith("user_rollback") && (
        <div className="flex items-start gap-2 rounded-lg border border-amber-500/30 bg-amber-500/5 p-3 text-[12px]">
          <Undo2 className="h-4 w-4 shrink-0 text-amber-500" />
          <span className="text-foreground">
            You went back from version {status.latestVersion}: it will not be installed automatically again.
            "Restart to update" still installs it.
          </span>
        </div>
      )}
      {status?.updateAvailable && status.autoInstallBlocked && !status.autoInstallBlockedReason?.startsWith("user_rollback") && (
        <div className="flex items-start gap-2 rounded-lg border border-amber-500/30 bg-amber-500/5 p-3 text-[12px]">
          <AlertCircle className="h-4 w-4 shrink-0 text-amber-500" />
          <span className="text-foreground">
            Version {status.latestVersion} failed before ({reasonText(status.autoInstallBlockedReason)}) and will not be
            installed automatically again. "Restart to update" still tries it — the previous version comes back if it fails.
          </span>
        </div>
      )}
      {installError && (
        <div className="flex items-start gap-2 rounded-lg border border-destructive/30 bg-destructive/5 p-3 text-[12px]">
          <AlertCircle className="h-4 w-4 shrink-0 text-destructive" />
          <span className="text-foreground">The update did not start: {installError}. The app keeps running.</span>
        </div>
      )}
    </div>
  );
}
