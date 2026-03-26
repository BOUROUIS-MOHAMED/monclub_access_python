import { useCallback, useEffect, useRef, useState } from "react";
import {
  getAccessUpdateStatus,
  checkAccessUpdate,
  downloadAccessUpdate,
  installAccessUpdate,
  cancelAccessUpdate,
  getAccessVersionInfo,
} from "@/api/accessUpdate";
import type { UpdateStatusResponse, UpdateVersionInfoResponse } from "@/api/types";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { cn } from "@/lib/utils";
import {
  Download,
  Zap,
  CheckCircle2,
  RefreshCw,
  Trash2,
  AlertCircle,
  Calendar,
  CalendarClock,
  HardDrive,
  Tag,
  Info,
  Shield,
  Loader2,
} from "lucide-react";

function formatBytes(bytes: number | null | undefined): string {
  if (!bytes) return "—";
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function formatDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleDateString(undefined, {
      year: "numeric",
      month: "long",
      day: "numeric",
    });
  } catch {
    return iso;
  }
}

function VersionBadge({ version, codename, variant = "latest" }: { version: string; codename?: string | null; variant?: "current" | "latest" }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-[12px] font-semibold tracking-wide",
        variant === "latest"
          ? "bg-gradient-to-r from-primary/20 to-primary/10 text-primary border border-primary/20"
          : "bg-muted text-muted-foreground border border-border",
      )}
    >
      <Tag className="h-3 w-3" />
      {version}{codename ? ` ${codename}` : ""}
    </span>
  );
}

function MetaRow({ icon: Icon, label, value }: { icon: React.ElementType; label: string; value: string }) {
  return (
    <div className="flex items-center gap-2.5 text-[13px]">
      <Icon className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
      <span className="text-muted-foreground">{label}</span>
      <span className="font-medium text-foreground ml-auto">{value}</span>
    </div>
  );
}

export default function UpdatePage() {
  const [status, setStatus] = useState<UpdateStatusResponse | null>(null);
  const [versionInfo, setVersionInfo] = useState<UpdateVersionInfoResponse | null>(null);
  const [checking, setChecking] = useState(false);
  const [downloading, setDownloading] = useState(false);
  const [installing, setInstalling] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const fetchStatus = useCallback(async () => {
    try {
      const s = await getAccessUpdateStatus();
      setStatus(s);
    } catch {
      // silent
    }
  }, []);

  useEffect(() => {
    fetchStatus();
    getAccessVersionInfo().then(setVersionInfo).catch(() => {});
    pollRef.current = setInterval(fetchStatus, 3000);
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, [fetchStatus]);

  const handleCheck = async () => {
    setChecking(true);
    try {
      await checkAccessUpdate();
      await fetchStatus();
    } catch {
      // silent
    } finally {
      setChecking(false);
    }
  };

  const handleDownload = async () => {
    setDownloading(true);
    try {
      await downloadAccessUpdate();
    } catch {
      // silent
    } finally {
      setDownloading(false);
    }
  };

  const handleInstall = async () => {
    setInstalling(true);
    try {
      await installAccessUpdate();
    } catch {
      setInstalling(false);
    }
  };

  const handleCancel = async () => {
    setCancelling(true);
    try {
      await cancelAccessUpdate();
      await fetchStatus();
    } catch {
      // silent
    } finally {
      setCancelling(false);
    }
  };

  const curVersion = status?.currentVersion ?? versionInfo?.currentVersion ?? "0.0.0";
  const curCodename = status?.currentCodename ?? versionInfo?.currentCodename ?? "";
  const isDownloading = status?.downloading ?? false;
  const progress = status?.progressPercent ?? null;
  const updateAvailable = status?.updateAvailable ?? false;

  return (
    <ScrollArea className="h-full">
      <div className="max-w-2xl mx-auto px-6 py-8 space-y-6">

        {/* Header */}
        <div className="flex items-start justify-between gap-4">
          <div>
            <h1 className="text-xl font-semibold text-foreground">MonClub Access</h1>
            <p className="text-[13px] text-muted-foreground mt-0.5">Software updates & release notes</p>
          </div>
          <Button
            variant="outline"
            size="sm"
            className="gap-2 text-[13px] shrink-0"
            onClick={handleCheck}
            disabled={checking}
          >
            {checking ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}
            Check for updates
          </Button>
        </div>

        {/* Current Version Card */}
        <div className="rounded-xl border border-border bg-card p-4 space-y-3">
          <div className="flex items-center gap-2">
            <div className="h-7 w-7 rounded-lg bg-primary/10 flex items-center justify-center">
              <Shield className="h-4 w-4 text-primary" />
            </div>
            <span className="text-[13px] font-medium text-foreground">Installed version</span>
          </div>
          <div className="flex items-center gap-3">
            <VersionBadge version={curVersion} codename={curCodename} variant="current" />
            {!updateAvailable && (
              <span className="flex items-center gap-1.5 text-[12px] text-emerald-500 font-medium">
                <CheckCircle2 className="h-3.5 w-3.5" />
                Up to date
              </span>
            )}
          </div>
        </div>

        {/* Update Available Card */}
        {updateAvailable && status && (
          <div className="rounded-xl border border-primary/20 bg-gradient-to-b from-primary/5 to-transparent overflow-hidden">
            {/* Top accent bar */}
            <div className="h-1 bg-gradient-to-r from-primary via-primary/70 to-primary/30" />

            <div className="p-5 space-y-5">
              {/* Version header */}
              <div className="flex items-start justify-between gap-3">
                <div className="space-y-1.5">
                  <div className="flex items-center gap-2">
                    <Zap className="h-4 w-4 text-primary" />
                    <span className="text-[13px] font-semibold text-foreground">Update available</span>
                  </div>
                  {status.latestVersion && (
                    <VersionBadge version={status.latestVersion} codename={status.latestCodename} variant="latest" />
                  )}
                </div>
              </div>

              <Separator className="opacity-50" />

              {/* Metadata */}
              <div className="space-y-2.5">
                {status.releaseDate && (
                  <MetaRow icon={Calendar} label="Released" value={formatDate(status.releaseDate)} />
                )}
                {status.availableUntil && (
                  <MetaRow icon={CalendarClock} label="Available until" value={formatDate(status.availableUntil)} />
                )}
                {status.sizeBytes && (
                  <MetaRow icon={HardDrive} label="Size" value={formatBytes(status.sizeBytes)} />
                )}
              </div>

              {/* Release notes */}
              {status.releaseNotes && (
                <>
                  <Separator className="opacity-50" />
                  <div>
                    <div className="flex items-center gap-1.5 mb-3">
                      <Info className="h-3.5 w-3.5 text-muted-foreground" />
                      <span className="text-[12px] font-medium text-muted-foreground uppercase tracking-wider">Release notes</span>
                    </div>
                    <div
                      className="prose prose-sm dark:prose-invert max-w-none text-[13px] leading-relaxed [&_h1]:text-base [&_h2]:text-[13px] [&_h3]:text-[13px] [&_ul]:pl-4 [&_li]:my-0.5 [&_p]:my-1"
                      dangerouslySetInnerHTML={{ __html: status.releaseNotes }}
                    />
                  </div>
                </>
              )}

              <Separator className="opacity-50" />

              {/* Download / Install actions */}
              <div className="space-y-3">
                {/* Progress bar */}
                {isDownloading && progress !== null && (
                  <div className="space-y-1.5">
                    <div className="flex justify-between text-[12px] text-muted-foreground">
                      <span>Downloading update…</span>
                      <span>{progress}%</span>
                    </div>
                    <Progress value={progress} className="h-2" />
                  </div>
                )}
                {isDownloading && progress === null && (
                  <div className="flex items-center gap-2 text-[13px] text-muted-foreground">
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                    <span>Downloading…</span>
                  </div>
                )}

                {/* Action buttons */}
                <div className="flex items-center gap-2">
                  {!status.downloaded && !isDownloading && (
                    <Button
                      className="gap-2 flex-1"
                      onClick={handleDownload}
                      disabled={downloading}
                    >
                      {downloading
                        ? <Loader2 className="h-4 w-4 animate-spin" />
                        : <Download className="h-4 w-4" />
                      }
                      Download update
                    </Button>
                  )}

                  {status.downloaded && !isDownloading && (
                    <>
                      <Button
                        className="gap-2 flex-1 bg-emerald-600 hover:bg-emerald-700 text-white"
                        onClick={handleInstall}
                        disabled={installing}
                      >
                        {installing
                          ? <Loader2 className="h-4 w-4 animate-spin" />
                          : <Zap className="h-4 w-4" />
                        }
                        Install now
                      </Button>
                      <Button
                        variant="outline"
                        size="icon"
                        className="h-9 w-9 text-muted-foreground hover:text-destructive hover:border-destructive/50"
                        onClick={handleCancel}
                        disabled={cancelling}
                        title="Delete downloaded file"
                      >
                        {cancelling
                          ? <Loader2 className="h-3.5 w-3.5 animate-spin" />
                          : <Trash2 className="h-3.5 w-3.5" />
                        }
                      </Button>
                    </>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* No update state */}
        {!updateAvailable && status && (
          <div className="rounded-xl border border-border bg-card/50 p-6 text-center space-y-2">
            <div className="flex justify-center">
              <div className="h-10 w-10 rounded-full bg-emerald-500/10 flex items-center justify-center">
                <CheckCircle2 className="h-5 w-5 text-emerald-500" />
              </div>
            </div>
            <p className="text-[14px] font-medium text-foreground">You're up to date</p>
            <p className="text-[12px] text-muted-foreground">
              MonClub Access {curVersion}{curCodename ? ` "${curCodename}"` : ""} is the latest version.
            </p>
            {status.lastCheckAt && (
              <p className="text-[11px] text-muted-foreground/60">
                Last checked {new Date(status.lastCheckAt * 1000).toLocaleTimeString()}
              </p>
            )}
          </div>
        )}

      </div>
    </ScrollArea>
  );
}
