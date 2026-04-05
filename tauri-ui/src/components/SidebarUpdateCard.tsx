import { ArrowRight, Download, Loader2, Sparkles } from "lucide-react";
import { cn } from "@/lib/utils";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import Lottie from "lottie-react";
import catAnimation from "@/assets/animations/cat-playing.json";


interface SidebarUpdateCardProps {
  updateAvailable: boolean;
  latestVersion?: string | null;
  latestCodename?: string | null;
  sidebarOpen: boolean;
  onClick: () => void;
  // New props — reflect background download state
  downloaded: boolean;
  downloading: boolean;
  progressPercent?: number | null;
}

export function SidebarUpdateCard({
  updateAvailable,
  latestVersion,
  latestCodename,
  sidebarOpen,
  onClick,
  downloaded,
  downloading,
  progressPercent,
}: SidebarUpdateCardProps) {
  if (!updateAvailable) return null;

  // Sub-label text changes based on download state
  const subLabel = downloading
    ? progressPercent != null
      ? `Downloading... ${progressPercent}%`
      : "Downloading..."
    : downloaded
    ? "Restart to update"
    : "Download update";

  return (
    <div className="shrink-0 px-3 pb-3">
      {sidebarOpen ? (
        <button
          onClick={onClick}
          className="group relative w-full overflow-hidden rounded-xl bg-card border border-border/50 text-left transition-all hover:border-primary/50 hover:shadow-[0_0_20px_-5px_hsl(var(--primary)/0.3)]"
        >
          {/* Subtle animated background gradient */}
          <div className="absolute inset-0 bg-gradient-to-br from-primary/5 via-transparent to-transparent opacity-50 group-hover:opacity-100 transition-opacity duration-500" />

          {/* Top border glow */}
          <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-primary/50 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500" />

          {/* Lottie Animation Header */}
          <div className="relative h-[88px] w-full bg-primary/[0.04] overflow-hidden flex items-center justify-center border-b border-border/40">
            <Lottie
              animationData={catAnimation}
              loop={true}
              className="absolute w-[140px] h-[140px] pointer-events-none"
            />
          </div>

          <div className="relative p-3.5">
            <div className="flex items-start justify-between mb-2.5">
              <div className="flex items-center gap-2">
                <div className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-primary/10 text-primary ring-1 ring-primary/25 group-hover:bg-primary/20 transition-colors">
                  <Sparkles className="h-3.5 w-3.5" />
                </div>
                <span className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground group-hover:text-primary transition-colors">
                  Update Ready
                </span>
              </div>
              <span className="flex h-2 w-2 mt-1 relative">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-primary opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-primary"></span>
              </span>
            </div>

            <div className="space-y-1">
              <div className="flex flex-wrap items-baseline gap-1.5">
                <span className="text-sm font-semibold tracking-tight text-foreground">
                  {latestVersion ? `Version ${latestVersion}` : "New version"}
                </span>
                {latestCodename && (
                  <span className="text-[11px] font-medium text-muted-foreground border border-border rounded-full px-1.5 py-0.5 bg-muted/50">
                    {latestCodename}
                  </span>
                )}
              </div>
              <p className="text-[12px] text-muted-foreground flex items-center gap-1 group-hover:text-foreground transition-colors">
                {downloading && <Loader2 className="h-3 w-3 animate-spin" />}
                {subLabel}
                {!downloading && (
                  <ArrowRight className="h-3 w-3 inline-block -translate-x-1 opacity-0 group-hover:translate-x-0 group-hover:opacity-100 transition-all duration-300" />
                )}
              </p>
            </div>
          </div>
        </button>
      ) : (
        <Tooltip>
          <TooltipTrigger asChild>
            <button
              onClick={onClick}
              className="group relative flex h-10 w-full items-center justify-center overflow-hidden rounded-xl bg-card border border-border/50 hover:border-primary/50 transition-all hover:shadow-[0_0_15px_-5px_hsl(var(--primary)/0.3)]"
            >
              <div className="absolute inset-0 bg-primary/5 opacity-0 group-hover:opacity-100 transition-opacity" />
              {downloading
                ? <Loader2 className="relative h-4 w-4 text-primary animate-spin" />
                : <Download className="relative h-4 w-4 text-muted-foreground group-hover:text-primary transition-colors" />
              }
              <span className="absolute top-1.5 right-1.5 flex h-1.5 w-1.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-primary opacity-75"></span>
                <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-primary"></span>
              </span>
            </button>
          </TooltipTrigger>
          <TooltipContent side="right" className="font-medium text-[12px]">
            {downloading
              ? progressPercent != null ? `Downloading... ${progressPercent}%` : "Downloading..."
              : downloaded
              ? `Restart to update${latestVersion ? ` · v${latestVersion}` : ""}`
              : `Update available${latestVersion ? ` · v${latestVersion}` : ""}`
            }
          </TooltipContent>
        </Tooltip>
      )}
    </div>
  );
}
