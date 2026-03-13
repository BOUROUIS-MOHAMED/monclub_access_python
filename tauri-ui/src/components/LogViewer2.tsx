import { useRef, useEffect } from "react";
import { ScrollArea } from "@/components/ui/scroll-area";
import { cn } from "@/lib/utils";

interface LogViewerProps {
  lines: string[];
  maxHeight?: string;
  className?: string;
  emptyText?: string;
}

export default function LogViewer({ lines, maxHeight = "300px", className, emptyText = "En attente de logs…" }: LogViewerProps) {
  const endRef = useRef<HTMLDivElement>(null);
  useEffect(() => { endRef.current?.scrollIntoView({ behavior: "smooth" }); }, [lines.length]);

  return (
    <ScrollArea className={cn("rounded-md border bg-[hsl(213,43%,8%)] dark:bg-[hsl(213,43%,6%)]", className)} style={{ maxHeight }}>
      <div className="p-3 font-mono text-xs leading-relaxed">
        {lines.length === 0 ? (
          <p className="text-zinc-500 italic">{emptyText}</p>
        ) : (
          lines.map((l, i) => (
            <div key={i} className={cn(
              l.startsWith("[STEP]") ? "text-sky-400" :
              l.startsWith("ERROR") || l.includes("error") ? "text-red-400" :
              l.startsWith("WARN") ? "text-amber-400" :
              "text-zinc-300"
            )}>{l}</div>
          ))
        )}
        <div ref={endRef} />
      </div>
    </ScrollArea>
  );
}

