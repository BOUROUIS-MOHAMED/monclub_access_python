import { useState, useEffect, useRef } from "react";
import { useApp } from "@/context/AppContext";
import { post, openSSE } from "@/api/client";
import { Card, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import StatusChip from "@/components/StatusChip2";
import { Bot, Play, Square, Wifi } from "lucide-react";
import { cn } from "@/lib/utils";

interface AgentEvent { type: string; ts: string; data: any; }

export default function AgentPage() {
  const { status } = useApp();
  const agent = status?.agent;
  const [events, setEvents] = useState<AgentEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const endRef = useRef<HTMLDivElement>(null);
  const esRef = useRef<EventSource | null>(null);

  useEffect(() => {
    const es = openSSE("/agent/events", (type, data) => {
      try {
        const parsed = JSON.parse(data);
        setEvents((prev) => [...prev.slice(-500), { type, ts: new Date().toISOString(), data: parsed }]);
      } catch {
        setEvents((prev) => [...prev.slice(-500), { type, ts: new Date().toISOString(), data }]);
      }
    });
    esRef.current = es;
    setConnected(true);
    es.onerror = () => setConnected(false);
    return () => { es.close(); setConnected(false); };
  }, []);

  useEffect(() => { endRef.current?.scrollIntoView({ behavior: "smooth" }); }, [events.length]);

  const eventColor = (type: string) => {
    if (type.includes("error") || type.includes("denied")) return "text-red-400";
    if (type.includes("granted") || type.includes("access")) return "text-emerald-400";
    if (type.includes("warn")) return "text-amber-400";
    return "text-foreground/70";
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Bot className="h-5 w-5 text-primary" />
          <h1 className="text-lg font-semibold">Agent Temps Réel</h1>
          {agent && <StatusChip variant={agent.running ? "online" : "offline"} label={agent.running ? "Actif" : "Arrêté"} />}
        </div>
        <div className="flex items-center gap-2">
          <Button size="sm" variant="outline" disabled={agent?.running} onClick={() => post("/agent/start")}>
            <Play className="h-3.5 w-3.5" /> Démarrer
          </Button>
          <Button size="sm" variant="outline" disabled={!agent?.running} onClick={() => post("/agent/stop")}>
            <Square className="h-3.5 w-3.5" /> Arrêter
          </Button>
        </div>
      </div>

      {/* Stats */}
      {agent && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
          {[
            { label: "Statut", value: agent.running ? "Actif" : "Arrêté" },
            { label: "File d'attente", value: String(agent.eventQueueDepth) },
            { label: "Décision moy.", value: `${agent.avgDecisionMs.toFixed(1)} ms` },
            { label: "Stream SSE", value: connected ? "Connecté" : "Déconnecté" },
          ].map(({ label, value }) => (
            <div key={label} className="rounded-lg border border-border bg-muted/40 px-4 py-3">
              <p className="text-[11px] uppercase tracking-widest text-muted-foreground font-medium">{label}</p>
              <p className="mt-2 text-sm font-semibold text-foreground">{value}</p>
            </div>
          ))}
        </div>
      )}

      {/* Events stream */}
      <Card className="p-0 overflow-hidden">
        <CardHeader className="px-4 py-3 border-b">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm flex items-center gap-2">
              <Wifi className={cn("h-4 w-4", connected ? "text-emerald-500" : "text-zinc-500")} />
              Événements
              <Badge variant="secondary" className="text-xs">{events.length}</Badge>
            </CardTitle>
            <Button size="sm" variant="ghost" onClick={() => setEvents([])}>Effacer</Button>
          </div>
        </CardHeader>
        <ScrollArea className="h-[calc(100vh-380px)]">
          <div className="p-3 font-mono text-xs leading-relaxed bg-background min-h-full">
            {events.length === 0 ? (
              <p className="text-muted-foreground/60 italic py-8 text-center">En attente d'événements de l'agent…</p>
            ) : (
              events.map((ev, i) => (
                <div key={i} className={cn("py-0.5 flex gap-2", eventColor(ev.type))}>
                  <span className="text-muted-foreground/60 shrink-0">{ev.ts.split("T")[1]?.substring(0, 8)}</span>
                  <Badge variant="outline" className="text-[10px] h-4 px-1">{ev.type}</Badge>
                  <span className="break-all">{typeof ev.data === "string" ? ev.data : JSON.stringify(ev.data)}</span>
                </div>
              ))
            )}
            <div ref={endRef} />
          </div>
        </ScrollArea>
      </Card>
    </div>
  );
}

