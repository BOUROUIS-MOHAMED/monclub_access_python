// Historique push — « Envois par heure »: one row per device, one square per local hour.
// Every value comes from GET /push-history/hourly (push_batch_history, grouped by the
// PC's local hour of created_at): batch counts per stored status and the stored pins_*.
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ChevronLeft, ChevronRight, Loader2 } from "lucide-react";

import { get } from "@/api/client";
import type { PushHourlyCell, PushHourlyResponse } from "@/api/types";
import { ActionButton } from "@/components/ui/action-button";
import { Note, Panel, PanelHeader } from "@/components/ui/panel";
import { DOT, INK, type Tone } from "@/components/ui/tone";
import { cn } from "@/lib/utils";

/** Same as the retention of push_batch_history (prune_push_batch_history, 30 days). */
const RETENTION_DAYS = 30;
const HOURS = Array.from({ length: 24 }, (_, h) => h);
const HOUR_GRID = { gridTemplateColumns: "repeat(24, minmax(0, 1fr))" };

function localDayString(d: Date): string {
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
}

function shiftDay(day: string, delta: number): string {
  const [y, m, d] = day.split("-").map(Number);
  return localDayString(new Date(y, m - 1, d + delta));
}

function dayLabel(day: string): string {
  const today = localDayString(new Date());
  if (day === today) return "Aujourd'hui";
  if (day === shiftDay(today, -1)) return "Hier";
  const [y, m, d] = day.split("-").map(Number);
  return new Date(y, m - 1, d).toLocaleDateString("fr-FR", { weekday: "long", day: "numeric", month: "long" });
}

/** The worst stored status of the hour decides the colour; the tooltip lists them all. */
function cellTone(c: PushHourlyCell): Tone {
  if (c.failed > 0) return "error";
  if (c.partial > 0) return "warning";
  if (c.inProgress > 0) return "info";
  if (c.success > 0) return "success";
  return "grey";
}

const plural = (n: number, one: string, many: string) => `${n} ${n > 1 ? many : one}`;

function cellTitle(deviceName: string, c: PushHourlyCell): string {
  const parts = [
    c.success ? plural(c.success, "réussi", "réussis") : "",
    c.partial ? plural(c.partial, "partiel", "partiels") : "",
    c.failed ? plural(c.failed, "en échec", "en échec") : "",
    c.inProgress ? `${c.inProgress} en cours` : "",
    c.other ? `${c.other} autre${c.other > 1 ? "s" : ""}` : "",
  ].filter(Boolean).join(", ");
  const pins = `PIN ${c.pinsSuccess} / ${c.pinsAttempted}${c.pinsFailed ? ` · ${c.pinsFailed} KO` : ""}`;
  return `${deviceName} · ${c.hour} h – ${c.hour + 1} h\n${plural(c.batches, "envoi", "envois")} : ${parts}\n${pins}`;
}

const LEGEND: { tone: Tone; l: string }[] = [
  { tone: "success", l: "Réussi" },
  { tone: "warning", l: "Partiel" },
  { tone: "error", l: "Échec" },
  { tone: "info", l: "En cours" },
];

export function PushHourlyMatrix({ refreshToken }: { refreshToken: number }) {
  const today = localDayString(new Date());
  const oldest = shiftDay(today, -RETENTION_DAYS);
  const [day, setDay] = useState(today);
  const [data, setData] = useState<PushHourlyResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Only the latest request may write: a slow answer for a day the operator already left
  // must not replace the day on screen.
  const reqRef = useRef(0);
  const load = useCallback(async (d: string) => {
    const req = ++reqRef.current;
    setLoading(true);
    setError(null);
    setData((prev) => (prev && prev.date === d ? prev : null));
    try {
      const res = await get<PushHourlyResponse>("/push-history/hourly", { date: d });
      if (req === reqRef.current) setData(res);
    } catch (err) {
      if (req === reqRef.current) { setData(null); setError(String(err)); }
    } finally {
      if (req === reqRef.current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load(day);
  }, [day, load, refreshToken]);

  const rows = useMemo(() => (data?.devices ?? []).map((dev) => {
    const byHour = new Map(dev.hours.map((c) => [c.hour, c]));
    const failedHours = dev.hours.filter((c) => c.failed > 0).length;
    return { dev, byHour, failedHours };
  }), [data]);

  return (
    <Panel>
      <PanelHeader
        title="Envois par heure"
        sub={`${dayLabel(day)} · heure de ce PC · une case par appareil et par heure, colorée par le pire statut de l'heure`}
      >
        <div className="flex items-center gap-1.5">
          <ActionButton
            kind="outline" size="sm" iconOnly icon={ChevronLeft} title="Jour précédent"
            disabled={day <= oldest} onClick={() => setDay(shiftDay(day, -1))}
          >Jour précédent</ActionButton>
          <input
            type="date"
            value={day}
            min={oldest}
            max={today}
            onChange={(event) => { if (event.target.value) setDay(event.target.value); }}
            aria-label="Jour affiché"
            className="h-8 rounded-lg border border-grey/32 bg-card px-2 font-mono text-[13px] text-foreground outline-none focus:border-primary"
          />
          <ActionButton
            kind="outline" size="sm" iconOnly icon={ChevronRight} title="Jour suivant"
            disabled={day >= today} onClick={() => setDay(shiftDay(day, 1))}
          >Jour suivant</ActionButton>
        </div>
      </PanelHeader>

      <div className="px-[18px] pb-4 pt-3">
        {error ? (
          <Note tone="error">{error}</Note>
        ) : loading && !data ? (
          <div className="flex justify-center py-6"><Loader2 className="h-6 w-6 animate-spin text-primary" /></div>
        ) : rows.length === 0 ? (
          <div className="py-4 text-center text-[13.5px] text-muted-foreground">
            Aucun envoi enregistré ce jour-là (l'historique push est gardé 30 jours).
          </div>
        ) : (
          <div className="overflow-x-auto">
            <div className="min-w-[760px]">
              <div className="flex items-end gap-2 pb-1.5">
                <div className="w-[170px] shrink-0" />
                <div className="grid flex-1 gap-[3px]" style={HOUR_GRID}>
                  {HOURS.map((h) => (
                    <div key={h} className="text-center font-mono text-[10.5px] text-muted-foreground">
                      {h % 3 === 0 ? h : ""}
                    </div>
                  ))}
                </div>
                <div className="w-[110px] shrink-0" />
              </div>
              {rows.map(({ dev, byHour, failedHours }) => (
                <div key={dev.deviceId} className="flex items-center gap-2 py-[3px]">
                  <div className="w-[170px] shrink-0 truncate text-[13px] font-semibold" title={`${dev.deviceName} · appareil #${dev.deviceId}`}>
                    {dev.deviceName || `Appareil #${dev.deviceId}`}
                  </div>
                  <div className="grid flex-1 gap-[3px]" style={HOUR_GRID}>
                    {HOURS.map((h) => {
                      const c = byHour.get(h);
                      return c ? (
                        <div
                          key={h}
                          role="img"
                          aria-label={cellTitle(dev.deviceName, c)}
                          title={cellTitle(dev.deviceName, c)}
                          className={cn("h-[18px] rounded-[4px]", DOT[cellTone(c)])}
                        />
                      ) : (
                        <div key={h} title={`${h} h – ${h + 1} h : rien envoyé`} className="h-[18px] rounded-[4px] bg-grey/12" />
                      );
                    })}
                  </div>
                  <div className={cn("w-[110px] shrink-0 text-right text-[12px]", failedHours ? INK.error : "text-muted-foreground")}>
                    {failedHours ? `${failedHours} h en échec` : "aucune heure en échec"}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
        <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1.5 text-[12px] text-muted-foreground">
          {LEGEND.map((it) => (
            <span key={it.tone} className="inline-flex items-center gap-1.5">
              <span className={cn("h-3 w-3 rounded-[3px]", DOT[it.tone])} />{it.l}
            </span>
          ))}
          <span className="inline-flex items-center gap-1.5"><span className="h-3 w-3 rounded-[3px] bg-grey/12" />Rien envoyé</span>
          {data && data.totals.batches > 0 && (
            <span className="ml-auto">
              {plural(data.totals.batches, "envoi", "envois")} · PIN {data.totals.pinsSuccess} / {data.totals.pinsAttempted}
              {data.totals.pinsFailed ? ` · ${data.totals.pinsFailed} KO` : ""}
            </span>
          )}
        </div>
      </div>
    </Panel>
  );
}
