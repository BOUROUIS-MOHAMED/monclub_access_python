// "Keep MonClub Access running (watchdog)" -- design section 12 (owner decision O7).
// Self-contained on purpose: the BLUE v5 redesign restyles it later without touching
// ConfigPage. Reads GET /api/v2/watchdog on mount, after a change and on "Refresh" (each read
// starts a hidden PowerShell on the PC, so there is no fast polling); the switch posts
// {enabled} and shows the fresh status the server returns.
import { useCallback, useEffect, useState } from "react";
import { ShieldCheck, Loader2, RefreshCw } from "lucide-react";

import { get, post, ApiError } from "@/api/client";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription,
  AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import {
  chipVariant, formatWhen, lastCheckText, loadLang, needsConfirm, saveLang, switchDisabled,
  watchdogChip, watchdogTexts, type Lang, type WatchdogStatus,
} from "@/lib/watchdogStatus";

// The server's worst case for one change: read 20 s + register 120 s (its hidden-launcher probe
// alone may take 30 s) + read 20 s + Enable/Disable 30 s + read 20 s = 210 s (review #3).
const CHANGE_TIMEOUT_MS = 240_000;

export default function WatchdogCard() {
  const [lang, setLang] = useState<Lang>(() => loadLang());
  const [status, setStatus] = useState<WatchdogStatus | null>(null);
  const [loading, setLoading] = useState(false);
  const [fetchError, setFetchError] = useState<string | null>(null);
  const [changeError, setChangeError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const t = watchdogTexts(lang);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await get<{ ok: boolean; watchdog: WatchdogStatus }>("/watchdog");
      setStatus(res.watchdog);
      setFetchError(null);
      setChangeError(null);
    } catch (e) {
      setFetchError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const apply = useCallback(async (enabled: boolean) => {
    setBusy(true);
    setChangeError(null);
    try {
      const res = await post<{ ok: boolean; watchdog: WatchdogStatus }>("/watchdog", { enabled }, CHANGE_TIMEOUT_MS);
      setStatus(res.watchdog);
      setFetchError(null);
    } catch (e) {
      setChangeError(e instanceof Error ? e.message : String(e));
      const fresh = e instanceof ApiError ? (e.payload?.watchdog as WatchdogStatus | undefined) : undefined;
      if (fresh) setStatus(fresh);
      else void load();
    } finally {
      setBusy(false);
    }
  }, [load]);

  const onSwitch = (next: boolean) => {
    if (needsConfirm(next)) setConfirmOpen(true);
    else void apply(next);
  };

  const toggleLang = () => {
    const next: Lang = lang === "fr" ? "en" : "fr";
    setLang(next);
    saveLang(next);
  };

  const chip = watchdogChip(status, fetchError);
  const minutes = status?.intervalMinutes ?? 2;
  const lastEvent = status?.lastLogEntry && !status.lastLogEntry.fromLastCheck ? status.lastLogEntry : null;

  return (
    <Card data-testid="watchdog-card">
      <CardHeader>
        <CardTitle className="text-sm flex items-center gap-2">
          <ShieldCheck className="h-4 w-4" /> {t.title}
          <Badge variant={chipVariant(chip)} className="text-xs" data-testid="watchdog-chip">{t.chip[chip]}</Badge>
          <span className="ml-auto flex items-center gap-1">
            <Button size="sm" variant="ghost" className="h-7 px-2 text-xs" onClick={toggleLang} title="FR / EN">
              {t.langSwitch}
            </Button>
            <Button size="sm" variant="ghost" className="h-7 px-2" onClick={() => { void load(); }}
              disabled={loading || busy} title={t.refresh} aria-label={t.refresh}>
              <RefreshCw className={loading ? "h-3.5 w-3.5 animate-spin" : "h-3.5 w-3.5"} />
            </Button>
          </span>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="flex items-start justify-between gap-4">
          <div className="space-y-1">
            <Label htmlFor="watchdog-switch">{t.switchLabel}</Label>
            <p className="text-sm text-muted-foreground">{t.explain(minutes)}</p>
            {status && status.registered !== null && (
              <p className="text-xs text-muted-foreground" data-testid="watchdog-last-check">
                {lastCheckText(status, lang)}
              </p>
            )}
            {lastEvent && (
              <p className="text-xs text-muted-foreground">
                {t.lastEvent} ({formatWhen(lastEvent.at, lang) ?? lastEvent.rawAt ?? "?"}) : {lastEvent.message}
              </p>
            )}
            {status && status.restartsLastHour > 0 && (
              <p className="text-xs text-muted-foreground">{t.restarts(status.restartsLastHour)}</p>
            )}
          </div>
          <div className="flex items-center gap-3">
            {busy && <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" aria-label={t.saving} />}
            <Switch
              id="watchdog-switch"
              data-testid="watchdog-switch"
              checked={status?.enabled === true}
              disabled={switchDisabled(status, busy || loading, fetchError)}
              onCheckedChange={(checked: boolean) => onSwitch(checked)}
            />
          </div>
        </div>

        {chip === "stoodDown" && status && (
          <Alert variant="warning"><AlertDescription>{t.stoodDown(status.restartsLastHour)}</AlertDescription></Alert>
        )}
        {chip === "notInstalled" && <p className="text-xs text-muted-foreground">{t.notInstalled}</p>}
        {chip === "off" && <p className="text-xs text-muted-foreground">{t.offHint}</p>}
        {status && !status.available && <p className="text-xs text-muted-foreground">{t.unavailable}</p>}
        {(fetchError || status?.lastError) && (
          <Alert variant="destructive">
            <AlertDescription>{t.readError} {status?.lastError || fetchError}</AlertDescription>
          </Alert>
        )}
        {changeError && (
          <Alert variant="destructive"><AlertDescription>{t.changeError} {changeError}</AlertDescription></Alert>
        )}
      </CardContent>

      <AlertDialog open={confirmOpen} onOpenChange={setConfirmOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t.confirmTitle}</AlertDialogTitle>
            <AlertDialogDescription>{t.confirmBody}</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t.cancel}</AlertDialogCancel>
            <AlertDialogAction onClick={() => { setConfirmOpen(false); void apply(false); }}>
              {t.confirmOk}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Card>
  );
}
