// "Keep MonClub Access running (watchdog)" -- design section 12 (owner decision O7).
// Self-contained on purpose: it sits in Configuration › « Démarrage Windows » without touching
// ConfigPage's save model. Reads GET /api/v2/watchdog on mount, after a change and on "Refresh"
// (each read starts a hidden PowerShell on the PC, so there is no fast polling); the switch posts
// {enabled} and shows the fresh status the server returns.
// v5 look (DialogRow / Chip / Note / ConfirmDialog). Only Configuration renders it — the TV build
// does not import it.
import { useCallback, useEffect, useState } from "react";
import { ShieldCheck, Loader2, RefreshCw } from "lucide-react";

import { get, post, ApiError } from "@/api/client";
import { Switch } from "@/components/ui/switch";
import { ActionButton } from "@/components/ui/action-button";
import { Chip, ToneIcon } from "@/components/ui/chip";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { DialogRow } from "@/components/ui/dialog-frame";
import { Note } from "@/components/ui/panel";
import type { Tone } from "@/components/ui/tone";
import {
  formatWhen, lastCheckText, loadLang, needsConfirm, saveLang, switchDisabled,
  watchdogChip, watchdogTexts, type Lang, type WatchdogChip, type WatchdogStatus,
} from "@/lib/watchdogStatus";

// The server's worst case for one change: read 20 s + register 120 s (its hidden-launcher probe
// alone may take 30 s) + read 20 s + Enable/Disable 30 s + read 20 s = 210 s (review #3).
const CHANGE_TIMEOUT_MS = 240_000;

// Same meaning as `chipVariant` (old badge look), in the v5 tones.
const CHIP_TONE: Record<WatchdogChip, Tone> = {
  loading: "grey", on: "success", off: "grey", notInstalled: "grey", stoodDown: "warning", error: "error",
};

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
    <div data-testid="watchdog-card">
      <div className="flex flex-wrap items-center gap-2.5 pb-1 pt-1">
        <ToneIcon icon={ShieldCheck} tone={CHIP_TONE[chip]} size={34} />
        <div className="min-w-[160px] flex-1 text-[14px] font-bold leading-snug">{t.title}</div>
        <Chip tone={CHIP_TONE[chip]} dot data-testid="watchdog-chip">{t.chip[chip]}</Chip>
        <ActionButton kind="ghost" size="xs" onClick={toggleLang} title="FR / EN">{t.langSwitch}</ActionButton>
        <ActionButton
          kind="outline" size="xs" iconOnly icon={RefreshCw} spin={loading}
          onClick={() => { void load(); }} disabled={loading || busy} title={t.refresh}
        >
          {t.refresh}
        </ActionButton>
      </div>

      <DialogRow
        label={<label htmlFor="watchdog-switch">{t.switchLabel}</label>}
        hint={(
          <>
            {t.explain(minutes)}
            {status && status.registered !== null && (
              <span className="mt-1 block text-[12px]" data-testid="watchdog-last-check">{lastCheckText(status, lang)}</span>
            )}
            {lastEvent && (
              <span className="mt-1 block text-[12px]">
                {t.lastEvent} ({formatWhen(lastEvent.at, lang) ?? lastEvent.rawAt ?? "?"}) : {lastEvent.message}
              </span>
            )}
            {status && status.restartsLastHour > 0 && (
              <span className="mt-1 block text-[12px]">{t.restarts(status.restartsLastHour)}</span>
            )}
          </>
        )}
        className="border-b-0"
      >
        {busy && <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" aria-label={t.saving} />}
        <Switch
          id="watchdog-switch"
          data-testid="watchdog-switch"
          checked={status?.enabled === true}
          disabled={switchDisabled(status, busy || loading, fetchError)}
          onCheckedChange={(checked: boolean) => onSwitch(checked)}
        />
      </DialogRow>

      <div className="flex flex-col gap-2">
        {chip === "stoodDown" && status && <Note tone="warning">{t.stoodDown(status.restartsLastHour)}</Note>}
        {chip === "notInstalled" && <Note tone="grey">{t.notInstalled}</Note>}
        {chip === "off" && <Note tone="grey">{t.offHint}</Note>}
        {status && !status.available && <Note tone="grey">{t.unavailable}</Note>}
        {(fetchError || status?.lastError) && (
          <Note tone="error">{t.readError} {status?.lastError || fetchError}</Note>
        )}
        {changeError && <Note tone="error">{t.changeError} {changeError}</Note>}
      </div>

      <ConfirmDialog
        open={confirmOpen}
        onOpenChange={setConfirmOpen}
        title={t.confirmTitle}
        description={t.confirmBody}
        cancelLabel={t.cancel}
        confirmLabel={t.confirmOk}
        confirmKind="primary"
        onConfirm={() => { setConfirmOpen(false); void apply(false); }}
      />
    </div>
  );
}
