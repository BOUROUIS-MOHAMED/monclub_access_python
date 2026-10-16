import { useState, useEffect, useCallback, useRef } from "react";
import { get, patch } from "@/api/client";
import { useApp } from "@/context/AppContext";
import {
  Card, CardContent, CardHeader, CardTitle,
} from "@/components/ui/card";
import {
  Button,
} from "@/components/ui/button";
import {
  Badge,
} from "@/components/ui/badge";
import {
  Input,
} from "@/components/ui/input";
import {
  Label,
} from "@/components/ui/label";
import {
  Switch,
} from "@/components/ui/switch";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import {
  Separator,
} from "@/components/ui/separator";
import {
  Accordion, AccordionContent, AccordionItem, AccordionTrigger,
} from "@/components/ui/accordion";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter,
} from "@/components/ui/dialog";
import {
  Alert, AlertDescription,
} from "@/components/ui/alert";
import {
  Settings, Save, Lock, Unlock, Loader2, CheckCircle, Download, Info,
  CreditCard, Wifi, Usb, Search, Radio, Music4, Sparkles, Upload, RotateCcw,
  Star,
} from "lucide-react";
import type { DiscoveredDevice } from "@/api/types";
import { useScanCard } from "@/hooks/useScanCard";
import WatchdogCard from "@/components/WatchdogCard";
import {
  DEFAULT_FEEDBACK_ANIMATIONS,
  DEFAULT_FEEDBACK_SOUNDS,
  currentFeedbackFileName,
  resetFeedbackSound,
  uploadFeedbackSound,
  type FeedbackSoundKind,
} from "@/lib/feedback";

// ── Anchor type for the favorites overlay ─────────────────────────────────────
// Vertical edges only — top/bottom horizontal anchors were removed from
// the picker because they never rendered reliably. Backend still accepts
// all 12 values for forward-compat; a stored top-/bottom- value falls back
// to right-center in the UI.
type OverlayAnchor =
  | "right-top" | "right-center" | "right-bottom"
  | "left-top"  | "left-center"  | "left-bottom";

const OVERLAY_ANCHORS: OverlayAnchor[] = [
  "right-top", "right-center", "right-bottom",
  "left-top", "left-center", "left-bottom",
];

const OVERLAY_ANCHOR_LABELS: Record<OverlayAnchor, string> = {
  "right-top": "Droite — haut",
  "right-center": "Droite — centre",
  "right-bottom": "Droite — bas",
  "left-top": "Gauche — haut",
  "left-center": "Gauche — centre",
  "left-bottom": "Gauche — bas",
};

function isOverlayAnchor(v: unknown): v is OverlayAnchor {
  return typeof v === "string" && (OVERLAY_ANCHORS as string[]).includes(v);
}

async function applyOverlayAnchor(anchor: OverlayAnchor): Promise<void> {
  try {
    const { invoke } = await import("@tauri-apps/api/core");
    await invoke("apply_favorites_overlay_anchor", { anchor, expanded: false });
  } catch {
    // Not running under Tauri, or the overlay window isn't open — harmless.
  }
}

/**
 * 12-position anchor selector. Renders a fake screen with clickable dots
 * around its border and a live preview of where the collapsed handle would
 * sit on the real monitor.
 */
function OverlayAnchorPicker({
  value,
  onChange,
}: {
  value: OverlayAnchor;
  onChange: (next: OverlayAnchor) => void;
}) {
  // Each anchor gets absolute coords on a [0..1] × [0..1] grid.
  const POS: Record<OverlayAnchor, { x: string; y: string; edge: "v" }> = {
    "right-top":      { x: "100%", y: "18%",  edge: "v" },
    "right-center":   { x: "100%", y: "50%",  edge: "v" },
    "right-bottom":   { x: "100%", y: "82%",  edge: "v" },
    "left-bottom":    { x: "0%",   y: "82%",  edge: "v" },
    "left-center":    { x: "0%",   y: "50%",  edge: "v" },
    "left-top":       { x: "0%",   y: "18%",  edge: "v" },
  };

  return (
    <div className="flex flex-col items-center gap-3">
      {/* Fake screen */}
      <div
        className="relative w-[320px] h-[200px] rounded-lg border-2 border-border bg-muted/30 shadow-inner"
        aria-label="Prévisualisation de l'écran"
      >
        {/* Monitor bezel highlight */}
        <div className="absolute inset-0 rounded-md pointer-events-none ring-1 ring-inset ring-border/50" />

        {/* Dots for each anchor */}
        {OVERLAY_ANCHORS.map((a) => {
          const p = POS[a];
          const active = a === value;
          return (
            <button
              key={a}
              type="button"
              title={OVERLAY_ANCHOR_LABELS[a]}
              onClick={() => onChange(a)}
              className={[
                "absolute -translate-x-1/2 -translate-y-1/2",
                "rounded-full focus:outline-none focus-visible:ring-2 focus-visible:ring-primary/60",
                "transition-all duration-150",
                active
                  ? "h-3.5 w-3.5 bg-primary ring-4 ring-primary/25 shadow-[0_0_0_1px_hsl(var(--background))]"
                  : "h-2.5 w-2.5 bg-muted-foreground/40 hover:bg-primary/80 hover:scale-125",
              ].join(" ")}
              style={{ left: p.x, top: p.y }}
              aria-label={`Ancre ${OVERLAY_ANCHOR_LABELS[a]}`}
              aria-pressed={active}
            />
          );
        })}

        {/* Handle pill preview at the selected anchor */}
        {(() => {
          const edge = value.split("-")[0];
          let style: React.CSSProperties;
          if (edge === "right") {
            style = { right: 0, top: "50%", transform: "translateY(-50%)", width: 6, height: 44, borderRadius: "6px 0 0 6px" };
            if (value === "right-top")    style = { ...style, top: "18%" };
            if (value === "right-bottom") style = { ...style, top: "82%" };
          } else {
            style = { left: 0, top: "50%", transform: "translateY(-50%)", width: 6, height: 44, borderRadius: "0 6px 6px 0" };
            if (value === "left-top")    style = { ...style, top: "18%" };
            if (value === "left-bottom") style = { ...style, top: "82%" };
          }
          return (
            <div
              aria-hidden
              className="absolute bg-primary/80 shadow-[0_0_8px_hsl(var(--primary)/0.6)] transition-all duration-200"
              style={style}
            />
          );
        })()}
      </div>
      <p className="text-xs text-muted-foreground">
        Position choisie : <span className="font-semibold text-foreground">{OVERLAY_ANCHOR_LABELS[value]}</span>
      </p>
    </div>
  );
}

// Access v3 imports (Partie 2, screen 05)
import { usePageChrome } from "@/context/PageChromeContext";
import { ArrowRightLeft } from "lucide-react";
import { hasAgentDevices } from "@/lib/agentMode";
import { cn } from "@/lib/utils";
import { ActionButton } from "@/components/ui/action-button";
import { Chip } from "@/components/ui/chip";
import { DialogFrame, DialogRow, DialogSection } from "@/components/ui/dialog-frame";
import { LineTabs } from "@/components/ui/line-tabs";
import { ListRow, Note, PageGrid, Panel, PanelHeader, PanelList } from "@/components/ui/panel";
import { Power, ScanLine, Volume2, Router, CircleAlert, LockOpen } from "lucide-react";

export default function ConfigPage() {
  const { status } = useApp();
  const [cfg, setCfg] = useState<Record<string, any>>({});
  // Snapshot of the config as last loaded/saved. The design's rail lists the
  // pending edits field by field; `dirty` alone is only a boolean, so the diff
  // is computed against this baseline — real values, nothing inferred.
  const [baseline, setBaseline] = useState<Record<string, any>>({});
  const [serverSettings, setServerSettings] = useState<Record<string, any>>({});
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [startupSaving, setStartupSaving] = useState(false);
  const [dirty, setDirty] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  // Advanced mode (password protected)
  const [advancedUnlocked, setAdvancedUnlocked] = useState(false);
  const [pwdDialogOpen, setPwdDialogOpen] = useState(false);
  const [pwdInput, setPwdInput] = useState("");
  const [pwdError, setPwdError] = useState(false);

  // Update info
  const [updateDialog, setUpdateDialog] = useState(false);

  // Card scanner discovery
  const { startDiscover, discovering, discoveredDevices } = useScanCard();
  const devicePushSoundInputRef = useRef<HTMLInputElement | null>(null);
  const syncCompleteSoundInputRef = useRef<HTMLInputElement | null>(null);
  const antiFraudDurationSoundInputRef = useRef<HTMLInputElement | null>(null);
  const antiFraudDailyLimitSoundInputRef = useRef<HTMLInputElement | null>(null);
  const [soundUploading, setSoundUploading] = useState({
    devicePush: false,
    syncComplete: false,
    antiFraudDuration: false,
    antiFraudDailyLimit: false,
  });

  // Unsaved edits (key → value), refreshed on every render below. The
  // immediate-save controls read it so a save or a reload never erases them.
  const pendingEditsRef = useRef<Record<string, any>>({});

  const broadcastFeedbackConfig = useCallback((nextCfg: Record<string, any>) => {
    if (typeof window === "undefined") return;
    window.dispatchEvent(new CustomEvent("access-feedback-config-updated", { detail: nextCfg }));
  }, []);

  const loadConfig = useCallback(async () => {
    setLoading(true);
    try {
      const res = await get<any>("/config");
      const nextCfg = res.config || res || {};
      // Silent migration: top-/bottom- anchors are no longer offered in the
      // picker. Coerce any legacy value to `right-center` and persist so
      // the Rust overlay also switches over. Runs once on load per process.
      const legacy = typeof nextCfg.favorites_overlay_anchor === "string"
        ? nextCfg.favorites_overlay_anchor
        : "";
      if (legacy && !isOverlayAnchor(legacy)) {
        try {
          const patched = await patch<any>("/config", { favorites_overlay_anchor: "right-center" });
          const patchedCfg = patched.config || { ...nextCfg, favorites_overlay_anchor: "right-center" };
          setCfg(patchedCfg);
          setBaseline(patchedCfg);
          setServerSettings(res.serverSettings || {});
          broadcastFeedbackConfig(patchedCfg);
          void applyOverlayAnchor("right-center");
          return;
        } catch {
          // fall through to normal load if the migration PATCH fails
        }
      }
      setCfg(nextCfg);
      setBaseline(nextCfg);
      setServerSettings(res.serverSettings || {});
      broadcastFeedbackConfig(nextCfg);
    } catch (e) { setError(String(e)); }
    finally { setLoading(false); }
  }, [broadcastFeedbackConfig]);

  useEffect(() => { loadConfig(); }, [loadConfig]);

  // Same GET as loadConfig (it IS loadConfig), then the unsaved edits are put
  // back on screen — except `savedKeys`, which must show the server's value.
  // `editsGenRef` moves on Annuler / Enregistrer: edits taken before one of those
  // must not come back after the reload.
  const editsGenRef = useRef(0);
  const reloadKeepingEdits = useCallback(async (savedKeys: string[] = []) => {
    const keep = { ...pendingEditsRef.current };
    for (const k of savedKeys) delete keep[k];
    const gen = editsGenRef.current;
    await loadConfig();
    if (gen === editsGenRef.current && Object.keys(keep).length) setCfg((p) => ({ ...p, ...keep }));
  }, [loadConfig]);

  const handleSave = async () => {
    editsGenRef.current += 1;
    setSaving(true); setError(null); setSuccess(false);
    try {
      const res = await patch<any>("/config", cfg);
      const nextCfg = res.config || cfg;
      setCfg(nextCfg);
      setBaseline(nextCfg);
      broadcastFeedbackConfig(nextCfg);
      // Reposition the floating favorites overlay (if open) to match the
      // newly-persisted anchor. Silent no-op under web.
      const nextAnchor = nextCfg.favorites_overlay_anchor;
      if (isOverlayAnchor(nextAnchor)) {
        void applyOverlayAnchor(nextAnchor);
      }
      setSuccess(true);
      setDirty(false);
      setTimeout(() => setSuccess(false), 3000);
    }
    catch (e) { setError(String(e)); }
    finally { setSaving(false); }
  };

  const update = (key: string, value: any) => {
    setCfg((p) => ({ ...p, [key]: value }));
    setDirty(true);
  };

  const patchFeedbackConfig = useCallback(async (changes: Record<string, any>) => {
    setError(null);
    const optimistic = { ...cfg, ...changes };
    setCfg(optimistic);
    broadcastFeedbackConfig(optimistic);
    try {
      const res = await patch<any>("/config", changes);
      const nextCfg = res.config || optimistic;
      // The answer is the WHOLE saved config: taking all of it erased every
      // unsaved edit on the page. Take only the keys just saved, and count
      // them as saved (baseline) so they never show as « non enregistré ».
      const saved = Object.fromEntries(Object.keys(changes).map((k) => [k, nextCfg[k]]));
      setCfg((p) => ({ ...p, ...saved }));
      setBaseline((b) => ({ ...b, ...saved }));
      broadcastFeedbackConfig(nextCfg);
    } catch (e) {
      setError(String(e));
      await reloadKeepingEdits(Object.keys(changes));
    }
  }, [broadcastFeedbackConfig, cfg, reloadKeepingEdits]);

  const handleFeedbackSoundUpload = useCallback(async (kind: FeedbackSoundKind, file: File | null) => {
    if (!file) return;
    setError(null);
    setSoundUploading((prev) => ({
      ...prev,
      devicePush: kind === "device-push" ? true : prev.devicePush,
      syncComplete: kind === "sync-complete" ? true : prev.syncComplete,
      antiFraudDuration: kind === "anti-fraud-duration" ? true : prev.antiFraudDuration,
      antiFraudDailyLimit: kind === "anti-fraud-daily-limit" ? true : prev.antiFraudDailyLimit,
    }));
    try {
      await uploadFeedbackSound(kind, file);
      await reloadKeepingEdits();
    } catch (e) {
      setError(String(e));
    } finally {
      setSoundUploading((prev) => ({
        ...prev,
        devicePush: kind === "device-push" ? false : prev.devicePush,
        syncComplete: kind === "sync-complete" ? false : prev.syncComplete,
        antiFraudDuration: kind === "anti-fraud-duration" ? false : prev.antiFraudDuration,
        antiFraudDailyLimit: kind === "anti-fraud-daily-limit" ? false : prev.antiFraudDailyLimit,
      }));
      if (kind === "device-push" && devicePushSoundInputRef.current) devicePushSoundInputRef.current.value = "";
      if (kind === "sync-complete" && syncCompleteSoundInputRef.current) syncCompleteSoundInputRef.current.value = "";
      if (kind === "anti-fraud-duration" && antiFraudDurationSoundInputRef.current) antiFraudDurationSoundInputRef.current.value = "";
      if (kind === "anti-fraud-daily-limit" && antiFraudDailyLimitSoundInputRef.current) antiFraudDailyLimitSoundInputRef.current.value = "";
    }
  }, [reloadKeepingEdits]);

  const handleFeedbackSoundReset = useCallback(async (kind: FeedbackSoundKind) => {
    setError(null);
    setSoundUploading((prev) => ({
      ...prev,
      devicePush: kind === "device-push" ? true : prev.devicePush,
      syncComplete: kind === "sync-complete" ? true : prev.syncComplete,
      antiFraudDuration: kind === "anti-fraud-duration" ? true : prev.antiFraudDuration,
      antiFraudDailyLimit: kind === "anti-fraud-daily-limit" ? true : prev.antiFraudDailyLimit,
    }));
    try {
      await resetFeedbackSound(kind);
      await reloadKeepingEdits();
    } catch (e) {
      setError(String(e));
    } finally {
      setSoundUploading((prev) => ({
        ...prev,
        devicePush: kind === "device-push" ? false : prev.devicePush,
        syncComplete: kind === "sync-complete" ? false : prev.syncComplete,
        antiFraudDuration: kind === "anti-fraud-duration" ? false : prev.antiFraudDuration,
        antiFraudDailyLimit: kind === "anti-fraud-daily-limit" ? false : prev.antiFraudDailyLimit,
      }));
    }
  }, [reloadKeepingEdits]);

  const handleStartupToggle = async (enabled: boolean) => {
    const previous = Boolean(cfg.start_on_system_startup ?? false);
    setCfg((p) => ({ ...p, start_on_system_startup: enabled }));
    setStartupSaving(true);
    setError(null);
    try {
      await patch("/config", { start_on_system_startup: enabled });
      setCfg((p) => ({ ...p, start_on_system_startup: enabled }));
      setBaseline((b) => ({ ...b, start_on_system_startup: enabled }));
    } catch (e) {
      setCfg((p) => ({ ...p, start_on_system_startup: previous }));
      setError(String(e));
    } finally {
      setStartupSaving(false);
    }
  };

  const handleUnlockAdvanced = () => {
    if (pwdInput === "94970082") { setAdvancedUnlocked(true); setPwdDialogOpen(false); setPwdError(false); setPwdInput(""); }
    else { setPwdError(true); }
  };

  const updates = status?.updates;
  const currentVersionDisplay = updates?.currentVersion && updates.currentVersion !== "0.0.0"
    ? updates.currentVersion
    : (updates?.currentReleaseId || "dev");
  const devicePushCustomFileName = currentFeedbackFileName(cfg.push_success_custom_sound_path);
  const syncCompleteCustomFileName = currentFeedbackFileName(cfg.sync_success_custom_sound_path);
  const antiFraudDurationCustomFileName = currentFeedbackFileName(cfg.anti_fraud_duration_custom_sound_path);
  const antiFraudDailyLimitCustomFileName = currentFeedbackFileName(cfg.anti_fraud_daily_limit_custom_sound_path);
  const devicePushUploading = soundUploading.devicePush;
  const syncCompleteUploading = soundUploading.syncComplete;
  const antiFraudDurationUploading = soundUploading.antiFraudDuration;
  const antiFraudDailyLimitUploading = soundUploading.antiFraudDailyLimit;

  // Pending edits, computed field by field against the last loaded/saved config.
  // NOTE: this and usePageChrome below MUST stay above the `if (loading)` early
  // return — a hook after a conditional return changes the hook count between
  // renders ("Rendered more hooks than during the previous render").
  const changes = Object.keys({ ...baseline, ...cfg })
    .filter((k) => JSON.stringify(baseline[k]) !== JSON.stringify(cfg[k]))
    .map((k) => ({ key: k, from: baseline[k], to: cfg[k] }));
  pendingEditsRef.current = Object.fromEntries(changes.map((c) => [c.key, c.to]));

  const fmtVal = (v: any): string => {
    if (v === true) return "activé";
    if (v === false) return "désactivé";
    if (v == null || v === "") return "vide";
    if (typeof v === "object") return JSON.stringify(v).slice(0, 40);
    return String(v).slice(0, 40);
  };

  // The header is published by an effect that re-runs only on its (primitive)
  // deps, so its buttons go through refs to always act on the current config.
  const handleSaveRef = useRef(handleSave);
  handleSaveRef.current = handleSave;
  const discardEdits = () => { editsGenRef.current += 1; setCfg(baseline); setDirty(false); };
  const discardEditsRef = useRef(discardEdits);
  discardEditsRef.current = discardEdits;

  // ── Access v5 (boards S22 / S23): sections become tabs ────────────────
  type ConfigTab = "updates" | "startup" | "dock" | "scanner" | "feedback" | "advanced";
  const [section, setSection] = useState<ConfigTab>("updates");

  usePageChrome(() => ({
    subtitle: changes.length > 0 ? (
      <Chip tone="warning">
        {changes.length} modification{changes.length > 1 ? "s" : ""} non enregistrée{changes.length > 1 ? "s" : ""}
      </Chip>
    ) : "Réglages de ce poste",
    actions: (
      <>
        <ActionButton
          kind="outline"
          onClick={() => discardEditsRef.current()}
          disabled={changes.length === 0 || saving}
        >
          Annuler
        </ActionButton>
        <ActionButton
          kind={dirty ? "primary" : "outline"}
          icon={saving ? Loader2 : Save}
          spin={saving}
          onClick={() => { void handleSaveRef.current(); }}
          disabled={!dirty || saving}
        >
          Enregistrer
        </ActionButton>
      </>
    ),
    // Primitives only — see PageChromeContext: an unstable dep loops the effect.
  }), [changes.length, dirty, saving]);

  if (loading) {
    return <div className="flex items-center justify-center py-20"><Loader2 className="h-8 w-8 animate-spin text-primary" /></div>;
  }

  // « Enregistré automatiquement »: these controls PATCH the moment they change
  // (startup switch, every Sons et animations control). They never count as
  // unsaved and Annuler does not touch them.
  const AUTO = (
    <Chip tone="info" size="sm" className="ml-2 align-[1px]">Enregistré automatiquement</Chip>
  );
  const SEPARATE_SAVE = (
    <Chip tone="grey" size="sm" className="ml-2 align-[1px]">Avec « Enregistrer »</Chip>
  );

  // Readers: a standalone terminal is held by its ULTRA worker and never shows in
  // the PullSDK session (`status.pullsdk`), so that flag alone said « non connecté »
  // on MB2000 gyms. Same rule as ProfilePage.
  const ultraWorkers = Object.values(status?.ultra?.devices ?? {});
  const ultraConnected = ultraWorkers.filter((d: any) => d?.connected).length;
  const pullsdkOn = !!status?.pullsdk?.connected;
  const readerValue = [
    ultraWorkers.length > 0 ? `${ultraConnected} / ${ultraWorkers.length} connecté${ultraWorkers.length > 1 ? "s" : ""}` : "",
    pullsdkOn ? `PullSDK ${status?.pullsdk?.ip || "connecté"}` : "",
  ].filter(Boolean).join(" · ") || "aucun connecté";
  const readerTone = ultraWorkers.length > 0
    ? (ultraConnected === ultraWorkers.length ? "success" : ultraConnected > 0 || pullsdkOn ? "warning" : "error")
    : pullsdkOn ? "success" : "grey";

  const soundFileRow = (opts: {
    uploading: boolean; fileName: string | null | undefined;
    inputRef: React.MutableRefObject<HTMLInputElement | null>; kind: FeedbackSoundKind;
  }) => (
    <DialogRow
      label={<>Fichier du son{AUTO}</>}
      hint={opts.fileName ? `Actuel : ${opts.fileName}` : "Aucun son personnalisé sélectionné."}
    >
      <input
        ref={opts.inputRef}
        type="file"
        accept=".mp3,.wav,.ogg,.m4a,audio/*"
        className="hidden"
        onChange={(event) => { void handleFeedbackSoundUpload(opts.kind, event.target.files?.[0] ?? null); }}
      />
      <ActionButton
        kind="outline"
        size="md"
        icon={opts.uploading ? Loader2 : Upload}
        spin={opts.uploading}
        disabled={opts.uploading}
        onClick={() => opts.inputRef.current?.click()}
      >
        {opts.fileName ? "Remplacer le son" : "Choisir un son"}
      </ActionButton>
      <ActionButton
        kind="ghost"
        size="md"
        icon={RotateCcw}
        disabled={opts.uploading || !opts.fileName}
        onClick={() => { void handleFeedbackSoundReset(opts.kind); }}
      >
        Réinitialiser
      </ActionButton>
    </DialogRow>
  );

  const sourceSelect = (key: string) => (
    <Select
      value={String(cfg[key] || "default")}
      onValueChange={(value) => { void patchFeedbackConfig({ [key]: value }); }}
    >
      <SelectTrigger className="h-9 w-[220px] rounded-lg border-grey/32 bg-card shadow-none"><SelectValue /></SelectTrigger>
      <SelectContent>
        <SelectItem value="default">Son par défaut</SelectItem>
        <SelectItem value="custom">Son personnalisé</SelectItem>
      </SelectContent>
    </Select>
  );

  const fbSwitch = (id: string, key: string, def: boolean) => (
    <Switch
      id={id}
      checked={Boolean(cfg[key] ?? def)}
      onCheckedChange={(checked: boolean) => { void patchFeedbackConfig({ [key]: checked }); }}
    />
  );

  const SECTIONS: { value: ConfigTab; label: string; icon: typeof Download }[] = [
    { value: "updates", label: "Mises à jour", icon: Download },
    { value: "startup", label: "Démarrage Windows", icon: Power },
    { value: "dock", label: "Dock des favoris", icon: Star },
    { value: "scanner", label: "Lecteur de cartes", icon: ScanLine },
    { value: "feedback", label: "Sons et animations", icon: Volume2 },
    { value: "advanced", label: "Paramètres avancés", icon: advancedUnlocked ? Unlock : Lock },
  ];
  const sectionTitle = SECTIONS.find((s) => s.value === section)?.label ?? "";

  return (
    <div className="flex flex-col gap-[18px]">
      <LineTabs<ConfigTab> className="-mt-1" value={section} onChange={setSection} items={SECTIONS} />

      {error && <Note tone="error">{error}</Note>}
      {success && <Note tone="success" className="flex items-center gap-2"><CheckCircle className="h-4 w-4" />Configuration enregistrée !</Note>}

      <PageGrid>
        <Panel className="col-span-8">
          <PanelHeader
            title={sectionTitle}
            sub={section === "feedback"
              ? "Chaque réglage de cet onglet est enregistré dès que vous le changez."
              : section === "dock" || section === "scanner" || (section === "advanced" && advancedUnlocked)
                ? "Les changements de cet onglet s'appliquent avec « Enregistrer » en haut de la page."
                : undefined}
          />
          <div className="px-[18px] pb-4 pt-1">

            {/* ── Mises à jour ─────────────────────────────────────────── */}
            {section === "updates" && (
              <>
                <DialogRow
                  label={updates?.componentDisplayName || "MonClub Access"}
                  hint={`Canal ${updates?.channel || "stable"} · plateforme ${updates?.platform || "WINDOWS"}`}
                >
                  <span className="inline-flex h-9 items-center rounded-lg bg-muted px-3 font-mono text-[13px]">{currentVersionDisplay}</span>
                </DialogRow>
                {updates?.updateAvailable ? (
                  <DialogRow
                    label={`Version ${updates.latestVersion ?? ""} disponible`}
                    hint={updates.downloaded ? "Téléchargée — à installer à la fermeture du club." : "À installer à la fermeture du club."}
                  >
                    <ActionButton kind="outline" size="md" icon={Info} onClick={() => setUpdateDialog(true)}>Voir les détails</ActionButton>
                  </DialogRow>
                ) : (
                  <DialogRow label="Aucune mise à jour disponible." className="border-b-0" />
                )}
              </>
            )}

            {/* ── Démarrage Windows ────────────────────────────────────── */}
            {section === "startup" && (
              <>
                <DialogRow
                  label={<label htmlFor="start-on-windows-switch">Ouvrir MonClub Access avec Windows{AUTO}</label>}
                  hint={(
                    <>
                      Quand cette option est activée, MonClub Access est ajouté au démarrage de Windows et son
                      interface s&apos;ouvre automatiquement à l&apos;ouverture de session.
                      <span className="mt-1 block text-[12px]">
                        En mode développement, la préférence est enregistrée, mais l&apos;inscription au démarrage
                        Windows ne s&apos;applique que sur les builds installés.
                      </span>
                    </>
                  )}
                >
                  {startupSaving && <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />}
                  <Switch
                    id="start-on-windows-switch"
                    checked={Boolean(cfg.start_on_system_startup ?? false)}
                    onCheckedChange={(checked: boolean) => { void handleStartupToggle(checked); }}
                  />
                </DialogRow>
                {/* Watchdog — self-contained card (its own switch and confirm). */}
                <div className="mt-4">
                  <WatchdogCard />
                </div>
              </>
            )}

            {/* ── Dock des favoris ─────────────────────────────────────── */}
            {section === "dock" && (
              <>
                <DialogRow
                  label={<>Emplacement du dock flottant{SEPARATE_SAVE}</>}
                  hint={(
                    <>
                      Choisissez l&apos;un des 6 points d&apos;ancrage pour le panneau d&apos;accès rapide.
                      Le panneau s&apos;ouvrira dans la direction opposée au bord sélectionné.
                    </>
                  )}
                >
                  <OverlayAnchorPicker
                    value={
                      isOverlayAnchor(cfg.favorites_overlay_anchor)
                        ? cfg.favorites_overlay_anchor
                        : "right-center"
                    }
                    onChange={(next) => update("favorites_overlay_anchor", next)}
                  />
                </DialogRow>
                <DialogRow
                  label={<label htmlFor="fav-show-all-switch">Afficher tous les presets de portes{SEPARATE_SAVE}</label>}
                  hint="Quand activé, le panneau liste tous les presets synchronisés, pas seulement ceux marqués comme favoris sur le tableau de bord. Les favoris apparaissent en premier."
                  className="border-b-0"
                >
                  <Switch
                    id="fav-show-all-switch"
                    checked={Boolean(cfg.favorites_overlay_show_all_presets ?? false)}
                    onCheckedChange={(checked: boolean) =>
                      update("favorites_overlay_show_all_presets", checked)
                    }
                  />
                </DialogRow>
              </>
            )}

            {/* ── Lecteur de cartes ────────────────────────────────────── */}
            {section === "scanner" && (
              <>
                <DialogRow label="Mode de connexion" hint="SCR100 via le réseau (TCP/IP port 4370)">
                  <Select
                    value={cfg.scanner_mode || "zkemkeeper"}
                    onValueChange={(value) => {
                      update("scanner_mode", value);
                    }}
                  >
                    <SelectTrigger className="h-9 w-[240px] rounded-lg border-grey/32 bg-card shadow-none">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="zkemkeeper"><Wifi className="h-3.5 w-3.5" /> SCR100 ZKEMKeeper</SelectItem>
                    </SelectContent>
                  </Select>
                </DialogRow>

                {/* Network mode settings */}
                {(cfg.scanner_mode === "zkemkeeper" || !cfg.scanner_mode) && (
                  <>
                    <DialogRow
                      label={<label htmlFor="scanner-ip">Adresse IP du SCR100</label>}
                      hint={!discovering && discoveredDevices.length === 0 && cfg.scanner_network_ip
                        ? <>IP configurée : <span className="font-mono">{cfg.scanner_network_ip}</span></>
                        : undefined}
                    >
                      <Input
                        id="scanner-ip"
                        placeholder="192.168.1.201"
                        value={cfg.scanner_network_ip || ""}
                        onChange={(e) => update("scanner_network_ip", e.target.value)}
                        className="h-9 w-[180px] rounded-lg border-grey/32 font-mono"
                      />
                    </DialogRow>
                    <DialogRow
                      label="Détecter sur le réseau"
                      hint="Cherche les appareils ZKTeco qui répondent sur le port 4370"
                      className={discoveredDevices.length > 0 ? undefined : "border-b-0"}
                    >
                      <ActionButton
                        kind="outline"
                        size="md"
                        icon={discovering ? Loader2 : Search}
                        spin={discovering}
                        onClick={() => startDiscover()}
                        disabled={discovering}
                        title="Scanner le réseau pour trouver les appareils ZKTeco (port 4370)"
                      >
                        {discovering ? "Scan…" : "Détecter"}
                      </ActionButton>
                    </DialogRow>

                    {/* Discovered devices list */}
                    {discoveredDevices.length > 0 && (
                      <div className="space-y-1.5 pt-3">
                        <Note tone="success">
                          {discoveredDevices.length} appareil{discoveredDevices.length > 1 ? "s" : ""} trouvé{discoveredDevices.length > 1 ? "s" : ""} — cliquez pour utiliser son adresse :
                        </Note>
                        {discoveredDevices.map((dev: DiscoveredDevice) => (
                          <button
                            key={dev.ip}
                            type="button"
                            className="flex w-full cursor-pointer items-center justify-between rounded-lg border border-grey/32 px-3 py-2 text-left text-[13.5px] transition-colors hover:bg-muted"
                            onClick={() => {
                              update("scanner_network_ip", dev.ip);
                            }}
                          >
                            <span className="flex items-center gap-2">
                              <Radio className="h-3.5 w-3.5 text-success-ink" />
                              <span className="font-mono text-[13px]">{dev.ip}</span>
                              {dev.serialNumber && (
                                <span className="text-[12.5px] text-muted-foreground">— {dev.serialNumber}</span>
                              )}
                            </span>
                            <span className="text-[12.5px] text-muted-foreground">{dev.model}</span>
                          </button>
                        ))}
                      </div>
                    )}
                  </>
                )}
              </>
            )}

            {/* ── Sons et animations (all saved immediately) ───────────── */}
            {section === "feedback" && (
              <>
                <DialogSection>Envoi réussi vers un appareil</DialogSection>
                <p className="text-[12.5px] text-muted-foreground">
                  Son et animation quand les données sont poussées avec succès vers un appareil ZKTeco.
                  Son par défaut : <span className="font-mono">{DEFAULT_FEEDBACK_SOUNDS.device_push_success}</span> ·
                  animation : <span className="font-mono">{DEFAULT_FEEDBACK_ANIMATIONS.device_push_success}</span>
                </p>
                <DialogRow label={<label htmlFor="push-success-sound-switch">Son{AUTO}</label>}>
                  {fbSwitch("push-success-sound-switch", "push_success_sound_enabled", true)}
                </DialogRow>
                <DialogRow label={<label htmlFor="push-success-animation-switch">Animation{AUTO}</label>}>
                  {fbSwitch("push-success-animation-switch", "push_success_animation_enabled", true)}
                </DialogRow>
                <DialogRow label={<>Répétition{AUTO}</>}>
                  <Select
                    value={String(cfg.push_success_repeat_mode || "per_device")}
                    onValueChange={(value) => { void patchFeedbackConfig({ push_success_repeat_mode: value }); }}
                  >
                    <SelectTrigger className="h-9 w-[260px] rounded-lg border-grey/32 bg-card shadow-none"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="per_device">Pour chaque appareil réussi</SelectItem>
                      <SelectItem value="per_run">Une seule fois par synchronisation</SelectItem>
                    </SelectContent>
                  </Select>
                </DialogRow>
                <DialogRow label={<>Source du son{AUTO}</>}>{sourceSelect("push_success_sound_source")}</DialogRow>
                {soundFileRow({ uploading: devicePushUploading, fileName: devicePushCustomFileName, inputRef: devicePushSoundInputRef, kind: "device-push" })}

                <DialogSection className="pt-5">Synchronisation terminée</DialogSection>
                <p className="text-[12.5px] text-muted-foreground">
                  Son et animation quand une synchronisation complète se termine avec succès.
                  Son par défaut : <span className="font-mono">{DEFAULT_FEEDBACK_SOUNDS.sync_completed_success}</span> ·
                  animation : <span className="font-mono">{DEFAULT_FEEDBACK_ANIMATIONS.sync_completed_success}</span>
                </p>
                <DialogRow label={<label htmlFor="sync-success-sound-switch">Son{AUTO}</label>}>
                  {fbSwitch("sync-success-sound-switch", "sync_success_sound_enabled", true)}
                </DialogRow>
                <DialogRow label={<label htmlFor="sync-success-animation-switch">Animation{AUTO}</label>} hint="Style : confetti et célébration">
                  <Sparkles className="h-4 w-4 text-warning-ink" />
                  {fbSwitch("sync-success-animation-switch", "sync_success_animation_enabled", true)}
                </DialogRow>
                <DialogRow label={<>Source du son{AUTO}</>}>{sourceSelect("sync_success_sound_source")}</DialogRow>
                {soundFileRow({ uploading: syncCompleteUploading, fileName: syncCompleteCustomFileName, inputRef: syncCompleteSoundInputRef, kind: "sync-complete" })}

                <DialogSection className="pt-5">Anti-fraude (durée)</DialogSection>
                <p className="text-[12.5px] text-muted-foreground">
                  Son joué quand un utilisateur est refusé pour tentative de passage trop rapide (anti-fraude durée).
                  Son par défaut : <span className="font-mono">{DEFAULT_FEEDBACK_SOUNDS.anti_fraud_duration}</span>
                </p>
                <DialogRow label={<label htmlFor="anti-fraud-duration-sound-switch">Son{AUTO}</label>}>
                  {fbSwitch("anti-fraud-duration-sound-switch", "anti_fraud_duration_sound_enabled", true)}
                </DialogRow>
                <DialogRow label={<>Source du son{AUTO}</>}>{sourceSelect("anti_fraud_duration_sound_source")}</DialogRow>
                {soundFileRow({ uploading: antiFraudDurationUploading, fileName: antiFraudDurationCustomFileName, inputRef: antiFraudDurationSoundInputRef, kind: "anti-fraud-duration" })}

                <DialogSection className="pt-5">Limite de passages journalière</DialogSection>
                <p className="text-[12.5px] text-muted-foreground">
                  Son joué quand un utilisateur dépasse sa limite de passages journalière (alerte seulement — l&apos;accès est accordé).
                  Son par défaut : <span className="font-mono">{DEFAULT_FEEDBACK_SOUNDS.anti_fraud_daily_limit}</span>
                </p>
                <DialogRow label={<label htmlFor="anti-fraud-daily-limit-sound-switch">Son{AUTO}</label>}>
                  {fbSwitch("anti-fraud-daily-limit-sound-switch", "anti_fraud_daily_limit_sound_enabled", true)}
                </DialogRow>
                <DialogRow label={<>Source du son{AUTO}</>}>{sourceSelect("anti_fraud_daily_limit_sound_source")}</DialogRow>
                {soundFileRow({ uploading: antiFraudDailyLimitUploading, fileName: antiFraudDailyLimitCustomFileName, inputRef: antiFraudDailyLimitSoundInputRef, kind: "anti-fraud-daily-limit" })}
              </>
            )}

            {/* ── Paramètres avancés (password) ────────────────────────── */}
            {section === "advanced" && (!advancedUnlocked ? (
              <DialogRow
                label="Paramètres avancés"
                hint="Session, synchronisation, barre des tâches, debug. Protégés par le mot de passe administrateur."
                className="border-b-0"
              >
                <ActionButton kind="dark" size="md" icon={LockOpen} onClick={() => setPwdDialogOpen(true)}>
                  Afficher
                </ActionButton>
              </DialogRow>
            ) : (
              <>
                <DialogSection>Général</DialogSection>
                <DialogRow label="Email de connexion">
                  <Input value={cfg.login_email || ""} onChange={(e) => update("login_email", e.target.value)} className="h-9 w-[240px] rounded-lg border-grey/32" />
                </DialogRow>
                <DialogRow label="Intervalle de sync (sec)" hint="En secondes">
                  <Input type="number" value={cfg.sync_interval_sec ?? 60} onChange={(e) => update("sync_interval_sec", parseInt(e.target.value) || 60)} className="h-9 w-[110px] rounded-lg border-grey/32 font-mono" />
                </DialogRow>
                <DialogRow label="Durée max session (min)" hint="43200 = 30 jours">
                  <Input type="number" value={cfg.max_login_age_minutes ?? 43200} onChange={(e) => update("max_login_age_minutes", parseInt(e.target.value) || 43200)} className="h-9 w-[110px] rounded-lg border-grey/32 font-mono" />
                </DialogRow>
                <DialogRow label="Délai de grâce hors ligne (jours)" hint="0 = les abonnements expirent à l'heure même sans internet">
                  <Input type="number" min={0} max={36500} value={cfg.offline_revoke_grace_days ?? 0} onChange={(e) => update("offline_revoke_grace_days", Math.min(36500, Math.max(0, parseInt(e.target.value) || 0)))} className="h-9 w-[110px] rounded-lg border-grey/32 font-mono" />
                </DialogRow>
                <DialogRow label="Sync appareils (DEVICE mode)">
                  <Switch checked={cfg.device_sync_enabled ?? true} onCheckedChange={(v: boolean) => update("device_sync_enabled", v)} />
                </DialogRow>

                <DialogSection className="pt-5">Barre des tâches</DialogSection>
                <DialogRow label="Activer l'icône de la barre des tâches">
                  <Switch checked={cfg.tray_enabled ?? true} onCheckedChange={(v: boolean) => update("tray_enabled", v)} />
                </DialogRow>
                <DialogRow label="Réduire dans la barre des tâches au lieu de fermer">
                  <Switch checked={cfg.minimize_to_tray_on_close ?? true} onCheckedChange={(v: boolean) => update("minimize_to_tray_on_close", v)} />
                </DialogRow>

                <DialogSection className="pt-5">Avancé</DialogSection>
                <DialogRow label="Mode debug">
                  <Switch checked={cfg.debug_mode ?? false} onCheckedChange={(v: boolean) => update("debug_mode", v)} />
                </DialogRow>
                <DialogRow label="Encodage empreinte">
                  <Input value={cfg.fingerprint_encoding || "BASE64"} onChange={(e) => update("fingerprint_encoding", e.target.value)} className="h-9 w-[140px] rounded-lg border-grey/32 font-mono" />
                </DialogRow>

                <DialogSection className="pt-5">Paramètres serveur (lecture seule)</DialogSection>
                {Object.keys(serverSettings).length > 0 ? (
                  Object.entries(serverSettings).map(([k, v]) => (
                    <DialogRow key={k} label={k} mono>
                      <span className="font-mono text-[13px]">{String(v)}</span>
                    </DialogRow>
                  ))
                ) : (
                  <p className="py-2 text-[13px] text-muted-foreground">Aucun paramètre serveur chargé.</p>
                )}
              </>
            ))}
          </div>
        </Panel>

        {/* ── Le rail ─────────────────────────────────────────────────── */}
        <div className="col-span-4 flex flex-col gap-[18px]">
          <Panel>
            <PanelHeader
              title={changes.length > 0 ? "Non enregistré" : "Tout est enregistré"}
              sub={changes.length > 0 ? "Annuler ou Enregistrer en haut de la page" : "Aucune modification en attente."}
            />
            {changes.length > 0 ? (
              <>
                {/* Raw setting keys on purpose — there is no French label catalogue
                    in the codebase, and inventing one risks mislabelling a field. */}
                <PanelList className="max-h-[260px] overflow-y-auto">
                  {changes.map((c) => (
                    <ListRow
                      key={c.key}
                      icon={ArrowRightLeft}
                      tone="warning"
                      mono
                      title={c.key}
                      sub={`${fmtVal(c.from)} → ${fmtVal(c.to)}`}
                    />
                  ))}
                </PanelList>
                <div className="flex gap-2 border-t border-dashed border-grey/20 px-[18px] py-3.5">
                  <ActionButton kind="outline" className="flex-1" onClick={discardEdits} disabled={saving}>
                    Annuler
                  </ActionButton>
                  <ActionButton kind="primary" className="flex-[1.3]" icon={saving ? Loader2 : Save} spin={saving} onClick={handleSave} disabled={saving}>
                    Enregistrer
                  </ActionButton>
                </div>
              </>
            ) : (
              <PanelList>
                <ListRow icon={CheckCircle} tone="success" title="Rien à enregistrer" sub="Les réglages « Enregistré automatiquement » sont déjà sauvegardés." wrap />
              </PanelList>
            )}
          </Panel>

          <Panel>
            <PanelHeader title="Ce poste" />
            <PanelList>
              <ListRow icon={Info} tone="grey" title="Version installée" value={currentVersionDisplay} valueMono />
              <ListRow icon={Download} tone="grey" title="Canal" value={`${updates?.channel || "stable"} · ${updates?.platform || "WINDOWS"}`} />
              {hasAgentDevices(status) && (
                <ListRow
                  icon={Router}
                  tone={status?.agent?.running ? "success" : "grey"}
                  title="Agent temps réel"
                  value={status?.agent?.running ? "actif" : "arrêté"}
                />
              )}
              <ListRow icon={Router} tone={readerTone} title="Lecteurs" value={readerValue} />
              {updates?.updateAvailable && (
                <ListRow
                  icon={CircleAlert}
                  tone="primary"
                  wrap
                  title={`Version ${updates.latestVersion ?? ""} disponible`}
                  sub={updates.downloaded ? "Téléchargée — à installer à la fermeture du club." : "À installer à la fermeture du club."}
                  actions={<ActionButton kind="outline" size="sm" icon={Info} onClick={() => setUpdateDialog(true)}>Voir les détails</ActionButton>}
                />
              )}
            </PanelList>
          </Panel>
        </div>
      </PageGrid>

      {/* Password dialog */}
      <DialogFrame
        open={pwdDialogOpen}
        onOpenChange={setPwdDialogOpen}
        width={440}
        title="Paramètres avancés"
        sub="Entrez le mot de passe administrateur."
        footer={(
          <>
            <ActionButton kind="outline" className="px-4" onClick={() => { setPwdDialogOpen(false); setPwdInput(""); }}>Annuler</ActionButton>
            <ActionButton kind="dark" className="px-4" icon={Unlock} onClick={handleUnlockAdvanced}>Déverrouiller</ActionButton>
          </>
        )}
      >
        <Input
          type="password"
          placeholder="Mot de passe"
          aria-label="Mot de passe"
          value={pwdInput}
          onChange={(e) => { setPwdInput(e.target.value); setPwdError(false); }}
          onKeyDown={(e) => { if (e.key === "Enter") handleUnlockAdvanced(); }}
          autoFocus
          className={cn("h-11 rounded-lg", pwdError ? "border-error" : "border-grey/32")}
        />
        {pwdError && <p className="mt-2 text-[13px] font-semibold text-error-ink">Mot de passe incorrect.</p>}
      </DialogFrame>

      {/* Update details dialog */}
      <DialogFrame
        open={updateDialog}
        onOpenChange={setUpdateDialog}
        width={480}
        title="Mise à jour disponible"
        footer={<ActionButton kind="dark" className="px-4" onClick={() => setUpdateDialog(false)}>Fermer</ActionButton>}
      >
        <DialogRow label="Composant"><span className="font-mono text-[13px]">{updates?.componentDisplayName || "MonClub Access"}</span></DialogRow>
        <DialogRow label="Version actuelle"><span className="font-mono text-[13px]">{updates?.currentVersion || updates?.currentReleaseId || "dev"}</span></DialogRow>
        <DialogRow label="Exécutable"><span className="font-mono text-[13px]">{updates?.mainExecutable || "MonClubAccess.exe"}</span></DialogRow>
        <DialogRow label="Package d'installation">
          <span className="font-mono text-[13px]">{updates?.latestVersion ? `monclub_access_${updates?.latestVersion}.exe` : "monclub_access_<version>.exe"}</span>
        </DialogRow>
        <DialogRow label="Fonctionnement" hint="Le .exe téléchargé installe ou met à jour automatiquement." />
        {updates?.installRoot && <DialogRow label="Dossier d'installation"><span className="break-all font-mono text-[12.5px]">{updates.installRoot}</span></DialogRow>}
        {updates?.lastCheckAt && <DialogRow label="Dernière vérification"><span className="font-mono text-[13px]">{updates.lastCheckAt}</span></DialogRow>}
        <Note className="mt-3">Contactez l'équipe MonClub pour obtenir la dernière version.</Note>
      </DialogFrame>
    </div>
  );
}
