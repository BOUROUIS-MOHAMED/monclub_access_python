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
} from "lucide-react";
import type { DiscoveredDevice } from "@/api/types";
import { useScanCard } from "@/hooks/useScanCard";
import {
  DEFAULT_FEEDBACK_ANIMATIONS,
  DEFAULT_FEEDBACK_SOUNDS,
  currentFeedbackFileName,
  resetFeedbackSound,
  uploadFeedbackSound,
  type FeedbackSoundKind,
} from "@/lib/feedback";

export default function ConfigPage() {
  const { status } = useApp();
  const [cfg, setCfg] = useState<Record<string, any>>({});
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

  const broadcastFeedbackConfig = useCallback((nextCfg: Record<string, any>) => {
    if (typeof window === "undefined") return;
    window.dispatchEvent(new CustomEvent("access-feedback-config-updated", { detail: nextCfg }));
  }, []);

  const loadConfig = useCallback(async () => {
    setLoading(true);
    try {
      const res = await get<any>("/config");
      const nextCfg = res.config || res || {};
      setCfg(nextCfg);
      setServerSettings(res.serverSettings || {});
      broadcastFeedbackConfig(nextCfg);
    } catch (e) { setError(String(e)); }
    finally { setLoading(false); }
  }, [broadcastFeedbackConfig]);

  useEffect(() => { loadConfig(); }, [loadConfig]);

  const handleSave = async () => {
    setSaving(true); setError(null); setSuccess(false);
    try {
      const res = await patch<any>("/config", cfg);
      const nextCfg = res.config || cfg;
      setCfg(nextCfg);
      broadcastFeedbackConfig(nextCfg);
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
      setCfg(nextCfg);
      broadcastFeedbackConfig(nextCfg);
    } catch (e) {
      setError(String(e));
      await loadConfig();
    }
  }, [broadcastFeedbackConfig, cfg, loadConfig]);

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
      await loadConfig();
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
  }, [loadConfig]);

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
      await loadConfig();
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
  }, [loadConfig]);

  const handleStartupToggle = async (enabled: boolean) => {
    const previous = Boolean(cfg.start_on_system_startup ?? false);
    setCfg((p) => ({ ...p, start_on_system_startup: enabled }));
    setStartupSaving(true);
    setError(null);
    try {
      await patch("/config", { start_on_system_startup: enabled });
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

  if (loading) {
    return <div className="flex items-center justify-center py-20"><Loader2 className="h-8 w-8 animate-spin text-primary" /></div>;
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Settings className="h-5 w-5 text-primary" />
          <h1 className="text-lg font-semibold">Configuration</h1>
        </div>
        {dirty && (
          <Button onClick={handleSave} disabled={saving}>
            {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
            Enregistrer
          </Button>
        )}
      </div>

      {error && <Alert variant="destructive"><AlertDescription>{error}</AlertDescription></Alert>}
      {success && <Alert variant="success"><CheckCircle className="h-4 w-4" /><AlertDescription>Configuration enregistrée !</AlertDescription></Alert>}

      {/* Updates section — always visible */}
      <Card>
        <CardHeader>
          <CardTitle className="text-sm flex items-center gap-2"><Download className="h-4 w-4" /> Mises à jour</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex items-center justify-between">
            <div className="space-y-1">
              <p className="text-sm">Composant: <code className="bg-muted px-1.5 py-0.5 rounded text-xs">{updates?.componentDisplayName || "MonClub Access"}</code></p>
              <p className="text-sm">Version actuelle: <code className="bg-muted px-1.5 py-0.5 rounded text-xs">{currentVersionDisplay}</code></p>
              <p className="text-xs text-muted-foreground">Canal {updates?.channel || "stable"} · Plateforme {updates?.platform || "WINDOWS"}</p>
              {updates?.updateAvailable ? (
                <Badge variant="warning" className="text-xs">Mise à jour disponible</Badge>
              ) : (
                <p className="text-sm text-muted-foreground">Aucune mise à jour disponible.</p>
              )}
            </div>
            {updates?.updateAvailable && (
              <Button size="sm" variant="outline" onClick={() => setUpdateDialog(true)}>
                <Info className="h-3.5 w-3.5" /> Détails
              </Button>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Advanced settings — locked by default */}
      <Card>
        <CardHeader>
          <CardTitle className="text-sm flex items-center gap-2"><Settings className="h-4 w-4" /> Demarrage Windows</CardTitle>
        </CardHeader>
        <CardContent className="flex items-start justify-between gap-4">
          <div className="space-y-1">
            <Label htmlFor="start-on-windows-switch">Ouvrir MonClub Access avec Windows</Label>
            <p className="text-sm text-muted-foreground">
              Quand cette option est activee, MonClub Access est ajoute au demarrage de Windows et son interface s&apos;ouvre automatiquement a l&apos;ouverture de session.
            </p>
            <p className="text-xs text-muted-foreground">
              En mode developpement, la preference est enregistree, mais l&apos;inscription au demarrage Windows ne s&apos;applique que sur les builds installes.
            </p>
          </div>
          <div className="flex items-center gap-3">
            {startupSaving && <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />}
            <Switch
              id="start-on-windows-switch"
              checked={Boolean(cfg.start_on_system_startup ?? false)}
              onCheckedChange={(checked: boolean) => { void handleStartupToggle(checked); }}
            />
          </div>
        </CardContent>
      </Card>

      {/* Card scanner settings — always visible */}
      <Card>
        <CardHeader>
          <CardTitle className="text-sm flex items-center gap-2">
            <CreditCard className="h-4 w-4" /> Lecteur de cartes
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Mode toggle */}
          <div className="flex items-center justify-between">
            <div className="space-y-1">
              <Label>Mode de connexion</Label>
              <p className="text-sm text-muted-foreground">
                SCR100 via le réseau (TCP/IP port 4370)
              </p>
            </div>
            <div className="flex items-center gap-2">
              <Select
                value={cfg.scanner_mode || "zkemkeeper"}
                onValueChange={(value) => {
                  update("scanner_mode", value);
                }}
              >
                <SelectTrigger className="w-[240px]">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="zkemkeeper"><Wifi className="h-3.5 w-3.5" /> SCR100 ZKEMKeeper</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          {/* Network mode settings */}
          {(cfg.scanner_mode === "zkemkeeper" || !cfg.scanner_mode) && (
            <div className="space-y-3 pt-2 border-t border-border/40">
              <div className="flex items-end gap-2">
                <div className="flex-1 space-y-1">
                  <Label htmlFor="scanner-ip">Adresse IP du SCR100</Label>
                  <Input
                    id="scanner-ip"
                    placeholder="192.168.1.201"
                    value={cfg.scanner_network_ip || ""}
                    onChange={(e) => update("scanner_network_ip", e.target.value)}
                  />
                </div>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => startDiscover()}
                  disabled={discovering}
                  title="Scanner le réseau pour trouver les appareils ZKTeco (port 4370)"
                >
                  {discovering ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <Search className="h-4 w-4" />
                  )}
                  {discovering ? "Scan..." : "Détecter"}
                </Button>
              </div>

              {/* Discovered devices list */}
              {discoveredDevices.length > 0 && (
                <div className="space-y-1">
                  <p className="text-xs text-muted-foreground">
                    {discoveredDevices.length} appareil(s) trouvé(s) :
                  </p>
                  {discoveredDevices.map((dev: DiscoveredDevice) => (
                    <button
                      key={dev.ip}
                      className="w-full flex items-center justify-between px-3 py-2 rounded-md border border-border hover:bg-accent text-left text-sm transition-colors"
                      onClick={() => {
                        update("scanner_network_ip", dev.ip);
                      }}
                    >
                      <span className="flex items-center gap-2">
                        <Radio className="h-3.5 w-3.5 text-emerald-500" />
                        <code className="text-xs font-mono">{dev.ip}</code>
                        {dev.serialNumber && (
                          <span className="text-xs text-muted-foreground">
                            — {dev.serialNumber}
                          </span>
                        )}
                      </span>
                      <span className="text-xs text-muted-foreground">{dev.model}</span>
                    </button>
                  ))}
                </div>
              )}

              {!discovering && discoveredDevices.length === 0 && cfg.scanner_network_ip && (
                <p className="text-xs text-muted-foreground">
                  IP configurée : <code className="bg-muted px-1 rounded">{cfg.scanner_network_ip}</code>
                </p>
              )}
            </div>
          )}

        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm flex items-center gap-2">
            <Music4 className="h-4 w-4" /> Feedback
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-5">
          <div className="space-y-3">
            <div className="flex items-start justify-between gap-4">
              <div className="space-y-1">
                <Label>Push appareil réussi</Label>
                <p className="text-sm text-muted-foreground">
                  Son et animation quand les données sont poussées avec succès vers un appareil ZKTeco.
                </p>
                <p className="text-xs text-muted-foreground">
                  Son par défaut : <code className="bg-muted px-1 rounded">{DEFAULT_FEEDBACK_SOUNDS.device_push_success}</code>
                </p>
                <p className="text-xs text-muted-foreground">
                  Animation : <code className="bg-muted px-1 rounded">{DEFAULT_FEEDBACK_ANIMATIONS.device_push_success}</code>
                </p>
              </div>
              <div className="grid min-w-[180px] gap-3">
                <div className="flex items-center justify-between gap-3">
                  <Label htmlFor="push-success-sound-switch" className="text-xs">Son</Label>
                  <Switch
                    id="push-success-sound-switch"
                    checked={Boolean(cfg.push_success_sound_enabled ?? true)}
                    onCheckedChange={(checked: boolean) => { void patchFeedbackConfig({ push_success_sound_enabled: checked }); }}
                  />
                </div>
                <div className="flex items-center justify-between gap-3">
                  <Label htmlFor="push-success-animation-switch" className="text-xs">Animation</Label>
                  <Switch
                    id="push-success-animation-switch"
                    checked={Boolean(cfg.push_success_animation_enabled ?? true)}
                    onCheckedChange={(checked: boolean) => { void patchFeedbackConfig({ push_success_animation_enabled: checked }); }}
                  />
                </div>
              </div>
            </div>

            <div className="grid gap-3 md:grid-cols-2">
              <div className="space-y-1.5">
                <Label>Répétition</Label>
                <Select
                  value={String(cfg.push_success_repeat_mode || "per_device")}
                  onValueChange={(value) => { void patchFeedbackConfig({ push_success_repeat_mode: value }); }}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="per_device">Pour chaque appareil réussi</SelectItem>
                    <SelectItem value="per_run">Une seule fois par synchronisation</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-1.5">
                <Label>Source du son</Label>
                <Select
                  value={String(cfg.push_success_sound_source || "default")}
                  onValueChange={(value) => { void patchFeedbackConfig({ push_success_sound_source: value }); }}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="default">Son par défaut</SelectItem>
                    <SelectItem value="custom">Son personnalisé</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <input
                ref={devicePushSoundInputRef}
                type="file"
                accept=".mp3,.wav,.ogg,.m4a,audio/*"
                className="hidden"
                onChange={(event) => { void handleFeedbackSoundUpload("device-push", event.target.files?.[0] ?? null); }}
              />
              <Button
                type="button"
                variant="outline"
                size="sm"
                disabled={devicePushUploading}
                onClick={() => devicePushSoundInputRef.current?.click()}
              >
                {devicePushUploading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Upload className="h-4 w-4" />}
                {devicePushCustomFileName ? "Remplacer le son" : "Choisir un son"}
              </Button>
              <Button
                type="button"
                variant="ghost"
                size="sm"
                disabled={devicePushUploading || !devicePushCustomFileName}
                onClick={() => { void handleFeedbackSoundReset("device-push"); }}
              >
                <RotateCcw className="h-4 w-4" /> Réinitialiser
              </Button>
              <span className="text-xs text-muted-foreground">
                {devicePushCustomFileName ? `Actuel : ${devicePushCustomFileName}` : "Aucun son personnalisé sélectionné."}
              </span>
            </div>
          </div>

          <Separator />

          <div className="space-y-3">
            <div className="flex items-start justify-between gap-4">
              <div className="space-y-1">
                <Label>Synchronisation terminée</Label>
                <p className="text-sm text-muted-foreground">
                  Son et animation quand une synchronisation complète se termine avec succès.
                </p>
                <p className="text-xs text-muted-foreground">
                  Son par défaut : <code className="bg-muted px-1 rounded">{DEFAULT_FEEDBACK_SOUNDS.sync_completed_success}</code>
                </p>
                <p className="text-xs text-muted-foreground">
                  Animation : <code className="bg-muted px-1 rounded">{DEFAULT_FEEDBACK_ANIMATIONS.sync_completed_success}</code>
                </p>
              </div>
              <div className="grid min-w-[180px] gap-3">
                <div className="flex items-center justify-between gap-3">
                  <Label htmlFor="sync-success-sound-switch" className="text-xs">Son</Label>
                  <Switch
                    id="sync-success-sound-switch"
                    checked={Boolean(cfg.sync_success_sound_enabled ?? true)}
                    onCheckedChange={(checked: boolean) => { void patchFeedbackConfig({ sync_success_sound_enabled: checked }); }}
                  />
                </div>
                <div className="flex items-center justify-between gap-3">
                  <Label htmlFor="sync-success-animation-switch" className="text-xs">Animation</Label>
                  <Switch
                    id="sync-success-animation-switch"
                    checked={Boolean(cfg.sync_success_animation_enabled ?? true)}
                    onCheckedChange={(checked: boolean) => { void patchFeedbackConfig({ sync_success_animation_enabled: checked }); }}
                  />
                </div>
              </div>
            </div>

            <div className="grid gap-3 md:grid-cols-2">
              <div className="space-y-1.5">
                <Label>Source du son</Label>
                <Select
                  value={String(cfg.sync_success_sound_source || "default")}
                  onValueChange={(value) => { void patchFeedbackConfig({ sync_success_sound_source: value }); }}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="default">Son par défaut</SelectItem>
                    <SelectItem value="custom">Son personnalisé</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-1.5">
                <Label>Style</Label>
                <div className="flex h-9 items-center gap-2 rounded-md border border-input px-3 text-sm text-muted-foreground">
                  <Sparkles className="h-4 w-4 text-amber-400" />
                  Confetti et célébration
                </div>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <input
                ref={syncCompleteSoundInputRef}
                type="file"
                accept=".mp3,.wav,.ogg,.m4a,audio/*"
                className="hidden"
                onChange={(event) => { void handleFeedbackSoundUpload("sync-complete", event.target.files?.[0] ?? null); }}
              />
              <Button
                type="button"
                variant="outline"
                size="sm"
                disabled={syncCompleteUploading}
                onClick={() => syncCompleteSoundInputRef.current?.click()}
              >
                {syncCompleteUploading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Upload className="h-4 w-4" />}
                {syncCompleteCustomFileName ? "Remplacer le son" : "Choisir un son"}
              </Button>
              <Button
                type="button"
                variant="ghost"
                size="sm"
                disabled={syncCompleteUploading || !syncCompleteCustomFileName}
                onClick={() => { void handleFeedbackSoundReset("sync-complete"); }}
              >
                <RotateCcw className="h-4 w-4" /> Réinitialiser
              </Button>
              <span className="text-xs text-muted-foreground">
                {syncCompleteCustomFileName ? `Actuel : ${syncCompleteCustomFileName}` : "Aucun son personnalisé sélectionné."}
              </span>
            </div>
          </div>

          <Separator />

          {/* ── Anti-fraude durée ── */}
          <div className="space-y-3">
            <div className="flex items-start justify-between gap-4">
              <div className="space-y-1">
                <Label>Anti-fraude durée</Label>
                <p className="text-sm text-muted-foreground">
                  Son joué quand un utilisateur est refusé pour tentative de passage trop rapide (anti-fraude durée).
                </p>
                <p className="text-xs text-muted-foreground">
                  Son par défaut : <code className="bg-muted px-1 rounded">{DEFAULT_FEEDBACK_SOUNDS.anti_fraud_duration}</code>
                </p>
              </div>
              <div className="grid min-w-[180px] gap-3">
                <div className="flex items-center justify-between gap-3">
                  <Label htmlFor="anti-fraud-duration-sound-switch" className="text-xs">Son</Label>
                  <Switch
                    id="anti-fraud-duration-sound-switch"
                    checked={Boolean(cfg.anti_fraud_duration_sound_enabled ?? true)}
                    onCheckedChange={(checked: boolean) => { void patchFeedbackConfig({ anti_fraud_duration_sound_enabled: checked }); }}
                  />
                </div>
              </div>
            </div>

            <div className="grid gap-3 md:grid-cols-2">
              <div className="space-y-1.5">
                <Label>Source du son</Label>
                <Select
                  value={String(cfg.anti_fraud_duration_sound_source || "default")}
                  onValueChange={(value) => { void patchFeedbackConfig({ anti_fraud_duration_sound_source: value }); }}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="default">Son par défaut</SelectItem>
                    <SelectItem value="custom">Son personnalisé</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <input
                ref={antiFraudDurationSoundInputRef}
                type="file"
                accept=".mp3,.wav,.ogg,.m4a,audio/*"
                className="hidden"
                onChange={(event) => { void handleFeedbackSoundUpload("anti-fraud-duration", event.target.files?.[0] ?? null); }}
              />
              <Button
                type="button"
                variant="outline"
                size="sm"
                disabled={antiFraudDurationUploading}
                onClick={() => antiFraudDurationSoundInputRef.current?.click()}
              >
                {antiFraudDurationUploading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Upload className="h-4 w-4" />}
                {antiFraudDurationCustomFileName ? "Remplacer le son" : "Choisir un son"}
              </Button>
              <Button
                type="button"
                variant="ghost"
                size="sm"
                disabled={antiFraudDurationUploading || !antiFraudDurationCustomFileName}
                onClick={() => { void handleFeedbackSoundReset("anti-fraud-duration"); }}
              >
                <RotateCcw className="h-4 w-4" /> Réinitialiser
              </Button>
              <span className="text-xs text-muted-foreground">
                {antiFraudDurationCustomFileName ? `Actuel : ${antiFraudDurationCustomFileName}` : "Aucun son personnalisé sélectionné."}
              </span>
            </div>
          </div>

          <Separator />

          {/* ── Limite journalière ── */}
          <div className="space-y-3">
            <div className="flex items-start justify-between gap-4">
              <div className="space-y-1">
                <Label>Limite de passages journalière</Label>
                <p className="text-sm text-muted-foreground">
                  Son joué quand un utilisateur dépasse sa limite de passages journalière (alerte seulement — l&apos;accès est accordé).
                </p>
                <p className="text-xs text-muted-foreground">
                  Son par défaut : <code className="bg-muted px-1 rounded">{DEFAULT_FEEDBACK_SOUNDS.anti_fraud_daily_limit}</code>
                </p>
              </div>
              <div className="grid min-w-[180px] gap-3">
                <div className="flex items-center justify-between gap-3">
                  <Label htmlFor="anti-fraud-daily-limit-sound-switch" className="text-xs">Son</Label>
                  <Switch
                    id="anti-fraud-daily-limit-sound-switch"
                    checked={Boolean(cfg.anti_fraud_daily_limit_sound_enabled ?? true)}
                    onCheckedChange={(checked: boolean) => { void patchFeedbackConfig({ anti_fraud_daily_limit_sound_enabled: checked }); }}
                  />
                </div>
              </div>
            </div>

            <div className="grid gap-3 md:grid-cols-2">
              <div className="space-y-1.5">
                <Label>Source du son</Label>
                <Select
                  value={String(cfg.anti_fraud_daily_limit_sound_source || "default")}
                  onValueChange={(value) => { void patchFeedbackConfig({ anti_fraud_daily_limit_sound_source: value }); }}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="default">Son par défaut</SelectItem>
                    <SelectItem value="custom">Son personnalisé</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <input
                ref={antiFraudDailyLimitSoundInputRef}
                type="file"
                accept=".mp3,.wav,.ogg,.m4a,audio/*"
                className="hidden"
                onChange={(event) => { void handleFeedbackSoundUpload("anti-fraud-daily-limit", event.target.files?.[0] ?? null); }}
              />
              <Button
                type="button"
                variant="outline"
                size="sm"
                disabled={antiFraudDailyLimitUploading}
                onClick={() => antiFraudDailyLimitSoundInputRef.current?.click()}
              >
                {antiFraudDailyLimitUploading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Upload className="h-4 w-4" />}
                {antiFraudDailyLimitCustomFileName ? "Remplacer le son" : "Choisir un son"}
              </Button>
              <Button
                type="button"
                variant="ghost"
                size="sm"
                disabled={antiFraudDailyLimitUploading || !antiFraudDailyLimitCustomFileName}
                onClick={() => { void handleFeedbackSoundReset("anti-fraud-daily-limit"); }}
              >
                <RotateCcw className="h-4 w-4" /> Réinitialiser
              </Button>
              <span className="text-xs text-muted-foreground">
                {antiFraudDailyLimitCustomFileName ? `Actuel : ${antiFraudDailyLimitCustomFileName}` : "Aucun son personnalisé sélectionné."}
              </span>
            </div>
          </div>
        </CardContent>
      </Card>

      {!advancedUnlocked ? (
        <div className="flex justify-center py-8">
          <Button variant="outline" onClick={() => setPwdDialogOpen(true)}>
            <Lock className="h-4 w-4" /> Afficher les paramètres avancés
          </Button>
        </div>
      ) : (
        <Accordion type="multiple" defaultValue={["general"]}>
          <AccordionItem value="general">
            <AccordionTrigger>Général</AccordionTrigger>
            <AccordionContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <Label>Email de connexion</Label>
                  <Input value={cfg.login_email || ""} onChange={(e) => update("login_email", e.target.value)} />
                </div>
                <div className="space-y-1.5">
                  <Label>Intervalle de sync (sec)</Label>
                  <Input type="number" value={cfg.sync_interval_sec ?? 60} onChange={(e) => update("sync_interval_sec", parseInt(e.target.value) || 60)} />
                </div>
                <div className="space-y-1.5">
                  <Label>Durée max session (min)</Label>
                  <Input type="number" value={cfg.max_login_age_minutes ?? 43200} onChange={(e) => update("max_login_age_minutes", parseInt(e.target.value) || 43200)} />
                  <p className="text-xs text-muted-foreground">43200 = 30 jours</p>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <Switch checked={cfg.device_sync_enabled ?? true} onCheckedChange={(v: boolean) => update("device_sync_enabled", v)} />
                <Label>Sync appareils (DEVICE mode)</Label>
              </div>
            </AccordionContent>
          </AccordionItem>

          <AccordionItem value="tray">
            <AccordionTrigger>Tray</AccordionTrigger>
            <AccordionContent className="space-y-3">
              <div className="flex items-center gap-3">
                <Switch checked={cfg.tray_enabled ?? true} onCheckedChange={(v: boolean) => update("tray_enabled", v)} />
                <Label>Activer le tray</Label>
              </div>
              <div className="flex items-center gap-3">
                <Switch checked={cfg.minimize_to_tray_on_close ?? true} onCheckedChange={(v: boolean) => update("minimize_to_tray_on_close", v)} />
                <Label>Minimiser dans le tray</Label>
              </div>
            </AccordionContent>
          </AccordionItem>

          <AccordionItem value="server-settings">
            <AccordionTrigger>Paramètres serveur (lecture seule)</AccordionTrigger>
            <AccordionContent>
              {Object.keys(serverSettings).length > 0 ? (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                  {Object.entries(serverSettings).map(([k, v]) => (
                    <div key={k} className="flex justify-between items-center py-1.5 px-2 rounded hover:bg-muted/50">
                      <span className="text-sm text-muted-foreground">{k}</span>
                      <span className="text-sm font-mono">{String(v)}</span>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-sm text-muted-foreground">Aucun paramètre serveur chargé.</p>
              )}
            </AccordionContent>
          </AccordionItem>

          <AccordionItem value="advanced">
            <AccordionTrigger>Avancé</AccordionTrigger>
            <AccordionContent className="space-y-3">
              <div className="flex items-center gap-3">
                <Switch checked={cfg.debug_mode ?? false} onCheckedChange={(v: boolean) => update("debug_mode", v)} />
                <Label>Mode debug</Label>
              </div>
              <div className="space-y-1.5">
                <Label>Encodage empreinte</Label>
                <Input value={cfg.fingerprint_encoding || "BASE64"} onChange={(e) => update("fingerprint_encoding", e.target.value)} />
              </div>
            </AccordionContent>
          </AccordionItem>
        </Accordion>
      )}

      {/* Password dialog */}
      <Dialog open={pwdDialogOpen} onOpenChange={setPwdDialogOpen}>
        <DialogContent className="max-w-xs">
          <DialogHeader>
            <DialogTitle>Paramètres avancés</DialogTitle>
            <DialogDescription>Entrez le mot de passe administrateur.</DialogDescription>
          </DialogHeader>
          <div className="space-y-2">
            <Input type="password" placeholder="Mot de passe" value={pwdInput} onChange={(e) => { setPwdInput(e.target.value); setPwdError(false); }}
              onKeyDown={(e) => { if (e.key === "Enter") handleUnlockAdvanced(); }} autoFocus />
            {pwdError && <p className="text-sm text-destructive">Mot de passe incorrect.</p>}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => { setPwdDialogOpen(false); setPwdInput(""); }}>Annuler</Button>
            <Button onClick={handleUnlockAdvanced}><Unlock className="h-4 w-4" /> Déverrouiller</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Update details dialog */}
      <Dialog open={updateDialog} onOpenChange={setUpdateDialog}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle>Mise à jour disponible</DialogTitle>
          </DialogHeader>
          <div className="space-y-2 text-sm">
            <p>Composant: <code className="bg-muted px-1 rounded">{updates?.componentDisplayName || "MonClub Access"}</code></p>
            <p>Version actuelle: <code className="bg-muted px-1 rounded">{updates?.currentVersion || updates?.currentReleaseId || "dev"}</code></p>
            <p>ExÃ©cutable: <code className="bg-muted px-1 rounded">{updates?.mainExecutable || "MonClubAccess.exe"}</code></p>
            <p>Package d&apos;installation: <code className="bg-muted px-1 rounded">{updates?.latestVersion ? `monclub_access_${updates?.latestVersion}.exe` : "monclub_access_<version>.exe"}</code></p>
            <p>Flux: <code className="bg-muted px-1 rounded">Le .exe telecharge installe ou met a jour automatiquement</code></p>
            {updates?.installRoot && <p>Install root: <code className="bg-muted px-1 rounded">{updates.installRoot}</code></p>}
            {updates?.lastCheckAt && <p>Dernière vérification: {updates.lastCheckAt}</p>}
            <Separator />
            <p className="text-muted-foreground">Contactez l'équipe MonClub pour obtenir la dernière version.</p>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setUpdateDialog(false)}>Fermer</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
