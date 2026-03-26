import { useState, useEffect, useCallback } from "react";
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
} from "lucide-react";

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

  const loadConfig = useCallback(async () => {
    setLoading(true);
    try {
      const res = await get<any>("/config");
      setCfg(res.config || res || {});
      setServerSettings(res.serverSettings || {});
    } catch (e) { setError(String(e)); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { loadConfig(); }, [loadConfig]);

  const handleSave = async () => {
    setSaving(true); setError(null); setSuccess(false);
    try { await patch("/config", cfg); setSuccess(true); setDirty(false); setTimeout(() => setSuccess(false), 3000); }
    catch (e) { setError(String(e)); }
    finally { setSaving(false); }
  };

  const update = (key: string, value: any) => {
    setCfg((p) => ({ ...p, [key]: value }));
    setDirty(true);
  };

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
        {advancedUnlocked && dirty && (
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
              <p className="text-sm">Version actuelle: <code className="bg-muted px-1.5 py-0.5 rounded text-xs">{updates?.currentVersion || updates?.currentReleaseId || "dev"}</code></p>
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
