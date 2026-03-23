import { useCallback, useEffect, useState } from "react";
import { Loader2, Settings2 } from "lucide-react";

import { Alert, AlertDescription } from "@/components/ui/alert";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { getTvConfig, patchTvConfig } from "@/tv/api";
import { setTvKeepBackgroundOnClose } from "@/tv/runtime/native";

type TvSettingsState = {
  start_on_system_startup: boolean;
  minimize_to_tray_on_close: boolean;
  autostart_bindings_enabled: boolean;
};

export default function TvSettingsPage() {
  const [settings, setSettings] = useState<TvSettingsState>({
    start_on_system_startup: false,
    minimize_to_tray_on_close: true,
    autostart_bindings_enabled: false,
  });
  const [loading, setLoading] = useState(true);
  const [savingKey, setSavingKey] = useState<keyof TvSettingsState | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const loadSettings = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const cfg = await getTvConfig();
      const nextState = {
        start_on_system_startup: Boolean(cfg.start_on_system_startup ?? false),
        minimize_to_tray_on_close: Boolean(cfg.minimize_to_tray_on_close ?? true),
        autostart_bindings_enabled: Boolean(cfg.autostart_bindings_enabled ?? false),
      };
      setSettings(nextState);
      await setTvKeepBackgroundOnClose(nextState.minimize_to_tray_on_close);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load TV settings.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadSettings();
  }, [loadSettings]);

  const persistToggle = useCallback(async (key: keyof TvSettingsState, value: boolean) => {
    const previous = settings[key];
    const nextState = { ...settings, [key]: value };
    setSettings(nextState);
    setSavingKey(key);
    setError(null);
    setSuccess(null);

    try {
      await patchTvConfig({ [key]: value });
      if (key === "minimize_to_tray_on_close") {
        await setTvKeepBackgroundOnClose(value);
      }
      setSuccess(
        key === "start_on_system_startup"
          ? "Startup preference saved."
          : key === "autostart_bindings_enabled"
          ? "Auto-start bindings setting saved."
          : "Background behavior saved."
      );
    } catch (err) {
      setSettings((current) => ({ ...current, [key]: previous }));
      if (key === "minimize_to_tray_on_close") {
        await setTvKeepBackgroundOnClose(previous);
      }
      setError(err instanceof Error ? err.message : "Failed to save TV settings.");
    } finally {
      setSavingKey(null);
    }
  }, [settings]);

  if (loading) {
    return (
      <div className="flex min-h-[18rem] items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <Card className="border-border/70 bg-card/80 shadow-sm">
        <CardHeader className="space-y-3">
          <div className="inline-flex w-fit items-center gap-2 rounded-full border border-border bg-muted/40 px-3 py-1 text-xs font-medium text-muted-foreground">
            <Settings2 className="h-3.5 w-3.5" />
            Standalone TV runtime preferences
          </div>
          <CardTitle className="text-2xl">MonClub TV settings</CardTitle>
          <CardDescription>
            Keep the TV runtime running in the background and decide whether Windows should start it automatically.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {error && (
            <Alert variant="destructive">
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}
          {success && (
            <Alert>
              <AlertDescription>{success}</AlertDescription>
            </Alert>
          )}

          <Card className="border-border/70">
            <CardContent className="flex items-start justify-between gap-4 p-5">
              <div className="space-y-1">
                <Label htmlFor="tv-startup-switch" className="text-sm font-semibold">
                  Auto start at Windows startup
                </Label>
                <p className="text-sm text-muted-foreground">
                  Register the packaged MonClub TV app in the current user startup list.
                </p>
                <p className="text-xs text-muted-foreground">
                  In development mode this setting is saved, but Windows startup registration only applies to packaged builds.
                </p>
              </div>
              <div className="flex items-center gap-3">
                {savingKey === "start_on_system_startup" && (
                  <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
                )}
                <Switch
                  id="tv-startup-switch"
                  checked={settings.start_on_system_startup}
                  onCheckedChange={(checked) => void persistToggle("start_on_system_startup", checked)}
                />
              </div>
            </CardContent>
          </Card>

          <Card className="border-border/70">
            <CardContent className="flex items-start justify-between gap-4 p-5">
              <div className="space-y-1">
                <Label htmlFor="tv-autostart-bindings-switch" className="text-sm font-semibold">
                  Auto-start player bindings on startup
                </Label>
                <p className="text-sm text-muted-foreground">
                  When enabled, any binding with the "Auto-start" option turned on will be launched automatically when MonClub TV starts.
                </p>
                <p className="text-xs text-muted-foreground">
                  The binding must also have "Enabled" set to on. This is the master switch — individual bindings can still opt out.
                </p>
              </div>
              <div className="flex items-center gap-3">
                {savingKey === "autostart_bindings_enabled" && (
                  <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
                )}
                <Switch
                  id="tv-autostart-bindings-switch"
                  checked={settings.autostart_bindings_enabled}
                  onCheckedChange={(checked) => void persistToggle("autostart_bindings_enabled", checked)}
                />
              </div>
            </CardContent>
          </Card>

          <Card className="border-border/70">
            <CardContent className="flex items-start justify-between gap-4 p-5">
              <div className="space-y-1">
                <Label htmlFor="tv-background-switch" className="text-sm font-semibold">
                  Keep MonClub TV running in background
                </Label>
                <p className="text-sm text-muted-foreground">
                  Closing the main UI hides it to the tray while bindings, player windows, and TV services keep running.
                </p>
                <p className="text-xs text-muted-foreground">
                  Turn this off only if closing the main window should fully stop the TV app.
                </p>
              </div>
              <div className="flex items-center gap-3">
                {savingKey === "minimize_to_tray_on_close" && (
                  <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
                )}
                <Switch
                  id="tv-background-switch"
                  checked={settings.minimize_to_tray_on_close}
                  onCheckedChange={(checked) => void persistToggle("minimize_to_tray_on_close", checked)}
                />
              </div>
            </CardContent>
          </Card>
        </CardContent>
      </Card>
    </div>
  );
}
