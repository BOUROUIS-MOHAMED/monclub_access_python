// The "Erase content" wizard (owner design 2026-09-27; server: app/core/erase_wizard.py,
// guide §3.2h). Five steps: 1 the tables and their counts (read-only), 2 the choice,
// 3 the options (forget, refill), 4 the confirmation (safety rules, typed name), 5 the run.
// Admin only: the password unlocks the page here and is checked AGAIN by the server for the
// erase and for Refill -- this screen is not the gate.
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { cn } from "@/lib/utils";
import { AlertTriangle, CheckCircle2, Loader2, Lock, ShieldAlert, Trash2, XCircle, PauseCircle } from "lucide-react";
import {
  liveEraseApi, type EraseApi, type ErasePreview, type EraseRun, type RefillOption,
} from "@/api/erase";
import { ERASE_TEXT, loadLang, saveLang, type Lang } from "@/lib/eraseWizardText";

type Props = {
  open: boolean;
  deviceId: number;
  deviceName: string;
  /** "refill": only the password and the Refill button (a turnstile on hold). */
  mode?: "erase" | "refill";
  api?: EraseApi;
  onClose: () => void;
  /** Called after a run ends or a refill, so the page reloads its holds. */
  onChanged?: () => void;
};

// C3: erasing the ``user`` table takes every readable rights and fingerprint table with it
// (the server refuses otherwise: USER_NEEDS_RIGHTS_AND_FINGERS).
const RIGHTS_AND_FINGERS = ["userauthorize", "templatev10", "template"];

function errCode(e: unknown): string | null {
  const code = e && typeof e === "object" ? (e as { code?: unknown }).code : null;
  return typeof code === "string" ? code : null;
}

function errText(e: unknown): string {
  if (e && typeof e === "object" && "message" in e) return String((e as { message: unknown }).message);
  return String(e);
}

function LangSwitch({ lang, setLang }: { lang: Lang; setLang: (l: Lang) => void }) {
  return (
    <div className="flex overflow-hidden rounded-lg border border-border text-[11px] font-bold">
      {(["fr", "en"] as Lang[]).map((l) => (
        <button
          key={l}
          type="button"
          onClick={() => setLang(l)}
          className={cn("px-2 py-0.5 uppercase", lang === l ? "bg-primary text-primary-foreground" : "text-muted-foreground")}
        >
          {l}
        </button>
      ))}
    </div>
  );
}

function Choice({
  name, checked, disabled, onChange, children, type = "radio", dim = disabled,
}: {
  name: string; checked: boolean; disabled?: boolean; onChange: () => void;
  children: React.ReactNode; type?: "radio" | "checkbox";
  /** Greyed out (default: when disabled). A choice LOCKED on stays at full strength. */
  dim?: boolean;
}) {
  return (
    <label className={cn(
      "flex cursor-pointer items-start gap-2.5 rounded-xl border px-3 py-2 text-[12.5px]",
      checked ? "border-primary bg-primary/[0.05]" : "border-border",
      disabled && "cursor-not-allowed", dim && "opacity-50",
    )}>
      <input
        type={type} name={name} checked={checked} disabled={disabled} onChange={onChange}
        className="mt-0.5 h-4 w-4 accent-[var(--primary,#e2203f)]"
      />
      <span className="min-w-0 flex-1">{children}</span>
    </label>
  );
}

export default function EraseWizardDialog({
  open, deviceId, deviceName, mode = "erase", api = liveEraseApi, onClose, onChanged,
}: Props) {
  const [lang, setLangState] = useState<Lang>(loadLang());
  const t = ERASE_TEXT[lang];
  const setLang = (l: Lang) => { setLangState(l); saveLang(l); };
  const schemeName = (sch: string | null | undefined) => (sch ? (t.schemes[sch] ?? sch) : t.unknown);

  const [password, setPassword] = useState("");
  const [unlocked, setUnlocked] = useState(false);
  const [checking, setChecking] = useState(false);
  const [lockError, setLockError] = useState<string | null>(null);

  const [step, setStep] = useState(0);
  const [preview, setPreview] = useState<ErasePreview | null>(null);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [chosen, setChosen] = useState<Set<string>>(new Set());
  const [forget, setForget] = useState<boolean | null>(null);
  const [refill, setRefill] = useState<RefillOption | null>(null);
  const [acceptFaces, setAcceptFaces] = useState(false);
  const [backupOnly, setBackupOnly] = useState(false);
  const [typedName, setTypedName] = useState("");
  const [startError, setStartError] = useState<string | null>(null);
  const [starting, setStarting] = useState(false);
  const [run, setRun] = useState<EraseRun | null>(null);
  const [refillMsg, setRefillMsg] = useState<string | null>(null);
  const [refillError, setRefillError] = useState<string | null>(null);
  const [refilling, setRefilling] = useState(false);
  const pollRef = useRef<number | null>(null);

  // The hold's pin scheme is ALWAYS read from /erase/holds (never the run's start value): the
  // Refill button sends it back and the server refuses when it moved since (review round 1).
  const [holdScheme, setHoldScheme] = useState<string | null | undefined>(undefined);
  const [stillHeld, setStillHeld] = useState(true);
  const [holdsUnknown, setHoldsUnknown] = useState(false);

  const reset = useCallback(() => {
    setPassword(""); setUnlocked(false); setLockError(null); setStep(0); setPreview(null);
    setPreviewError(null); setChosen(new Set()); setForget(null); setRefill(null);
    setAcceptFaces(false); setBackupOnly(false); setTypedName(""); setStartError(null);
    setRun(null); setRefillMsg(null); setRefillError(null);
    setHoldScheme(undefined); setStillHeld(true); setHoldsUnknown(false);
  }, []);

  useEffect(() => { if (!open) reset(); }, [open, reset]);
  useEffect(() => () => { if (pollRef.current) window.clearInterval(pollRef.current); }, []);

  const loadPreview = useCallback(async () => {
    setLoading(true); setPreviewError(null);
    try { setPreview(await api.preview(deviceId)); }
    catch (e) { setPreview(null); setPreviewError(errText(e)); }
    finally { setLoading(false); }
  }, [api, deviceId]);

  // Refill mode reads the hold list, not the preview: the preview needs the turnstile connected,
  // and on the cutover night its cables may be out when the operator comes to press Refill.
  const loadHold = useCallback(async () => {
    setLoading(true); setPreviewError(null);
    try {
      const res = await api.holds();
      const h = (res.holds ?? []).find((x) => Number(x.deviceId) === deviceId);
      setHoldsUnknown(!!res.loadFailed);
      setStillHeld(!!h || !!res.loadFailed); setHoldScheme(h ? (h.pinScheme ?? null) : undefined);
    } catch (e) { setPreviewError(errText(e)); }
    finally { setLoading(false); }
  }, [api, deviceId]);

  const unlock = useCallback(async () => {
    if (!password.trim() || checking) return;
    setChecking(true); setLockError(null);
    try {
      const res = await api.verifyPassword(password);
      if (res.ok) { setUnlocked(true); if (mode === "refill") void loadHold(); else void loadPreview(); }
      else setLockError(res.error || "—");
    } catch (e) { setLockError(errText(e)); }
    finally { setChecking(false); }
  }, [api, password, checking, loadPreview, loadHold, mode]);

  const protocol = preview?.device.protocol;
  const usersKey = protocol === "ZK_STANDALONE" ? "users" : "user";
  const facesRaw = preview?.extra?.faces;
  // An unreadable face count is NOT zero: faces may be there, and none can be backed up.
  const facesUnknown = facesRaw === null || facesRaw === undefined;
  const faces = Number(facesRaw ?? 0) || 0;
  const needFaces = protocol === "ZK_STANDALONE" && chosen.has("users") && !backupOnly
    && (facesUnknown || faces > 0);
  const forgetAllowed = chosen.has(usersKey);
  // MB2000: erasing the users forces "forget" (the server refuses "keep": USERS_ERASE_NEEDS_FORGET).
  const forgetForced = protocol === "ZK_STANDALONE" && chosen.has("users");
  useEffect(() => { if (!forgetAllowed && forget === true) setForget(null); }, [forgetAllowed, forget]);
  useEffect(() => { if (forgetForced && forget !== true) setForget(true); }, [forgetForced, forget]);
  const requiredByUser = useMemo(() => (protocol === "ZK_PULLSDK" && chosen.has("user")
    ? (preview?.tables ?? []).filter((r) => r.erasable && RIGHTS_AND_FINGERS.includes(r.key)).map((r) => r.key)
    : []), [protocol, chosen, preview]);

  const optionsReady = backupOnly || (forget !== null && refill !== null && (!needFaces || acceptFaces));
  const nameOk = preview ? typedName.trim() === preview.device.name : false;

  const pollStatus = useCallback(() => {
    if (pollRef.current) window.clearInterval(pollRef.current);
    const tick = async () => {
      try {
        const s = await api.status();
        if (s.run) setRun(s.run);
        if (s.run && s.run.state !== "RUNNING") {
          if (pollRef.current) window.clearInterval(pollRef.current);
          pollRef.current = null;
          onChanged?.();
        }
      } catch { /* the next tick retries */ }
    };
    void tick();
    pollRef.current = window.setInterval(tick, 1000);
  }, [api, onChanged]);

  const start = useCallback(async () => {
    if (!preview || starting) return;
    setStarting(true); setStartError(null);
    try {
      await api.start(deviceId, {
        previewId: preview.previewId, tables: Array.from(chosen), typedName: typedName.trim(),
        password, backupOnly: backupOnly || undefined,
        ...(backupOnly ? {} : { forget: forget ?? undefined, refill: refill ?? undefined }),
        acceptFaceLoss: needFaces ? acceptFaces : undefined,
      });
      setStep(4);
      pollStatus();
    } catch (e) { setStartError(errText(e)); }
    finally { setStarting(false); }
  }, [api, deviceId, preview, chosen, typedName, password, backupOnly, forget, refill, needFaces,
      acceptFaces, starting, pollStatus]);

  const doRefill = useCallback(async () => {
    if (refilling || holdScheme === undefined || holdsUnknown) return;
    setRefilling(true); setRefillError(null);
    try {
      const res = await api.refill(deviceId, password, holdScheme);
      setRefillMsg(t.refilledWith(schemeName(res.pinScheme)));
      onChanged?.();
      if (mode === "erase" && run) setRun({ ...run, holdKept: false });
      setStillHeld(false);
      if (preview) setPreview({ ...preview, hold: null });
    } catch (e) {
      if (errCode(e) === "PIN_SCHEME_CHANGED") {
        const now = (e as { payload?: { pinScheme?: string | null } | null }).payload?.pinScheme ?? null;
        setRefillError(t.schemeChanged(schemeName(now)));
        void loadHold();
      } else setRefillError(errText(e));
    }
    finally { setRefilling(false); }
  }, [api, deviceId, password, refilling, holdScheme, holdsUnknown, t, onChanged, mode, run, preview, loadHold]);

  // Erase mode: a hold panel (a held turnstile at step 1, or a run that kept the hold) shows the
  // scheme read from /erase/holds NOW, and Refill sends that one.
  const showsHold = mode === "erase" && unlocked
    && ((step === 0 && !!preview?.hold) || (!!run && run.state !== "RUNNING" && !!run.holdKept));
  useEffect(() => { if (showsHold) void loadHold(); }, [showsHold, loadHold]);

  const toggle = (key: string) => setChosen((prev) => {
    const s = new Set(prev);
    if (s.has(key)) s.delete(key);
    else {
      s.add(key);
      if (protocol === "ZK_PULLSDK" && key === "user") {
        for (const r of preview?.tables ?? []) if (r.erasable && RIGHTS_AND_FINGERS.includes(r.key)) s.add(r.key);
      }
    }
    return s;
  });

  const busy = run?.state === "RUNNING";

  // ── rendering ────────────────────────────────────────────────────────────
  const header = (
    <DialogHeader>
      <div className="flex items-center justify-between gap-3 pr-6">
        <DialogTitle className="flex items-center gap-2 text-[15px]">
          <Trash2 className="h-4 w-4 text-primary" />
          {t.title} — {deviceName}
        </DialogTitle>
        <LangSwitch lang={lang} setLang={setLang} />
      </div>
      {unlocked && mode === "erase" && (
        <ol className="mt-2 flex gap-1.5">
          {t.steps.map((label, i) => (
            <li key={label} className={cn(
              "flex items-center gap-1.5 rounded-lg px-2 py-1 text-[11px] font-bold",
              i === step ? "bg-primary text-primary-foreground"
                : i < step ? "bg-primary/[0.09] text-primary" : "bg-muted text-muted-foreground",
            )}>
              <span>{i + 1}</span><span>{label}</span>
            </li>
          ))}
        </ol>
      )}
    </DialogHeader>
  );

  const lockScreen = (
    <div className="flex flex-col gap-3">
      <div className="flex items-center gap-2 text-[13px] font-bold"><Lock className="h-4 w-4" />{t.lockTitle}</div>
      <p className="text-[12.5px] text-muted-foreground">{t.lockText}</p>
      <Label htmlFor="erase-pw" className="text-[12px]">{t.password}</Label>
      <Input
        id="erase-pw" type="password" value={password} autoFocus
        onChange={(e) => setPassword(e.target.value)}
        onKeyDown={(e) => { if (e.key === "Enter") void unlock(); }}
      />
      {lockError && <Alert variant="destructive"><AlertDescription>{lockError}</AlertDescription></Alert>}
      <DialogFooter>
        <Button variant="outline" onClick={onClose}>{t.close}</Button>
        <Button onClick={() => void unlock()} disabled={!password.trim() || checking}>
          {checking ? <><Loader2 className="mr-1.5 h-4 w-4 animate-spin" />{t.checking}</> : t.unlock}
        </Button>
      </DialogFooter>
    </div>
  );

  const holdPanel = (hold: boolean) => hold ? (
    <Alert className="border-amber-500/40 bg-amber-500/[0.08]">
      <PauseCircle className="h-4 w-4 text-amber-600" />
      <AlertDescription className="flex flex-col gap-2 text-[12.5px]">
        <span className="font-semibold">{t.holdBanner}</span>
        {holdsUnknown
          ? <span className="text-destructive">{t.holdsUnknown}</span>
          : <span>{t.schemeNote(holdScheme === undefined ? t.unknown : schemeName(holdScheme))}</span>}
        {protocol === "ZK_STANDALONE" && preview?.limits?.mbPinsPerPass ? (
          <span className="text-muted-foreground">{t.mbPasses(preview.limits.mbPinsPerPass)}</span>
        ) : null}
        <div className="flex flex-wrap items-center gap-2">
          <Button size="sm" onClick={() => void doRefill()}
                  disabled={refilling || holdScheme === undefined || holdsUnknown}>
            {refilling ? <Loader2 className="mr-1.5 h-4 w-4 animate-spin" /> : null}{t.refillButton}
          </Button>
          <span className="text-[11px] text-muted-foreground">{t.refillNeedsInternet}</span>
        </div>
        {refillError && <span className="text-destructive">{refillError}</span>}
      </AlertDescription>
    </Alert>
  ) : null;

  const countsTable = (withAfter: boolean) => {
    const rows = preview?.tables ?? [];
    return (
      <table className="w-full text-[12.5px]">
        <thead>
          <tr className="border-b border-border text-left text-[10.5px] uppercase tracking-[0.12em] text-muted-foreground">
            <th className="py-1.5 font-bold">{t.table}</th>
            <th className="py-1.5 text-right font-bold">{withAfter ? t.before : t.rows}</th>
            {withAfter && <th className="py-1.5 text-right font-bold">{t.after}</th>}
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => {
            const before = withAfter ? run?.countsBefore?.tables?.[r.key] : r.count;
            const after = run?.countsAfter?.tables?.[r.key];
            return (
              <tr key={r.key} className="border-b border-border/50 last:border-0">
                <td className="py-1.5">
                  <div className="font-semibold">{t.tableLabels[r.key] ?? r.key}</div>
                  {!r.erasable && !withAfter && (
                    <div className="text-[11px] text-muted-foreground">{t.reasons[r.reason ?? ""] ?? r.reason}</div>
                  )}
                </td>
                <td className="py-1.5 text-right font-mono">{before ?? t.unknown}</td>
                {withAfter && (
                  <td className={cn("py-1.5 text-right font-mono",
                    run?.tables.includes(r.key) && after === 0 && "text-emerald-600")}>{after ?? t.unknown}</td>
                )}
              </tr>
            );
          })}
        </tbody>
      </table>
    );
  };

  const extraLines = preview && protocol === "ZK_STANDALONE" ? (
    <div className="flex flex-col gap-0.5 text-[12px] text-muted-foreground">
      <span>{t.admins}{t.colon} <b className="text-foreground">{preview.extra.admins ?? t.unknown}</b></span>
      <span>{t.faces}{t.colon} <b className={cn("text-foreground", (faces > 0 || facesUnknown) && "text-amber-600")}>{preview.extra.faces ?? t.unknown}</b></span>
    </div>
  ) : null;

  let body: React.ReactNode;
  if (!unlocked) body = lockScreen;
  else if (mode === "refill") {
    body = (
      <div className="flex flex-col gap-3">
        {loading && <Loader2 className="h-5 w-5 animate-spin text-primary" />}
        {previewError && <Alert variant="destructive"><AlertDescription>{previewError}</AlertDescription></Alert>}
        {!loading && !refillMsg && holdPanel(stillHeld)}
        {!loading && !stillHeld && !refillMsg && <p className="text-[12.5px] text-muted-foreground">{t.notOnHold}</p>}
        {refillMsg && <Alert><CheckCircle2 className="h-4 w-4 text-emerald-600" /><AlertDescription>{refillMsg}</AlertDescription></Alert>}
        <DialogFooter><Button variant="outline" onClick={onClose}>{t.close}</Button></DialogFooter>
      </div>
    );
  } else if (step === 0) {
    body = (
      <div className="flex flex-col gap-3">
        <p className="text-[12px] text-muted-foreground">{t.readOnly}</p>
        {previewError && <Alert variant="destructive"><AlertDescription>{previewError}</AlertDescription></Alert>}
        {loading && !preview ? <Loader2 className="h-5 w-5 animate-spin text-primary" /> : countsTable(false)}
        {extraLines}
        {preview?.hold && holdPanel(true)}
        <DialogFooter>
          <Button variant="outline" onClick={() => void loadPreview()} disabled={loading}>{t.reread}</Button>
          <Button onClick={() => setStep(1)} disabled={!preview}>{t.next}</Button>
        </DialogFooter>
      </div>
    );
  } else if (step === 1) {
    body = (
      <div className="flex flex-col gap-2">
        <p className="text-[12px] text-muted-foreground">{t.chooseHelp}</p>
        {(preview?.tables ?? []).map((r) => {
          const locked = requiredByUser.includes(r.key);
          return (
            <Choice key={r.key} type="checkbox" name="erase-table" checked={chosen.has(r.key)}
                    disabled={!r.erasable || locked} dim={!r.erasable} onChange={() => toggle(r.key)}>
              <div className="flex items-center justify-between gap-2">
                <span className="font-semibold">{t.tableLabels[r.key] ?? r.key}</span>
                <span className="font-mono text-muted-foreground">{r.count ?? t.unknown}</span>
              </div>
              {!r.erasable && <div className="text-[11px] text-muted-foreground">{t.reasons[r.reason ?? ""] ?? r.reason}</div>}
              {locked && <div className="text-[11px] text-muted-foreground">{t.requiredByUser}</div>}
            </Choice>
          );
        })}
        <DialogFooter>
          <Button variant="outline" onClick={() => setStep(0)}>{t.back}</Button>
          <Button onClick={() => setStep(2)} disabled={chosen.size === 0}>{t.next}</Button>
        </DialogFooter>
      </div>
    );
  } else if (step === 2) {
    body = (
      <div className="flex flex-col gap-3">
        <Choice type="checkbox" name="backup-only" checked={backupOnly} onChange={() => setBackupOnly((v) => !v)}>
          {t.backupOnly}
        </Choice>
        {!backupOnly && (
          <>
            <div className="text-[12.5px] font-bold">{t.forgetTitle}</div>
            <Choice name="forget" checked={forget === true} disabled={!forgetAllowed} onChange={() => setForget(true)}>
              {t.forgetYes}
              {!forgetAllowed && <div className="text-[11px] text-muted-foreground">{t.forgetNeedsUsers}</div>}
            </Choice>
            <Choice name="forget" checked={forget === false} disabled={forgetForced} onChange={() => setForget(false)}>
              {t.forgetNo}
              {forgetForced && <div className="text-[11px] text-muted-foreground">{t.forgetForcedMb}</div>}
            </Choice>
            <div className="mt-1 text-[12.5px] font-bold">{t.refillTitle}</div>
            <Choice name="refill" checked={refill === "now"} onChange={() => setRefill("now")}>{t.refillNow}</Choice>
            <Choice name="refill" checked={refill === "auto"} onChange={() => setRefill("auto")}>
              {t.refillAuto}<div className="text-[11px] text-muted-foreground">{t.refillAutoHelp}</div>
            </Choice>
            <Choice name="refill" checked={refill === "hold"} onChange={() => setRefill("hold")}>
              {t.refillHold}<div className="text-[11px] text-muted-foreground">{t.refillHoldHelp}</div>
            </Choice>
            {needFaces && (
              <Choice type="checkbox" name="faces" checked={acceptFaces} onChange={() => setAcceptFaces((v) => !v)}>
                <span className="text-amber-700">{facesUnknown ? t.acceptFacesUnknown : t.acceptFaces(faces)}</span>
              </Choice>
            )}
          </>
        )}
        <DialogFooter>
          <Button variant="outline" onClick={() => setStep(1)}>{t.back}</Button>
          <Button onClick={() => setStep(3)} disabled={!optionsReady}>{t.next}</Button>
        </DialogFooter>
      </div>
    );
  } else if (step === 3 && preview) {
    const refillLabel = refill === "now" ? t.refillNow : refill === "auto" ? t.refillAuto : t.refillHold;
    body = (
      <div className="flex flex-col gap-3">
        <div className="rounded-xl border border-border p-3 text-[12.5px]">
          <div className="mb-1 font-bold">{t.summary}</div>
          <div>{t.willErase}{t.colon} <b>{Array.from(chosen).map((k) => t.tableLabels[k] ?? k).join(", ")}</b></div>
          {!backupOnly && <div>{t.willForget}{t.colon} <b>{forget ? t.forgotten : t.kept}</b></div>}
          {!backupOnly && <div>{t.willRefill}{t.colon} <b>{refillLabel}</b></div>}
          {backupOnly && <div className="font-semibold">{t.backupOnly}</div>}
        </div>
        <Alert className="border-primary/30 bg-primary/[0.04]">
          <ShieldAlert className="h-4 w-4 text-primary" />
          <AlertDescription className="text-[12px]">
            <div className="mb-1 font-bold">{t.rulesTitle}</div>
            <ul className="list-disc space-y-0.5 pl-4">
              {t.rules.map((r) => <li key={r}>{r}</li>)}
              {protocol === "ZK_STANDALONE" && <li>{t.ruleAdmins}</li>}
            </ul>
          </AlertDescription>
        </Alert>
        <Label htmlFor="erase-name" className="text-[12.5px]">
          {t.typeName} <b className="font-mono">{preview.device.name}</b>
        </Label>
        <Input id="erase-name" value={typedName} onChange={(e) => setTypedName(e.target.value)} autoComplete="off" />
        {startError && <Alert variant="destructive"><AlertDescription>{startError}</AlertDescription></Alert>}
        <DialogFooter>
          <Button variant="outline" onClick={() => setStep(2)}>{t.back}</Button>
          <Button variant={backupOnly ? "default" : "destructive"} onClick={() => void start()}
                  disabled={!nameOk || starting}>
            {starting ? <Loader2 className="mr-1.5 h-4 w-4 animate-spin" /> : <Trash2 className="mr-1.5 h-4 w-4" />}
            {backupOnly ? t.backupButton : t.erase}
          </Button>
        </DialogFooter>
      </div>
    );
  } else {
    const state = run?.state ?? "RUNNING";
    const Icon = state === "DONE" ? CheckCircle2 : state === "RUNNING" ? Loader2 : state === "FAILED" ? XCircle : AlertTriangle;
    body = (
      <div className="flex flex-col gap-3">
        <div className={cn("flex items-center gap-2 text-[14px] font-bold",
          state === "DONE" ? "text-emerald-600" : state === "RUNNING" ? "text-foreground" : "text-destructive")}>
          <Icon className={cn("h-5 w-5", state === "RUNNING" && "animate-spin")} />{t.states[state] ?? state}
        </div>
        {run?.progress && (
          <div className="text-[12px] text-muted-foreground">{run.progress.phase} — {t.progress(run.progress.done, run.progress.total)}</div>
        )}
        <ol className="flex max-h-[180px] flex-col gap-1 overflow-y-auto text-[12px]">
          {(run?.steps ?? []).map((s, i) => (
            <li key={`${s.step}-${i}`} className="flex items-start gap-2">
              {s.ok ? <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-600" />
                : <XCircle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-destructive" />}
              <span className="font-mono text-muted-foreground">{s.at.slice(11)}</span>
              <span>{t.stepLabels[s.step] ?? (s.step.startsWith("erase_") ? t.eraseOf(s.step.slice(6)) : s.step)}</span>
            </li>
          ))}
        </ol>
        {run?.error && <Alert variant="destructive"><AlertDescription className="text-[12px]">{run.error}</AlertDescription></Alert>}
        {state === "INCOMPLETE" && <p className="text-[12px] text-muted-foreground">{t.incompleteHelp}</p>}
        {run?.countsBefore && countsTable(true)}
        {run?.backup && (
          <div className="break-all text-[11.5px] text-muted-foreground">
            {t.backupFile}{t.colon} <span className="font-mono">{run.backup.path}</span>
          </div>
        )}
        {run && run.state !== "RUNNING" && run.holdKept && holdPanel(true)}
        {refillMsg && <Alert><CheckCircle2 className="h-4 w-4 text-emerald-600" /><AlertDescription>{refillMsg}</AlertDescription></Alert>}
        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={busy}>{t.close}</Button>
        </DialogFooter>
      </div>
    );
  }

  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o && !busy) onClose(); }}>
      <DialogContent className="max-h-[92vh] max-w-2xl overflow-y-auto">
        {header}
        {body}
      </DialogContent>
    </Dialog>
  );
}
