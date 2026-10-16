import { useState, useEffect, useRef, useCallback } from "react";
import EnrollTurnstileStatus from "@/components/EnrollTurnstileStatus";
import { useEnroll, useUsers, useDevices } from "@/api/hooks";
import { ApiError, openSSE } from "@/api/client";
import { useEnrollment } from "@/context/EnrollmentContext";
import { usePageChrome } from "@/context/PageChromeContext";
import { cn } from "@/lib/utils";
import { User, Info, Activity, Cable, CircleCheck, Search, Server, X } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { ScrollArea } from "@/components/ui/scroll-area";
import LogViewer from "@/components/LogViewer2";
import { Fingerprint, Play, Square, Trash2, Loader2, Volume2, VolumeX } from "lucide-react";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import EnrollOverlay, { type EnrollPhase } from "@/components/EnrollOverlay";
import { useEnrollSounds } from "@/hooks/useEnrollSounds";
import { usePhaseTimeout } from "@/hooks/usePhaseTimeout";
import { ActionButton } from "@/components/ui/action-button";
import { Chip } from "@/components/ui/chip";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { DialogFrame } from "@/components/ui/dialog-frame";
import { ListRow, Note, Panel, PanelHeader, PanelList } from "@/components/ui/panel";

export default function EnrollPage() {
  const enroll = useEnroll();
  const { data: userData } = useUsers();
  const users: any[] = userData?.users ?? [];

  // A template is only delivered to devices whose synced payload has
  // fingerprintEnabled=true -- the push path drops it otherwise
  // (device_sync._collect_templates_for_pin returns [] for that device). The
  // capture itself still succeeds and still reaches the backend, so without
  // this check the page reports success for something no reader will receive.
  const { data: deviceData } = useDevices(false);
  const devicesLoaded = !!deviceData;
  const fpDevices = (deviceData?.devices ?? []).filter((d: any) => d?.fingerprintEnabled);
  const noFingerprintDevice = devicesLoaded && fpDevices.length === 0;
  const { enrollMeta, clearMeta } = useEnrollment();

  // Backend is the only implemented mode right now.
  const [enrollType, setEnrollType] = useState<"LOCAL" | "BACKEND">("BACKEND");
  const [selectedUserId, setSelectedUserId] = useState("");
  const [label, setLabel] = useState("");
  const [pin, setPin] = useState("");
  const [cardNo, setCardNo] = useState("");
  const [fingerId, setFingerId] = useState("0");

  // Pre-fill from remote trigger
  useEffect(() => {
    if (enrollMeta) {
      if (enrollMeta.userId) setSelectedUserId(enrollMeta.userId);
      if (enrollMeta.fingerId !== undefined) setFingerId(String(enrollMeta.fingerId));
    }
  }, [enrollMeta]);

  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<string | null>(null);
  const [logs, setLogs] = useState<string[]>([]);

  // Overlay state
  const [overlayOpen, setOverlayOpen] = useState(false);
  const [phase, setPhaseRaw] = useState<EnrollPhase>("idle");
  const [scanProgress, setScanProgress] = useState(0);
  const scanProgressRef = useRef(0);

  // Debounce: hold "lift_finger" for at least 1.5 s so the user actually sees it.
  // Without this, the ZK SDK sends "captured" then 350 ms later "waiting for sample"
  // which makes "LEVEZ LE DOIGT" flash invisibly.
  const phaseRef = useRef<EnrollPhase>("idle");
  const holdUntilRef = useRef(0);
  const deferredTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const LIFT_HOLD_MS = 1500;

  const setPhase = useCallback((next: EnrollPhase) => {
    const now = Date.now();

    // If we're still holding lift_finger and incoming is wait_finger, defer it
    if (
      phaseRef.current === "lift_finger" &&
      next === "wait_finger" &&
      now < holdUntilRef.current
    ) {
      // Schedule the transition for after the hold expires
      if (deferredTimerRef.current) clearTimeout(deferredTimerRef.current);
      deferredTimerRef.current = setTimeout(() => {
        phaseRef.current = next;
        setPhaseRaw(next);
        deferredTimerRef.current = null;
      }, holdUntilRef.current - now);
      return;
    }

    // Clear any pending deferred transition (e.g. if success/failed arrives)
    if (deferredTimerRef.current) {
      clearTimeout(deferredTimerRef.current);
      deferredTimerRef.current = null;
    }

    // If entering lift_finger, set the hold deadline
    if (next === "lift_finger") {
      holdUntilRef.current = now + LIFT_HOLD_MS;
    }

    phaseRef.current = next;
    setPhaseRaw(next);
  }, []);

  // Sound + timeout
  const [soundEnabled, setSoundEnabled] = useState(() => localStorage.getItem("enroll.soundEnabled") !== "false");
  const { playSound } = useEnrollSounds(soundEnabled);
  const timedOut = usePhaseTimeout(phase);
  const [retryAvailable, setRetryAvailable] = useState(false);

  const [fingerprints, setFingerprints] = useState<any[]>([]);
  const [fpLoading, setFpLoading] = useState(false);
  const [userSearch, setUserSearch] = useState("");

  const esRef = useRef<EventSource | null>(null);
  const startReqRef = useRef(false);
  const lastEnrollErrorRef = useRef("");

  const [errorOpen, setErrorOpen] = useState(false);
  const [errorMsg, setErrorMsg] = useState("");

  const safeStringify = (v: any, maxLen = 2000) => {
    try {
      const seen = new WeakSet();
      const s = JSON.stringify(
        v,
        (_k, val) => {
          if (typeof val === "object" && val !== null) {
            if (seen.has(val)) return "[Circular]";
            seen.add(val);
          }
          if (typeof val === "function") return `[Function ${val.name || "anonymous"}]`;
          return val;
        },
        2,
      );
      return s.length > maxLen ? `${s.slice(0, maxLen)}\n...(truncated)` : s;
    } catch {
      try {
        return String(v);
      } catch {
        return "Unknown error";
      }
    }
  };

  const errToMessage = (e: any) => {
    if (!e) return "Une erreur est survenue.";

    if (e instanceof TypeError && /fetch/i.test(e.message || "")) {
      return (
        "Impossible de joindre le serveur local (http://127.0.0.1:8788).\n" +
        "Verifiez que l'application Python est bien lancee puis reessayez."
      );
    }

    if (e instanceof ApiError) {
      const anyE = e as any;
      const status = anyE?.status ? ` (HTTP ${anyE.status})` : "";
      const body = anyE?.body
        ? `\n\n${typeof anyE.body === "string" ? anyE.body : safeStringify(anyE.body, 1500)}`
        : "";
      return `${e.message}${status}${body}`;
    }

    if (e instanceof Error) return e.message || String(e);
    if (typeof e === "string") return e;
    return safeStringify(e);
  };

  const showError = useCallback((e: any) => {
    setErrorMsg(errToMessage(e));
    setErrorOpen(true);
  }, []);

  const loadFingerprints = useCallback(async () => {
    setFpLoading(true);
    try {
      const res = await enroll.listFingerprints();
      setFingerprints(res || []);
    } catch {
      setFingerprints([]);
    } finally {
      setFpLoading(false);
    }
  }, [enroll]);

  useEffect(() => {
    void loadFingerprints();
  }, [loadFingerprints]);

  // Parse a step/log string → EnrollPhase
  const stepToPhase = useCallback((s: string): EnrollPhase | null => {
    const l = s.toLowerCase();
    if (!l) return null;
    if (l.includes("waiting for sample"))                                    return "wait_finger";
    if (l.includes("captured"))                                              return "lift_finger";
    if (l.includes("rejected"))                                              return "sample_rejected";
    if (l.includes("merging") || l.includes("merged") || l.includes("encoding")) return "processing";
    if (l.includes("saving to backend"))                                     return "push";
    if (l.includes("initializing scanner") || l.includes("opening device")) return "device_init";
    if (l.includes("enrollment..."))                                         return "wait_finger";
    if (l.includes("checking") || l.includes("resolving") || l.includes("sync")) return "connecting";
    return null;
  }, []);

  useEffect(() => {
    const FINAL = new Set(["success", "failed", "cancelled", "error"]);

    try {
      const es = openSSE("/enroll/events", (type, data) => {
        // Note: on SSE reconnect, server replays full snapshot automatically
        try {
          // Structured phase events (authoritative, from enriched Python backend)
          if (type === "phase" && data?.phase) {
            const phaseMap: Record<string, EnrollPhase> = {
              connecting: "connecting",
              device_init: "device_init",
              wait_finger: "wait_finger",
              sample_captured: "lift_finger",
              sample_rejected: "sample_rejected",
              processing: "processing",
              push: "push",
            };
            const mapped = phaseMap[data.phase as string];
            if (mapped) {
              if ((mapped === "lift_finger" || mapped === "sample_rejected") && typeof data.sampleNum === "number") {
                scanProgressRef.current = data.sampleNum;
                setScanProgress(data.sampleNum);
              }
              // Sound triggers
              if (data.phase === "sample_captured") playSound("sample_captured");
              if (data.phase === "sample_rejected") playSound("sample_rejected");
              setPhase(mapped);
            }
            return;
          }

          if (type === "log") {
            const line =
              typeof data === "string"
                ? data
                : data?.line != null
                  ? String(data.line)
                  : data?.text != null
                    ? String(data.text)
                    : safeStringify(data, 800);

            if (/^ERROR:/i.test(line)) {
              lastEnrollErrorRef.current = line.replace(/^ERROR:\s*/i, "").trim();
            }

            // Track captured samples from log lines
            const capMatch = line.match(/sample\s+(\d+)\/3\s+captured/i);
            if (capMatch) {
              const n = parseInt(capMatch[1], 10);
              scanProgressRef.current = n;
              setScanProgress(n);
              setPhase("lift_finger");
            } else {
              const derived = stepToPhase(line);
              if (derived && derived !== "lift_finger") setPhase(derived);
            }

            setLogs((prev) => {
              if (prev.length && prev[prev.length - 1] === line) return prev;
              const next = [...prev, line];
              return next.length > 1500 ? next.slice(-1500) : next;
            });
            return;
          }

          if (type === "step") {
            const step =
              typeof data === "string"
                ? data
                : data?.step != null
                  ? String(data.step)
                  : safeStringify(data, 300);

            // Update phase from step string (step is authoritative current state)
            const capMatch = step.match(/sample\s+(\d+)\/3\s+captured/i);
            if (capMatch) {
              const n = parseInt(capMatch[1], 10);
              scanProgressRef.current = n;
              setScanProgress(n);
              setPhase("lift_finger");
            } else {
              const derived = stepToPhase(step);
              if (derived) setPhase(derived);
            }

            setLogs((prev) => [...prev, step]);
            return;
          }

          if (FINAL.has(type)) {
            const r = data?.result ? String(data.result) : type;
            setResult(r);
            setRunning(false);
            startReqRef.current = false;
            void loadFingerprints();

            // Drive overlay to terminal state
            if (r === "success") {
              setPhase("success");
              setRetryAvailable(false);
              playSound("success");
              // overlay auto-dismisses after 3 s via its own timer
            } else if (r === "cancelled") {
              setPhase("cancelled");
              setOverlayOpen(false);
              setRetryAvailable(false);
            } else {
              // Check if failure happened during push phase — retry available
              setRetryAvailable(phaseRef.current === "push");
              setPhase("failed");
              playSound("failed");
              // overlay stays open so user sees the error
            }

            if (r !== "success" && r !== "cancelled") {
              showError(lastEnrollErrorRef.current || "Enrolement echoue. Verifiez les logs.");
            }
          }
        } catch (err) {
          showError(err);
          setRunning(false);
          startReqRef.current = false;
        }
      });

      esRef.current = es;
      return () => {
        try {
          es.close();
        } catch {
          // ignore
        }
        if (esRef.current === es) esRef.current = null;
      };
    } catch (err) {
      showError(err);
      return () => {};
    }
  }, [loadFingerprints, showError, stepToPhase]);

  const handleStart = async () => {
    if (running || startReqRef.current) return;

    if (enrollType === "LOCAL") {
      showError("Le mode LOCAL n'est pas implemente pour le moment. Utilisez le mode BACKEND.");
      return;
    }

    startReqRef.current = true;
    lastEnrollErrorRef.current = "";
    scanProgressRef.current = 0;

    setRunning(true);
    setResult(null);
    setLogs(["Demarrage..."]);
    setScanProgress(0);
    setPhase("connecting");
    setOverlayOpen(true);

    try {
      const u = users.find((x) => String(x.userId) === selectedUserId);
      await enroll.start({
        type: "BACKEND",
        target: "backend",
        userId: u ? u.userId : undefined,
        fullName: u ? u.fullName : undefined,
        fingerId: parseInt(fingerId, 10) || 0,
      });
    } catch (e) {
      setResult("error");
      setRunning(false);
      startReqRef.current = false;
      lastEnrollErrorRef.current = errToMessage(e);
      setPhase("failed");   // overlay shows error + "Fermer" button
      showError(e);
    }
  };

  const handleCancel = async () => {
    try {
      await enroll.cancel();
    } catch {
      // ignore
    }
    setRunning(false);
    setResult("cancelled");
    startReqRef.current = false;
    setOverlayOpen(false);
    setPhase("idle");
  };

  const handleOverlayDismiss = useCallback(() => {
    setOverlayOpen(false);
    setPhase("idle");
    setRetryAvailable(false);
  }, [setPhase]);

  const handleRetryPush = useCallback(async () => {
    setPhase("push");
    setRetryAvailable(false);
    try {
      await enroll.retryPush();
      // SSE will deliver the success/failed event
    } catch (e) {
      setPhase("failed");
      showError(e);
    }
  }, [enroll, setPhase, showError]);

  const toggleSound = useCallback(() => {
    setSoundEnabled((prev) => {
      const next = !prev;
      localStorage.setItem("enroll.soundEnabled", String(next));
      return next;
    });
  }, []);

  // Cancel enrollment if user navigates away from this page while it's running.
  // Also clean up the deferred lift_finger timer.
  const runningRef = useRef(false);
  runningRef.current = running;
  useEffect(() => {
    return () => {
      if (deferredTimerRef.current) clearTimeout(deferredTimerRef.current);
      if (runningRef.current) {
        // Fire-and-forget cancel — the Python worker will stop scanning
        enroll.cancel().catch(() => {});
      }
    };
  }, [enroll]);

  const removeFp = async (id: number) => {
    try {
      await enroll.deleteFingerprint(id);
      void loadFingerprints();
    } catch {
      // ignore
    }
  };

  const filteredUsers = userSearch
    ? users.filter((u) =>
        `${u.fullName} ${u.userId} ${u.phone || ""} ${u.email || ""}`
          .toLowerCase()
          .includes(userSearch.toLowerCase()),
      )
    : users.slice(0, 50);

  const selectedUser = users.find((u) => String(u.userId) === selectedUserId);

  // ── Access v5 (boards S15 capture / S16 terminé) ──────────────────────
  // The subject is the capture in progress, not a form. `scanProgress` is the
  // REAL 0–3 sample counter the SSE stream reports (data.sampleNum, and the
  // "sample N/3 captured" log line); `phase` is the authoritative step.
  const phaseCopy: Record<string, { title: string; hint: string }> = {
    idle: { title: "Prêt à enrôler", hint: "Choisissez un membre et un doigt, puis démarrez la capture." },
    connecting: { title: "Connexion…", hint: "Vérification des informations." },
    device_init: { title: "Ouverture du lecteur", hint: "Initialisation du scanner ZK9500." },
    wait_finger: { title: "Posez votre doigt", hint: "Appuyez fermement sur le scanner ZK9500." },
    lift_finger: { title: "Levez le doigt", hint: "Puis reposez-le pour l'échantillon suivant." },
    sample_rejected: { title: "Échantillon rejeté", hint: "Qualité insuffisante — reposez le doigt." },
    pushing: { title: "Envoi à l'appareil…", hint: "L'empreinte est transmise au lecteur." },
    success: { title: "Empreinte enregistrée", hint: "La capture est terminée." },
    failed: { title: "Échec de la capture", hint: "Consultez le journal ci-dessous." },
    cancelled: { title: "Capture annulée", hint: "Vous pouvez relancer une capture." },
  };
  const pc = phaseCopy[phase] ?? phaseCopy.idle;
  const captureActive = running && phase !== "idle";
  const done = !running && result === "success";

  // Slots this member already has in the local copy of the server roster
  // (/sync/cache/users carries each member's fingerprints with their slot).
  const existingSlots = new Set<number>(
    (Array.isArray(selectedUser?.fingerprints) ? selectedUser.fingerprints : [])
      .map((f: any) => Number(f?.fingerId))
      .filter((n: number) => Number.isInteger(n)),
  );
  const fingerNum = parseInt(fingerId, 10);
  const [fpToDelete, setFpToDelete] = useState<any | null>(null);

  usePageChrome(() => ({
    fill: true,
    subtitle: captureActive
      ? `Capture en cours${selectedUser?.fullName ? ` · ${selectedUser.fullName}` : ""}`
      : done
        ? `Empreinte enregistrée${selectedUser?.fullName ? ` · ${selectedUser.fullName}` : ""}`
        : `${fingerprints.length} empreinte${fingerprints.length > 1 ? "s" : ""} locale${fingerprints.length > 1 ? "s" : ""}`,
    actions: (
      <>
        <ActionButton kind="outline" icon={soundEnabled ? Volume2 : VolumeX} onClick={toggleSound}>
          {soundEnabled ? "Son activé" : "Son coupé"}
        </ActionButton>
        <ActionButton kind={running ? "danger" : "outline"} icon={Square} onClick={handleCancel} disabled={!running}>
          Annuler la capture
        </ActionButton>
      </>
    ),
    // Primitives only — a changing function reference here loops the effect.
  }), [captureActive, done, selectedUser?.fullName, fingerprints.length, soundEnabled, running]);

  const stateChip = captureActive
    ? { l: "EN COURS", tone: "primary" as const }
    : done
      ? { l: "TERMINÉ", tone: "success" as const }
      : result === "cancelled"
        ? { l: "ANNULÉ", tone: "warning" as const }
        : result
          ? { l: "ÉCHEC", tone: "error" as const }
          : { l: "AU REPOS", tone: "grey" as const };

  return (
    <>
    <EnrollOverlay
      open={overlayOpen}
      phase={phase}
      scanProgress={scanProgress}
      fullName={selectedUser?.fullName ?? enrollMeta?.fullName}
      fingerId={parseInt(fingerId, 10)}
      errorMsg={lastEnrollErrorRef.current || undefined}
      timedOut={timedOut}
      retryAvailable={retryAvailable}
      onCancel={handleCancel}
      onDismiss={handleOverlayDismiss}
      onRetryPush={handleRetryPush}
    />
    <div className="grid h-full min-h-0 grid-cols-12 gap-[18px]">
      {/* ── Le sujet : la capture ───────────────────────────────────────── */}
      <div className="col-span-8 flex min-h-0 flex-col gap-[18px] overflow-y-auto">
        <Panel className="flex-none">
          <PanelHeader
            title="Doigt et capture"
            sub={selectedUser
              ? `${selectedUser.fullName || "Ce membre"} : ${existingSlots.size} doigt${existingSlots.size > 1 ? "s" : ""} déjà enregistré${existingSlots.size > 1 ? "s" : ""} (copie locale du serveur)`
              : "Choisissez un membre dans « Nouvelle capture »"}
          />
          {/* Slot picker: the same fingerId as the « Doigt » field (numbers only — Access names no finger). */}
          <div className="px-[18px] pt-3">
            <div role="group" aria-label="Doigt" className="flex flex-wrap items-center gap-1.5">
              {Array.from({ length: 10 }, (_, i) => {
                const on = i === fingerNum;
                const has = existingSlots.has(i);
                return (
                  <button
                    key={i}
                    type="button"
                    aria-pressed={on}
                    disabled={running}
                    title={`Doigt ${i}${has ? " (déjà enregistré)" : ""}`}
                    onClick={() => setFingerId(String(i))}
                    className={cn(
                      "grid h-10 w-10 cursor-pointer place-items-center rounded-lg border font-mono text-[15px] font-bold transition-colors disabled:cursor-not-allowed disabled:opacity-60",
                      i === 5 && "ml-3",
                      on && has && "ring-2 ring-success ring-offset-2 ring-offset-card",
                      on
                        ? "border-primary bg-primary text-primary-foreground"
                        : has
                          ? "border-success bg-success/16 text-success-ink"
                          : "border-grey/32 bg-card text-muted-foreground hover:text-foreground",
                    )}
                  >
                    {i}
                  </button>
                );
              })}
            </div>
            <div className="mt-2 text-[12.5px] text-muted-foreground">
              Vert = déjà enregistré pour ce membre · numéros 0 à 9 comme dans le tableau de bord
            </div>
            {existingSlots.has(fingerNum) && (
              <div className="mt-1 text-[12.5px] font-semibold text-success-ink">
                Le doigt {fingerNum} est déjà enregistré pour ce membre.
              </div>
            )}
          </div>

          {/* The live capture panel — phase + sample counter are both real. */}
          <div
            className={cn(
              "m-[18px] mt-4 flex items-center gap-7 rounded-xl px-7 py-6",
              done ? "bg-success/8" : "bg-muted",
            )}
          >
            <div className="relative flex h-24 w-24 flex-none items-center justify-center">
              {captureActive && <span className="absolute h-[92px] w-[92px] animate-ping rounded-full bg-primary/12" />}
              <div className={cn(
                "relative flex h-20 w-20 items-center justify-center rounded-full border-2 bg-card",
                done ? "border-success text-success-ink" : captureActive ? "border-primary text-primary" : "border-grey/32 text-muted-foreground",
              )}>
                {done ? <CircleCheck className="h-10 w-10" /> : <Fingerprint className="h-10 w-10" />}
              </div>
            </div>

            <div className="min-w-0 flex-1">
              <Chip tone={stateChip.tone} className="mb-2">{stateChip.l}</Chip>
              <h2 className="mb-1.5 text-[24px] font-bold leading-[1.15] text-foreground">{pc.title}</h2>
              <p className="mb-3.5 text-[14px] leading-[1.55] text-muted-foreground">{pc.hint}</p>
              <div className="flex items-center gap-[11px]">
                <span className="flex items-center gap-2">
                  {[1, 2, 3].map((i) => (
                    <span
                      key={i}
                      className={cn(
                        "h-[13px] w-[13px] rounded-full border-2",
                        scanProgress >= i ? "border-success bg-success" : "border-grey/32",
                      )}
                    />
                  ))}
                </span>
                <span className="text-[13px] text-muted-foreground">
                  échantillon <b className="text-foreground">{Math.min(3, Math.max(0, scanProgress))}</b> sur 3
                </span>
              </div>
            </div>

            <div className="flex-none text-right">
              <div className="mb-1 text-[12px] font-bold uppercase tracking-[0.04em] text-muted-foreground">Doigt</div>
              <div className="font-num text-[40px] font-bold leading-none">{fingerId}</div>
            </div>
          </div>
        </Panel>

        {result && (
          <Note
            className="flex-none"
            tone={result === "success" ? "success" : result === "cancelled" ? "warning" : "error"}
          >
            {result === "success" ? "Enrôlement réussi !" : result === "cancelled" ? "Enrôlement annulé." : "Enrôlement échoué."}
          </Note>
        )}
        {result === "success" && <EnrollTurnstileStatus className="flex-none" />}

        {/* Journal — the same `logs` the SSE stream fills (raw lines, not translated). */}
        <Panel className="flex min-h-[180px] flex-1 flex-col">
          <PanelHeader title="Journal de la capture" sub="Flux en direct du lecteur (source : flux SSE)" className="flex-none" />
          <div className="mt-3 min-h-0 flex-1 overflow-y-auto border-t border-dashed border-grey/20 px-[18px] py-2.5 font-mono text-[12px] leading-[1.9] text-foreground">
            {logs.length === 0 ? (
              <p className="pt-6 text-center font-sans text-[13.5px] text-muted-foreground">En attente du démarrage…</p>
            ) : logs.map((line, i) => (
              <div key={i} className="break-all">{line}</div>
            ))}
          </div>
        </Panel>
      </div>

      {/* ── Le rail ─────────────────────────────────────────────────────── */}
      <div className="col-span-4 flex min-h-0 flex-col gap-[18px] overflow-y-auto">
        <Panel className="flex-none">
          <PanelHeader title="Membre" />
          <PanelList>
            {selectedUser ? (
              <ListRow
                icon={User}
                tone="primary"
                title={selectedUser.fullName || "—"}
                sub={`ID ${selectedUser.userId}`}
              />
            ) : (
              <ListRow icon={User} tone="grey" title="Aucun membre sélectionné" />
            )}
            <ListRow icon={Server} tone="grey" title="Type d'enrôlement" value={enrollType === "BACKEND" ? "Serveur (backend)" : "Local"} />
            <ListRow icon={Fingerprint} tone="grey" title="Doigt" value={fingerId} valueMono />
            <ListRow icon={Cable} tone="grey" title="Lecteur" value="ZK9500 · USB" />
            <ListRow icon={Activity} tone="grey" title="Étape" value={pc.title} valueTone={captureActive ? "primary" : undefined} />
          </PanelList>
        </Panel>

        {enrollMeta && (
          <Note className="flex flex-none items-start gap-2.5">
            <Info className="mt-0.5 h-4 w-4 shrink-0" />
            <span className="flex-1">
              Capture lancée depuis le tableau de bord.
              {enrollMeta.fullName ? ` Membre : ${enrollMeta.fullName}.` : ""} Le membre doit lever puis
              reposer le doigt entre chaque échantillon.
            </span>
            <ActionButton kind="ghost" size="xs" iconOnly icon={X} onClick={clearMeta}>Masquer</ActionButton>
          </Note>
        )}

        {/* Setup — member picker + finger + start. Kept in the rail so the
            capture stays the subject, per the design. */}
        <Panel className="flex-none">
          <PanelHeader title="Nouvelle capture" />
          <div className="flex flex-col gap-2.5 px-[18px] pb-4 pt-3">
            <div className="flex h-9 items-center gap-2 rounded-lg border border-grey/32 bg-card px-3 focus-within:border-primary">
              <Search className="h-[17px] w-[17px] shrink-0 text-muted-foreground" />
              <input
                placeholder="Rechercher un membre…"
                aria-label="Rechercher un membre"
                value={userSearch}
                onChange={(e) => setUserSearch(e.target.value)}
                className="min-w-0 flex-1 bg-transparent text-[13.5px] text-foreground outline-none placeholder:text-muted-foreground"
              />
            </div>
            {userSearch && (
              <div className="max-h-36 overflow-y-auto rounded-lg border border-grey/32">
                {filteredUsers.length === 0 ? (
                  <p className="p-2.5 text-center text-[13px] text-muted-foreground">Aucun membre trouvé</p>
                ) : filteredUsers.map((u: any) => (
                  <button
                    key={u.userId}
                    type="button"
                    onClick={() => setSelectedUserId(String(u.userId))}
                    className={cn(
                      "flex w-full cursor-pointer items-center justify-between gap-2 px-3 py-2 text-left text-[13px] transition-colors hover:bg-muted",
                      selectedUserId === String(u.userId) && "bg-primary/8 text-primary-ink",
                    )}
                  >
                    <span className="truncate font-semibold">{u.fullName || "—"}</span>
                    <span className="shrink-0 font-mono text-[12px] text-muted-foreground">#{u.userId}</span>
                  </button>
                ))}
              </div>
            )}
            <div className="flex items-center gap-2">
              <span className="text-[13.5px] font-semibold">Doigt</span>
              <span className="text-[12.5px] text-muted-foreground">0 à 9</span>
              <Input
                type="number"
                min={0}
                max={9}
                value={fingerId}
                onChange={(e) => setFingerId(e.target.value)}
                disabled={running}
                aria-label="Doigt (0 à 9)"
                className="h-9 w-16 rounded-lg border-grey/32 font-mono text-[13.5px]"
              />
              <ActionButton
                kind="primary"
                className="ml-auto"
                icon={running ? Loader2 : Play}
                spin={running}
                onClick={handleStart}
                disabled={running || (enrollType === "BACKEND" && !selectedUserId)}
                title={noFingerprintDevice
                  ? "Aucun appareil synchronisé n'accepte les empreintes : la capture sera enregistrée mais ne sera envoyée à aucun lecteur."
                  : undefined}
              >
                {running ? "En cours…" : "Démarrer"}
              </ActionButton>
            </div>
            {/* Do not silently promise a delivery that cannot happen. The capture
                is still allowed (it is saved to the backend and will be pushed as
                soon as a device is enabled) -- but say so. */}
            {noFingerprintDevice ? (
              <Note tone="warning" className="text-[12.5px]">
                Aucun appareil synchronisé n'accepte les empreintes
                (<span className="font-mono">fingerprintEnabled</span> désactivé).
                L'empreinte sera enregistrée sur le compte du membre, mais elle ne sera
                envoyée à aucun lecteur tant qu'un appareil ne l'autorise pas.
              </Note>
            ) : null}
          </div>
        </Panel>

        <Panel className="flex-none">
          <PanelHeader title={`Déjà enregistrées · ${fingerprints.length}`} sub="Empreintes stockées sur ce PC">
            {fpLoading && <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />}
          </PanelHeader>
          <PanelList>
            {fingerprints.length === 0 ? (
              <div className="py-2 text-[13px] text-muted-foreground">Aucune empreinte locale stockée.</div>
            ) : fingerprints.map((fp: any) => (
              <ListRow
                key={fp.id}
                icon={Fingerprint}
                tone="grey"
                title={fp.label || fp.pin || `#${fp.id}`}
                sub={`doigt ${fp.fingerId} · ${fp.templateSize} o`}
                trailing={(
                  <ActionButton kind="danger" size="xs" iconOnly icon={Trash2} title="Supprimer l'empreinte" onClick={() => setFpToDelete(fp)}>
                    Supprimer l'empreinte
                  </ActionButton>
                )}
              />
            ))}
          </PanelList>
        </Panel>
      </div>

      <div className="hidden">
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Nouvelle empreinte</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-1.5">
              <Label>Type d&apos;enrolement</Label>
              <Select value={enrollType} onValueChange={(v: string) => setEnrollType(v as "LOCAL" | "BACKEND")}> 
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="LOCAL" disabled>Local (non disponible)</SelectItem>
                  <SelectItem value="BACKEND">Backend (serveur)</SelectItem>
                </SelectContent>
              </Select>
            </div>

            {enrollType === "BACKEND" ? (
              <div className="space-y-2">
                <Label>Utilisateur</Label>
                <Input
                  placeholder="Rechercher par nom, ID, telephone..."
                  value={userSearch}
                  onChange={(e) => setUserSearch(e.target.value)}
                />
                <ScrollArea className="h-40 border rounded-md">
                  {filteredUsers.length === 0 ? (
                    <p className="text-sm text-muted-foreground p-3 text-center">Aucun utilisateur trouve</p>
                  ) : (
                    filteredUsers.map((u) => (
                      <div
                        key={u.userId}
                        className={`flex justify-between items-center px-3 py-2 text-sm cursor-pointer hover:bg-muted transition-colors ${
                          selectedUserId === String(u.userId) ? "bg-primary/10 text-primary" : ""
                        }`}
                        onClick={() => setSelectedUserId(String(u.userId))}
                      >
                        <span className="font-medium">{u.fullName || "-"}</span>
                        <span className="text-xs text-muted-foreground">#{u.userId}</span>
                      </div>
                    ))
                  )}
                </ScrollArea>
                {selectedUserId && (
                  <Alert variant="info">
                    <AlertDescription>
                      Selectionne: <strong>{users.find((u) => String(u.userId) === selectedUserId)?.fullName}</strong> - ID: {selectedUserId}
                    </AlertDescription>
                  </Alert>
                )}
              </div>
            ) : (
              <>
                <div className="space-y-1.5">
                  <Label>Label</Label>
                  <Input value={label} onChange={(e) => setLabel(e.target.value)} disabled={running} />
                </div>
                <div className="space-y-1.5">
                  <Label>PIN</Label>
                  <Input value={pin} onChange={(e) => setPin(e.target.value)} disabled={running} />
                </div>
                <div className="space-y-1.5">
                  <Label>Card No</Label>
                  <Input value={cardNo} onChange={(e) => setCardNo(e.target.value)} disabled={running} />
                </div>
              </>
            )}

            <div className="space-y-1.5">
              <Label>Finger ID (0-9)</Label>
              <Input type="number" value={fingerId} onChange={(e) => setFingerId(e.target.value)} disabled={running} />
            </div>

            <div className="flex gap-2">
              <Button onClick={handleStart} disabled={running || (enrollType === "BACKEND" && !selectedUserId)}>
                {running ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" /> En cours...
                  </>
                ) : (
                  <>
                    <Play className="h-4 w-4" /> Demarrer
                  </>
                )}
              </Button>
              <Button variant="outline" onClick={handleCancel} disabled={!running}>
                <Square className="h-4 w-4" /> Annuler
              </Button>
            </div>

            {result && (
              <Alert variant={result === "success" ? "success" : result === "cancelled" ? "warning" : "destructive"}>
                <AlertDescription>
                  {result === "success" ? "Enrolement reussi !" : result === "cancelled" ? "Enrolement annule." : "Enrolement echoue."}
                </AlertDescription>
              </Alert>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Journal d&apos;enrolement</CardTitle>
          </CardHeader>
          <CardContent>
            <LogViewer lines={logs} maxHeight="350px" emptyText="En attente du demarrage..." />
          </CardContent>
        </Card>
      </div>

      <div className="hidden">
      <Separator />
      <div className="flex items-center gap-3">
        <Fingerprint className="h-4 w-4 text-primary" />
        <h2 className="text-base font-semibold">Empreintes locales</h2>
        <Badge variant="secondary" className="text-xs">{fingerprints.length}</Badge>
        {fpLoading && <Loader2 className="h-4 w-4 animate-spin" />}
      </div>

      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>ID</TableHead>
              <TableHead>Label</TableHead>
              <TableHead>PIN</TableHead>
              <TableHead>Carte</TableHead>
              <TableHead>Doigt</TableHead>
              <TableHead>Taille</TableHead>
              <TableHead>Cree</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {fingerprints.length === 0 ? (
              <TableRow>
                <TableCell colSpan={8} className="h-24 text-center text-muted-foreground">Aucune empreinte locale stockee.</TableCell>
              </TableRow>
            ) : (
              fingerprints.map((fp) => (
                <TableRow key={fp.id}>
                  <TableCell className="font-mono text-xs">{fp.id}</TableCell>
                  <TableCell>{fp.label || "-"}</TableCell>
                  <TableCell>{fp.pin || "-"}</TableCell>
                  <TableCell>{fp.cardNo || "-"}</TableCell>
                  <TableCell>{fp.fingerId}</TableCell>
                  <TableCell>{fp.templateSize}</TableCell>
                  <TableCell className="text-xs">{fp.createdAt?.replace("T", " ") || "-"}</TableCell>
                  <TableCell className="text-right">
                    <Button
                      size="icon"
                      variant="ghost"
                      className="h-7 w-7 text-destructive"
                      onClick={() => {
                        if (confirm(`Supprimer l'empreinte #${fp.id} ?`)) void removeFp(fp.id);
                      }}
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>
      </div>

      <DialogFrame
        open={errorOpen}
        onOpenChange={setErrorOpen}
        lockOutside
        width={480}
        title="Erreur"
        footer={<ActionButton kind="dark" className="px-5" onClick={() => setErrorOpen(false)}>OK</ActionButton>}
      >
        <p className="whitespace-pre-wrap text-[13.5px] text-foreground">{errorMsg}</p>
      </DialogFrame>

      <ConfirmDialog
        open={!!fpToDelete}
        onOpenChange={(o) => { if (!o) setFpToDelete(null); }}
        title={`Supprimer l'empreinte #${fpToDelete?.id ?? ""} ?`}
        confirmLabel="Supprimer"
        onConfirm={() => {
          const fp = fpToDelete;
          setFpToDelete(null);
          if (fp) void removeFp(fp.id);
        }}
      />
    </div>
    </>
  );
}
