import { useState, useEffect, useRef, useCallback } from "react";
import { useEnroll, useUsers } from "@/api/hooks";
import { ApiError, openSSE } from "@/api/client";
import { useEnrollment } from "@/context/EnrollmentContext";
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

export default function EnrollPage() {
  const enroll = useEnroll();
  const { data: userData } = useUsers();
  const users: any[] = userData?.users ?? [];
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
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <Fingerprint className="h-5 w-5 text-primary" />
        <h1 className="text-lg font-semibold">Enrolement d&apos;empreinte</h1>
        <div className="ml-auto">
          <Button variant="ghost" size="icon" className="h-8 w-8" onClick={toggleSound} title={soundEnabled ? "Son active" : "Son desactive"}>
            {soundEnabled ? <Volume2 className="h-4 w-4" /> : <VolumeX className="h-4 w-4 text-muted-foreground" />}
          </Button>
        </div>
      </div>

      {enrollMeta && (
        <div className="relative rounded-xl overflow-hidden border border-primary/30 bg-gradient-to-r from-primary/10 via-primary/5 to-transparent p-4">
          <div className="flex items-center gap-3">
            <div className="flex-shrink-0 w-10 h-10 rounded-full bg-primary/20 flex items-center justify-center">
              <Fingerprint className="h-5 w-5 text-primary animate-pulse" />
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-semibold text-foreground">Enrolement demarre depuis le tableau de bord</p>
              <p className="text-xs text-muted-foreground truncate">
                {enrollMeta.fullName ? `Membre : ${enrollMeta.fullName}` : `ID : ${enrollMeta.userId}`}
                {enrollMeta.fingerId !== undefined ? ` · Doigt #${enrollMeta.fingerId}` : ""}
              </p>
            </div>
            <button
              className="text-xs text-muted-foreground hover:text-foreground transition-colors px-2 py-1 rounded"
              onClick={clearMeta}
            >
              ×
            </button>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
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

      <AlertDialog open={errorOpen} onOpenChange={setErrorOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Erreur</AlertDialogTitle>
            <AlertDialogDescription className="whitespace-pre-wrap">{errorMsg}</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogAction>OK</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
    </>
  );
}

