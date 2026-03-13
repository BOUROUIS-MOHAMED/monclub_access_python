import { useState, useEffect, useRef, useCallback } from "react";
import { useEnroll, useUsers } from "@/api/hooks";
import { ApiError, openSSE } from "@/api/client";
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
import { Fingerprint, Play, Square, Trash2, Loader2 } from "lucide-react";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";

export default function EnrollPage() {
  const enroll = useEnroll();
  const { data: userData } = useUsers();
  const users: any[] = userData?.users ?? [];

  // Backend is the only implemented mode right now.
  const [enrollType, setEnrollType] = useState<"LOCAL" | "BACKEND">("BACKEND");
  const [selectedUserId, setSelectedUserId] = useState("");
  const [label, setLabel] = useState("");
  const [pin, setPin] = useState("");
  const [cardNo, setCardNo] = useState("");
  const [fingerId, setFingerId] = useState("0");

  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<string | null>(null);
  const [logs, setLogs] = useState<string[]>([]);

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

  useEffect(() => {
    const FINAL = new Set(["success", "failed", "cancelled", "error"]);

    try {
      const es = openSSE("/enroll/events", (type, data) => {
        try {
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
            setLogs((prev) => [...prev, step]);
            return;
          }

          if (FINAL.has(type)) {
            const r = data?.result ? String(data.result) : type;
            setResult(r);
            setRunning(false);
            startReqRef.current = false;
            void loadFingerprints();

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
  }, [loadFingerprints, showError]);

  const handleStart = async () => {
    if (running || startReqRef.current) return;

    if (enrollType === "LOCAL") {
      showError("Le mode LOCAL n'est pas implemente pour le moment. Utilisez le mode BACKEND.");
      return;
    }

    startReqRef.current = true;
    lastEnrollErrorRef.current = "";

    setRunning(true);
    setResult(null);
    setLogs(["Demarrage..."]);

    try {
      const selectedUser = users.find((u) => String(u.userId) === selectedUserId);

      await enroll.start({
        type: "BACKEND",
        target: "backend",
        userId: selectedUser ? selectedUser.userId : undefined,
        fullName: selectedUser ? selectedUser.fullName : undefined,
        fingerId: parseInt(fingerId, 10) || 0,
      });
    } catch (e) {
      setResult("error");
      setRunning(false);
      startReqRef.current = false;
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
  };

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

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <Fingerprint className="h-5 w-5 text-primary" />
        <h1 className="text-lg font-semibold">Enrolement d&apos;empreinte</h1>
      </div>

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
  );
}

