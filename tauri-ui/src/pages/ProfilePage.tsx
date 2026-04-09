import { useState } from "react";
import { useApp } from "@/context/AppContext";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { AlertTriangle, LogOut } from "lucide-react";

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-xl border border-border bg-card overflow-hidden">
      <div className="flex items-center gap-2 px-4 py-3 border-b border-border">
        <span className="text-[13px] font-semibold text-foreground">{title}</span>
      </div>
      <div className="px-4 py-3 space-y-2 text-[13px]">{children}</div>
    </div>
  );
}

function KV({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between py-0.5">
      <span className="text-muted-foreground">{label}</span>
      <span className="text-right text-foreground">{value ?? "—"}</span>
    </div>
  );
}

function formatDate(isoStr: string | null): string {
  if (!isoStr) return "—";
  const d = new Date(isoStr);
  if (isNaN(d.getTime())) return isoStr;
  const day = d.getDate();
  const monthNames = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
  ];
  const month = monthNames[d.getMonth()];
  const year = d.getFullYear();
  const h = String(d.getHours()).padStart(2, "0");
  const m = String(d.getMinutes()).padStart(2, "0");
  return `${day} ${month} ${year} at ${h}:${m}`;
}


export default function ProfilePage() {
  const { status, logout } = useApp();
  const [logoutConfirm, setLogoutConfirm] = useState(false);

  if (!status) return <p className="text-[13px] text-muted-foreground">Chargement…</p>;

  const s = status.session;
  const avatarLetter = s.email ? s.email[0].toUpperCase() : "?";

  const handleLogout = async () => {
    setLogoutConfirm(false);
    await logout();
  };

  return (
    <div className="space-y-4 max-w-4xl mx-auto">

      {/* Section 1 — Account card */}
      <div className="rounded-xl border border-border bg-card overflow-hidden">
        <div className="px-6 py-6 flex flex-col sm:flex-row items-start sm:items-center gap-5">
          {/* Avatar */}
          <div className="flex h-16 w-16 shrink-0 items-center justify-center rounded-full bg-primary/15 text-primary text-2xl font-bold select-none">
            {avatarLetter}
          </div>
          <div className="flex-1 min-w-0 space-y-1.5">
            <div className="text-base font-semibold text-foreground truncate">
              {s.email ?? "—"}
            </div>
            <div className="flex flex-wrap items-center gap-2">
              {s.restricted ? (
                <Badge className="border-red-500/30 bg-red-500/10 text-red-400 text-[11px]">
                  Restricted
                </Badge>
              ) : (
                <Badge className="border-emerald-500/30 bg-emerald-500/10 text-emerald-400 text-[11px]">
                  Logged in
                </Badge>
              )}
              {s.restricted && s.reasons.map((reason) => (
                <Badge key={reason} className="border-red-500/20 bg-red-500/8 text-red-300 text-[11px]">
                  {reason}
                </Badge>
              ))}
            </div>
            <div className="text-[12px] text-muted-foreground">
              Last login: {formatDate(s.lastLoginAt)}
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">

        {/* Section 2 — Session card */}
        <div className="space-y-3">
          <Section title="Session">
            <KV
              label="Session expires in"
              value={
                s.loginDaysRemaining != null ? (
                  <span className={`flex items-center gap-1 ${s.loginWarning ? "text-amber-400" : "text-foreground"}`}>
                    {s.loginWarning && <AlertTriangle className="h-3.5 w-3.5 text-amber-400" />}
                    {s.loginDaysRemaining} day{s.loginDaysRemaining !== 1 ? "s" : ""}
                  </span>
                ) : "—"
              }
            />
            <KV label="Last login" value={formatDate(s.lastLoginAt)} />
          </Section>
          {s.loginWarning && s.loginDaysRemaining != null && s.loginDaysRemaining < 7 && (
            <Alert variant="warning">
              <AlertTriangle className="h-4 w-4" />
              <AlertDescription>
                Your session expires soon. Please log in again to renew it.
              </AlertDescription>
            </Alert>
          )}
        </div>

        {/* Section 3 — Contract card */}
        <div className="space-y-3">
          <Section title="Contract">
            <KV
              label="Status"
              value={
                s.contractStatus ? (
                  <Badge className="border-emerald-500/30 bg-emerald-500/10 text-emerald-400 text-[11px]">
                    Active
                  </Badge>
                ) : (
                  <Badge className="border-red-500/30 bg-red-500/10 text-red-400 text-[11px]">
                    Inactive
                  </Badge>
                )
              }
            />
            <KV label="Contract ends" value={formatDate(s.contractEndDate)} />
            <KV
              label="Days remaining"
              value={
                s.contractDaysRemaining != null ? (
                  <span className={`flex items-center gap-1 ${s.contractWarning ? "text-amber-400" : "text-foreground"}`}>
                    {s.contractWarning && <AlertTriangle className="h-3.5 w-3.5 text-amber-400" />}
                    {s.contractDaysRemaining} day{s.contractDaysRemaining !== 1 ? "s" : ""}
                  </span>
                ) : "—"
              }
            />
          </Section>
          {s.contractWarning && (
            <Alert variant="destructive">
              <AlertTriangle className="h-4 w-4" />
              <AlertDescription>
                Your contract expires soon. Contact MonClub to renew.
              </AlertDescription>
            </Alert>
          )}
        </div>

        {/* Section 4 — System card */}
        <Section title="System">
          <KV label="Appareils (DEVICE)" value={status.mode?.DEVICE ?? 0} />
          <KV label="Appareils (AGENT)" value={status.mode?.AGENT ?? 0} />
          <KV label="Appareils (ULTRA)" value={status.mode?.ULTRA ?? 0} />
          <KV
            label="Last sync"
            value={status.sync?.lastSyncAt ? formatDate(status.sync.lastSyncAt) : "Never"}
          />
          <KV
            label="Device connected"
            value={
              status.pullsdk?.connected ? (
                <Badge className="border-emerald-500/30 bg-emerald-500/10 text-emerald-400 text-[11px]">Yes</Badge>
              ) : (
                <Badge className="border-muted/30 bg-muted/10 text-muted-foreground text-[11px]">No</Badge>
              )
            }
          />
          {status.pullsdk?.connected && status.pullsdk.deviceId != null && (
            <KV label="Device ID" value={`#${status.pullsdk.deviceId}`} />
          )}
        </Section>

        {/* Section 5 — Actions */}
        <Section title="Actions">
          <p className="text-[12px] text-muted-foreground mb-3">
            Log out of MonClub Access. You will need to enter your credentials again to access the application.
          </p>
          <Button
            variant="destructive"
            size="sm"
            className="w-full h-9 text-[13px] gap-2"
            onClick={() => setLogoutConfirm(true)}
          >
            <LogOut className="h-3.5 w-3.5" />
            Log Out
          </Button>
        </Section>

      </div>

      {/* Logout confirmation dialog */}
      <Dialog open={logoutConfirm} onOpenChange={setLogoutConfirm}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle>Log out?</DialogTitle>
            <DialogDescription>
              Are you sure you want to log out? You will need to enter your credentials again.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setLogoutConfirm(false)}>Cancel</Button>
            <Button variant="destructive" onClick={handleLogout}>
              <LogOut className="h-3.5 w-3.5" />
              Log Out
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
