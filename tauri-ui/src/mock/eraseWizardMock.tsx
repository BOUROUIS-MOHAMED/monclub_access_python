// A mock of the Erase-content wizard for screenshots and design review: the real dialog
// (src/components/EraseWizardDialog.tsx) over a SIMULATED local API -- no Python app, no device.
// Served by the Vite dev server only (erase-mock.html); `vite build` ships index.html alone.
// The admin password of the mock is "admin".
import ReactDOM from "react-dom/client";
import { useMemo, useState } from "react";
import EraseWizardDialog from "@/components/EraseWizardDialog";
import { Button } from "@/components/ui/button";
import { installSemanticTokenStyles } from "@/theme/colors";
import type { EraseApi, EraseCounts, EraseHold, ErasePreview, EraseRun, EraseStartBody } from "@/api/erase";
import { Router, Trash2, PauseCircle } from "lucide-react";
import { ERASE_TEXT, saveLang, type Lang } from "@/lib/eraseWizardText";
import "@/index.css";

installSemanticTokenStyles();

type MockDevice = { id: number; name: string; ip: string; protocol: "ZK_PULLSDK" | "ZK_STANDALONE" };
const DEVICES: MockDevice[] = [
  { id: 5, name: "Entrée 1", ip: "192.168.0.202", protocol: "ZK_PULLSDK" },
  { id: 8, name: "Sortie", ip: "192.168.1.247", protocol: "ZK_STANDALONE" },
];

// Mock options (URL): ?faces=unknown -- the MB2000 does not report its face count;
// ?incomplete=1 -- the C3 keeps its user rows after the erase (the run ends INCOMPLETE).
type MockOpts = { facesUnknown: boolean; incomplete: boolean };

function makeApi(onHolds: (h: Set<number>) => void, initialHeld: number[] = [],
                 opts: MockOpts = { facesUnknown: false, incomplete: false }): EraseApi {
  let run: EraseRun | null = null;
  const holds = new Set<number>(initialHeld);
  // Illustrative numbers only (a mock): no real panel was read.
  const counts = (d: MockDevice): EraseCounts => d.protocol === "ZK_PULLSDK"
    ? { tables: { user: 1690, userauthorize: 1690, templatev10: 0, template: null, transaction: 48213 }, extra: {} }
    : { tables: { users: 1838, fingerprints: 2023, attendance: 70 },
        extra: { admins: 2, faces: opts.facesUnknown ? null : 0, passwords: 0 } };
  const rows = (d: MockDevice) => d.protocol === "ZK_PULLSDK"
    ? [
      { key: "user", count: 1690, erasable: true },
      { key: "userauthorize", count: 1690, erasable: true },
      { key: "templatev10", count: 0, erasable: true },
      { key: "template", count: null, erasable: false, reason: "UNREADABLE" },
      { key: "transaction", count: 48213, erasable: false, reason: "DOOR_LOG_NOT_SUPPORTED" },
    ]
    : [
      { key: "users", count: 1838, erasable: true },
      { key: "fingerprints", count: 2023, erasable: true },
      { key: "attendance", count: 70, erasable: false, reason: "DOOR_LOG_NOT_SUPPORTED" },
    ];
  const now = () => new Date().toTimeString().slice(0, 8);
  const at = () => `2026-09-27 ${now()}`;
  return {
    async verifyPassword(pw) {
      await new Promise((r) => setTimeout(r, 300));
      return pw === "admin" ? { ok: true } : { ok: false, error: "Mot de passe incorrect" };
    },
    async preview(did) {
      const d = DEVICES.find((x) => x.id === did)!;
      await new Promise((r) => setTimeout(r, 400));
      const p: ErasePreview = {
        ok: true, previewId: `pv-${did}`, device: { id: d.id, name: d.name, ip: d.ip, port: "4370", protocol: d.protocol },
        pinScheme: holds.has(did) ? "ACCOUNT" : "MEMBERSHIP", tables: rows(d), extra: counts(d).extra,
        hold: holds.has(did) ? { reason: "erase", since: "2026-09-27 23:41:07" } : null, run,
        limits: { mbPinsPerPass: d.protocol === "ZK_STANDALONE" ? 50 : null },
        // Lane 1b: what the refill would write (illustrative numbers).
        refill: {
          scheme: holds.has(did) ? "ACCOUNT" : "MEMBERSHIP",
          members: d.protocol === "ZK_PULLSDK" ? 1688 : 1836, withheld: 0,
          ...(holds.has(did) ? {} : { ifAccount: { members: d.protocol === "ZK_PULLSDK" ? 1601 : 1742, withheld: 0 } }),
          lastSyncOk: true, cacheUpdatedAt: "2026-09-27 23:30:12", problem: null, accountProblem: null,
          // Lane 1c: the list's age and its limit (illustrative).
          staleWhy: null, lastSyncAgeSec: 240, syncMaxAgeSec: 2700,
        },
        // Lane 1c: who the refill will not put back (illustrative people, not a real terminal).
        notRefilled: d.protocol === "ZK_PULLSDK"
          ? { count: 0, scheme: "MEMBERSHIP", people: [] }
          : { count: 2, scheme: "MEMBERSHIP", people: [
            { pin: "777", name: "Agent entretien" }, { pin: "9001", name: "Ancien système" }] },
      };
      return p;
    },
    async start(did, body: EraseStartBody) {
      const d = DEVICES.find((x) => x.id === did)!;
      if (body.typedName !== d.name) throw new Error("the typed name is not this turnstile's name");
      if (!body.backupOnly && body.otherPcsClosed !== true) throw new Error("OTHER_PCS_NOT_CONFIRMED");
      if (!body.backupOnly && d.protocol === "ZK_STANDALONE" && body.acceptNotRefilled !== true) {
        throw Object.assign(new Error("2 person(s) are not in the refill roster"),
          { code: "NOT_REFILLED_UNCONFIRMED", payload: { count: 2 } });
      }
      const before = counts(d);
      const failC3 = opts.incomplete && d.protocol === "ZK_PULLSDK";
      const after: EraseCounts = d.protocol === "ZK_PULLSDK"
        ? { tables: { ...before.tables, user: failC3 ? 1690 : 0, userauthorize: 0, templatev10: 0 }, extra: {} }
        : { tables: { ...before.tables, users: 2, fingerprints: 3 }, extra: before.extra };
      run = {
        runId: "20260927-234107-3fa9c1", deviceId: did,
        device: { id: d.id, name: d.name, ip: d.ip, port: "4370", protocol: d.protocol },
        protocol: d.protocol, tables: body.tables, forget: body.forget ?? null, refill: body.refill ?? null,
        backupOnly: !!body.backupOnly, state: "RUNNING", step: "start", steps: [], countsBefore: null,
        countsAfter: null, backup: null, progress: null, error: null, holdKept: null, erased: false,
        pinScheme: "MEMBERSHIP",
      };
      const plan: Array<() => void> = [
        () => run!.steps.push({ step: "hold", ok: true, at: at() }),
        () => run!.steps.push({ step: "idle", ok: true, at: at() }),
        () => { run!.countsBefore = before; run!.steps.push({ step: "counts_before", ok: true, at: at() }); },
        () => {
          run!.backup = { path: `C:\\ProgramData\\MonClub Access\\access\\erase_backups\\20260927-234107-3fa9c1_device${did}\\backup.json`, sha256: "9f2c…", rows: 3380, rowCounts: {} };
          run!.steps.push({ step: "backup", ok: true, at: at() });
        },
        // The server's order (erase_wizard.C3_ERASE_ORDER): fingers and door rights before the user rows.
        ...(d.protocol === "ZK_PULLSDK"
          ? ["templatev10", "template", "userauthorize", "user"].filter((t) => body.tables.includes(t))
          : [body.tables.includes("users") ? "users" : "fingerprints"]
        ).map((t) => () => run!.steps.push({ step: `erase_${t}`, ok: true, at: at() })),
        () => { run!.countsAfter = after; run!.steps.push({ step: "counts_after", ok: !failC3, at: at() }); },
        ...(failC3 ? [
          () => run!.steps.push({ step: "records_invalidated", ok: true, at: at() }),
          () => {
            holds.add(did); onHolds(new Set(holds));
            run!.steps.push({ step: "finish", ok: false, at: at() });
            run!.error = "NOT_VERIFIED: rows left or unreadable: {'user': 1690}";
            run!.state = "INCOMPLETE"; run!.holdKept = true;
          },
        ] : [
        () => run!.steps.push({ step: body.forget ? "forget" : "keep_records", ok: true, at: at() }),
        () => run!.steps.push({ step: "wipe_reported", ok: true, at: at() }),
        () => {
          const hold = body.refill === "hold";
          if (hold) { holds.add(did); onHolds(new Set(holds)); }
          else run!.steps.push({ step: "refill", ok: true, at: at() });
          run!.steps.push({ step: "finish", ok: true, at: at() });
          run!.state = "DONE"; run!.holdKept = hold;
        },
        ]),
      ];
      plan.forEach((fn, i) => setTimeout(fn, 500 * (i + 1)));
      return { ok: true, runId: run.runId };
    },
    async status() { return { ok: true, running: run?.state === "RUNNING", run: run ? JSON.parse(JSON.stringify(run)) : null }; },
    async refill(did, _password, expectedPinScheme) {
      // The server's interlock: the scheme the page showed must still be the recorded one.
      if (expectedPinScheme !== "ACCOUNT") {
        throw Object.assign(new Error("the pin scheme is ACCOUNT now"),
          { code: "PIN_SCHEME_CHANGED", payload: { pinScheme: "ACCOUNT" } });
      }
      holds.delete(did); onHolds(new Set(holds));
      // Lane 1c: what the refill writes, with one illustrative warning (withheld rows).
      return { ok: true, pinScheme: "ACCOUNT", passRequested: true, invalidated: 1838,
               refill: { scheme: "ACCOUNT", members: 1742, withheld: 3, problem: "REFILL_WITHHELD" },
               adminPins: [], adminCheck: did === 8 ? "CHECKED" : "NOT_APPLICABLE" };
    },
    // A turnstile on hold after the cutover's switch: the refill will write "Par personne" pins.
    async holds() {
      return { ok: true, loadFailed: false, holds: Array.from(holds).map((id): EraseHold => ({
        deviceId: id, reason: "erase", since: "2026-09-27 23:41:07", pinScheme: "ACCOUNT" })) };
    },
  };
}

function MockPage() {
  const params = new URLSearchParams(window.location.search);
  const initialHeld = params.get("held") ? [Number(params.get("held"))] : [];
  const [held, setHeld] = useState<Set<number>>(new Set(initialHeld));
  const opts: MockOpts = { facesUnknown: params.get("faces") === "unknown", incomplete: params.get("incomplete") === "1" };
  const api = useMemo(() => makeApi(setHeld, initialHeld, opts), []);  // eslint-disable-line react-hooks/exhaustive-deps
  const [dlg, setDlg] = useState<{ d: MockDevice; mode: "erase" | "refill" } | null>(() => {
    const id = Number(params.get("device") || 0);
    const d = DEVICES.find((x) => x.id === id);
    return d ? { d, mode: params.get("mode") === "refill" ? "refill" : "erase" } : null;
  });
  return (
    <div className="min-h-screen bg-background p-8 text-foreground">
      <div className="mb-4 flex items-center gap-2 text-[13px] font-extrabold"><Router className="h-4 w-4 text-primary" />Le parc (maquette)</div>
      <div className="max-w-3xl overflow-hidden rounded-3xl bg-card shadow">
        {DEVICES.map((d) => (
          <div key={d.id} className="flex items-center justify-between border-b border-border px-6 py-3.5 last:border-0">
            <div>
              <div className="text-[14px] font-bold">{d.name}</div>
              <div className="text-[11px] text-muted-foreground">{d.protocol === "ZK_PULLSDK" ? "C3-400 · PullSDK" : "MB2000 · ZKTeco autonome"} · {d.ip}</div>
            </div>
            <div className="flex gap-1.5">
              {held.has(d.id) && (
                <Button variant="outline" className="h-7 gap-1.5 rounded-[14px] border-amber-500/50 px-3 text-[11.5px] font-semibold text-amber-700"
                        onClick={() => setDlg({ d, mode: "refill" })}>
                  <PauseCircle className="h-3.5 w-3.5" />Remplir
                </Button>
              )}
              <Button variant="outline" size="icon" className="h-7 w-7 rounded-[14px]" onClick={() => setDlg({ d, mode: "erase" })}>
                <Trash2 className="h-3.5 w-3.5" />
              </Button>
            </div>
          </div>
        ))}
      </div>
      {dlg && (
        <EraseWizardDialog open deviceId={dlg.d.id} deviceName={dlg.d.name} mode={dlg.mode} api={api}
                           onClose={() => setDlg(null)} onChanged={() => undefined} />
      )}
    </div>
  );
}

// ── Screenshot autoplay (mock only): ?device=5&shot=<stop>&lang=en walks the dialog like an
// operator would -- password, tables, options, typed name, erase -- and stops at <stop>, so a
// headless browser can capture each step (tools: chrome --headless --screenshot).
const SHOTS = ["lock", "content", "choose", "options", "confirm", "done", "refill"] as const;

function sleep(ms: number) { return new Promise((r) => setTimeout(r, ms)); }
function setInput(el: HTMLInputElement | null | undefined, value: string) {
  if (!el) return;
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!;
  setter.call(el, value);
  el.dispatchEvent(new Event("input", { bubbles: true }));
}
function clickButton(text: string) {
  const b = Array.from(document.querySelectorAll("button")).find((x) => (x.textContent || "").trim().startsWith(text));
  b?.click();
}
function tick(text: string) {
  const l = Array.from(document.querySelectorAll("label")).find((x) => (x.textContent || "").includes(text));
  l?.querySelector("input")?.click();
}

async function autoplay(stop: string, lang: Lang, deviceId: number) {
  const t = ERASE_TEXT[lang];
  const at = (name: (typeof SHOTS)[number]) => SHOTS.indexOf(name) <= SHOTS.indexOf(stop as (typeof SHOTS)[number]);
  await sleep(600);
  setInput(document.querySelector<HTMLInputElement>("#erase-pw"), "admin");
  if (stop === "lock") return;
  await sleep(200); clickButton(t.unlock); await sleep(1200);
  if (stop === "refill" || !at("choose")) return;
  clickButton(t.next); await sleep(300);
  // C3: ticking the users ticks and locks the rights and fingerprint tables.
  if (deviceId === 5) { tick(t.tableLabels.user); } else { tick(t.tableLabels.users); }
  await sleep(200);
  if (!at("options")) return;
  clickButton(t.next); await sleep(300);
  tick(t.forgetYes.slice(0, 30)); tick(t.refillHold);
  if (deviceId === 8) tick(t.acceptFacesUnknown.slice(0, 30));
  await sleep(200);
  if (!at("confirm")) return;
  clickButton(t.next); await sleep(300);
  setInput(document.querySelector<HTMLInputElement>("#erase-name"), deviceId === 5 ? "Entrée 1" : "Sortie");
  await sleep(200);
  if (!at("done")) return;
  clickButton(t.erase); await sleep(8000);
}

const _params = new URLSearchParams(window.location.search);
const _lang: Lang = _params.get("lang") === "en" ? "en" : "fr";
saveLang(_lang);
ReactDOM.createRoot(document.getElementById("root")!).render(<MockPage />);
const _shot = _params.get("shot");
if (_shot && (SHOTS as readonly string[]).includes(_shot)) {
  void autoplay(_shot, _lang, Number(_params.get("device") || 5));
}
