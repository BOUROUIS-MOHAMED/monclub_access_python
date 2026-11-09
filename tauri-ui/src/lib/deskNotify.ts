import type { PopupEvent } from "../api/types";
import { dayNumber, localDayNumber, feeLines, parseFees, feeDueSoonDays } from "./feeAlerts.ts";

export interface DeskNotifySettings {
  enabled: boolean;
  mode: "ALL" | "REFUSALS_AND_ALERTS" | "REFUSALS_ONLY";
  position: "TOP_LEFT" | "TOP_CENTER" | "TOP_RIGHT" | "BOTTOM_LEFT" | "BOTTOM_CENTER" | "BOTTOM_RIGHT";
  screen: number;
  durationSec: number;
  maxVisible: number;
  sound: boolean;
  renewButton: boolean;
  payRestButton: boolean;
  testNonce: number;
}
export const DESK_DEFAULTS: DeskNotifySettings = { enabled: false, mode: "REFUSALS_AND_ALERTS", position: "BOTTOM_RIGHT",
  screen: 0, durationSec: 8, maxVisible: 3, sound: false, renewButton: true, payRestButton: true, testNonce: 0 };
export interface DeskNotifyAction { action: "open" | "renew" | "payRest" | "assignCard"; activeMembershipId?: number; cardNo?: string }
export function deskReentry(e: PopupEvent): boolean {
  return e.reason === "DENY_ANTI_FRAUD_CARD" || e.reason === "DENY_ANTI_FRAUD_QR";
}
export function deskDaysLeft(validTo: string, now: Date): number | null {
  const day = dayNumber(validTo);
  return day === null ? null : day - localDayNumber(now);
}
export function deskBirthday(e: PopupEvent, now: Date): boolean {
  const match = /^\d{4}-(\d{2})-(\d{2})/.exec(e.userBirthday || "");
  return !!match && Number(match[1]) === now.getMonth() + 1 && Number(match[2]) === now.getDate();
}
export function deskAccepts(e: PopupEvent, s: DeskNotifySettings, now = new Date()): boolean {
  if (!s.enabled) return false;
  if (e.deskTest) return true;
  if (s.mode === "ALL") return true;
  if (s.mode === "REFUSALS_ONLY") return !e.allowed && !deskReentry(e);
  if (!e.allowed || deskBirthday(e, now) || (e.repeatCount || 0) > 0) return true;
  const days = deskDaysLeft(e.userValidTo, now);
  return (days !== null && days >= 0 && days <= 7) || feeLines(parseFees(e.fees), now, feeDueSoonDays(e.feeDueSoonDays)).length > 0;
}
export function deskDuration(e: PopupEvent, seconds: number): number { return seconds * 1000 * (e.allowed ? 1 : 2); }
export function deskAdvance(remaining: number, elapsed: number, paused: boolean): number {
  return paused ? remaining : Math.max(0, remaining - Math.max(0, elapsed));
}
export function deskActionPath(a: DeskNotifyAction): string {
  if (a.action === "assignCard" && a.cardNo) return `/users?assignCard=${encodeURIComponent(a.cardNo)}`;
  if (!Number.isSafeInteger(a.activeMembershipId) || (a.activeMembershipId || 0) <= 0) return "/users";
  const member = `/users?member=${a.activeMembershipId}`;
  return a.action === "renew" || a.action === "payRest" ? `${member}&action=${a.action}` : member;
}

/** SSE can deliver an enable-and-test heartbeat before the page's settings poll. */
export class DeskTestInbox {
  private pending = new Map<string, PopupEvent>();
  receive(event: PopupEvent): boolean {
    if (!event.deskTest) return false;
    this.pending.set(event.eventId, event);
    if (this.pending.size > 32) this.pending.delete(this.pending.keys().next().value!);
    return true;
  }
  drain(settings: DeskNotifySettings): PopupEvent[] {
    const events = settings.enabled ? [...this.pending.values()] : [];
    this.pending.clear();
    return events;
  }
}

export function deskScrollOffset(scrollHeight: number, clientHeight: number, position: string): number {
  return position.startsWith("BOTTOM_") ? Math.max(0, scrollHeight - clientHeight) : 0;
}
