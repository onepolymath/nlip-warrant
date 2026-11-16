import type { Money } from "./types";

export function money(m: Money | undefined): string {
  if (!m) return "—";
  const symbol =
    m.currency === "GBP" ? "£" : m.currency === "USD" ? "$" : m.currency === "EUR" ? "€" : "";
  const value = (m.minor / 100).toLocaleString("en-GB", {
    minimumFractionDigits: m.minor % 100 ? 2 : 0,
  });
  return symbol ? `${symbol}${value}` : `${value} ${m.currency}`;
}

export const short = (id: string, n = 8): string => `${id.slice(0, n)}…`;

export function humanReason(reason: string | null | undefined): string {
  if (!reason) return "";
  return reason.replace(/_/g, " ");
}

export function clockTime(epoch: number): string {
  return new Date(epoch * 1000).toISOString().slice(11, 19) + " UTC";
}

export function pct(x: number): string {
  return `${Math.round(x * 100)}%`;
}
