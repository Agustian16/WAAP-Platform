import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export const cn = (...c: ClassValue[]) => twMerge(clsx(c));

/** Parse IPv4 address or CIDR. Returns null when invalid. Host bits are zeroed in `normalized`. */
export function parseCidr(input: string) {
  const m = input.trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?$/);
  if (!m) return null;
  const oct = m.slice(1, 5).map(Number);
  if (oct.some((o) => o > 255)) return null;
  const bits = m[5] === undefined ? 32 : Number(m[5]);
  if (bits > 32) return null;
  const ipNum = (o: number[]) => ((o[0] << 24) >>> 0) + (o[1] << 16) + (o[2] << 8) + o[3];
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  const net = (ipNum(oct) & mask) >>> 0;
  const normalized = `${[net >>> 24, (net >>> 16) & 255, (net >>> 8) & 255, net & 255].join(".")}/${bits}`;
  return {
    bits,
    normalized,
    contains(ip: string) {
      const p = ip.split(".").map(Number);
      return p.length === 4 && ((ipNum(p) & mask) >>> 0) === net;
    },
  };
}

const nf = new Intl.NumberFormat("en-US");
export const fmtNum = (n: number) => nf.format(Math.round(n));
export const fmtCompact = (n: number) => new Intl.NumberFormat("en-US", { notation: "compact", maximumFractionDigits: 1 }).format(n);

export const fmtTime = (t: number | string) => {
  const d = new Date(t);
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
};
export const fmtClock = (t: number) => {
  const d = new Date(t);
  return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
};
export function relTime(t: number | string) {
  const s = Math.round((Date.now() - new Date(t).getTime()) / 1000);
  if (s < 0) { const f = -s; return f < 3600 ? `in ${Math.round(f / 60)}m` : f < 86400 ? `in ${Math.round(f / 3600)}h` : `in ${Math.round(f / 86400)}d`; }
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export const cssVar = (name: string) =>
  typeof window === "undefined" ? "#888" : getComputedStyle(document.documentElement).getPropertyValue(name).trim() || "#888";

export function download(filename: string, content: string | Blob, type = "application/json") {
  const blob = typeof content === "string" ? new Blob([content], { type }) : content;
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}
