"use client";
// Corazium brand mark: vector redraw of brand/corazium-logo.jpg (shield, double-line C, chip, three circuit traces)
// so it stays sharp at 24-48px and readable on both themes. Colors come from --logo-* tokens in globals.css.
import * as React from "react";
import { cn } from "@/lib/utils";

export function LogoMark({ size = 28, className, title }: { size?: number; className?: string; title?: string }) {
  const id = React.useId().replace(/:/g, "");
  return (
    <svg width={size} height={size} viewBox="-1 -1 55 58" fill="none" className={cn("shrink-0", className)} role={title ? "img" : undefined} aria-label={title} aria-hidden={title ? undefined : true}>
      <defs>
        <linearGradient id={`${id}s`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" style={{ stopColor: "var(--logo-a)" }} />
          <stop offset="1" style={{ stopColor: "var(--logo-b)" }} />
        </linearGradient>
        <radialGradient id={`${id}c`} cx="0.5" cy="0.5" r="0.6">
          <stop offset="0" style={{ stopColor: "var(--logo-glow-a)" }} />
          <stop offset="1" style={{ stopColor: "var(--logo-glow-b)" }} />
        </radialGradient>
      </defs>
      {/* shield, open on the right where the circuit leaves it */}
      <path d="M44.6 21.5V8.2Q33.5 7.4 23 1Q12.5 7.4 1.4 8.2V25C1.4 39.5 10.5 49.8 23 55.2C33.4 50.8 40.8 43.4 44.2 31.4" stroke={`url(#${id}s)`} strokeWidth="3.4" strokeLinecap="round" strokeLinejoin="round" />
      {/* double-line C */}
      <path d="M35.6 16.9A16 16 0 1 0 35.6 36.5L32.5 33.1A11.6 11.6 0 1 1 32.5 20.3Z" stroke={`url(#${id}s)`} strokeWidth="1.6" strokeLinejoin="round" />
      {/* circuit traces */}
      <g stroke="var(--logo-line)" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round">
        <path d="M26 24.9H31L32.2 24H43.6L48.4 18.3" />
        <path d="M26 26.2H49.4" />
        <path d="M26 27.5H31L32.2 28.4H43.6L47.6 33.4" />
        <path d="M21 23.2V20.4M23 23.2V20.4M25 23.2V20.4M21 29.2V32M23 29.2V32M25 29.2V32M20 25H17M20 27.4H17" />
        <circle cx="49.6" cy="17" r="1.7" />
        <circle cx="51.4" cy="26.2" r="1.7" />
        <circle cx="48.6" cy="34.6" r="1.7" />
      </g>
      {/* chip */}
      <rect x="20" y="23.2" width="6" height="6" rx="1.1" fill={`url(#${id}c)`} stroke="var(--logo-line)" strokeWidth="1" />
    </svg>
  );
}

/** Mark + wordmark. `sub` adds the product line under the name (sidebar). */
export function Logo({ size = 28, sub, className }: { size?: number; sub?: string; className?: string }) {
  return (
    <span className={cn("inline-flex items-center gap-2.5", className)}>
      <LogoMark size={size} />
      <span className="flex min-w-0 flex-col leading-none">
        <span className="font-brand text-[15px] font-bold tracking-[0.045em] text-[rgb(var(--brand-ink))]">CORAZIUM</span>
        {sub ? <span className="mt-1 text-[10.5px] font-medium tracking-[0.01em] text-muted">{sub}</span> : null}
      </span>
    </span>
  );
}
