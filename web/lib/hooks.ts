"use client";
import { useCallback, useEffect, useRef, useState } from "react";
import { useTheme } from "next-themes";

export type Async<T> = { data: T | undefined; error: unknown; loading: boolean; reload: () => void; setData: (fn: (d: T | undefined) => T | undefined) => void };

/** Minimal data hook: loading / error / data / reload. Stale responses from earlier deps are dropped. */
export function useAsync<T>(fn: () => Promise<T>, deps: unknown[]): Async<T> {
  const [state, setState] = useState<{ data?: T; error?: unknown; loading: boolean }>({ loading: true });
  const [n, setN] = useState(0);
  const seq = useRef(0);
  useEffect(() => {
    const id = ++seq.current;
    setState((s) => ({ ...s, loading: true, error: undefined }));
    fn().then(
      (data) => id === seq.current && setState({ data, loading: false }),
      (error) => id === seq.current && setState((s) => ({ data: s.data, error, loading: false })),
    );
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, n]);
  const reload = useCallback(() => setN((x) => x + 1), []);
  const setData = useCallback((f: (d: T | undefined) => T | undefined) => setState((s) => ({ ...s, data: f(s.data) })), []);
  return { data: state.data, error: state.error, loading: state.loading, reload, setData };
}

/** Resolves CSS custom properties to concrete colors for canvas/WebGL renderers; re-reads on theme change. */
export function useCssColors<K extends string>(names: readonly K[]): Record<K, string> | null {
  const { resolvedTheme } = useTheme();
  const [colors, setColors] = useState<Record<K, string> | null>(null);
  const key = names.join(",");
  useEffect(() => {
    // Resolve inside a .viz scope so canvas renderers keep the palette charts shipped with.
    const probe = document.createElement("div");
    probe.className = "viz";
    probe.hidden = true;
    document.body.appendChild(probe);
    const cs = getComputedStyle(probe);
    setColors(Object.fromEntries(names.map((n) => [n, cs.getPropertyValue(n).trim()])) as Record<K, string>);
    probe.remove();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [resolvedTheme, key]);
  return colors;
}

export function useInterval(fn: () => void, ms: number | null) {
  const ref = useRef(fn);
  ref.current = fn;
  useEffect(() => {
    if (ms === null) return;
    const t = setInterval(() => ref.current(), ms);
    return () => clearInterval(t);
  }, [ms]);
}
