"use client";
import * as React from "react";
import { usePathname } from "next/navigation";
import { ThemeProvider } from "next-themes";
import { X, CheckCircle, WarningOctagon, Info } from "@phosphor-icons/react";
import { auth, setSession, usingMock } from "@/lib/api";
import type { Role } from "@/lib/types";
import { cn } from "@/lib/utils";

// ---------- Session / RBAC (FR-5.1) ----------
// With a backend, the session is whoever signed in through OIDC (NFR-2.2) and the role comes from the control plane.
// Without one, the role switcher in the user menu lets each role's UI be reviewed with mock data.
const PEOPLE: Record<Role, { name: string; email: string }> = {
  Admin: { name: "Budi", email: "budi@domain.com" },
  "SecOps Analyst": { name: "Ahmad", email: "ahmad@domain.com" },
  Auditor: { name: "External Auditor", email: "audit@domain.com" },
};
type Session = { role: Role; name: string; email: string; setRole: (r: Role) => void; can: (a: Permission) => boolean };
export type Permission = "respond" | "editPolicy" | "deploy" | "writeRule" | "admin";
const MATRIX: Record<Permission, Role[]> = {
  respond: ["Admin", "SecOps Analyst"],
  writeRule: ["Admin", "SecOps Analyst"],
  editPolicy: ["Admin"],
  deploy: ["Admin"],
  admin: ["Admin"],
};
const SessionCtx = React.createContext<Session | null>(null);
export const useSession = () => React.useContext(SessionCtx)!;

function SessionProvider({ children }: { children: React.ReactNode }) {
  const [role, setRoleState] = React.useState<Role>("SecOps Analyst");
  React.useEffect(() => {
    try { const r = localStorage.getItem("coraza.role") as Role | null; if (r && r in PEOPLE) setRoleState(r); } catch { /* storage blocked */ }
  }, []);
  const [me, setMe] = React.useState<{ name: string; email: string; role: Role } | null>(null);
  const publicPage = usePathname()?.startsWith("/login") ?? false;
  React.useEffect(() => {
    // A 401 here sends the browser to /login (see call() in lib/api.ts); the console renders nothing until then.
    if (!usingMock && !publicPage && !me) auth.me().then(setMe).catch(() => {});
  }, [publicPage, me]);
  const p = usingMock ? { ...PEOPLE[role], role } : me;
  if (p) setSession({ name: p.name, role: p.role });
  const pRole = p?.role, pName = p?.name, pEmail = p?.email;
  const value = React.useMemo<Session | null>(() => pRole && pName !== undefined && pEmail !== undefined ? ({
    role: pRole, name: pName, email: pEmail,
    setRole: (r) => { if (!usingMock) return; setRoleState(r); try { localStorage.setItem("coraza.role", r); } catch { /* storage blocked */ } },
    can: (a) => MATRIX[a].includes(pRole),
  }) : null, [pRole, pName, pEmail]);
  if (!value && publicPage) return <>{children}</>; // the sign-in page needs no session
  if (!value) return <div role="status" className="flex min-h-dvh items-center justify-center text-[13px] text-muted">Checking your session...</div>;
  return <SessionCtx.Provider value={value}>{children}</SessionCtx.Provider>;
}

// ---------- Toasts ----------
type Toast = { id: number; tone: "ok" | "error" | "info"; title: string; body?: string; action?: { label: string; href: string } };
const ToastCtx = React.createContext<(t: Omit<Toast, "id">) => void>(() => {});
export const useToast = () => React.useContext(ToastCtx);

function ToastProvider({ children }: { children: React.ReactNode }) {
  const [items, setItems] = React.useState<Toast[]>([]);
  const push = React.useCallback((t: Omit<Toast, "id">) => {
    const id = Date.now() + Math.random();
    setItems((x) => [...x.slice(-3), { ...t, id }]);
    setTimeout(() => setItems((x) => x.filter((i) => i.id !== id)), t.tone === "error" ? 9000 : 6000);
  }, []);
  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div aria-live="polite" className="pointer-events-none fixed bottom-4 left-4 z-[60] flex w-[min(360px,calc(100vw-32px))] flex-col gap-2 max-sm:[&>*:not(:last-child)]:hidden">
        {items.map((t) => {
          const Icon = t.tone === "ok" ? CheckCircle : t.tone === "error" ? WarningOctagon : Info;
          return (
            <div key={t.id} className="pointer-events-auto flex items-start gap-3 rounded-lg border border-border-strong bg-surface p-3 shadow-pop animate-in fade-in-0 slide-in-from-bottom-2">
              <Icon size={18} weight="fill" aria-hidden className={cn("mt-px shrink-0", t.tone === "ok" ? "text-good" : t.tone === "error" ? "text-crit" : "text-accent")} />
              <div className="min-w-0 flex-1">
                <p className="text-[13px] font-medium">{t.title}</p>
                {t.body ? <p className="mt-0.5 break-words text-[12px] text-fg-2">{t.body}</p> : null}
                {t.action ? <a href={t.action.href} className="mt-1 inline-block text-[12px] font-medium text-accent underline-offset-2 hover:underline">{t.action.label}</a> : null}
              </div>
              <button aria-label="Dismiss notification" onClick={() => setItems((x) => x.filter((i) => i.id !== t.id))} className="rounded p-0.5 text-muted hover:bg-surface-2 hover:text-fg">
                <X size={14} aria-hidden />
              </button>
            </div>
          );
        })}
      </div>
    </ToastCtx.Provider>
  );
}

export function Providers({ children }: { children: React.ReactNode }) {
  return (
    <ThemeProvider attribute="class" defaultTheme="dark" enableSystem={false} disableTransitionOnChange>
      <SessionProvider>
        <ToastProvider>{children}</ToastProvider>
      </SessionProvider>
    </ThemeProvider>
  );
}
