"use client";
import * as React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import * as RDialog from "@radix-ui/react-dialog";
import { useTheme } from "next-themes";
import {
  Pulse, Crosshair, ListMagnifyingGlass, ShieldCheck, FileCode, ShieldWarning, HardDrives, ClockCounterClockwise, GearSix,
  List, X, Moon, Sun, Bell, SignOut, CaretUpDown, CaretRight, Database, type Icon as PhIcon,
} from "@phosphor-icons/react";
import { useSession, useToast } from "./providers";
import { Button, Menu, MenuContent, MenuItem, MenuLabel, MenuRadioGroup, MenuRadioItem, MenuSeparator, MenuTrigger, Switch } from "./ui";
import { StageTag } from "./atoms";
import { Logo } from "./brand";
import { attacks, fleet, subscribeAttackStream, usingMock, mockFailing, setMockFailing } from "@/lib/api";
import { stageMeta } from "@/lib/killchain";
import type { Campaign, EdgeNode, Role, StageKey } from "@/lib/types";
import { cn, relTime } from "@/lib/utils";

/*
  Icon system (Phosphor, one family):
  - Nav glyphs name the job, not a generic shape: Pulse = live overview, Crosshair = attack targeting (the same
    glyph marks attacker nodes in the graph), shields for the protect group, server racks for the fleet.
  - Sizes: 12 carets, 14 inline/sm buttons, 16 buttons & menus, 18 navigation and top bar.
  - Weight: regular at rest, duotone + accent when active, fill only for status icons. Color carries state, never decoration.
*/
type NavItem = { href: string; label: string; Icon: PhIcon; admin?: boolean };
const NAV: { group: string; items: NavItem[] }[] = [
  { group: "Monitor", items: [
    { href: "/", label: "Overview", Icon: Pulse },
    { href: "/attacks", label: "Attack Map", Icon: Crosshair },
    { href: "/logs", label: "Log Explorer", Icon: ListMagnifyingGlass },
  ] },
  { group: "Protect", items: [
    { href: "/policies", label: "Policies & CRS", Icon: ShieldCheck },
    { href: "/rules", label: "Custom Rules", Icon: FileCode },
    { href: "/threat-intel", label: "IP Reputation", Icon: ShieldWarning },
  ] },
  { group: "Operate", items: [
    { href: "/fleet", label: "Fleet", Icon: HardDrives },
    { href: "/audit", label: "Audit Trail", Icon: ClockCounterClockwise },
    { href: "/admin", label: "Administration", Icon: GearSix, admin: true },
  ] },
];
const SUB: Record<string, string> = { new: "New rule", report: "Incident report" };

const isActive = (href: string, path: string) => (href === "/" ? path === "/" : path.startsWith(href));

/** Real-state counters for the sidebar: critical active campaigns (live) and fleet health. */
function useShellStatus() {
  const path = usePathname();
  const [cmps, setCmps] = React.useState<Campaign[] | null>(null);
  const [nodes, setNodes] = React.useState<EdgeNode[] | null>(null);
  React.useEffect(() => { attacks.campaigns().then(setCmps, () => setCmps(null)); }, []);
  React.useEffect(() => { fleet.list().then(setNodes, () => setNodes(null)); }, [path]);
  React.useEffect(() => subscribeAttackStream((m) => setCmps((l) => {
    if (!l) return l;
    const i = l.findIndex((c) => c.id === m.campaign.id);
    return i < 0 ? [m.campaign, ...l] : l.map((c, k) => (k === i ? m.campaign : c));
  })), []);
  const critical = cmps?.filter((c) => c.status === "ACTIVE" && c.risk_score >= 75).length ?? 0;
  const online = nodes?.filter((n) => n.status !== "OFFLINE").length ?? 0;
  const degraded = nodes?.some((n) => n.status === "WARN") ?? false;
  const pending = nodes?.filter((n) => n.status !== "OFFLINE" && n.sync_status === "PENDING_UPDATE").length ?? 0;
  return { critical, nodes, online, degraded, pending };
}

function NavLinks({ onNavigate, status }: { onNavigate?: () => void; status: ReturnType<typeof useShellStatus> }) {
  const path = usePathname();
  const { can } = useSession();
  const badge = (href: string) => {
    if (href === "/attacks" && status.critical) return <span className="tnum rounded bg-crit/15 px-1.5 text-[11px] font-semibold leading-5 text-crit" title={`${status.critical} active campaigns at risk 75 or higher`}>{status.critical}</span>;
    if (href === "/fleet" && status.pending) return <span className="tnum rounded bg-warn/15 px-1.5 text-[11px] font-semibold leading-5 text-warn" title={`${status.pending} nodes waiting for a config push`}>{status.pending}</span>;
    return null;
  };
  return (
    <nav aria-label="Main" className="flex flex-col gap-6 px-3 py-5">
      {NAV.map((g) => (
        <div key={g.group} role="group" aria-labelledby={`nav-${g.group}`}>
          <p id={`nav-${g.group}`} className="mb-1.5 px-2.5 text-[11px] font-medium text-muted">{g.group}</p>
          <ul className="flex flex-col gap-0.5">
            {g.items.filter((i) => !i.admin || can("admin")).map(({ href, label, Icon }) => {
              const active = isActive(href, path);
              const b = badge(href);
              return (
                <li key={href}>
                  <Link
                    href={href}
                    onClick={onNavigate}
                    aria-current={active ? "page" : undefined}
                    className={cn(
                      "group relative flex h-9 items-center gap-2.5 rounded-md px-2.5 text-[13px] text-fg-2 transition-colors duration-150 hover:bg-surface-2/80 hover:text-fg",
                      active && "bg-accent/[0.09] font-medium text-fg hover:bg-accent/[0.13]",
                    )}
                  >
                    {/* the rail marks the current page, the one state the nav must show */}
                    <span aria-hidden className={cn("absolute -left-3 top-2 bottom-2 w-[3px] rounded-r-full bg-accent transition-opacity duration-150", active ? "opacity-100" : "opacity-0")} />
                    <Icon size={18} weight={active ? "duotone" : "regular"} aria-hidden className={cn("shrink-0 transition-colors duration-150", active ? "text-accent" : "text-muted group-hover:text-fg-2")} />
                    <span className="min-w-0 flex-1 truncate">{label}</span>
                    {b}
                  </Link>
                </li>
              );
            })}
          </ul>
        </div>
      ))}
    </nav>
  );
}


function SidebarBody({ onNavigate, status }: { onNavigate?: () => void; status: ReturnType<typeof useShellStatus> }) {
  const tone = !status.nodes ? "bg-muted" : status.online < status.nodes.length ? "bg-crit" : status.degraded ? "bg-warn" : "bg-good";
  return (
    <>
      <div className="min-h-0 flex-1 overflow-y-auto"><NavLinks onNavigate={onNavigate} status={status} /></div>
      <div className="border-t border-border p-3">
        <Link href="/fleet" onClick={onNavigate} className="group flex items-center gap-2.5 rounded-md px-2.5 py-2 transition-colors duration-150 hover:bg-surface-2/80">
          <span className={cn("h-2 w-2 shrink-0 rounded-full", tone)} aria-hidden />
          <span className="min-w-0 flex-1 leading-tight">
            <span className="block text-[12px] font-medium text-fg">{status.nodes ? `${status.online} of ${status.nodes.length} nodes online` : "Checking fleet"}</span>
            <span className="block text-[11px] text-muted">Coraza v3 · OWASP CRS v4</span>
          </span>
          <CaretRight size={12} aria-hidden className="text-muted transition-transform duration-150 group-hover:translate-x-0.5" />
        </Link>
      </div>
    </>
  );
}

type Note = { id: string; campaign: string; stage: StageKey; at: number; actor: string };

function useEscalations() {
  const toast = useToast();
  const [notes, setNotes] = React.useState<Note[]>([]);
  const [unread, setUnread] = React.useState(0);
  React.useEffect(() => subscribeAttackStream((m) => {
    if (!m.escalatedTo) return;
    const n: Note = { id: `${m.campaign.id}-${m.escalatedTo}`, campaign: m.campaign.id, stage: m.escalatedTo, at: Date.now(), actor: m.campaign.actor_key };
    setNotes((x) => [n, ...x].slice(0, 20));
    setUnread((u) => u + 1);
    toast({ tone: "info", title: `Escalation: ${stageMeta(m.escalatedTo).name}`, body: `${m.campaign.actor_key} in ${m.campaign.id}, risk ${m.campaign.risk_score}`, action: { label: "Open campaign", href: `/attacks?campaign=${m.campaign.id}` } });
  }), [toast]);
  return { notes, unread, clear: () => setUnread(0) };
}

function Breadcrumb() {
  const path = usePathname();
  const group = NAV.find((g) => g.items.some((i) => isActive(i.href, path)));
  const item = group?.items.find((i) => isActive(i.href, path));
  if (!group || !item) return null;
  const rest = item.href === "/" ? "" : path.slice(item.href.length).split("/").filter(Boolean)[0];
  const sub = rest ? SUB[rest] ?? (item.href === "/rules" ? "Rule editor" : null) : null;
  return (
    <nav aria-label="Breadcrumb" className="hidden min-w-0 items-center gap-1.5 text-[13px] lg:flex">
      <span className="text-muted">{group.group}</span>
      <CaretRight size={12} aria-hidden className="text-border-strong" />
      {sub ? (
        <>
          <Link href={item.href} className="truncate text-fg-2 transition-colors hover:text-fg">{item.label}</Link>
          <CaretRight size={12} aria-hidden className="text-border-strong" />
          <span aria-current="page" className="truncate font-medium text-fg">{sub}</span>
        </>
      ) : (
        <span aria-current="page" className="truncate font-medium text-fg">{item.label}</span>
      )}
    </nav>
  );
}

const Divider = () => <span aria-hidden className="mx-1 hidden h-5 w-px bg-border sm:block" />;

function TopBar({ onMenu }: { onMenu: () => void }) {
  const { theme, setTheme } = useTheme();
  const s = useSession();
  const { notes, unread, clear } = useEscalations();
  const [failing, setFailing] = React.useState(false);
  React.useEffect(() => setFailing(mockFailing()), []);
  return (
    <header className="no-print sticky top-0 z-30 flex h-14 items-center gap-1.5 border-b border-border bg-bg/85 px-4 backdrop-blur-md sm:px-6">
      <Button variant="ghost" size="icon" className="-ml-2 lg:hidden" aria-label="Open navigation" onClick={onMenu}><List size={18} aria-hidden /></Button>
      <Link href="/" className="lg:hidden" aria-label="Corazium home"><Logo size={26} /></Link>
      <Breadcrumb />
      <div className="flex-1" />
      {usingMock ? (
        <span className="mr-1 hidden h-7 items-center gap-1.5 rounded-md border border-border bg-surface/60 px-2 text-[11px] font-medium text-fg-2 sm:inline-flex" title="NEXT_PUBLIC_API_URL is not set, so data comes from the in-browser mock API.">
          <Database size={14} aria-hidden className="text-muted" />Mock API · sample data
        </span>
      ) : null}
      <Divider />
      <Menu onOpenChange={(o) => o && clear()}>
        <MenuTrigger asChild>
          <Button variant="ghost" size="icon" aria-label={`Escalation alerts${unread ? `, ${unread} new` : ""}`} className="relative">
            <Bell size={18} weight={unread ? "duotone" : "regular"} aria-hidden className={unread ? "text-fg" : undefined} />
            {unread ? <span className="tnum absolute right-0.5 top-0.5 min-w-[18px] rounded-full bg-crit px-1 text-center text-[10px] font-semibold leading-[18px] text-white ring-2 ring-bg">{unread > 9 ? "9+" : unread}</span> : null}
          </Button>
        </MenuTrigger>
        <MenuContent className="w-[min(340px,calc(100vw-24px))]">
          <MenuLabel>Kill chain escalations</MenuLabel>
          {notes.length === 0 ? (
            <p className="px-2 pb-3 pt-1 text-[12px] text-fg-2">None since you opened the console. Escalations appear here when a campaign reaches a higher stage.</p>
          ) : notes.map((n) => (
            <MenuItem key={n.id} asChild className="h-auto py-2">
              <Link href={`/attacks?campaign=${n.campaign}`} className="flex flex-col items-start gap-0.5">
                <StageTag stage={n.stage} />
                <span className="font-mono text-[11px] text-fg-2">{n.actor} · {n.campaign}</span>
                <span className="text-[11px] text-muted">{relTime(n.at)}</span>
              </Link>
            </MenuItem>
          ))}
        </MenuContent>
      </Menu>
      <Button variant="ghost" size="icon" aria-label="Toggle light or dark theme" onClick={() => setTheme(theme === "dark" ? "light" : "dark")}>
        <Sun size={18} aria-hidden className="hidden dark:block" />
        <Moon size={18} aria-hidden className="dark:hidden" />
      </Button>
      <Divider />
      <Menu>
        <MenuTrigger asChild>
          <button className="flex h-9 items-center gap-2.5 rounded-md py-1 pl-1 pr-1.5 transition-colors duration-150 hover:bg-surface-2/80 data-[state=open]:bg-surface-2" aria-label={`Account: ${s.name}, ${s.role}`}>
            <span className="flex h-7 w-7 items-center justify-center rounded-md bg-accent/15 text-[12px] font-semibold text-accent ring-1 ring-inset ring-accent/25" aria-hidden>{s.name[0]}</span>
            <span className="hidden text-left leading-tight md:block">
              <span className="block text-[12px] font-medium">{s.name}</span>
              <span className="block text-[11px] text-muted">{s.role}</span>
            </span>
            <CaretUpDown size={12} className="hidden text-muted md:block" aria-hidden />
          </button>
        </MenuTrigger>
        <MenuContent className="w-64">
          <div className="px-2 py-2">
            <p className="text-[13px] font-medium">{s.name}</p>
            <p className="text-[12px] text-muted">{s.email}</p>
          </div>
          <MenuSeparator />
          <MenuLabel>Review as role (mock session)</MenuLabel>
          <MenuRadioGroup value={s.role} onValueChange={(v) => s.setRole(v as Role)}>
            {(["Admin", "SecOps Analyst", "Auditor"] as Role[]).map((r) => <MenuRadioItem key={r} value={r}>{r}</MenuRadioItem>)}
          </MenuRadioGroup>
          {usingMock ? (
            <>
              <MenuSeparator />
              <div className="flex items-center justify-between gap-3 px-2 py-1.5">
                <label htmlFor="mock-fail" className="text-[12px] text-fg-2">Simulate API outage</label>
                <Switch id="mock-fail" label="Simulate API outage" checked={failing} onCheckedChange={(v) => { setMockFailing(v); setFailing(v); location.reload(); }} />
              </div>
            </>
          ) : null}
          <MenuSeparator />
          <MenuItem asChild><Link href="/login"><SignOut size={16} aria-hidden />Sign out</Link></MenuItem>
        </MenuContent>
      </Menu>
    </header>
  );
}

export function Shell({ children }: { children: React.ReactNode }) {
  const [open, setOpen] = React.useState(false);
  const status = useShellStatus();
  return (
    <div className="min-h-dvh">
      <aside className="no-print fixed inset-y-0 left-0 z-30 hidden w-60 flex-col border-r border-border bg-chrome lg:flex">
        <Link href="/" aria-label="Corazium home" className="flex h-14 shrink-0 items-center px-4 transition-opacity hover:opacity-80"><Logo size={30} sub="WAF Control Plane" /></Link>
        <SidebarBody status={status} />
      </aside>
      <RDialog.Root open={open} onOpenChange={setOpen}>
        <RDialog.Portal>
          <RDialog.Overlay className="fixed inset-0 z-40 bg-black/55 data-[state=open]:animate-in data-[state=open]:fade-in-0 lg:hidden" />
          <RDialog.Content className="fixed inset-y-0 left-0 z-50 flex w-72 max-w-[85vw] flex-col border-r border-border bg-chrome shadow-pop data-[state=open]:animate-in data-[state=open]:slide-in-from-left-8 lg:hidden">
            <div className="flex h-14 shrink-0 items-center justify-between px-4">
              <RDialog.Title asChild><span><Logo size={28} sub="WAF Control Plane" /></span></RDialog.Title>
              <RDialog.Description className="sr-only">Main navigation</RDialog.Description>
              <RDialog.Close asChild><Button variant="ghost" size="icon" aria-label="Close navigation"><X size={18} aria-hidden /></Button></RDialog.Close>
            </div>
            <SidebarBody status={status} onNavigate={() => setOpen(false)} />
          </RDialog.Content>
        </RDialog.Portal>
      </RDialog.Root>
      <div className="lg:pl-60 print:pl-0">
        <TopBar onMenu={() => setOpen(true)} />
        <main id="main" className="mx-auto w-full max-w-[1600px] px-4 py-6 sm:px-6 sm:py-7">{children}</main>
      </div>
    </div>
  );
}
