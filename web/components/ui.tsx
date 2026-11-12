"use client";
// Shared primitives. Radix supplies behavior (focus traps, keyboard, ARIA); styling is local tokens.
// Radius: 4px controls, 6px panels. No pills except status dots that mark real state.
import * as React from "react";
import * as RDialog from "@radix-ui/react-dialog";
import * as RTabs from "@radix-ui/react-tabs";
import * as RSwitch from "@radix-ui/react-switch";
import * as RMenu from "@radix-ui/react-dropdown-menu";
import { X, WarningOctagon, ArrowClockwise, CircleNotch } from "@phosphor-icons/react";
import { cn } from "@/lib/utils";

type BtnProps = React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "secondary" | "ghost" | "danger"; size?: "sm" | "md" | "icon" };
export const Button = React.forwardRef<HTMLButtonElement, BtnProps>(({ className, variant = "secondary", size = "md", ...p }, ref) => (
  <button
    ref={ref}
    className={cn(
      // One button family: 6px radius, steps on hover, presses 1px on click (disabled buttons stay put).
      "inline-flex shrink-0 select-none items-center justify-center gap-1.5 whitespace-nowrap rounded-md font-medium transition-[background-color,border-color,color,box-shadow,transform] duration-150 enabled:active:translate-y-px disabled:opacity-45",
      size === "sm" && "h-8 px-2.5 text-[12px]",
      size === "md" && "h-9 px-3.5 text-[13px]",
      size === "icon" && "h-9 w-9",
      variant === "primary" && "bg-accent text-accent-fg shadow-[inset_0_1px_0_rgb(255_255_255/0.18),0_1px_2px_rgb(0_0_0/0.15)] enabled:hover:bg-accent/90 enabled:active:bg-accent/85",
      variant === "secondary" && "border border-border-strong bg-surface text-fg shadow-[0_1px_1px_rgb(0_0_0/0.04)] enabled:hover:border-muted/60 enabled:hover:bg-surface-2 enabled:active:bg-surface-3",
      variant === "ghost" && "text-fg-2 enabled:hover:bg-surface-2 enabled:hover:text-fg enabled:active:bg-surface-3",
      variant === "danger" && "bg-crit text-white shadow-[inset_0_1px_0_rgb(255_255_255/0.15)] enabled:hover:bg-crit/90 enabled:active:bg-crit/85 dark:text-bg",
      className,
    )}
    {...p}
  />
));
Button.displayName = "Button";

export const Input = React.forwardRef<HTMLInputElement, React.InputHTMLAttributes<HTMLInputElement>>(({ className, ...p }, ref) => (
  <input
    ref={ref}
    className={cn(
      "h-9 w-full min-w-0 rounded-md border border-border-strong bg-input px-2.5 text-[13px] text-fg shadow-[inset_0_1px_1px_rgb(0_0_0/0.04)] transition-[border-color,box-shadow] duration-150 placeholder:text-muted/80 hover:border-muted/70 focus-visible:border-accent focus-visible:outline-none focus-visible:ring-[3px] focus-visible:ring-accent/25 disabled:opacity-60",
      className,
    )}
    {...p}
  />
));
Input.displayName = "Input";

export const Textarea = React.forwardRef<HTMLTextAreaElement, React.TextareaHTMLAttributes<HTMLTextAreaElement>>(({ className, ...p }, ref) => (
  <textarea
    ref={ref}
    className={cn("w-full rounded-md border border-border-strong bg-input px-2.5 py-2 text-[13px] text-fg shadow-[inset_0_1px_1px_rgb(0_0_0/0.04)] transition-[border-color,box-shadow] duration-150 placeholder:text-muted/80 hover:border-muted/70 focus-visible:border-accent focus-visible:outline-none focus-visible:ring-[3px] focus-visible:ring-accent/25", className)}
    {...p}
  />
));
Textarea.displayName = "Textarea";

/** Native select: keyboard, mobile pickers and screen readers for free. */
export const Select = React.forwardRef<HTMLSelectElement, React.SelectHTMLAttributes<HTMLSelectElement>>(({ className, ...p }, ref) => (
  <select
    ref={ref}
    className={cn("h-9 min-w-0 rounded-md border border-border-strong bg-input pl-2.5 pr-7 text-[13px] text-fg transition-[border-color,box-shadow] duration-150 hover:border-muted/70 focus-visible:border-accent focus-visible:outline-none focus-visible:ring-[3px] focus-visible:ring-accent/25 disabled:opacity-60", className)}
    {...p}
  />
));
Select.displayName = "Select";

export function Field({ label, hint, error, children, htmlFor, className }: { label: string; hint?: React.ReactNode; error?: string | null; children: React.ReactNode; htmlFor: string; className?: string }) {
  return (
    <div className={cn("flex min-w-0 flex-col gap-1.5", className)}>
      <label htmlFor={htmlFor} className="text-[12px] font-medium text-fg-2">{label}</label>
      {children}
      {error ? <p className="text-[12px] text-crit" role="alert">{error}</p> : hint ? <p className="text-[12px] text-muted">{hint}</p> : null}
    </div>
  );
}

export function Switch({ checked, onCheckedChange, disabled, label, id }: { checked: boolean; onCheckedChange: (v: boolean) => void; disabled?: boolean; label: string; id?: string }) {
  return (
    <RSwitch.Root
      id={id}
      checked={checked}
      onCheckedChange={onCheckedChange}
      disabled={disabled}
      aria-label={label}
      className="relative inline-flex h-5 w-9 shrink-0 items-center rounded-full border border-border-strong bg-surface-3 shadow-[inset_0_1px_2px_rgb(0_0_0/0.12)] transition-colors duration-150 hover:border-muted/70 data-[state=checked]:border-accent data-[state=checked]:bg-accent disabled:opacity-50"
    >
      <RSwitch.Thumb className="block h-3.5 w-3.5 translate-x-0.5 rounded-full bg-fg-2 shadow-sm transition-transform duration-150 data-[state=checked]:translate-x-[18px] data-[state=checked]:bg-accent-fg" />
    </RSwitch.Root>
  );
}

export const Tabs = RTabs.Root;
export function TabsList({ className, ...p }: RTabs.TabsListProps) {
  return <RTabs.List className={cn("flex min-w-0 gap-1 overflow-x-auto overflow-y-hidden border-b border-border", className)} {...p} />;
}
export function TabsTrigger({ className, ...p }: RTabs.TabsTriggerProps) {
  return (
    <RTabs.Trigger
      className={cn(
        "-mb-px flex h-10 shrink-0 items-center gap-1.5 border-b-2 border-transparent px-3 text-[13px] font-medium text-muted transition-colors duration-150 hover:border-border-strong hover:text-fg-2 data-[state=active]:border-accent data-[state=active]:text-fg",
        className,
      )}
      {...p}
    />
  );
}
export const TabsContent = RTabs.Content;

export function Dialog({ open, onOpenChange, title, description, children, footer, wide }: { open: boolean; onOpenChange: (v: boolean) => void; title: string; description?: React.ReactNode; children?: React.ReactNode; footer?: React.ReactNode; wide?: boolean }) {
  return (
    <RDialog.Root open={open} onOpenChange={onOpenChange}>
      <RDialog.Portal>
        <RDialog.Overlay className="fixed inset-0 z-50 bg-black/55 data-[state=open]:animate-in data-[state=open]:fade-in-0" />
        <RDialog.Content
          className={cn(
            "fixed left-1/2 top-1/2 z-50 flex max-h-[calc(100dvh-32px)] w-[calc(100vw-32px)] -translate-x-1/2 -translate-y-1/2 flex-col rounded-lg border border-border-strong bg-surface shadow-pop data-[state=open]:animate-in data-[state=open]:fade-in-0 data-[state=open]:zoom-in-[0.98]",
            wide ? "max-w-3xl" : "max-w-lg",
          )}
        >
          <div className="flex items-start justify-between gap-4 border-b border-border px-5 py-4">
            <div className="min-w-0">
              <RDialog.Title className="text-[15px] font-semibold">{title}</RDialog.Title>
              {description ? <RDialog.Description className="mt-1 text-[13px] text-fg-2">{description}</RDialog.Description> : <RDialog.Description className="sr-only">{title}</RDialog.Description>}
            </div>
            <RDialog.Close asChild>
              <Button variant="ghost" size="icon" aria-label="Close" className="-mr-2 -mt-1"><X size={16} aria-hidden /></Button>
            </RDialog.Close>
          </div>
          <div className="min-h-0 overflow-y-auto px-5 py-4">{children}</div>
          {footer ? <div className="flex flex-wrap justify-end gap-2 rounded-b-lg border-t border-border bg-surface-2/40 px-5 py-3">{footer}</div> : null}
        </RDialog.Content>
      </RDialog.Portal>
    </RDialog.Root>
  );
}

/** Right-side drawer for inspectors (log detail, node detail). Full width on phones. */
export function Sheet({ open, onOpenChange, title, subtitle, children, footer }: { open: boolean; onOpenChange: (v: boolean) => void; title: React.ReactNode; subtitle?: React.ReactNode; children: React.ReactNode; footer?: React.ReactNode }) {
  return (
    <RDialog.Root open={open} onOpenChange={onOpenChange}>
      <RDialog.Portal>
        <RDialog.Overlay className="fixed inset-0 z-40 bg-black/40" />
        <RDialog.Content className="fixed inset-y-0 right-0 z-40 flex w-full max-w-[640px] flex-col border-l border-border-strong bg-surface shadow-pop data-[state=open]:animate-in data-[state=open]:slide-in-from-right-8">
          <div className="flex items-start justify-between gap-4 border-b border-border px-5 py-4">
            <div className="min-w-0">
              <RDialog.Title className="truncate text-[15px] font-semibold">{title}</RDialog.Title>
              <RDialog.Description className={subtitle ? "mt-0.5 text-[12px] text-muted" : "sr-only"}>{subtitle ?? "Details"}</RDialog.Description>
            </div>
            <RDialog.Close asChild>
              <Button variant="ghost" size="icon" aria-label="Close panel" className="-mr-2"><X size={16} aria-hidden /></Button>
            </RDialog.Close>
          </div>
          <div className="min-h-0 flex-1 overflow-y-auto">{children}</div>
          {footer ? <div className="flex flex-wrap gap-2 border-t border-border bg-surface-2/40 px-5 py-3">{footer}</div> : null}
        </RDialog.Content>
      </RDialog.Portal>
    </RDialog.Root>
  );
}

export const Menu = RMenu.Root;
export const MenuTrigger = RMenu.Trigger;
export function MenuContent({ className, ...p }: RMenu.DropdownMenuContentProps) {
  return (
    <RMenu.Portal>
      <RMenu.Content sideOffset={8} align="end" className={cn("z-50 min-w-[200px] rounded-lg border border-border-strong bg-surface p-1 shadow-pop data-[state=open]:animate-in data-[state=open]:fade-in-0 data-[state=open]:zoom-in-[0.98]", className)} {...p} />
    </RMenu.Portal>
  );
}
export function MenuItem({ className, ...p }: RMenu.DropdownMenuItemProps) {
  return <RMenu.Item className={cn("flex h-8 cursor-pointer select-none items-center gap-2 rounded-md px-2 text-[13px] text-fg outline-none transition-colors duration-100 data-[disabled]:cursor-not-allowed data-[highlighted]:bg-surface-2 data-[disabled]:opacity-50 [&>svg]:text-muted", className)} {...p} />;
}
export const MenuLabel = ({ className, ...p }: RMenu.DropdownMenuLabelProps) => <RMenu.Label className={cn("px-2 py-1.5 text-[11px] font-medium text-muted", className)} {...p} />;
export const MenuSeparator = () => <RMenu.Separator className="my-1 h-px bg-border" />;
export const MenuRadioGroup = RMenu.RadioGroup;
export function MenuRadioItem({ className, children, ...p }: RMenu.DropdownMenuRadioItemProps) {
  return (
    <RMenu.RadioItem className={cn("flex h-8 cursor-pointer select-none items-center gap-2 rounded-md px-2 text-[13px] outline-none transition-colors duration-100 data-[highlighted]:bg-surface-2", className)} {...p}>
      <span className="flex h-3.5 w-3.5 items-center justify-center rounded-full border border-border-strong"><RMenu.ItemIndicator className="h-1.5 w-1.5 rounded-full bg-accent" /></span>
      {children}
    </RMenu.RadioItem>
  );
}

// ---------- States (R-27): each names the cause and the next action ----------

export function Loading({ label, className }: { label: string; className?: string }) {
  return (
    <div role="status" className={cn("flex items-center justify-center gap-2 py-12 text-[13px] text-muted", className)}>
      <CircleNotch size={16} className="animate-spin" aria-hidden />
      {label}
    </div>
  );
}

export function ErrorState({ title, error, onRetry, className }: { title: string; error: unknown; onRetry?: () => void; className?: string }) {
  return (
    <div role="alert" className={cn("flex flex-col items-center justify-center gap-2 px-4 py-12 text-center", className)}>
      <WarningOctagon size={22} className="text-crit" aria-hidden />
      <p className="text-[14px] font-medium">{title}</p>
      <p className="max-w-md text-[13px] text-fg-2">{error instanceof Error ? error.message : String(error)}</p>
      {onRetry ? <Button size="sm" onClick={onRetry} className="mt-1"><ArrowClockwise size={14} aria-hidden />Retry</Button> : null}
    </div>
  );
}

export function Empty({ title, body, action, className }: { title: string; body?: React.ReactNode; action?: React.ReactNode; className?: string }) {
  return (
    <div className={cn("flex flex-col items-center justify-center gap-1.5 px-4 py-12 text-center", className)}>
      <p className="text-[14px] font-medium">{title}</p>
      {body ? <p className="max-w-md text-[13px] text-fg-2">{body}</p> : null}
      {action ? <div className="mt-2">{action}</div> : null}
    </div>
  );
}

export function PageHeader({ title, description, actions }: { title: string; description?: React.ReactNode; actions?: React.ReactNode }) {
  return (
    <header className="flex flex-col gap-3 pb-6 sm:flex-row sm:items-end sm:justify-between">
      <div className="min-w-0">
        <h1 className="text-[22px] font-semibold leading-7 tracking-[-0.012em]">{title}</h1>
        {description ? <p className="mt-1.5 max-w-2xl text-[13px] leading-5 text-fg-2">{description}</p> : null}
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </header>
  );
}

export function SectionTitle({ children, aside, id }: { children: React.ReactNode; aside?: React.ReactNode; id?: string }) {
  return (
    <div className="flex min-h-[48px] items-center justify-between gap-3 px-4 pb-2 pt-3">
      <h2 id={id} className="text-[13px] font-semibold">{children}</h2>
      {aside}
    </div>
  );
}

export function Kbd({ children }: { children: React.ReactNode }) {
  return <kbd className="rounded border border-border-strong bg-surface-2 px-1.5 font-mono text-[11px] text-fg-2">{children}</kbd>;
}

/** Scroll container for wide tables so the page never scrolls horizontally on phones. */
export function TableWrap({ children, className, label }: { children: React.ReactNode; className?: string; label: string }) {
  return <div className={cn("relative overflow-x-auto", className)} role="region" aria-label={label} tabIndex={0}>{children}</div>;
}
