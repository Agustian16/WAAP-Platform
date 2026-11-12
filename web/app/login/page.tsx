"use client";
// NFR-2.2: OIDC single sign-on with mandatory MFA. In mock mode the provider redirect is simulated.
import * as React from "react";
import { useRouter } from "next/navigation";
import { usingMock } from "@/lib/api";
import { Button } from "@/components/ui";
import { Logo } from "@/components/brand";

const PROVIDERS = ["Keycloak", "Okta", "Google Workspace"];

export default function LoginPage() {
  const router = useRouter();
  const [busy, setBusy] = React.useState<string | null>(null);
  const go = (p: string) => {
    setBusy(p);
    if (!usingMock) { location.href = `${process.env.NEXT_PUBLIC_API_URL}/auth/oidc/login?provider=${encodeURIComponent(p.toLowerCase())}`; return; }
    setTimeout(() => router.push("/"), 600);
  };
  return (
    <main className="flex min-h-dvh items-center justify-center px-4 py-10">
      <div className="w-full max-w-sm">
        <Logo size={44} sub="WAF Control Plane" className="[&_span.font-brand]:text-[20px]" />
        <h1 className="mt-8 text-[22px] font-semibold tracking-tight">Sign in to Corazium</h1>
        <p className="mt-1 text-[13px] text-fg-2">Sign in with your organization account. Multi-factor authentication is required.</p>
        <div className="mt-6 flex flex-col gap-2">
          {PROVIDERS.map((p) => (
            <Button key={p} className="h-11 justify-start px-4 text-[14px]" disabled={!!busy} onClick={() => go(p)}>
              {busy === p ? `Redirecting to ${p}...` : `Continue with ${p}`}
            </Button>
          ))}
        </div>
        <p className="mt-6 text-[12px] text-muted">
          {usingMock ? "Mock mode: no identity provider is configured, so sign-in goes straight to the console." : "You will return here after your identity provider verifies you."}
        </p>
      </div>
    </main>
  );
}
