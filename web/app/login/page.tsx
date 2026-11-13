"use client";
// NFR-2.2: OIDC single sign-on with mandatory MFA. In mock mode the provider redirect is simulated.
import * as React from "react";
import { useRouter } from "next/navigation";
import { auth, usingMock } from "@/lib/api";
import { Button } from "@/components/ui";
import { Logo } from "@/components/brand";

// Mock mode shows the providers the PRD names; with a backend, the list is whatever the control plane has configured.
const MOCK_PROVIDERS = ["Keycloak", "Okta", "Google Workspace"].map((name) => ({ id: name.toLowerCase(), name }));

export default function LoginPage() {
  const router = useRouter();
  const [busy, setBusy] = React.useState<string | null>(null);
  const [providers, setProviders] = React.useState<{ id: string; name: string }[] | null>(usingMock ? MOCK_PROVIDERS : null);
  const [error, setError] = React.useState<string | null>(null);
  React.useEffect(() => {
    if (!usingMock) auth.providers().then(setProviders, () => setError("The control plane is not reachable. Check that it is running, then reload."));
  }, []);
  const go = (p: { id: string; name: string }) => {
    setBusy(p.name);
    if (!usingMock) { location.href = auth.loginUrl(p.id); return; }
    setTimeout(() => router.push("/"), 600);
  };
  return (
    <main className="flex min-h-dvh items-center justify-center px-4 py-10">
      <div className="w-full max-w-sm">
        <Logo size={44} sub="WAF Control Plane" className="[&_span.font-brand]:text-[20px]" />
        <h1 className="mt-8 text-[22px] font-semibold tracking-tight">Sign in to Corazium</h1>
        <p className="mt-1 text-[13px] text-fg-2">Sign in with your organization account. Multi-factor authentication is required.</p>
        <div className="mt-6 flex flex-col gap-2">
          {error ? <p role="alert" className="text-[13px] text-crit">{error}</p> : null}
          {providers === null && !error ? <p role="status" className="text-[13px] text-muted">Loading sign-in options...</p> : null}
          {providers?.length === 0 ? <p role="alert" className="text-[13px] text-fg-2">No identity provider is configured on the control plane. Set OIDC_ISSUER, OIDC_CLIENT_ID and OIDC_CLIENT_SECRET, then restart it.</p> : null}
          {providers?.map((p) => (
            <Button key={p.id} className="h-11 justify-start px-4 text-[14px]" disabled={!!busy} onClick={() => go(p)}>
              {busy === p.name ? `Redirecting to ${p.name}...` : `Continue with ${p.name}`}
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
