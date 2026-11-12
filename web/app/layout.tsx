import type { Metadata, Viewport } from "next";
import { IBM_Plex_Sans, IBM_Plex_Mono, Montserrat } from "next/font/google";
import { Providers } from "@/components/providers";
import "./globals.css";

// IBM Plex: drawn for technical/enterprise interfaces, with a true mono sibling for IPs, rule IDs and SecLang.
const sans = IBM_Plex_Sans({ subsets: ["latin"], weight: ["400", "500", "600"], variable: "--font-sans", display: "swap" });
const mono = IBM_Plex_Mono({ subsets: ["latin"], weight: ["400", "500"], variable: "--font-mono", display: "swap" });
// Montserrat Bold only for the CORAZIUM wordmark: the closest open match to the geometric caps in the logo.
const brand = Montserrat({ subsets: ["latin"], weight: ["700"], variable: "--font-brand", display: "swap" });

export const metadata: Metadata = {
  title: { default: "Corazium", template: "%s · Corazium" },
  description: "Corazium: control plane and observability hub for OWASP Coraza WAF fleets.",
};
export const viewport: Viewport = { width: "device-width", initialScale: 1 };

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning className={`${sans.variable} ${mono.variable} ${brand.variable}`}>
      <body className="font-sans text-[14px]">
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
