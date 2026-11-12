// Sigma-free module so pages can import pictograms and graph types without pulling WebGL code into SSR.
import type { GNodeType } from "@/lib/attack-graph";

const svg = (body: string) => `data:image/svg+xml;utf8,${encodeURIComponent(`<svg xmlns="http://www.w3.org/2000/svg" width="96" height="96" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${body}</svg>`)}`;
// Pictograms by node type (FR-6.5 "ikon berdasarkan tipe"). Drawn as masks, tinted for contrast against the node color.
export const PICTO: Record<GNodeType, string> = {
  attacker: svg('<circle cx="12" cy="12" r="7"/><path d="M12 2v5M12 17v5M2 12h5M17 12h5"/>'),
  cluster: svg('<circle cx="7" cy="8" r="3"/><circle cx="17" cy="8" r="3"/><circle cx="12" cy="17" r="3"/>'),
  site: svg('<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3.5 3 14.5 0 18M12 3c-3 3.5-3 14.5 0 18"/>'),
  endpoint: svg('<path d="M15 4 9 20"/><path d="M5 8 2 12l3 4M19 8l3 4-3 4"/>'),
  category: svg('<path d="M12 3 4 6v6c0 5 3.5 8 8 9 4.5-1 8-4 8-9V6z"/>'),
  edgenode: svg('<rect x="4" y="4" width="16" height="6" rx="1"/><rect x="4" y="14" width="16" height="6" rx="1"/><path d="M8 7h.01M8 17h.01"/>'),
};

export type GraphColors = Record<"--stage-0" | "--stage-1" | "--stage-2" | "--stage-3" | "--stage-4" | "--stage-5" | "--stage-6" | "--fg" | "--fg-2" | "--muted" | "--surface" | "--surface-3" | "--border-strong" | "--accent" | "--c-crit", string>;
export interface GraphApi { zoomIn(): void; zoomOut(): void; reset(): void; focus(id: string): void; png(name: string): Promise<void>; svg(name: string): void }

