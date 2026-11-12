# Corazium Console (web)

Frontend for the Coraza WAF control plane described in `../Coraza_WAF_Management_Dashboard_PRD.md`.

```bash
npm install
npm run dev      # http://localhost:3000
npm test         # SecLang linter/sandbox/exception builder, kill chain mapping, risk score, CIDR parsing
npm run build
```

## Backend

`NEXT_PUBLIC_API_URL` points the console at the Go control plane. When it is unset, `lib/api.ts` answers every call from an in-browser mock (`lib/mock/data.ts`) with the same shapes, and the top bar shows "Mock API · sample data".

- REST paths are declared next to each call in `lib/api.ts` (`/api/v1/...`).
- Live attack events come from `WebSocket /ws/attacks` (mock: a timer that runs the same campaign correlation rules as FR-6.2).
- Mock attacker IPs use RFC 5737 documentation ranges and RFC 6996 private ASNs, plus the two examples from the PRD.

## Map

| Route | PRD |
| --- | --- |
| `/` | FR-4.1 overview, ranked by active campaign risk |
| `/attacks` | Module 6: attack graph, geo map, campaign list, kill chain x ATT&CK matrix, timeline, replay |
| `/attacks/report?campaign=` | FR-6.16 incident report (print to PDF) |
| `/logs` | Module 3: log explorer, transaction inspector, one-click exception |
| `/policies` | FR-2.1/2.2 CRS switches, paranoia level, thresholds, exceptions, deploy |
| `/rules`, `/rules/[id]` | FR-2.3/2.4 visual builder, Monaco SecLang editor with linter, test sandbox |
| `/threat-intel` | FR-4.2 block/allow lists, threat feeds |
| `/fleet` | Module 1 nodes, health, sync status, enrollment |
| `/audit` | FR-5.2 audit trail |
| `/admin` | FR-5.1 roles, FR-5.3 GitOps, kill chain mapping, correlation settings |
| `/login` | NFR-2.2 OIDC sign-in |

The role switcher in the user menu (mock session only) shows each role's UI; the same menu can simulate an API outage to review error states.
