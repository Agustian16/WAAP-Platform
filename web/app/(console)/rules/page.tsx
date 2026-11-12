"use client";
import * as React from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Plus, Trash } from "@phosphor-icons/react";
import { policies, rules } from "@/lib/api";
import { useAsync } from "@/lib/hooks";
import { Button, Dialog, Empty, ErrorState, Loading, PageHeader, Switch, TableWrap } from "@/components/ui";
import { Mono } from "@/components/atoms";
import { useSession, useToast } from "@/components/providers";
import type { CustomRule } from "@/lib/types";
import { fmtTime, relTime } from "@/lib/utils";

export default function RulesPage() {
  const s = useSession();
  const toast = useToast();
  const router = useRouter();
  const list = useAsync(() => rules.list(), []);
  const sites = useAsync(() => policies.sites(), []);
  const [del, setDel] = React.useState<CustomRule | null>(null);
  const siteName = (id: string | null) => (id ? sites.data?.find((x) => x.id === id)?.domain_name ?? "..." : "All sites");

  const toggle = async (r: CustomRule, v: boolean) => {
    try { const n = await rules.setActive(r.id, v); list.setData((l) => l?.map((x) => (x.id === n.id ? n : x))); toast({ tone: "ok", title: `Rule ${r.rule_id} ${v ? "enabled" : "disabled"}`, body: "Deploy from Policies & CRS to push it." }); }
    catch (e) { toast({ tone: "error", title: "Update failed", body: (e as Error).message }); }
  };

  return (
    <>
      <PageHeader title="Custom Rules" description="SecLang rules you own, on top of the OWASP CRS. Analysts save drafts; Admins activate them."
        actions={s.can("writeRule") ? <Button variant="primary" onClick={() => router.push("/rules/new")}><Plus size={16} aria-hidden />New rule</Button> : undefined} />
      <div className="panel">
        {list.error && !list.data ? <ErrorState title="Rules could not be loaded" error={list.error} onRetry={list.reload} /> : !list.data ? <Loading label="Loading rules" /> : list.data.length === 0 ? (
          <Empty title="No custom rules yet" body="The CRS covers common attacks. Write a custom rule when you need an app-specific check." action={s.can("writeRule") ? <Button variant="primary" onClick={() => router.push("/rules/new")}>Write the first rule</Button> : undefined} />
        ) : (
          <TableWrap label="Custom rules">
            <table className="data-table">
              <thead><tr><th>Rule ID</th><th>Name</th><th>Scope</th><th>State</th><th>Last change</th>{s.can("editPolicy") ? <th><span className="sr-only">Actions</span></th> : null}</tr></thead>
              <tbody>
                {list.data.map((r) => (
                  <tr key={r.id} data-clickable onClick={() => router.push(`/rules/${r.id}`)}>
                    <td><Mono>{r.rule_id}</Mono></td>
                    <td><Link href={`/rules/${r.id}`} onClick={(e) => e.stopPropagation()} className="font-medium hover:text-accent hover:underline">{r.name}</Link></td>
                    <td className="text-[12px] text-fg-2">{siteName(r.site_id)}</td>
                    <td onClick={(e) => e.stopPropagation()}>
                      {s.can("editPolicy") ? (
                        <label className="inline-flex items-center gap-2 text-[12px]" htmlFor={`act-${r.id}`}><Switch id={`act-${r.id}`} label={`Rule ${r.rule_id} active`} checked={r.is_active} onCheckedChange={(v) => toggle(r, v)} />{r.is_active ? "Active" : "Draft"}</label>
                      ) : <span className={r.is_active ? "text-[12px]" : "text-[12px] text-muted"}>{r.is_active ? "Active" : "Draft"}</span>}
                    </td>
                    <td className="text-[12px] text-fg-2" title={fmtTime(r.updated_at)}>{r.created_by}, {relTime(r.updated_at)}</td>
                    {s.can("editPolicy") ? <td className="text-right" onClick={(e) => e.stopPropagation()}><Button size="icon" variant="ghost" aria-label={`Delete rule ${r.rule_id}`} onClick={() => setDel(r)}><Trash size={16} aria-hidden /></Button></td> : null}
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
        )}
      </div>
      <Dialog open={!!del} onOpenChange={(v) => !v && setDel(null)} title={`Delete rule ${del?.rule_id}?`} description="The rule is removed from the next deployed config. Its history stays in the audit trail."
        footer={<><Button onClick={() => setDel(null)}>Cancel</Button><Button variant="danger" onClick={async () => {
          try { await rules.remove(del!.id); list.reload(); toast({ tone: "ok", title: `Rule ${del!.rule_id} deleted` }); } catch (e) { toast({ tone: "error", title: "Delete failed", body: (e as Error).message }); }
          setDel(null);
        }}>Delete rule</Button></>} />
    </>
  );
}
