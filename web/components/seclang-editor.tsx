"use client";
// Monaco (VS Code core) with SecLang highlighting, completion and live lint markers (FR-2.3 Code Mode).
// Monaco loads from the jsDelivr CDN; if that fails the editor degrades to a plain textarea with the same linter.
import * as React from "react";
import Editor, { loader, type OnMount } from "@monaco-editor/react";
import { useTheme } from "next-themes";
import { ACTIONS, DIRECTIVES, OPERATORS, TRANSFORMS, VARIABLES, type Diagnostic } from "@/lib/seclang";
import { Textarea, Loading } from "./ui";

let registered = false;
type Pos = { lineNumber: number; column: number };
type Monaco = Parameters<OnMount>[1];

function register(monaco: Monaco) {
  if (registered) return;
  registered = true;
  monaco.languages.register({ id: "seclang" });
  monaco.languages.setMonarchTokensProvider("seclang", {
    directives: DIRECTIVES, variables: VARIABLES, actions: ACTIONS,
    tokenizer: {
      root: [
        [/#.*$/, "comment"],
        [/@[a-zA-Z]+/, "keyword.operator"],
        [/\b(id|phase|status|severity|msg|logdata|tag|ver|rev|t|ctl|setvar|chain|skipAfter):/, "attribute.name"],
        [/\b(deny|block|pass|allow|drop|redirect|log|nolog|auditlog|noauditlog|capture)\b/, "keyword.action"],
        [/[A-Za-z_]+/, { cases: { "@directives": "keyword", "@variables": "variable", "@default": "identifier" } }],
        [/'[^']*'/, "string"],
        [/\d+/, "number"],
        [/\\$/, "delimiter"],
      ],
    },
  });
  const kinds = monaco.languages.CompletionItemKind;
  monaco.languages.registerCompletionItemProvider("seclang", {
    triggerCharacters: ["@", ":", ","],
    provideCompletionItems: (model: { getWordUntilPosition(p: Pos): { startColumn: number; endColumn: number }; getLineContent(n: number): string }, pos: Pos) => {
      const word = model.getWordUntilPosition(pos);
      const range = { startLineNumber: pos.lineNumber, endLineNumber: pos.lineNumber, startColumn: word.startColumn, endColumn: word.endColumn };
      const before = model.getLineContent(pos.lineNumber).slice(0, pos.column - 1);
      if (before.endsWith("@") || /@\w*$/.test(before)) return { suggestions: OPERATORS.map((o) => ({ label: o, kind: kinds.Operator, insertText: o, range })) };
      if (/t:\w*$/.test(before)) return { suggestions: TRANSFORMS.map((t) => ({ label: t, kind: kinds.Function, insertText: t, range })) };
      return {
        suggestions: [
          ...DIRECTIVES.map((d) => ({ label: d, kind: kinds.Keyword, insertText: d, range })),
          ...VARIABLES.map((v) => ({ label: v, kind: kinds.Variable, insertText: v, range })),
          ...ACTIONS.map((a) => ({ label: a, kind: kinds.Property, insertText: a, range })),
          { label: "SecRule (template)", kind: kinds.Snippet, insertTextRules: monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet, range,
            insertText: 'SecRule ${1:ARGS} "@rx ${2:pattern}" \\\\\n    "id:${3:900100},\\\\\n    phase:${4:2},\\\\\n    deny,\\\\\n    status:403,\\\\\n    msg:\'${5:Describe the attack}\',\\\\\n    severity:\'CRITICAL\'"' },
        ],
      };
    },
  });
  monaco.editor.defineTheme("coraza-dark", { base: "vs-dark", inherit: true, rules: [{ token: "keyword", foreground: "40c4b0", fontStyle: "bold" }, { token: "variable", foreground: "86b6ef" }, { token: "keyword.operator", foreground: "f28f68" }, { token: "attribute.name", foreground: "c3c2b7" }, { token: "keyword.action", foreground: "f9bb9b" }], colors: { "editor.background": "#17181b", "editor.lineHighlightBackground": "#1e2024" } });
  monaco.editor.defineTheme("coraza-light", { base: "vs", inherit: true, rules: [{ token: "keyword", foreground: "0b7668", fontStyle: "bold" }, { token: "variable", foreground: "184f95" }, { token: "keyword.operator", foreground: "b02e2e" }, { token: "attribute.name", foreground: "52514e" }, { token: "keyword.action", foreground: "8c1f45" }], colors: { "editor.background": "#ffffff" } });
}

export interface EditorHandle { revealLine(line: number): void }

export const SecLangEditor = React.forwardRef<EditorHandle, { value: string; onChange: (v: string) => void; diagnostics: Diagnostic[]; readOnly?: boolean; height?: number }>(
  function SecLangEditor({ value, onChange, diagnostics, readOnly, height = 360 }, ref) {
    const { resolvedTheme } = useTheme();
    const [failed, setFailed] = React.useState(false);
    const ed = React.useRef<Parameters<OnMount>[0] | null>(null);
    const mon = React.useRef<Monaco | null>(null);
    const ta = React.useRef<HTMLTextAreaElement>(null);
    React.useEffect(() => {
      let done = false;
      loader.init().then(() => { done = true; }, () => setFailed(true));
      const t = setTimeout(() => { if (!done) setFailed(true); }, 12000);
      return () => clearTimeout(t);
    }, []);
    React.useImperativeHandle(ref, () => ({
      revealLine(line) {
        if (ed.current) { ed.current.revealLineInCenter(line); ed.current.setPosition({ lineNumber: line, column: 1 }); ed.current.focus(); }
        else if (ta.current) { const idx = value.split("\n").slice(0, line - 1).join("\n").length + (line > 1 ? 1 : 0); ta.current.focus(); ta.current.setSelectionRange(idx, idx); }
      },
    }), [value]);
    React.useEffect(() => {
      const m = mon.current, e = ed.current;
      if (!m || !e) return;
      const model = e.getModel();
      if (!model) return;
      m.editor.setModelMarkers(model, "seclang-lint", diagnostics.map((d) => ({
        startLineNumber: d.line, endLineNumber: d.endLine, startColumn: 1, endColumn: model.getLineMaxColumn(d.endLine),
        message: d.message, severity: d.severity === "error" ? m.MarkerSeverity.Error : m.MarkerSeverity.Warning,
      })));
    }, [diagnostics]);

    if (failed) {
      return (
        <div>
          <label htmlFor="seclang-fallback" className="sr-only">SecLang source</label>
          <Textarea id="seclang-fallback" ref={ta} value={value} onChange={(e) => onChange(e.target.value)} readOnly={readOnly} spellCheck={false} className="rounded-none border-0 font-mono text-[13px] leading-relaxed" style={{ height }} />
          <p className="border-t border-border px-3 py-1.5 text-[11px] text-warn">The Monaco editor could not load from the CDN, so this is a plain editor. Linting still runs.</p>
        </div>
      );
    }
    return (
      <Editor
        height={height}
        language="seclang"
        value={value}
        theme={resolvedTheme === "light" ? "coraza-light" : "coraza-dark"}
        beforeMount={register}
        onMount={(e, m) => { ed.current = e; mon.current = m; m.editor.setTheme(resolvedTheme === "light" ? "coraza-light" : "coraza-dark"); }}
        onChange={(v) => onChange(v ?? "")}
        loading={<Loading label="Loading Monaco editor" />}
        options={{ readOnly, minimap: { enabled: false }, fontFamily: "IBM Plex Mono, ui-monospace, monospace", fontSize: 13, lineHeight: 21, scrollBeyondLastLine: false, wordWrap: "on", renderLineHighlight: "line", tabSize: 4, automaticLayout: true, padding: { top: 10 } }}
      />
    );
  },
);
