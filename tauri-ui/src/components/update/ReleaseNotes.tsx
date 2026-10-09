import { createElement, Fragment, type ReactNode } from "react";
import { parseReleaseNotes, type ReleaseNoteNode } from "@/lib/releaseNotes";

function render(nodes: ReleaseNoteNode[], prefix: string): ReactNode[] {
  return nodes.map((node, index) => {
    const key = `${prefix}.${index}`;
    if (node.type === "text") return <Fragment key={key}>{node.text}</Fragment>;
    if (node.tag === "br") return <br key={key} />;
    // node.tag is one of the parser's allowlisted formatting tags; no attribute is passed.
    return createElement(node.tag, { key }, ...render(node.children, key));
  });
}

/** Release notes as React elements -- never raw HTML (updater audit D33). */
export default function ReleaseNotes({ html, className }: { html: string | null | undefined; className?: string }) {
  const nodes = parseReleaseNotes(html);
  if (nodes.length === 0) return null;
  return <div className={className}>{render(nodes, "n")}</div>;
}
