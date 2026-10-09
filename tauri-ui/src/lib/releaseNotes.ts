// Release notes are hand-typed HTML from the dashboard. They used to be injected with
// dangerouslySetInnerHTML (updater audit D33): anyone who can edit a release could run
// script in the desk PC's webview. This parser keeps a small allowlist of formatting
// tags as a tree that React renders as elements; every attribute is dropped, links become
// their text (a click would navigate the Tauri webview away) and everything else keeps
// only its text. Pure TypeScript (no DOMParser) so node:test can run it.

export type ReleaseNoteTag =
  | "p" | "br" | "ul" | "ol" | "li" | "strong" | "b" | "em" | "i"
  | "h1" | "h2" | "h3" | "h4" | "code";

export type ReleaseNoteNode =
  | { type: "text"; text: string }
  | { type: "element"; tag: ReleaseNoteTag; children: ReleaseNoteNode[] };

const ALLOWED = new Set<string>(["p", "br", "ul", "ol", "li", "strong", "b", "em", "i", "h1", "h2", "h3", "h4", "code"]);
const VOID = new Set<string>(["br", "hr", "img", "input", "meta", "link", "area", "base", "col", "embed", "source", "track", "wbr"]);
// Their content is never text for a reader: dropped whole.
const DROP_WITH_CONTENT = new Set<string>(["script", "style", "iframe", "object", "template", "noscript", "textarea", "title", "svg", "math", "select"]);
const MAX_INPUT = 20000;
const MAX_DEPTH = 20;

const NAMED: Record<string, string> = { amp: "&", lt: "<", gt: ">", quot: "\"", apos: "'", nbsp: " " };

export function decodeEntities(text: string): string {
  return text.replace(/&(#x[0-9a-fA-F]+|#[0-9]+|[a-zA-Z]+);/g, (whole, body: string) => {
    if (body[0] === "#") {
      const code = body[1] === "x" || body[1] === "X" ? parseInt(body.slice(2), 16) : parseInt(body.slice(1), 10);
      if (!Number.isFinite(code) || code <= 0 || code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff)) return "";
      return String.fromCodePoint(code);
    }
    const named = NAMED[body.toLowerCase()];
    return named ?? whole;
  });
}

interface Frame {
  tag: string | null; // null = root, or a tag we unwrapped
  node: { children: ReleaseNoteNode[] } ;
}

function pushText(target: ReleaseNoteNode[], raw: string): void {
  const text = decodeEntities(raw);
  if (!text) return;
  const last = target[target.length - 1];
  if (last && last.type === "text") last.text += text;
  else target.push({ type: "text", text });
}

function plainTextNodes(text: string): ReleaseNoteNode[] {
  const out: ReleaseNoteNode[] = [];
  const lines = decodeEntities(text).split(/\r?\n/);
  lines.forEach((line, i) => {
    if (i > 0) out.push({ type: "element", tag: "br", children: [] });
    if (line) out.push({ type: "text", text: line });
  });
  return out;
}

/** Parse release-notes HTML into an allowlisted tree. Never throws. */
export function parseReleaseNotes(input: string | null | undefined): ReleaseNoteNode[] {
  if (!input) return [];
  const source = String(input).slice(0, MAX_INPUT);
  if (!/<[a-zA-Z!/]/.test(source)) return plainTextNodes(source);

  const root: { children: ReleaseNoteNode[] } = { children: [] };
  const stack: Frame[] = [{ tag: null, node: root }];
  let dropUntil: string | null = null;
  let i = 0;

  const current = () => stack[stack.length - 1].node.children;

  while (i < source.length) {
    const lt = source.indexOf("<", i);
    if (lt === -1) {
      if (!dropUntil) pushText(current(), source.slice(i));
      break;
    }
    if (lt > i && !dropUntil) pushText(current(), source.slice(i, lt));

    // Comments / doctype / CDATA: skipped.
    if (source.startsWith("<!--", lt)) {
      const end = source.indexOf("-->", lt + 4);
      i = end === -1 ? source.length : end + 3;
      continue;
    }
    if (source[lt + 1] === "!" || source[lt + 1] === "?") {
      const end = source.indexOf(">", lt + 1);
      i = end === -1 ? source.length : end + 1;
      continue;
    }

    const match = /^<\s*(\/?)\s*([a-zA-Z][a-zA-Z0-9-]*)/.exec(source.slice(lt, lt + 64));
    if (!match) {
      // A lone "<" (e.g. "a < b"): it is text.
      if (!dropUntil) pushText(current(), "<");
      i = lt + 1;
      continue;
    }
    // Find the end of the tag, skipping quoted attribute values.
    let j = lt + match[0].length;
    let quote: string | null = null;
    while (j < source.length) {
      const ch = source[j];
      if (quote) {
        if (ch === quote) quote = null;
      } else if (ch === "\"" || ch === "'") {
        quote = ch;
      } else if (ch === ">") {
        break;
      }
      j++;
    }
    i = j + 1;
    const closing = match[1] === "/";
    const tag = match[2].toLowerCase();

    if (dropUntil) {
      if (closing && tag === dropUntil) dropUntil = null;
      continue;
    }
    if (DROP_WITH_CONTENT.has(tag)) {
      if (!closing && !/\/\s*$/.test(source.slice(lt, j))) dropUntil = tag;
      continue;
    }

    if (closing) {
      // Close the nearest matching open frame (and everything opened inside it).
      for (let k = stack.length - 1; k > 0; k--) {
        if (stack[k].tag === tag) {
          stack.length = k;
          break;
        }
      }
      continue;
    }

    if (tag === "br") {
      current().push({ type: "element", tag: "br", children: [] });
      continue;
    }
    if (VOID.has(tag)) continue;

    if (ALLOWED.has(tag) && stack.length < MAX_DEPTH) {
      const el: ReleaseNoteNode = { type: "element", tag: tag as ReleaseNoteTag, children: [] };
      current().push(el);
      stack.push({ tag, node: el });
    } else {
      // Unknown or disallowed tag (a, div, span, img...): keep its text, not the tag.
      stack.push({ tag, node: stack[stack.length - 1].node });
    }
  }
  return root.children;
}

/** The plain text of a parsed tree (for tests and empty checks). */
export function releaseNotesText(nodes: ReleaseNoteNode[]): string {
  return nodes
    .map((n) => (n.type === "text" ? n.text : n.tag === "br" ? "\n" : releaseNotesText(n.children)))
    .join("");
}
