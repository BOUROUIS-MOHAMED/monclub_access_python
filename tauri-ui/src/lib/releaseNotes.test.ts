import assert from "node:assert/strict";
import test from "node:test";

import { decodeEntities, parseReleaseNotes, releaseNotesText, type ReleaseNoteNode } from "./releaseNotes.ts";

function tags(nodes: ReleaseNoteNode[]): string[] {
  const out: string[] = [];
  const walk = (list: ReleaseNoteNode[]) => {
    for (const n of list) {
      if (n.type === "element") {
        out.push(n.tag);
        walk(n.children);
      }
    }
  };
  walk(nodes);
  return out;
}

test("formatting tags are kept as a tree", () => {
  const nodes = parseReleaseNotes("<h2>New</h2><ul><li><strong>Faster</strong> sync</li><li>Fix</li></ul><p>Bye<br>now</p>");
  assert.deepEqual(tags(nodes), ["h2", "ul", "li", "strong", "li", "p", "br"]);
  assert.equal(releaseNotesText(nodes), "NewFaster syncFixBye\nnow");
});

test("script, style and iframe are dropped with their content", () => {
  const nodes = parseReleaseNotes("<p>a</p><script>alert(1)</script><style>p{}</style><iframe src=x>y</iframe><p>b</p>");
  assert.equal(releaseNotesText(nodes), "ab");
  assert.deepEqual(tags(nodes), ["p", "p"]);
});

test("event handlers and every attribute are dropped", () => {
  const nodes = parseReleaseNotes('<p onclick="alert(1)" style="x">hi</p><img src=x onerror="alert(2)">');
  assert.deepEqual(nodes, [{ type: "element", tag: "p", children: [{ type: "text", text: "hi" }] }]);
});

test("links become their text, other unknown tags are unwrapped", () => {
  const nodes = parseReleaseNotes('<p>See <a href="javascript:alert(1)">this <b>page</b></a> <div>and <span>that</span></div></p>');
  assert.equal(releaseNotesText(nodes), "See this page and that");
  assert.deepEqual(tags(nodes), ["p", "b"]);
});

test("an attribute value holding > does not end the tag early", () => {
  const nodes = parseReleaseNotes('<p title="a > b">x</p>');
  assert.equal(releaseNotesText(nodes), "x");
});

test("entities are decoded to text, never re-parsed as markup", () => {
  const nodes = parseReleaseNotes("<p>&lt;script&gt;alert(1)&lt;/script&gt; &amp; &#233;&#x41;</p>");
  assert.equal(releaseNotesText(nodes), "<script>alert(1)</script> & éA");
  assert.deepEqual(tags(nodes), ["p"]);
});

test("plain text keeps its line breaks", () => {
  const nodes = parseReleaseNotes("Line one\nLine two");
  assert.equal(releaseNotesText(nodes), "Line one\nLine two");
});

test("a lone < is text", () => {
  assert.equal(releaseNotesText(parseReleaseNotes("<p>1 < 2</p>")), "1 < 2");
});

test("comments and unclosed junk never throw", () => {
  assert.equal(releaseNotesText(parseReleaseNotes("<!-- x --><p>ok</p><script>never closed")), "ok");
  assert.deepEqual(parseReleaseNotes(null), []);
  assert.deepEqual(parseReleaseNotes(""), []);
});

test("invalid numeric entities decode to nothing", () => {
  assert.equal(decodeEntities("a&#0;b&#xD800;c&#1114112;d"), "abcd");
});
