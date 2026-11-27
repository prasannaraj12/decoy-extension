import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { Investigation } from "../src/timeline";
import { extractLinks } from "../src/scanner/message";
import { describeLocalStatus, toLocalStatus, type LocalStatus } from "../src/ai/status";
import { approve, consume, createDraft, ConsentError } from "../src/ai/consent";

const links = (i: Investigation) => i.events.filter((e) => e.kind === "link").map((e) => e.detail);
const message = (i: Investigation, text: string) => { extractLinks(text).repos.forEach((r) => i.messageRepos.add(r)); i.add({ kind: "message", title: "m" }); };
const repo = (i: Investigation, slug: string) => { i.scannedRepos.add(slug); i.add({ kind: "repo", title: "r" }); };

describe("timeline linking", () => {
  it.each([
    ["message first", (i: Investigation) => { message(i, "clone https://github.com/Evil/Test.git,"); repo(i, "evil/test"); }],
    ["repo first", (i: Investigation) => { repo(i, "evil/test"); message(i, "clone github.com/evil/test now"); }],
  ])("links a message to the repo it points at (%s)", (_n, run) => { const i = new Investigation(); run(i); expect(links(i)).toEqual(["evil/test"]); });
  it("links each repo once", () => {
    const i = new Investigation();
    message(i, "https://github.com/a/b https://github.com/c/d"); repo(i, "a/b"); repo(i, "a/b"); repo(i, "c/d");
    expect(links(i)).toEqual(["a/b", "c/d"]);
  });
  it.each(["https://github.com/a/other", "https://notgithub.com/a/b", "https://github.com.evil.xyz/a/b", "no links"])("does not link unrelated text: %s", (text) => {
    const i = new Investigation(); message(i, text); repo(i, "a/b"); expect(links(i)).toEqual([]);
  });
  it("keeps events in chronological order, with the link after what caused it", () => {
    const i = new Investigation(); message(i, "github.com/a/b"); repo(i, "a/b"); i.add({ kind: "cloud", title: "c" });
    expect(i.events.map((e) => e.kind)).toEqual(["message", "repo", "link", "cloud"]);
    expect(i.events.map((e) => e.at)).toEqual([...i.events.map((e) => e.at)].sort((x, y) => x - y));
  });
  it("links the demo message", () => {
    const i = new Investigation(); message(i, readFileSync(join(__dirname, "../demo-assessment/RECRUITER_MESSAGE.txt"), "utf8")); repo(i, "prasannaraj12/decoy-demo-assessment");
    expect(links(i)).toHaveLength(1);
  });
});

describe("model status", () => {
  const all: LocalStatus[] = ["available", "downloadable", "downloading", "unavailable", "no-api", "failed"];
  it("every state has its own label and button", () => {
    expect(new Set(all.map((s) => describeLocalStatus(s).label)).size).toBe(all.length);
    expect(new Set(all.map((s) => describeLocalStatus(s).button)).size).toBe(all.length);
  });
  it("only claims readiness when available", () => { for (const s of all) expect(/ready/i.test(describeLocalStatus(s).detail + describeLocalStatus(s).button)).toBe(s === "available"); });
  it("the button is enabled only where pressing it can help", () => expect(all.filter((s) => describeLocalStatus(s).canPrepare)).toEqual(["downloadable", "downloading", "failed"]));
  it.each([undefined, null, "", "readily", "AVAILABLE", true])("treats an unknown value (%j) as failed", (v) => expect(toLocalStatus(v)).toBe("failed"));
});

describe("consent", () => {
  it("returns exactly the text that was shown", () => { const d = createDraft("shown" as any); expect(consume(approve(d, "shown"))).toBe("shown"); });
  it.each(["shown ", "Shown", "", "shown\nextra"])("refuses when the preview differs: %j", (shown) => expect(() => approve(createDraft("shown" as any), shown)).toThrow(ConsentError));
  it("refuses a forged draft", () => expect(() => approve({ text: "x", redactions: [] } as any, "x")).toThrow(ConsentError));
  it("refuses a forged or copied approval", () => {
    const a = approve(createDraft("x" as any), "x");
    expect(() => consume({ ...a })).toThrow(ConsentError);
    expect(() => consume({ text: "x" } as any)).toThrow(ConsentError);
  });
  it("is single use", () => { const a = approve(createDraft("x" as any), "x"); consume(a); expect(() => consume(a)).toThrow(/already used/); });
  it("cannot be edited after approval", () => {
    const a: any = approve(createDraft("x" as any), "x");
    expect(() => { a.text = "raw"; }).toThrow(TypeError);
  });
});
