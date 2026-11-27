import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// Use the real SDK *browser* build (what Vite bundles). Node's entry has no on-device adapter.
// @ts-ignore - the ESM file has no adjacent type declarations
vi.mock("firebase/ai", () => import("../node_modules/@firebase/ai/dist/esm/index.esm.js"));
vi.mock("firebase/app-check", () => ({ initializeAppCheck: () => ({}), ReCaptchaEnterpriseProvider: class {} }));

const g = globalThis as any;
const CANARY = "PRIVATE_CANARY_MESSAGE";
let requests: { url: string; body: string }[] = [];
let load: () => Promise<typeof import("../src/ai/hybrid")>;

const fakeLM = (status: string | (() => string)) => ({
  availability: vi.fn(async () => (typeof status === "function" ? status() : status)),
  create: vi.fn(async () => ({ prompt: async () => "nano reply", destroy() {} })),
});
/** Anything sent over a real network scheme. */
const networkRequests = () => requests.filter((r) => /^https?:/i.test(r.url));

beforeEach(() => {
  vi.resetModules();
  g.window = g;
  g.self = g;
  delete g.LanguageModel;
  requests = [];
  vi.stubGlobal("fetch", async (url: any, init: any) => {
    requests.push({ url: String(url), body: String(init?.body ?? "") });
    return new Response(JSON.stringify({ candidates: [{ content: { parts: [{ text: "cloud reply" }] } }] }), { status: 200 });
  });
  for (const [k, v] of Object.entries({ API_KEY: "real-key", PROJECT_ID: "real-project", APP_ID: "real-app" })) vi.stubEnv("VITE_FIREBASE_" + k, v);
  load = () => import("../src/ai/hybrid");
});
/** Loaded from the same module graph as hybrid.ts, so approvals are recognised. */
const approved = async (text = "redacted evidence") => {
  const { createDraft, approve } = await import("../src/ai/consent");
  return approve(createDraft(text as any), text);
};
afterEach(() => { vi.unstubAllGlobals(); vi.unstubAllEnvs(); delete g.LanguageModel; });

describe("askLocal fails closed", () => {
  it("documents why the guard exists: the bare SDK sends ONLY_ON_DEVICE text to the cloud without LanguageModel", async () => {
    const sdk: any = await import("firebase/ai");
    const { initializeApp } = await import("firebase/app");
    const ai = sdk.getAI(initializeApp({ apiKey: "k", projectId: "p", appId: "a" }, "bare-sdk"), { backend: new sdk.GoogleAIBackend() });
    await sdk.getGenerativeModel(ai, { mode: sdk.InferenceMode.ONLY_ON_DEVICE }).generateContent(CANARY);
    expect(networkRequests().some((r) => r.body.includes(CANARY))).toBe(true);
  });

  it("sends nothing when LanguageModel is missing", async () => {
    const { askLocal, LocalUnavailableError } = await load();
    await expect(askLocal(CANARY)).rejects.toBeInstanceOf(LocalUnavailableError);
    expect(requests).toHaveLength(0);
  });

  it.each(["unavailable", "downloadable", "downloading"])("sends nothing and starts no download when the model is %s", async (status) => {
    g.LanguageModel = fakeLM(status);
    const { askLocal, LocalUnavailableError } = await load();
    await expect(askLocal(CANARY)).rejects.toBeInstanceOf(LocalUnavailableError);
    expect(requests).toHaveLength(0);
    expect(g.LanguageModel.create).not.toHaveBeenCalled();
  });

  it.each([
    ["throws", () => { throw new Error("boom"); }],
    ["returns a state Decoy doesn't know", () => "ready-ish"],
    ["returns nothing", () => undefined as any],
  ])("fails closed when availability() %s", async (_n, status) => {
    g.LanguageModel = fakeLM(status);
    const { askLocal, localModelStatus, LocalUnavailableError } = await load();
    expect(await localModelStatus()).toBe("failed");
    await expect(askLocal(CANARY)).rejects.toBeInstanceOf(LocalUnavailableError);
    expect(requests).toHaveLength(0);
  });

  it("stays off the network and discards the reply if LanguageModel vanishes after the check", async () => {
    const LM = fakeLM("available");
    LM.availability.mockImplementation(async () => { delete g.LanguageModel; return "available"; });
    g.LanguageModel = LM;
    const { askLocal, InferencePolicyError } = await load();
    await expect(askLocal(CANARY)).rejects.toBeInstanceOf(InferencePolicyError);
    expect(requests.map((r) => new URL(r.url).protocol)).toEqual(["decoy-blocked:"]); // backstop exercised
    expect(networkRequests()).toHaveLength(0);
  });

  it("fails without any request when the on-device session itself fails", async () => {
    g.LanguageModel = fakeLM("available");
    g.LanguageModel.create.mockRejectedValue(new Error("no memory"));
    const { askLocal } = await load();
    await expect(askLocal(CANARY)).rejects.toThrow(/no memory/);
    expect(requests).toHaveLength(0);
  });

  it("keeps real Firebase credentials out of the local path, even in the blocked fall-through", async () => {
    const LM = fakeLM("available");
    LM.availability.mockImplementation(async () => { delete g.LanguageModel; return "available"; });
    g.LanguageModel = LM;
    const sent: string[] = [];
    vi.stubGlobal("fetch", async (u: any, i: any) => { sent.push(String(u) + JSON.stringify([...new Headers(i?.headers)])); throw new TypeError("blocked"); });
    const { askLocal } = await load();
    await expect(askLocal(CANARY)).rejects.toThrow();
    expect(sent).toHaveLength(1);
    expect(sent[0]).not.toMatch(/real-key|real-project|real-app/);
  });

  it("treats a hanging availability check as failed, and sends nothing", async () => {
    vi.useFakeTimers();
    try {
      g.LanguageModel = fakeLM("available");
      g.LanguageModel.availability.mockImplementation(() => new Promise(() => {}));
      const { askLocal, LocalUnavailableError } = await load();
      const result = expect(askLocal(CANARY)).rejects.toBeInstanceOf(LocalUnavailableError);
      await vi.advanceTimersByTimeAsync(10_000);
      await result;
      expect(g.LanguageModel.create).not.toHaveBeenCalled();
      expect(requests).toHaveLength(0);
    } finally { vi.useRealTimers(); }
  });

  it("gives up on a hanging reply, makes no request, and works again afterwards", async () => {
    vi.useFakeTimers();
    try {
      g.LanguageModel = fakeLM("available");
      g.LanguageModel.create.mockImplementationOnce(() => new Promise(() => {}));
      const { askLocal, LocalTimeoutError } = await load();
      const result = expect(askLocal(CANARY)).rejects.toBeInstanceOf(LocalTimeoutError);
      await vi.advanceTimersByTimeAsync(180_000);
      await result;
      expect(requests).toHaveLength(0);
      expect(await askLocal(CANARY)).toMatchObject({ source: "on_device" });
    } finally { vi.useRealTimers(); }
  });

  it("recovers once LanguageModel is available", async () => {
    const { askLocal } = await load();
    await expect(askLocal(CANARY)).rejects.toThrow();
    g.LanguageModel = fakeLM("available");
    expect(await askLocal(CANARY)).toMatchObject({ source: "on_device", text: "nano reply" });
    expect(requests).toHaveLength(0);
  });

  it("asks Chrome about the same options the SDK uses to create the session", async () => {
    g.LanguageModel = fakeLM("available");
    const { askLocal } = await load();
    await askLocal(CANARY);
    const asked = g.LanguageModel.availability.mock.calls.map((c: any[]) => c[0]);
    for (const a of asked) expect(a).toEqual(g.LanguageModel.create.mock.calls[0][0]);
  });
});

describe("prepareLocalModel is honest", () => {
  it.each([undefined, "unavailable"])("throws when the model is %s", async (status) => {
    if (status) g.LanguageModel = fakeLM(status);
    const { prepareLocalModel } = await load();
    await expect(prepareLocalModel()).rejects.toThrow(/On-device model:/);
  });
  it("throws if the model is still not available afterwards", async () => {
    g.LanguageModel = fakeLM("downloadable");
    const { prepareLocalModel } = await load();
    await expect(prepareLocalModel()).rejects.toThrow(/still downloadable/);
  });
});

describe("askCloud", () => {
  it("returns a reply reported as in_cloud and does not touch LanguageModel", async () => {
    g.LanguageModel = fakeLM("available");
    const { askCloud } = await load();
    expect(await askCloud(await approved())).toMatchObject({ source: "in_cloud" });
    expect(g.LanguageModel.create).not.toHaveBeenCalled();
    expect(networkRequests()).toHaveLength(1);
  });
  it("sends exactly the approved text and nothing else", async () => {
    const { askCloud } = await load();
    await askCloud(await approved("EXACT [EMAIL_1] TEXT"));
    expect(JSON.parse(networkRequests()[0].body).contents).toEqual([{ role: "user", parts: [{ text: "EXACT [EMAIL_1] TEXT" }] }]);
  });
  it.each([["a plain string", "raw"], ["a look-alike object", { text: "raw" }]])("refuses %s without any request", async (_n, value) => {
    const { askCloud } = await load();
    await expect(askCloud(value as any)).rejects.toThrow(/not been approved/);
    expect(requests).toHaveLength(0);
  });
  it("refuses to reuse an approval", async () => {
    const { askCloud } = await load();
    const p = await approved();
    await askCloud(p);
    await expect(askCloud(p)).rejects.toThrow(/already used/);
    expect(networkRequests()).toHaveLength(1);
  });
  it.each(["", "YOUR_API_KEY"])("refuses without any request when Firebase is not configured (%j)", async (key) => {
    vi.stubEnv("VITE_FIREBASE_API_KEY", key);
    const { askCloud, testCloud, CloudNotConfiguredError } = await load();
    await expect(askCloud(await approved())).rejects.toBeInstanceOf(CloudNotConfiguredError);
    await expect(Promise.resolve().then(testCloud)).rejects.toBeInstanceOf(CloudNotConfiguredError);
    expect(requests).toHaveLength(0);
  });
  it("still works on-device when Firebase is not configured", async () => {
    vi.stubEnv("VITE_FIREBASE_API_KEY", "");
    g.LanguageModel = fakeLM("available");
    const { askLocal } = await load();
    expect(await askLocal(CANARY)).toMatchObject({ source: "on_device" });
    expect(requests).toHaveLength(0);
  });
});

describe("a source that does not match the request is rejected", () => {
  // Covers a future SDK that omits or changes inferenceSource.
  it.each([
    ["askLocal", "in_cloud"], ["askLocal", undefined], ["askCloud", "on_device"], ["askCloud", undefined],
  ] as const)("%s rejects %s", async (fn, source) => {
    vi.doMock("firebase/ai", async () => ({
      getAI: () => ({}), GoogleAIBackend: class {},
      InferenceMode: { ONLY_ON_DEVICE: "only_on_device", ONLY_IN_CLOUD: "only_in_cloud" },
      InferenceSource: { ON_DEVICE: "on_device", IN_CLOUD: "in_cloud" },
      getGenerativeModel: () => ({ generateContent: async () => ({ response: { text: () => "x", inferenceSource: source } }) }),
    }));
    g.LanguageModel = fakeLM("available");
    const m = await load();
    await expect(m[fn](fn === "askCloud" ? await approved() : ("x" as any))).rejects.toBeInstanceOf(m.InferencePolicyError);
    vi.doUnmock("firebase/ai");
  });
});
