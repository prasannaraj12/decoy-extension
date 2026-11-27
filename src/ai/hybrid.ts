import { initializeApp } from "firebase/app";
import { initializeAppCheck, ReCaptchaEnterpriseProvider } from "firebase/app-check";
import { getAI, getGenerativeModel, GoogleAIBackend, InferenceMode, InferenceSource, type GenerativeModel } from "firebase/ai";
import { FIREBASE_CONFIG, FIREBASE_CONFIGURED, RECAPTCHA_ENTERPRISE_SITE_KEY, CLOUD_MODEL, APP_CHECK_DEBUG } from "../config";
import { approve, consume, createDraft, type ApprovedPayload } from "./consent";
import { redact } from "../redact";
import { toLocalStatus, type LocalStatus } from "./status";

export type { LocalStatus } from "./status";
export type Source = "on_device" | "in_cloud" | "unknown";
export interface AIResult { text: string; source: Source; ms: number; }

/** Thrown before any inference call is made: the prompt has not been passed to the SDK. */
export class LocalUnavailableError extends Error {}
/** Thrown before any cloud call is made. */
export class CloudNotConfiguredError extends Error {}
/** The on-device model did not answer in time. Any late reply is ignored. */
export class LocalTimeoutError extends Error {}
/** The SDK answered from somewhere other than the requested source. The result is discarded. */
export class InferencePolicyError extends Error {}

// ---------- Local ----------

/** Chrome's availability check can hang when DNS is broken; inference can be very slow on a first load. */
const STATUS_TIMEOUT_MS = 10_000;
const LOCAL_TIMEOUT_MS = 180_000;

function withTimeout<T>(p: Promise<T>, ms: number, message: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout>;
  return Promise.race([p, new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new LocalTimeoutError(message)), ms); })]).finally(() => clearTimeout(timer));
}

/** Text-only, so Decoy's availability check and the SDK ask Chrome exactly the same question. */
const DEVICE_OPTIONS = {
  expectedInputs: [{ type: "text" as const, languages: ["en"] }],
  expectedOutputs: [{ type: "text" as const, languages: ["en"] }],
};

/** Not a network scheme: fetch() rejects it without opening a connection. */
const NO_NETWORK_URL = "decoy-blocked://local-only";

/**
 * Raw private text goes ONLY here.
 *
 * ONLY_ON_DEVICE is not sufficient by itself. In @firebase/ai 3.1.0, if window.LanguageModel is
 * missing when the model is built, the SDK creates no on-device adapter and sends the request to
 * the cloud despite the mode. Layers on top of the mode:
 *  1. The model is built, and called, only after requireLocalModel() passes.
 *  2. `baseUrl` (a documented RequestOptions field) is a non-network URL.
 *  3. It belongs to its own Firebase app with no real credentials and no App Check.
 *  4. The manifest CSP limits which hosts the panel can reach, and does not include that URL.
 */
let localModel: GenerativeModel | undefined;
function getLocalModel(): GenerativeModel {
  if (!localModel) {
    const app = initializeApp({ apiKey: "local-only", projectId: "local-only", appId: "local-only" }, "decoy-local");
    localModel = getGenerativeModel(
      getAI(app, { backend: new GoogleAIBackend() }),
      { mode: InferenceMode.ONLY_ON_DEVICE, onDeviceParams: { createOptions: DEVICE_OPTIONS } },
      { baseUrl: NO_NETWORK_URL },
    );
  }
  return localModel;
}

/** Chrome's own report on whether Gemini Nano can run here. */
export async function localModelStatus(): Promise<LocalStatus> {
  const LM = (globalThis as any).LanguageModel;
  if (!LM?.availability) return "no-api";
  try { return toLocalStatus(await withTimeout(Promise.resolve(LM.availability(DEVICE_OPTIONS)), STATUS_TIMEOUT_MS, "Availability check timed out.")); } catch { return "failed"; }
}

/** Must be called from a click handler (Chrome requires a user gesture to download the model). */
export async function prepareLocalModel(onProgress?: (p: number) => void) {
  const before = await localModelStatus();
  if (before === "no-api" || before === "unavailable" || before === "failed") throw new LocalUnavailableError(`On-device model: ${before}.`);
  await getLocalModel().initializeDeviceModel(onProgress);
  const after = await localModelStatus();
  if (after !== "available") throw new LocalUnavailableError(`On-device model is still ${after}.`);
}

/** Refuses anything but "available", so a scan also never starts a multi-GB model download. */
async function requireLocalModel() {
  const status = await localModelStatus();
  if (status === "available") return;
  const hint = status === "downloadable" || status === "downloading" ? " Download the on-device model first." : "";
  throw new LocalUnavailableError(`On-device model: ${status}.${hint}`);
}

async function run(model: GenerativeModel, prompt: string): Promise<AIResult> {
  const t0 = performance.now();
  const res = await model.generateContent(prompt);
  return {
    text: res.response.text(),
    source: (res.response.inferenceSource as Source) ?? "unknown",
    ms: Math.round(performance.now() - t0),
  };
}

/** Runs on-device or throws. Only a response the SDK reports as on_device is accepted. */
export async function askLocal(prompt: string): Promise<AIResult> {
  await requireLocalModel();
  let r: AIResult;
  // A model built without its on-device adapter can never recover, so rebuild it next time.
  try { r = await withTimeout(run(getLocalModel(), prompt), LOCAL_TIMEOUT_MS, `No on-device reply within ${LOCAL_TIMEOUT_MS / 1000} seconds.`); } catch (e) { localModel = undefined; throw e; }
  if (r.source !== InferenceSource.ON_DEVICE) {
    localModel = undefined;
    throw new InferencePolicyError(`Refusing result: on-device was required but the SDK reported "${r.source}".`);
  }
  return r;
}

// ---------- Cloud ----------

/** Built on first use, so opening the panel or scanning locally makes no Firebase request at all. */
let cloudModel: GenerativeModel | undefined;
function getCloudModel(): GenerativeModel {
  if (!FIREBASE_CONFIGURED) throw new CloudNotConfiguredError("Firebase is not configured (see .env.example). Nothing was sent.");
  if (!cloudModel) {
    const app = initializeApp(FIREBASE_CONFIG);
    // The token is printed to the console on first run: register it in Firebase console → App Check.
    if (APP_CHECK_DEBUG) (self as any).FIREBASE_APPCHECK_DEBUG_TOKEN = true;
    if (APP_CHECK_DEBUG || RECAPTCHA_ENTERPRISE_SITE_KEY) {
      // Must precede getAI(), which captures App Check when it is constructed.
      initializeAppCheck(app, {
        provider: new ReCaptchaEnterpriseProvider(RECAPTCHA_ENTERPRISE_SITE_KEY || "debug-only"),
        isTokenAutoRefreshEnabled: false,
      });
    }
    cloudModel = getGenerativeModel(getAI(app, { backend: new GoogleAIBackend() }), {
      mode: InferenceMode.ONLY_IN_CLOUD,
      inCloudParams: { model: CLOUD_MODEL },
    });
  }
  return cloudModel;
}

/** Accepts only a payload the user approved, once. */
export async function askCloud(approved: ApprovedPayload): Promise<AIResult> {
  const model = getCloudModel();
  const r = await run(model, consume(approved));
  if (r.source !== InferenceSource.IN_CLOUD) {
    throw new InferencePolicyError(`Refusing result: cloud was required but the SDK reported "${r.source}".`);
  }
  return r;
}

/** Connectivity check. Takes no input: the prompt is a constant. */
export function testCloud(): Promise<AIResult> {
  const draft = createDraft(redact("Reply with one short sentence confirming you are running.").text);
  return askCloud(approve(draft, draft.text));
}
