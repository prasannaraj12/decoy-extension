/** What Chrome reports about Gemini Nano, plus "no-api" (no LanguageModel) and "failed" (the check itself failed). */
export type LocalStatus = "available" | "downloadable" | "downloading" | "unavailable" | "no-api" | "failed";

const CHROME_STATES: readonly string[] = ["available", "downloadable", "downloading", "unavailable"];

/** Anything Chrome returns that we don't recognise is treated as a failure, never as ready. */
export const toLocalStatus = (v: unknown): LocalStatus => (CHROME_STATES.includes(v as string) ? (v as LocalStatus) : "failed");

export interface StatusView { label: string; detail: string; button: string; canPrepare: boolean; }

const VIEWS: Record<LocalStatus, StatusView> = {
  available: { label: "Available", detail: "Ready. Messages can be analysed on this device.", button: "On-device model ready", canPrepare: false },
  downloadable: { label: "Not downloaded", detail: "Supported here, but the model must be downloaded first (several GB).", button: "Download on-device model", canPrepare: true },
  downloading: { label: "Downloading", detail: "Chrome is downloading the model. On-device analysis is off until it finishes.", button: "Resume / show progress", canPrepare: true },
  unavailable: { label: "Unavailable", detail: "Chrome reports that this device or profile can't run the model.", button: "Not available on this device", canPrepare: false },
  "no-api": { label: "Not supported", detail: "This browser has no LanguageModel API.", button: "Not supported in this browser", canPrepare: false },
  failed: { label: "Check failed", detail: "Chrome's availability check failed, so on-device analysis is off.", button: "Check again", canPrepare: true },
};

export const describeLocalStatus = (s: LocalStatus): StatusView => VIEWS[s];
