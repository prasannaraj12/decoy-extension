import type { RedactedText, Redaction } from "../redact";

// Binds what the user saw to what is sent, at runtime (the RedactedText brand is compile-time only).
// draft -> approve(draft, text on screen) -> consume() once, inside askCloud().

export interface CloudDraft { readonly text: RedactedText; readonly redactions: readonly Redaction[]; }
export interface ApprovedPayload { readonly text: RedactedText; }

export class ConsentError extends Error {}

const drafts = new WeakSet<object>();
const approvals = new WeakSet<object>();

export function createDraft(text: RedactedText, redactions: readonly Redaction[] = []): CloudDraft {
  const draft = Object.freeze({ text, redactions: Object.freeze([...redactions]) });
  drafts.add(draft);
  return draft;
}

/** `shownText` must be read back from the preview itself, so a mismatch between preview and payload is refused. */
export function approve(draft: CloudDraft, shownText: string): ApprovedPayload {
  if (!drafts.has(draft)) throw new ConsentError("Not a reviewed draft. Nothing was sent.");
  if (shownText !== draft.text) throw new ConsentError("The preview does not match the payload. Nothing was sent.");
  const approved = Object.freeze({ text: draft.text });
  approvals.add(approved);
  return approved;
}

/** One approval authorises one request. */
export function consume(p: ApprovedPayload): RedactedText {
  if (!approvals.delete(p)) throw new ConsentError("This payload has not been approved, or the approval was already used. Nothing was sent.");
  return p.text;
}
