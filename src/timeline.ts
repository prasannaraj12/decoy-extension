export type EventKind = "message" | "repo" | "finding" | "cloud" | "link";

export interface TimelineEvent {
  at: number;
  kind: EventKind;
  title: string;
  detail?: string;
  source?: "on_device" | "in_cloud" | "rules";
}

/** One investigation = one chronological chain. Persist to Firestore later. */
export class Investigation {
  events: TimelineEvent[] = [];
  messageRepos = new Set<string>();
  scannedRepos = new Set<string>();

  add(e: Omit<TimelineEvent, "at">) {
    this.events.push({ ...e, at: Date.now() });
    this.correlate();
  }

  /** Deterministic correlation: the repo you scanned was linked in the message. */
  private correlate() {
    for (const r of this.scannedRepos) {
      if (this.messageRepos.has(r) && !this.events.some((e) => e.kind === "link" && e.detail === r)) {
        this.events.push({ at: Date.now(), kind: "link", source: "rules",
          title: "Attack chain linked: the message pointed to this repository", detail: r });
      }
    }
  }
}
