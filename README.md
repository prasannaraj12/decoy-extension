# Decoy

**Detect the deception before you execute it.**

Decoy is a pre-execution check for developers. Developers run other people's code every day: a repository a "recruiter" sends, a script from "IT support", setup instructions from a stranger. Decoy helps answer three questions before you run it: where did it come from, is there evidence that it is harmful, and what should you check first?

It is a Chrome extension built for #BuildHybridAI 2026 with the **Firebase AI Logic Hybrid Inference SDK**. Messages and code are analysed on your device with Gemini Nano. Decoy is a prototype; it reduces risk but cannot prove that anything is safe.

## What it does

| Part | What it does | Status |
|---|---|---|
| **Message check** | Rules find warning signs in a message, email or set of instructions, such as a request to paste a command, a download-and-run command, a claim to be IT support, a request for a password or one-time code, or remote control. A combined assessment gives *low concern*, *worth checking* or *high concern*, and describes the message, not the sender. Gemini Nano explains the findings on-device. | Implemented; tested on real Nano |
| **Repository check** | Reads a public GitHub repository without cloning or running it: install scripts, credential access, hidden payloads, download-and-run commands, auto-running editor tasks and suspicious network calls. Each finding has a rule, file, line, evidence, severity, confidence and recommended action. A partial scan is *Incomplete*, never clean. | Implemented; tested on real Nano |
| **AttackChain timeline** | Links a message to the repository it points at. If a full scan rates that repository *Do not run*, the message's assessment rises to *high concern*. | Implemented; tested |
| **Cloud report** | After you approve the exact redacted text, Gemini in the cloud writes a short incident report. Source code and the full message are never sent. | Implemented; **not yet tested live** |

The first demo uses a fake recruiter, a common case. The checks themselves don't depend on who sent the message.

**Planned, not built:** scanning npm packages as downloaded, local folders and other code hosts; saved investigations; a redesigned interface.

## How hybrid inference is used

| Data | Where it is analysed | SDK mode |
|---|---|---|
| Raw message (private) | Gemini Nano, on-device | `InferenceMode.ONLY_ON_DEVICE`, plus Decoy's own fail-closed guard (see below) |
| Flagged code lines | Gemini Nano, on-device | `ONLY_ON_DEVICE` |
| Redacted evidence summary (short message quotes; rule, severity, file and line for code, never the code itself), after the user approves the exact text | Gemini in the cloud | `InferenceMode.ONLY_IN_CLOUD` |

Every response shows the `inferenceSource` reported by the SDK (`on_device` / `in_cloud`). A response is accepted only if its source matches the requested mode (`src/ai/hybrid.ts`).

**Fail-closed guard.** In `@firebase/ai` 3.1.0, `ONLY_ON_DEVICE` sends the request to the cloud when `window.LanguageModel` is missing. Decoy checks that Chrome reports the model as `available` before passing any text to the SDK. The on-device model also has a non-network endpoint and its own Firebase app without real credentials, and the manifest CSP only allows GitHub and Firebase hosts.

**Consent is bound to content.** `askCloud()` accepts only a payload approved against the text read back from the preview, once. Source code is never included. A message containing a likely seed phrase is refused.

**Partial scans are never clean.** Failed downloads, oversized files, binaries, submodules and parse errors are listed and give an *Incomplete* result.

**Evidence first, AI second.** Findings come from deterministic rules (`src/scanner/`), each with rule ID, file, line, evidence, severity, confidence and remediation. The model only explains them; it never produces findings or scores. Redaction is deterministic too (`src/redact.ts`). It is pattern matching and can miss things, which is why the user reviews the exact text.

## Setup

### Build and load the extension

1. Install the dependencies: `npm ci`
2. Build: `npm run build`
3. Open `chrome://extensions` (Chrome ≥ 139 on desktop) and turn on **Developer mode**.
4. Click **Load unpacked** and choose the `dist/` folder.
5. Click the Decoy toolbar icon to open the side panel.

After every rebuild, click the reload icon on Decoy's card in `chrome://extensions` and reopen the panel. Keep the project in a path without `#`: Vite's build and tests fail there.

Decoy works without Firebase in local-only mode. Cloud requests are then refused before any network call.

### Configure Firebase AI Logic

1. In the Firebase console, create a project. Decoy needs no paid plan. If a step asks you to add billing, stop and check first.
2. Open **AI Logic** and choose the **Gemini Developer API**.
3. In Project settings, register a **Web app**.
4. Copy `.env.example` to `.env`, fill in that app's config, then rebuild and reload.

`.env` is git-ignored, but its values are written into the extension bundle, which anyone can read. Never put a service-account key or any private server key there.

### Configure App Check

1. In the Firebase console, open **App Check** and register the Web app. If it asks for a reCAPTCHA key, create one for the registration. The extension itself can't load reCAPTCHA, so it uses a debug token.
2. Keep `VITE_APP_CHECK_DEBUG=true` in `.env`.
3. Open Decoy, right-click inside the side panel → **Inspect** → **Console**, then click **Test cloud** once. The console prints a debug token.
4. Add the token under App Check → Apps → **Manage debug tokens**. Each Chrome profile has its own. Don't commit or share it.
5. Turn on enforcement for Firebase AI Logic, then run the controlled test below.

## Real-device validation

**Status: on-device passed (temporary profile); cloud and App Check pending.** Tick an item only after seeing it on a real device. Automated tests use a stubbed network and a fake `LanguageModel`, so they can't prove these.

- [x] The side panel shows *Available* for on-device Gemini Nano.
- [x] **Test on-device** returns a reply with the `On-device · Gemini Nano` badge.
- [x] **Test on-device** returns a new reply with the network disconnected.
- [ ] **Test cloud** returns a reply with the `Cloud · Gemini` badge (profile A, debug token registered).
- [ ] App Check enforcement is verified with the controlled test below.

**Evidence for the ticked items.** Chrome 158.0.8127.37 on Windows 11, docked side panel, buttons clicked by a local script, using a **temporary Chrome profile with copied model files**. In online runs the model-download and cloud AI hosts were blocked, and GitHub responses were served from `demo-assessment/`.

| Validation | Build `5e2c5fdf` | Build `c8abda7d` (current) |
|---|---|---|
| Online Nano inference | Passed | Passed |
| Offline Nano inference (Wi-Fi off, confirmed before and after each step) | Passed: two replies and a message scan | **Not tested** |
| Docked side panel | Passed | Passed |
| Message scan and repository explanations on Nano | Passed | Passed |
| Combined assessment and "Do not run" escalation | Not in this build | Passed |
| Right-click **Scan with Decoy** | Handler passed; menu not tested | **Not tested** |
| Default Chrome profile, fresh model download | Not tested | Not tested |
| Firebase cloud inference, App Check enforcement | Pending | Pending |

See [TESTING.md](TESTING.md) for the manual checklist.

### Test Gemini Nano

1. Open the panel and read the status line.
2. *Not downloaded*: click **Download on-device model** (several GB) and wait for *Available*. *Unavailable* or *Not supported*: this device or browser can't run it, so stop and record that. *Check failed*: click **Check again**.
3. Click **Test on-device**. Pass: a reply with the `On-device · Gemini Nano` badge. Record the badge, the reply and the time in ms, or the exact error.

### Test Nano offline

1. Complete the test above first, so the model is already downloaded.
2. Turn Wi-Fi off and unplug any network cable. Confirm that an ordinary website fails to load.
3. Close and reopen the panel, then click **Test on-device**.
4. Pass: a **new** reply with the same badge. This is stronger evidence than the badge alone, which is the SDK's own label.
5. Click **Test cloud** while still offline. It must fail and show no reply.

### Controlled App Check test

A failure before the token is registered proves nothing alone: a wrong API key fails too. So use one build in two Chrome profiles, where the only difference is the registered token. A second profile is needed because a successful App Check token is cached, so deleting the debug token in the console has no immediate effect.

0. In the console, confirm the app is registered under App Check and that Firebase AI Logic shows as **enforced**. Allow time for a change to take effect.
1. **Profile A, token registered:** must succeed. This shows the configuration is valid.
2. **Profile B, same `dist/`, token not registered:** must fail.
3. **Profile A again:** must still succeed, which rules out an outage or quota problem.
4. **Register B's token, then retry in B:** must succeed.

Only 0–4 together show that App Check caused the failure in step 2. To diagnose any step, right-click in the panel → **Inspect** → **Network** and note the status of both calls. This table comes from reading the SDK source and has not been confirmed against a live project:

| `exchangeDebugToken` | `generateContent` | Meaning |
|---|---|---|
| OK | OK | Working |
| Failed | Failed, and the error names App Check | Consistent with enforcement. Confirm with steps 1 and 3 |
| Failed | OK | App Check is **not** enforced |
| OK | Failed | Token accepted. Check the AI Logic setup, model name, quota and API key restrictions |
| Failed | Failed, other error | Configuration problem. Check the API key, project ID and app ID |
| No request | No request | Decoy refused locally: `.env` is not filled in, or the build is old |

When the exchange fails, the SDK still sends the request with a placeholder token. App Check limits who gets an answer; it does not stop the approved text from leaving the device.

If on-device or App Check won't work inside the extension, move `sidepanel.html` and `src/` into a hosted Firebase web app. Keep the extension as a thin right-click menu that opens the web app with the selected text.

## Known limitations

Decoy reduces risk; it does not guarantee safety or complete privacy.

- **Redaction is pattern matching and can miss things**: names inside domains (`daniel-hart.vercel.app`), handles without `@`, digits spelled out as words, keys with spaces inside them, and seed phrases in languages other than English. Ordinary words in short message quotes are sent after consent. Always read the preview.
- **Media files are not inspected** (images, fonts, audio, video, PDF). They are counted and shown, but don't make a scan incomplete. Commands that run such a file with `node`, `python` or a shell are flagged.
- **Static analysis can be evaded**, for example by building strings at runtime or passing data between files. `binding.gyp`, `.npmrc` and devcontainer commands have no dedicated rules. "No known indicators" is not proof of safety.
- **Message rules are English keywords.** Reworded messages can slip through, and ordinary messages can still raise flags. A single weak signal never gives more than *low concern*, and a legitimate installer such as `curl … | sh` shows as *worth checking*.
- **Repository checks cover public GitHub only.** A package downloaded from npm can differ from its repository.
- **Nano can be slow.** A message explanation took about 20 to 48 seconds on the test laptop. A reply that takes over 3 minutes is abandoned; rule findings are unaffected.
- **App Check uses debug tokens in the extension**, because extension pages can't load reCAPTCHA's script. Each browser profile generates its own token, which must be registered before cloud works there.
- **The timeline is kept in memory** and is lost when the panel closes.
- **`npm audit`** reports 4 high entries, all from one package: `@grpc/grpc-js` 1.9.16, pulled in by Firestore inside `firebase` ([GHSA-m9gg-hp2v-232j](https://github.com/advisories/GHSA-m9gg-hp2v-232j), [GHSA-f596-whhp-79r4](https://github.com/advisories/GHSA-f596-whhp-79r4)). Decoy does not import Firestore, and the built bundle contains no gRPC or Firestore module. Don't run `npm audit fix --force`: it downgrades Firebase to 9.14.0. Review again when Firestore is added.

## Commands

- `npm test`: 484 tests covering scanner rules and completeness, message rules and assessment, GitHub fetching, redaction, consent, the cloud payload, timeline linking and the inference guard (against the real SDK browser build, with the network stubbed).
- `npm run typecheck`: TypeScript checks.
- `npm run build`: builds the extension into `dist/`.

## Demo fixture

`demo-assessment/` is a **harmless simulated** malicious coding assessment, together with a sample recruiter message. It is published separately as `prasannaraj12/decoy-demo-assessment`, which the sample message links to. The company and contact details are fictional. It makes no network calls (the endpoint is `.invalid` and disabled), and its "secret" is a fake `DEMO_API_KEY`.

Decoy is inspired by reported recruitment-based attacks on crypto and tech companies. The demo is a simulated scenario, not a reconstruction of any specific incident.

## License

Apache-2.0. See [LICENSE](LICENSE).
