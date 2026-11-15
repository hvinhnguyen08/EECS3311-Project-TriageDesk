# TriageDesk Stage 2 demo video script

One continuous recording, about 18 minutes, with a timestamp per feature. Write the timestamps into the report's demo index (section 7) after recording.

Every segment follows the same pattern the course asks for:
- **Say** the feature ID and name.
- **Show** the input.
- **Run** the feature.
- **Show** the output.
- **Show** one error case.

Each segment uses the GUI and the CLI, so both interfaces appear throughout.

Conventions below:
- **SAY:** words to speak (paraphrase freely).
- **DO:** what to click or type.
- **SHOW:** what should be on screen; pause 2–3 seconds on it.
- Commands are typed in PowerShell in the project folder `V:\YorkU\EECS3311-Project-TriageDesk`.

---

## 0. Before you hit record (off camera)

1. Make sure `.env` has `LLM_PROVIDER=openai` and a working key. **Do not open `.env` on camera**, and close any editor tab that shows it.
2. Open a **new** PowerShell window (no command history on screen), then:
   ```powershell
   cd V:\YorkU\EECS3311-Project-TriageDesk
   C:\tools\maven\bin\mvn.cmd -q package -DskipTests
   $env:TRIAGEDESK_DATA_DIR = "demo-data"
   Clear-Host
   ```
   `demo-data` gives the demo a clean, empty data folder, so case IDs come out as in this script (CASE-0001 SSH, CASE-0002 web scan, CASE-0003 rootkit) and your normal `data` folder is untouched. If you need to re-record, delete the `demo-data` folder and `reports\` first.
3. Increase the terminal font (Ctrl + mouse wheel) so text is readable in the video. Maximise the window.
4. Optional: if you have AbuseIPDB / VirusTotal keys in `.env`, F07 shows real scores; without them it shows `n/a` (that is fine and is explained in F07).
5. Close notifications, email, and other apps. Start the screen recorder (e.g. Win+Alt+R with Xbox Game Bar, or OBS).

---

## 1. Intro (0:00, ~45 s)

**SAY:** "This is TriageDesk, my EECS 3311 Stage 2 project, by Hoang Vinh Nguyen. It is a SOC alert triage assistant: it imports Wazuh alerts and raw logs, runs rule-based detections, groups findings into prioritised cases, and uses a tool-calling AI agent to help triage, enrich, map to MITRE ATT&CK, plan the response and write the report. The analyst makes every final decision. It is Java 21 with a JavaFX GUI and a picocli CLI, both on one facade. I'll go through all 13 features in workflow order."

**DO:** Briefly show the repository in the browser (GitHub page) or the folder tree: `src/`, `samples/`, `README.md`, `CHANGES.md`.

Optional (adds ~30 s): run `mvn test` and show `Tests run: 202, Failures: 0`.

---

## 2. Empty start: F03 and F13 error cases (~45 s)

Showing the empty state first gives two error cases cleanly.

**SAY:** "The data folder is empty. First, what happens with no data."

**DO (CLI):**
```powershell
.\triagedesk.cmd detect
.\triagedesk.cmd stats
```
**SHOW:** `Error: Import a file first` from detect, and `No data. Import a file to begin.` from stats.

**SAY:** "Detection and the dashboard handle an empty data set without crashing."

---

## 3. F01 Import Wazuh alerts (~1 min 15 s)

**SAY:** "F01, import Wazuh alerts. The input is `samples/alerts.json`, one JSON alert per line."

**DO:** Show the input: `Get-Content samples\alerts.json -TotalCount 2` (or open it in an editor for 3 seconds).

**DO (CLI):**
```powershell
.\triagedesk.cmd import samples\alerts.json
```
**SHOW:** `Imported 12 events from alerts.json (wazuh format), skipped 0 unreadable lines`.

**Error case (CLI):**
```powershell
.\triagedesk.cmd import samples\errors\alerts-with-bad-lines.json
```
**SHOW:** `Imported 2 events from alerts-with-bad-lines.json (wazuh format), skipped 3 unreadable lines`.
**SAY:** "Malformed lines are skipped and counted, not fatal."

---

## 4. F02 Import raw logs (~1 min 30 s)

**SAY:** "F02, import raw logs: Linux auth.log and Apache access logs. The format is detected automatically by the Factory Method in `LogParserFactory`."

**DO:** Launch the GUI **from the same PowerShell window** (so it uses `demo-data`):
```powershell
.\triagedesk-gui.cmd
```
The window opens on the **Dashboard** tab (it already counts the alerts from F01).

**DO (GUI):**
1. Click the **Cases and imports** tab.
2. Click **Import files...**.
3. In the dialog, go to `samples`, Ctrl+click `auth.log` and `access.log`, click **Open**.

**SHOW:** the status line reports 35 events from auth.log (auth format) and 51 from access.log (apache format); both files appear in the imported-files list on the left.

**Error case (GUI):** click **Import files...** again, pick `samples\errors\unsupported-format.txt`.
**SHOW:** the "Unsupported file format" error.

**Error case (CLI, optional):** `.\triagedesk.cmd import samples\nope.log` → `Error: File not found: samples\nope.log`.

---

## 5. F03 Rule-based detections (~1 min)

**SAY:** "F03, detections. Four detector strategies run over all events: Wazuh alerts of level 7 or more, SSH brute force, a successful login after failures, and web scanning. Thresholds are configurable in `.env`."

**DO (GUI):** click **Run detections**.

**SHOW:** the status line says 8 findings; the case table fills with 3 cases.

**SAY:** "Eight findings: five Wazuh alerts, the brute force and the successful `deploy` login from 203.0.113.7, and the web scan from 198.51.100.23. Running detections again does not duplicate anything."

**DO:** click **Run detections** a second time; **SHOW** the case count stays at 3.

---

## 6. F05 Prioritised case list (~1 min)

**SAY:** "F05, the prioritised case queue. Related findings share a case by source IP, or by host when there is no IP, within 60 minutes. Severity is the highest finding; priority adds points for extra findings and agreeing detectors."

**SHOW (GUI):** the case table, coloured by severity: CASE-0001 SSH compromise (HIGH, 80, 4 findings), CASE-0003 rootkit on db01 (CRITICAL, 80), CASE-0002 web scan (HIGH, 75).

**DO (CLI):**
```powershell
.\triagedesk.cmd cases
```
**SHOW:** the same three cases: the CLI and GUI share data.

**Error case (CLI):**
```powershell
.\triagedesk.cmd show CASE-9999
```
**SHOW:** `Error: No case with ID CASE-9999`.

---

## 7. F04 AI log summary (~1 min 30 s)

**SAY:** "F04, AI log summary. The agent summarises one imported file. Its tools are restricted to that file by the `BatchScopedTool` decorator."

**DO (GUI):** on **Cases and imports**, select `auth.log` in the file list on the left, click **Summarise with AI**. Wait for the progress indicator.

**SHOW:** the **AI log summary** panel: it should lead with the brute force followed by the successful `deploy` login. Scroll to the **Tool calls** list and point at a `search_events` / `count_by` call.

**SAY:** "Every fact can be checked against the tool calls, which ran on the real imported data."

**Error case (CLI):**
```powershell
.\triagedesk.cmd summarize missing.log
```
**SHOW:** `Error: No imported file named 'missing.log'. Imported files: ...`.

---

## 8. F09 Case lifecycle and notes, part 1 (~1 min 15 s)

(Shown before triage so the State-pattern error is clean while the case is NEW.)

**SAY:** "F09, case lifecycle. Cases follow the State pattern: NEW, INVESTIGATING, ESCALATED, CLOSED. A state only allows certain actions."

**Error case first (CLI):**
```powershell
.\triagedesk.cmd status CASE-0001 escalate -m "too early"
```
**SHOW:** `Error: Cannot escalate a case that is NEW. Allowed: start, close`.

**DO (GUI):** double-click **CASE-0001** in the case table to open its tab.
**SHOW:** findings and evidence timeline on the left. Point out that **Escalate...** is greyed out and only **Start investigation** and **Close...** are enabled.

**DO (GUI):** click **Start investigation**.
**SHOW:** the state becomes INVESTIGATING and **Escalate...** is now enabled.

(The rest of F09 is in section 14.)

---

## 9. F06 AI triage (~1 min 30 s)

**SAY:** "F06, AI triage. The agent investigates the case with its tools and returns a validated JSON verdict with confidence and reasoning. Anything invalid becomes NEEDS_REVIEW."

**DO (GUI):** in the CASE-0001 tab, open the **AI triage and response** sub-tab, click **AI triage**.

**SHOW:** verdict (expected TRUE_POSITIVE), confidence, and the reasoning: brute force, successful `deploy` login, the denied sudo and the `authorized_keys` change. Scroll the tool-call list.

**DO (CLI):** show the same verdict stored on the case:
```powershell
.\triagedesk.cmd show CASE-0001
```

**Error case:** close CASE-0002 **in the GUI** (not the CLI, see the note at the top of section 12), then try to triage it in the CLI:
1. **DO (GUI):** go back to **Cases and imports**, double-click **CASE-0002**, click **Close...**, choose **true positive**, comment `Scanner blocked at the WAF`, OK.
2. **DO (CLI):**
   ```powershell
   .\triagedesk.cmd triage CASE-0002
   ```
**SHOW:** triage of a CLOSED case is refused. CASE-0002 is not used again until the dashboard, where it counts as a closed case.

---

## 10. F07 IOC enrichment (~1 min)

**SAY:** "F07, threat-intel enrichment. IOCs are extracted from the case and looked up through the Adapter pattern: AbuseIPDB and VirusTotal adapters built on a Template Method base class. Results are cached for 24 hours; private IPs are never sent out."

**DO (GUI):** in CASE-0001, open **Indicators and ATT&CK**, click **Enrich IOCs**.

**SHOW:** the IOC table (203.0.113.7 and others) with scores and the source text.

**SAY (pick the one that applies):**
- With keys: "The sample data uses reserved documentation addresses, so the real services report them as clean."
- Without keys: "No API keys are configured here, so each lookup shows score n/a instead of failing. This is the graceful-degradation error case."

**DO (CLI, shows caching):**
```powershell
.\triagedesk.cmd enrich CASE-0001
```
**SHOW:** the same results returned quickly (cache).

---

## 11. F08 MITRE ATT&CK mapping (~1 min 15 s)

**SAY:** "F08, ATT&CK mapping. Technique IDs from Wazuh and the detectors are resolved in a bundled catalogue of 96 techniques. The AI can suggest more, and only IDs in the catalogue are kept."

**DO (GUI):** in **Indicators and ATT&CK**, tick **also ask the AI**, click **Map to ATT&CK**.

**SHOW:** the technique table with a source column: T1110.001 / T1110 / T1078 *from detection*, and T1548.003 (Sudo and Sudo Caching) *from AI* for the denied sudo.

**DO (CLI, deterministic only):**
```powershell
.\triagedesk.cmd map CASE-0003
```
**SHOW:** the rootkit case's technique from the Wazuh alert, no AI call.

**Error case:** `.\triagedesk.cmd map CASE-9999` → `Error: ...`. If the AI suggested an ID outside the catalogue, the output lists it as rejected; point at it if it appears.

---

## 12. F10 Response recommendations (~1 min 15 s)

**SAY:** "F10, response recommendations. It needs a triage verdict first."

**Error case first (CLI):**
```powershell
.\triagedesk.cmd respond CASE-0003
```
**SHOW:** `Error: Run AI Triage first: CASE-0003 has no verdict yet`.

**DO (GUI):** back in CASE-0001, **AI triage and response** sub-tab, click **Recommend response**.

**SHOW:** 3 to 8 ordered steps naming 203.0.113.7, the `deploy` account and web01, each with its reason.

**DO:** tick the first two step check boxes.

**DO (CLI):** read the case from the saved data:
```powershell
.\triagedesk.cmd show CASE-0001
```
**SHOW:** steps 1–2 marked done (GUI and CLI agree).

> **Note:** the GUI reads the saved cases only when it starts. While it is open, **change cases in the GUI and only read them in the CLI** (`cases`, `show`). A change made in the CLI to a case the GUI then changes again (for example `done CASE-0001 3`) is overwritten by the GUI and not shown there. The CLI changes in this script only touch CASE-0003, which the GUI does not change.

---

## 13. F11 Incident report (~1 min 30 s)

**SAY:** "F11, the incident report. Case facts, timeline, IOCs, techniques, verdict and plan come straight from the case data. Only the executive summary and analysis come from the AI, and they are labelled AI-generated."

**DO (GUI):** in CASE-0001 click **Generate report**, then click the **Open report:** link.

**SHOW:** `reports/CASE-0001.md` opens. Scroll through: executive summary (AI-generated label), findings, timeline, IOCs, ATT&CK, verdict, response plan, history.

**Error case (CLI): AI unavailable.** This overrides the key for this one command only; the real key is not shown:
```powershell
$env:LLM_API_KEY = "invalid"
.\triagedesk.cmd report CASE-0003
Remove-Item Env:LLM_API_KEY
```
**SHOW:** a warning that the AI narrative is unavailable, and the report is still written with `[AI narrative unavailable]`.

---

## 14. F09 Case lifecycle and notes, part 2 (~1 min)

**DO (GUI):** in CASE-0001:
1. Click **Escalate...** → dialog "Why does this case need L2 / incident response?" → type `deploy account compromised via SSH brute force` → OK.
2. Open **Notes and history**, type `Disabled the deploy account and rotated SSH keys` in the note box, press Enter.
3. Click **Close...** → choose resolution **true positive**, comment `Contained; keys rotated` → OK.

**SHOW:** the history lists every transition and the note with timestamps; only **Reopen** is enabled now.

**DO (CLI):**
```powershell
.\triagedesk.cmd note CASE-0003 Escalated to the DB team for rootkit check
.\triagedesk.cmd status CASE-0003 close -m "no resolution given"
```
**SHOW:** `Error: Close the case as true_positive, false_positive or benign` (the `--as` resolution is required).

---

## 15. F12 Ask the Agent (~1 min 30 s)

**SAY:** "F12, Ask the Agent: free-form questions answered with tool calls on the imported data, with the tokens used."

**DO (GUI):** click the **Ask the Agent** tab. Click one of the **Try:** example questions, then type your own and press Enter:
`Which IPs failed SSH login more than 10 times, and did any of them later log in?`

**SHOW:** the answer (203.0.113.7, then the `deploy` login), its tool calls, and the "Answered with ... tokens" line.

**Error case (CLI):** a question about data that is not there:
```powershell
.\triagedesk.cmd ask Were there any events from 10.9.9.9?
```
**SHOW:** the agent searches and says it found none, rather than inventing events.
Optionally: `.\triagedesk.cmd ask` with no question → usage error.

---

## 16. F13 Dashboard (~1 min)

**SAY:** "F13, the dashboard."

**DO (GUI):** click the **Dashboard** tab (it refreshes when selected).

**SHOW:** tiles (events, files, open and closed cases), bar charts of the top source IPs and accounts, the pie chart of cases by state (now with closed cases), and the imported-file list.

**DO (CLI):**
```powershell
.\triagedesk.cmd stats
```
**SHOW:** the same numbers in text. (The empty-data error case was shown in section 2.)

---

## 17. Wrap-up (~30 s)

**SAY:** "That covers all 13 features in both the GUI and the CLI, with an error case for each. The design patterns are MVC, Facade, Strategy, Factory Method, Adapter, State, Command, Decorator and Template Method. The details, the changes from Stage 1 and the UML are in the stage 2 report. Thanks for watching."

Stop recording. Close the GUI.

---

## After recording

1. Upload the video (YouTube **Unlisted**, or OneDrive/Google Drive with "anyone with the link can view"). Open the link in a private window to check it plays without signing in.
2. Write down the start time of each section and put them in the report:

   | Feature | Section | Timestamp |
   |---|---|---|
   | F01 Import Wazuh alerts | 3 | |
   | F02 Import raw logs | 4 | |
   | F03 Detections | 2, 5 | |
   | F04 AI log summary | 7 | |
   | F05 Case list | 6 | |
   | F06 AI triage | 9 | |
   | F07 IOC enrichment | 10 | |
   | F08 ATT&CK mapping | 11 | |
   | F09 Case lifecycle and notes | 8, 14 | |
   | F10 Response recommendations | 12 | |
   | F11 Incident report | 13 | |
   | F12 Ask the Agent | 15 | |
   | F13 Dashboard | 2, 16 | |

   YouTube links can jump to a time: `https://youtu.be/VIDEO_ID?t=245` (seconds).
3. Before sharing, scrub through the video once to check that no API key, `.env` content or personal notification appears.
4. Delete the `demo-data` folder and `reports\CASE-000*.md` from the demo if you don't want them in the repo (both should stay uncommitted).

### If something goes wrong on camera

- **AI call is slow or times out:** wait; if it fails, say "the provider timed out, which is shown as an error and the case is unchanged", then click the button again.
- **Different case numbers:** the `demo-data` folder was not empty. Delete it and restart the GUI and terminal steps.
- **GUI shows other data than the CLI:** the GUI was not started from the PowerShell window where `TRIAGEDESK_DATA_DIR` was set.
