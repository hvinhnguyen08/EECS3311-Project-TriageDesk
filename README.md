# TriageDesk

An AI assistant for SOC alert triage and log analysis. EECS 3311 (Fall 2026) course project by Hoang Vinh Nguyen.

TriageDesk imports Wazuh alerts and raw logs (Linux auth.log, Apache/Nginx access logs), runs rule-based detections and groups the findings into a prioritised case list. A tool-using AI agent then helps the analyst triage each case, enrich IOCs with threat intelligence, map the case to MITRE ATT&CK, plan the response and draft the incident report. The analyst makes every final decision.

Stack: Java 21, Maven, JavaFX (GUI), picocli (CLI), an OpenAI-compatible LLM (OpenAI, Groq, OpenRouter, or a local Ollama model).

## Stage 2: implementation (in progress)

### Prerequisites

- JDK 21 (for example Eclipse Temurin 21)
- Maven 3.9 or newer
- Git

Check with `java -version` and `mvn -v`.

### Local configuration and API keys

Real keys live only in a local `.env` file, which `.gitignore` excludes. Never commit it.

1. Copy the example configuration:
   - Windows (PowerShell): `Copy-Item .env.example .env`
   - macOS/Linux: `cp .env.example .env`
2. Edit `.env`:
   - `LLM_PROVIDER=openai` to use a real model, or `mock` to run offline with scripted replies.
   - `LLM_BASE_URL`, `LLM_MODEL` and `LLM_API_KEY` for any OpenAI-compatible endpoint. For Ollama use `LLM_BASE_URL=http://localhost:11434/v1` and any non-empty key.
   - `ABUSEIPDB_API_KEY` and `VIRUSTOTAL_API_KEY` are optional; a provider without a key is skipped.

Environment variables with the same names override the values in `.env`.

### Build and test

```
mvn test
mvn package
```

`mvn package` runs the tests and builds `target/triagedesk.jar` with all dependencies.

### Command-line interface

Run the CLI with `.\triagedesk.cmd` on Windows (PowerShell needs the `.\`) or `./triagedesk` on macOS/Linux. Both run `java -jar target/triagedesk.jar`, so `java` must be on your PATH. The examples below write `triagedesk` for short. Data is kept in `./data` unless `TRIAGEDESK_DATA_DIR` or `--data-dir DIR` says otherwise, so each command sees what earlier commands imported.

| Command | Feature | Example |
|---|---|---|
| `import FILE...` | F01, F02 | `triagedesk import samples/alerts.json samples/auth.log samples/access.log` |
| `detect` | F03, F05 | `triagedesk detect` |
| `cases` | F05 | `triagedesk cases` |
| `show CASE_ID` | F05, F09 | `triagedesk show CASE-0001` |
| `status CASE_ID ACTION [-m TEXT] [--as RESOLUTION]` | F09 | `triagedesk status CASE-0001 escalate -m "deploy account compromised"`<br>`triagedesk status CASE-0002 close --as true_positive -m "Blocked at the WAF"` |
| `note CASE_ID TEXT...` | F09 | `triagedesk note CASE-0001 Disabled the deploy account` |
| `stats` | F13 | `triagedesk stats` |
| `enrich CASE_ID` | F07 | `triagedesk enrich CASE-0001` |
| `triage CASE_ID` | F06 | `triagedesk triage CASE-0001` |
| `summarize FILE_NAME` | F04 | `triagedesk summarize auth.log` |
| `ask QUESTION...` | F12 | `triagedesk ask Which IPs failed SSH login more than 10 times?` |

`triagedesk --help` and `triagedesk COMMAND --help` describe every option. Errors are printed as one `Error: ...` line and the command exits with code 1.

Example session on the sample data:

```
> triagedesk import samples/alerts.json samples/auth.log samples/access.log
Imported 12 events from alerts.json (wazuh format), skipped 0 unreadable lines
Imported 35 events from auth.log (auth format), skipped 0 unreadable lines
Imported 51 events from access.log (apache format), skipped 0 unreadable lines
> triagedesk detect
Detectors found 8 findings.
3 case(s) created or updated:
ID         STATE         SEVERITY PRI FIND  TITLE
CASE-0001  NEW           HIGH      80    4  Brute force from 203.0.113.7: 13 failed logins in 2m31s against 4 accounts (+...
CASE-0003  NEW           CRITICAL  80    1  Wazuh rule 510 (level 12): Host-based anomaly detection event (rootcheck): Tr...
CASE-0002  NEW           HIGH      75    3  Wazuh rule 31151 (level 10): Web server 400 error code: multiple attempts fro...
> triagedesk status CASE-0001 escalate -m "too early"
Error: Cannot escalate a case that is NEW. Allowed: start, close
> triagedesk status CASE-0001 start
CASE-0001 is now INVESTIGATING.
```

Closing accepts `tp` and `fp` as short forms of `true_positive` and `false_positive`.

### Project layout

| Package | Contents |
|---|---|
| `ca.yorku.triagedesk.cli` | `TriageDeskCli`: picocli command-line interface |
| `ca.yorku.triagedesk.facade` | `SocAssistant` (Facade): one method per feature, used by the CLI and the GUI |
| `ca.yorku.triagedesk.config` | `AppConfig`: loads `.env` and environment variables |
| `ca.yorku.triagedesk.domain` | `SecurityEvent`, `Finding`, `Case`, `Ioc`, `AttackTechnique`, `TriageVerdict`, `ResponsePlan`, `DashboardStats`, `AgentResult`, `Severity`, `Verdict` |
| `ca.yorku.triagedesk.ingest` | `LogParserFactory` (Factory Method), `LogParser` and `WazuhAlertParser`, `AuthLogParser`, `ApacheLogParser`; `EventStore` (events in memory and in `data/events.jsonl`) |
| `ca.yorku.triagedesk.detect` | `DetectionEngine` (Strategy context) and the `Detector` strategies `WazuhAlertDetector`, `BruteForceDetector`, `SuccessAfterFailureDetector`, `WebScanDetector` |
| `ca.yorku.triagedesk.casemgmt` | `CaseManager`: groups findings into prioritised cases, applies lifecycle actions and notes, and saves each case to `data/cases/CASE-nnnn.json`; `CaseState` and `NewState`, `InvestigatingState`, `EscalatedState`, `ClosedState` (State pattern) |
| `ca.yorku.triagedesk.agent` | `SocAgent` (tool-use loop, triage, summary, answers); `Tool` commands `SearchEventsTool`, `CountByTool` in a `ToolRegistry` (Command), `BatchScopedTool` (Decorator); `LlmClient` (Strategy) with `OpenAiClient` (any OpenAI-compatible service: OpenAI, Groq, OpenRouter, Ollama) and `MockLlmClient` (offline, scripted); `ChatMessage`, `ToolCall`, `LlmReply` |
| `ca.yorku.triagedesk.intel` | `EnrichmentService` (IOC extraction, lookups, 24 h cache), `IocExtractor`; `ThreatIntelProvider` with the adapters `AbuseIpDbAdapter` and `VirusTotalAdapter` (Adapter) built on `RestIntelAdapter` (Template Method) |
| `ca.yorku.triagedesk.util` | `Json`: shared Jackson configuration |

### Detection rules

| Detector | Fires when (defaults, configurable in `.env`) | Severity | ATT&CK |
|---|---|---|---|
| `WazuhAlertDetector` | Wazuh alert with rule level 7 or higher (`DETECT_WAZUH_MIN_LEVEL`); repeated alerts of one rule for one IP/host are merged | from rule level | from the alert |
| `BruteForceDetector` | 10 or more failed logins from one IP within 5 minutes (`DETECT_BRUTE_FORCE_*`) | HIGH | T1110.001 |
| `SuccessAfterFailureDetector` | a successful login from an IP with 5 or more failures in the previous 10 minutes (`DETECT_SUCCESS_AFTER_FAILURE_*`) | HIGH | T1110, T1078 |
| `WebScanDetector` | 30 or more HTTP 404 responses to one IP within 2 minutes (`DETECT_WEB_SCAN_*`) | MEDIUM | T1595.003 |

On the three sample files together the detectors produce 8 findings: 5 Wazuh alerts, the SSH brute force and the successful `deploy` login from 203.0.113.7, and the web scan from 198.51.100.23.

### Cases

Related findings share a case: the same source IP, or the same host for a finding without an IP, within 60 minutes. A case's severity is the highest of its findings; its priority (0 to 100) is 20 per severity level plus 5 per extra finding (at most 15) plus 5 when more than one detector agrees. Running detections again does not duplicate anything. The 8 sample findings become 3 cases: the SSH compromise of `deploy` on web01 (4 findings, priority 80), the rootkit alert on db01 (CRITICAL, 80) and the web scan and SQL injection from 198.51.100.23 (3 findings, 75).

### How the agent works

`SocAgent.runLoop` sends the task and the tools allowed for it to the model. When the model asks for a tool, the agent runs it on the imported data and sends the result back; this repeats until the model answers or `LLM_MAX_STEPS` (default 6) is reached, after which the model is asked once, without tools, for its best answer and the result is marked incomplete. Tool errors (for example an unknown filter) are returned to the model so it can correct the call. Every call is recorded in a tool trace shown to the analyst, so each fact in an answer can be checked.

| Tool | What it does |
|---|---|
| `search_events` | Events matching filters (batchId, source, host, user, srcIp, category, ruleId, text, since, until, minLevel): total count plus up to 50 events |
| `count_by` | Counts of matching events grouped by a field (srcIp, user, host, ..., or an attribute such as status), largest first |
| `lookup_ioc` | Reputation (0 to 100) of an IP, domain, URL or hash from AbuseIPDB and VirusTotal; private IPs are never sent out (triage and questions only) |

The AI commands (`triage`, `summarize`, `ask`) print the agent's answer, every tool call it made, and the tokens used. `triage` stores the verdict on the case and moves a NEW case to INVESTIGATING; anything that is not a valid JSON verdict, or a run that hit the step limit, is stored as NEEDS_REVIEW. `summarize` limits the tools to the chosen file. With `LLM_PROVIDER=mock` the commands run offline: they make real tool calls but say clearly that no model assessed the data.

### Threat-intel enrichment

`enrich CASE_ID` extracts the case's IPv4 addresses, URLs (and their domains) and MD5/SHA-1/SHA-256 hashes, looks each one up with every configured service and stores the result on the case. Free API keys from [AbuseIPDB](https://www.abuseipdb.com/) (IPs) and [VirusTotal](https://www.virustotal.com/) (IPs, domains, URLs, hashes) go in `.env` as `ABUSEIPDB_API_KEY` and `VIRUSTOTAL_API_KEY`; a service without a key is skipped and its indicators are listed with score `n/a`. Private addresses are never sent out, results are cached for 24 hours in `data/intel-cache.json`, and a timeout or rate limit only marks that service's answer as unavailable. The sample data uses reserved documentation addresses, so real services report them as clean.

### Case lifecycle

| State | Allowed actions | Next state |
|---|---|---|
| NEW | `start`, `close` | INVESTIGATING, CLOSED |
| INVESTIGATING | `escalate` (reason required), `close` | ESCALATED, CLOSED |
| ESCALATED | `close` | CLOSED |
| CLOSED | `reopen` | INVESTIGATING |

Closing requires a resolution (`true_positive`, `false_positive` or `benign`) and a comment. Any other action is refused with a message listing the allowed ones, and the case is left unchanged. Recording an AI verdict moves a NEW case to INVESTIGATING. Every transition and note is timestamped in the case history.

### Supported input formats and sample data

| Format | Detected by | Sample file |
|---|---|---|
| Wazuh `alerts.json` (one JSON alert per line) | first line starts with `{` | [samples/alerts.json](samples/alerts.json) |
| Linux `auth.log` (classic or ISO syslog prefix) | syslog prefix | [samples/auth.log](samples/auth.log) |
| Apache/Nginx access log (common or combined) | access-log line | [samples/access.log](samples/access.log) |

The samples are synthetic and use only documentation IP ranges (203.0.113.0/24, 198.51.100.0/24), private addresses and example domains. They contain an SSH brute force followed by a successful login (203.0.113.7), a web directory scan and SQL injection attempt (198.51.100.23), and normal activity. [samples/errors/](samples/errors/) holds files for demonstrating the error cases: an alerts file with malformed lines and a file in an unsupported format.

Differences from the Stage 1 design are recorded in [CHANGES.md](CHANGES.md).

## Stage 1: design

- Report: [EECS3311-Project-TriageDesk.pdf](EECS3311-Project-TriageDesk.pdf)
- Full-size UML diagrams: [diagrams/](diagrams/)
- PlantUML sources for the diagrams: [puml/](puml/)

| Report section | Diagram file |
|---|---|
| 3. UML Class Diagram, Parts 1 to 5 | `class-part1-presentation-facade` to `class-part5-agent` (`class-full` shows all parts together) |
| 5. Use-Case Diagram | `usecase` |
| 7. Sequence Diagrams, SD01 to SD07 | `sd01-import-detect` to `sd07-dashboard` |
