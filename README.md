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
```

GUI and CLI launch commands will be added here as those parts are implemented.

### Project layout

| Package | Contents |
|---|---|
| `ca.yorku.triagedesk.config` | `AppConfig`: loads `.env` and environment variables |
| `ca.yorku.triagedesk.domain` | `SecurityEvent`, `Finding`, `Case`, `Ioc`, `AttackTechnique`, `TriageVerdict`, `ResponsePlan`, `DashboardStats`, `AgentResult`, `Severity`, `Verdict` |
| `ca.yorku.triagedesk.ingest` | `LogParserFactory` (Factory Method), `LogParser` and `WazuhAlertParser`, `AuthLogParser`, `ApacheLogParser`; `EventStore` (events in memory and in `data/events.jsonl`) |
| `ca.yorku.triagedesk.detect` | `DetectionEngine` (Strategy context) and the `Detector` strategies `WazuhAlertDetector`, `BruteForceDetector`, `SuccessAfterFailureDetector`, `WebScanDetector` |
| `ca.yorku.triagedesk.casemgmt` | `CaseManager`: groups findings into prioritised cases, applies lifecycle actions and notes, and saves each case to `data/cases/CASE-nnnn.json`; `CaseState` and `NewState`, `InvestigatingState`, `EscalatedState`, `ClosedState` (State pattern) |
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
