# TriageDesk

An AI assistant for SOC alert triage and log analysis. EECS 3311 (Fall 2026) course project by Hoang Vinh Nguyen.

TriageDesk imports Wazuh alerts and raw logs (Linux auth.log, Apache/Nginx access logs), runs rule-based detections and groups the findings into a prioritised case list. A tool-using AI agent then helps the analyst triage each case, enrich IOCs with threat intelligence, map the case to MITRE ATT&CK, plan the response and draft the incident report. The analyst makes every final decision.

Planned stack: Java 21, JavaFX (GUI), picocli (CLI), an OpenAI-compatible LLM (OpenAI, or a local Ollama model).

## Stage 1: design

- Report: [EECS3311-Project-TriageDesk.pdf](EECS3311-Project-TriageDesk.pdf)
- Full-size UML diagrams: [diagrams/](diagrams)
- PlantUML sources for the diagrams: [puml/](puml)

| Report section | Diagram file |
|---|---|
| 3. UML Class Diagram, Parts 1 to 5 | class-part1-presentation-facade to class-part5-agent (class-full shows all parts together) |
| 5. Use-Case Diagram | usecase |
| 7. Sequence Diagrams, SD01 to SD07 | sd01-import-detect to sd07-dashboard |
