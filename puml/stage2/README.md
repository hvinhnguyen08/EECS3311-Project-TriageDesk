# Stage 2 UML diagrams (as implemented)

These PlantUML sources describe the submitted code; the rendered images are in [`../../diagrams/stage2/`](../../diagrams/stage2/). The Stage 1 design diagrams are kept unchanged one level up for comparison. Differences between the two are explained in [`CHANGES.md`](../../CHANGES.md).

| Diagram | Contents | Patterns shown |
|---|---|---|
| `class-part1-presentation-facade` | JavaFX GUI (views, controllers, `UiTasks`), CLI, `SocAssistant` | MVC, Facade |
| `class-part2-domain-state` | Domain records, `Case`, `CaseState` and its states, `CaseManager` | State |
| `class-part3-ingest-detect` | Parsers, `LogParserFactory`, `EventStore`, detectors, `DetectionEngine` | Factory Method, Strategy |
| `class-part4-intel-attack-report` | `EnrichmentService`, threat-intel adapters, `AttackMapper`, `ReportGenerator` | Adapter, Template Method |
| `class-part5-agent` | `SocAgent`, `LlmClient`s, tools, `ToolRegistry`, `BatchScopedTool` | Command, Strategy, Decorator |
| `class-full` | Overview of all packages and their relations (members in Parts 1 to 5) | all |
| `usecase` | UC01 to UC11 and the external services | |
| `sd01` to `sd07` | Runtime interactions for F01 to F13, using the real class and method names | |

To render them (PlantUML 1.2024+, no Graphviz needed because the class diagrams use the built-in layout):

```
java -DPLANTUML_LIMIT_SIZE=16384 -jar plantuml.jar -tpng -o ../../diagrams/stage2 puml/stage2/*.puml
```

or paste a file into https://www.planttext.com.
