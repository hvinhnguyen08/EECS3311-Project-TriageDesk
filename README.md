# TriageDesk: diagram kit for the Stage 1 report

Only the diagrams the Stage 1 instructions require are included: the class diagram, the use-case diagram and the sequence diagrams.

| Report section | Reference image (png/) | Source (plantuml/) |
|---|---|---|
| 3. Class diagram, Part 1 | class-part1-presentation-facade.png | class-part1-presentation-facade.puml |
| 3. Class diagram, Part 2 | class-part2-domain-state.png | class-part2-domain-state.puml |
| 3. Class diagram, Part 3 | class-part3-ingest-detect.png | class-part3-ingest-detect.puml |
| 3. Class diagram, Part 4 | class-part4-intel-attack-report.png | class-part4-intel-attack-report.puml |
| 3. Class diagram, Part 5 | class-part5-agent.png | class-part5-agent.puml |
| 3. Class diagram, all parts on one page (optional) | class-full.png | class-full.puml |
| 5. Use-case diagram | usecase.png | usecase.puml |
| 7. SD01 to SD07 | sd01-...png to sd07-...png | sd01-...puml to sd07-...puml |

Every class, method and call in these files matches the report. The sequence diagrams were checked automatically against the class diagram.

## Tools you can use

### 1. PlantUML: the exact same diagrams, fastest

Each `.puml` file is plain text that produces the diagram.

1. Open https://www.planttext.com or https://www.plantuml.com/plantuml.
2. Paste the whole contents of a `.puml` file.
3. Download the result as PNG or SVG.

To change something, such as a method name, edit the text and render again. Every file is self-contained, so nothing else needs to be installed.

### 2. draw.io (diagrams.net): if you want to draw them by hand

draw.io is free and works in the browser. It can save straight to Google Drive.

- **Redraw:** turn on the UML shape library (More Shapes, then UML). Copy each diagram box by box, using the PNG in `png/` as your reference.
- **Import:** draw.io can also create a diagram from PlantUML text through Arrange > Insert > Advanced > PlantUML. The result is edited by changing the text, not by dragging shapes.

### 3. StarUML or Visual Paradigm Community Edition

These are dedicated UML desktop tools. Use them if you prefer a traditional UML editor.

## Inserting the diagrams into the Google Doc

1. Replace each yellow `[Insert ... here]` placeholder: Insert > Image > Upload from computer.
2. Drag the image to the full page width.
3. If a diagram is still hard to read, put it on its own landscape page:
   - Add a section break before and after it (Insert > Break > Section break).
   - Choose File > Page setup, set the orientation to Landscape, and apply it to "This section".
4. Export the report with File > Download > PDF.
