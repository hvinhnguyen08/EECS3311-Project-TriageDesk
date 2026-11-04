package ca.yorku.triagedesk.gui;

import ca.yorku.triagedesk.casemgmt.CaseActions;
import ca.yorku.triagedesk.domain.AttackTechnique;
import ca.yorku.triagedesk.domain.Case;
import ca.yorku.triagedesk.domain.Finding;
import ca.yorku.triagedesk.domain.Ioc;
import ca.yorku.triagedesk.domain.ResponsePlan;
import ca.yorku.triagedesk.domain.SecurityEvent;
import ca.yorku.triagedesk.domain.TriageVerdict;
import java.nio.file.Path;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.IntConsumer;
import javafx.beans.property.ReadOnlyObjectWrapper;
import javafx.collections.FXCollections;
import javafx.geometry.Insets;
import javafx.geometry.Orientation;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.ButtonType;
import javafx.scene.control.CheckBox;
import javafx.scene.control.ChoiceBox;
import javafx.scene.control.Dialog;
import javafx.scene.control.Hyperlink;
import javafx.scene.control.Label;
import javafx.scene.control.ListView;
import javafx.scene.control.ProgressIndicator;
import javafx.scene.control.ScrollPane;
import javafx.scene.control.SplitPane;
import javafx.scene.control.Tab;
import javafx.scene.control.TabPane;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.control.TextInputDialog;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;

/** JavaFX implementation of the case screen. */
public class CaseViewFx implements CaseView {

    private final BorderPane root = new BorderPane();
    private final Label header = new Label();
    private final Label title = new Label();
    private final Button startButton = new Button("Start investigation");
    private final Button escalateButton = new Button("Escalate...");
    private final Button closeButton = new Button("Close...");
    private final Button reopenButton = new Button("Reopen");
    private final Button reportButton = new Button("Generate report");
    private final Hyperlink reportLink = new Hyperlink();

    private final TableView<Finding> findings = new TableView<>();
    private final TableView<SecurityEvent> timeline = new TableView<>();

    private final Button triageButton = new Button("AI triage");
    private final Label verdict = new Label("Not triaged yet.");
    private final TextArea reasoning = new TextArea();
    private final ListView<String> trace = new ListView<>();
    private final Button respondButton = new Button("Recommend response");
    private final VBox planBox = new VBox(4);

    private final Button enrichButton = new Button("Enrich IOCs");
    private final TableView<Ioc> iocs = new TableView<>();
    private final Button mapButton = new Button("Map to ATT&CK");
    private final CheckBox askAi = new CheckBox("also ask the AI");
    private final TableView<AttackTechnique> techniques = new TableView<>();

    private final ListView<String> notes = new ListView<>();
    private final TextField noteInput = new TextField();
    private final Button addNoteButton = new Button("Add note");
    private final ListView<String> history = new ListView<>();

    private final Label status = new Label("Ready.");
    private final ProgressIndicator busy = new ProgressIndicator();

    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneOffset.UTC);

    private IntConsumer onStepDone = n -> { };
    private final Consumer<Path> reportOpener;
    private Path lastReport;

    /** @param reportOpener opens a written report (for example in the system's default app) */
    public CaseViewFx(Consumer<Path> reportOpener) {
        this.reportOpener = reportOpener;
        header.getStyleClass().add("case-header");
        title.getStyleClass().add("case-title");
        title.setWrapText(true);
        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);
        HBox actions = new HBox(6, startButton, escalateButton, closeButton, reopenButton, spacer, reportButton);
        actions.setAlignment(Pos.CENTER_LEFT);
        reportLink.setMnemonicParsing(false);
        reportLink.setOnAction(e -> {
            if (lastReport != null) {
                reportOpener.accept(lastReport);
            }
        });
        VBox top = new VBox(4, header, title, actions, reportLink);
        top.setPadding(new Insets(10, 10, 6, 10));
        root.setTop(top);

        buildTables();
        VBox findingsBox = MainViewFx.box(MainViewFx.heading("Findings"), findings);
        VBox.setVgrow(findings, Priority.ALWAYS);
        VBox timelineBox = MainViewFx.box(MainViewFx.heading("Evidence timeline"), timeline);
        VBox.setVgrow(timeline, Priority.ALWAYS);
        SplitPane left = new SplitPane(findingsBox, timelineBox);
        left.setOrientation(Orientation.VERTICAL);
        left.setDividerPositions(0.35);

        TabPane right = new TabPane(
                new Tab("AI triage and response", aiPane()),
                new Tab("Indicators and ATT&CK", intelPane()),
                new Tab("Notes and history", notesPane()));
        right.getTabs().forEach(t -> t.setClosable(false));

        SplitPane centre = new SplitPane(left, right);
        centre.setDividerPositions(0.6);
        root.setCenter(centre);

        busy.setPrefSize(16, 16);
        busy.setVisible(false);
        HBox statusBar = new HBox(8, busy, status);
        statusBar.setPadding(new Insets(4, 8, 4, 8));
        statusBar.getStyleClass().add("status-bar");
        root.setBottom(statusBar);
    }

    public Node getRoot() {
        return root;
    }

    private Node aiPane() {
        verdict.getStyleClass().add("verdict");
        reasoning.setEditable(false);
        reasoning.setWrapText(true);
        reasoning.setPrefRowCount(6);
        trace.setPrefHeight(120);
        trace.setPlaceholder(new Label("The agent's tool calls appear here."));
        planBox.setPadding(new Insets(2, 0, 0, 0));
        VBox box = MainViewFx.box(
                new HBox(8, MainViewFx.heading("Verdict"), triageButton), verdict, reasoning,
                new Label("Tool calls"), trace,
                new HBox(8, MainViewFx.heading("Response plan"), respondButton), planBox);
        ScrollPane scroll = new ScrollPane(box);
        scroll.setFitToWidth(true);
        return scroll;
    }

    private Node intelPane() {
        iocs.setPlaceholder(new Label("Not enriched yet."));
        techniques.setPlaceholder(new Label("Not mapped yet."));
        VBox box = MainViewFx.box(
                new HBox(8, MainViewFx.heading("Indicators of compromise"), enrichButton), iocs,
                new HBox(8, MainViewFx.heading("MITRE ATT&CK"), mapButton, askAi), techniques);
        VBox.setVgrow(iocs, Priority.ALWAYS);
        VBox.setVgrow(techniques, Priority.ALWAYS);
        return box;
    }

    private Node notesPane() {
        noteInput.setPromptText("Type a note and press Enter");
        HBox.setHgrow(noteInput, Priority.ALWAYS);
        notes.setPlaceholder(new Label("No notes yet."));
        VBox box = MainViewFx.box(MainViewFx.heading("Analyst notes"), notes, new HBox(6, noteInput, addNoteButton),
                MainViewFx.heading("History"), history);
        VBox.setVgrow(notes, Priority.ALWAYS);
        VBox.setVgrow(history, Priority.ALWAYS);
        return box;
    }

    private void buildTables() {
        findings.getColumns().setAll(List.of(
                col("Detector", Finding::detector, 130), col("Severity", f -> f.severity().name(), 75),
                col("Finding", Finding::title, 380), col("First seen", f -> TIME.format(f.firstSeen()), 140),
                col("Events", f -> f.events().size(), 55)));
        timeline.getColumns().setAll(List.of(
                col("Time (UTC)", e -> TIME.format(e.timestamp()), 140), col("Source", SecurityEvent::source, 62),
                col("Host", SecurityEvent::host, 58), col("User", SecurityEvent::user, 62),
                col("Source IP", SecurityEvent::srcIp, 100), col("Event", SecurityEvent::message, 420)));
        for (TableColumn<?, ?> c : timeline.getColumns().subList(0, 5)) {
            c.setMinWidth(c.getPrefWidth());
        }
        findings.getColumns().get(4).setMinWidth(55);
        iocs.getColumns().setAll(List.of(
                col("Type", Ioc::type, 60), col("Value", Ioc::value, 200),
                col("Score", i -> i.isScored() ? String.valueOf(i.score()) : "n/a", 55), col("Source", Ioc::source, 360)));
        techniques.getColumns().setAll(List.of(
                col("ID", AttackTechnique::id, 85), col("Technique", AttackTechnique::name, 220),
                col("Tactics", AttackTechnique::tactic, 300)));
        for (TableView<?> t : List.of(findings, timeline, iocs, techniques)) {
            t.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN);
        }
    }

    private static <T> TableColumn<T, Object> col(String name, Function<T, Object> value, double width) {
        TableColumn<T, Object> c = new TableColumn<>(name);
        c.setCellValueFactory(cd -> new ReadOnlyObjectWrapper<>(value.apply(cd.getValue())));
        c.setPrefWidth(width);
        return c;
    }

    @Override
    public void render(Case c) {
        header.setText(String.format(Locale.ROOT, "%s    %s    priority %d    %s%s", c.getId(), c.getSeverity(),
                c.getPriority(), c.getState().name(), c.getResolution() != null ? " (" + c.getResolution() + ")" : ""));
        title.setText(c.getTitle());
        List<String> allowed = c.getState().allowedActions();
        startButton.setDisable(!allowed.contains(CaseActions.START));
        escalateButton.setDisable(!allowed.contains(CaseActions.ESCALATE));
        closeButton.setDisable(!allowed.contains(CaseActions.CLOSE));
        reopenButton.setDisable(!allowed.contains(CaseActions.REOPEN));
        triageButton.setDisable(c.isClosed());

        findings.setItems(FXCollections.observableArrayList(c.getFindings()));
        timeline.setItems(FXCollections.observableArrayList(c.getEvents()));
        iocs.setItems(FXCollections.observableArrayList(c.getIocs()));
        techniques.setItems(FXCollections.observableArrayList(c.getTechniques()));

        TriageVerdict v = c.getVerdict();
        if (v == null) {
            verdict.setText("Not triaged yet.");
            reasoning.clear();
            trace.getItems().clear();
        } else {
            verdict.setText(String.format(Locale.ROOT, "%s  (confidence %.2f)", v.verdict(), v.confidence()));
            reasoning.setText(v.reasoning());
            trace.setItems(FXCollections.observableArrayList(v.toolTrace()));
        }
        respondButton.setDisable(v == null);
        renderPlan(c.getResponsePlan());

        notes.setItems(FXCollections.observableArrayList(c.getNotes()));
        history.setItems(FXCollections.observableArrayList(c.getHistory()));
    }

    private void renderPlan(ResponsePlan plan) {
        planBox.getChildren().clear();
        if (plan == null) {
            planBox.getChildren().add(new Label("No response plan yet (run AI triage first)."));
            return;
        }
        for (int i = 0; i < plan.getSteps().size(); i++) {
            int stepNumber = i + 1;
            CheckBox step = new CheckBox(stepNumber + ". " + plan.getSteps().get(i));
            step.setMnemonicParsing(false);  // keep underscores in names such as authorized_keys
            step.setWrapText(true);
            step.setSelected(plan.isDone(i));
            step.setDisable(plan.isDone(i));  // done steps stay done
            step.setOnAction(e -> {
                if (step.isSelected()) {
                    onStepDone.accept(stepNumber);
                }
            });
            planBox.getChildren().add(step);
        }
    }

    @Override
    public void showReportPath(Path report, String warning) {
        lastReport = report;
        reportLink.setText("Open report: " + report.toAbsolutePath().normalize());
        if (warning != null) {
            showError(warning + "\nThe report was written without the AI narrative.");
        }
    }

    @Override
    public void showMessage(String message) {
        status.setText(message);
    }

    @Override
    public void showError(String message) {
        status.setText("Error: " + message.lines().findFirst().orElse(""));
        Alert alert = new Alert(Alert.AlertType.ERROR, message);
        alert.setHeaderText(null);
        alert.setTitle("TriageDesk");
        if (root.getScene() != null) {
            alert.initOwner(root.getScene().getWindow());
        }
        alert.show();
    }

    @Override
    public void setBusy(boolean isBusy, String what) {
        busy.setVisible(isBusy);
        for (Button b : List.of(triageButton, respondButton, enrichButton, mapButton, reportButton, addNoteButton)) {
            b.setDisable(isBusy || (b == respondButton && verdict.getText().startsWith("Not triaged")));
        }
        if (isBusy) {
            status.setText(what);
        }
    }

    @Override
    public Optional<String> askEscalationReason() {
        TextInputDialog dialog = new TextInputDialog();
        dialog.setTitle("Escalate case");
        dialog.setHeaderText("Why does this case need L2 / incident response?");
        dialog.setContentText("Reason:");
        owner(dialog);
        return dialog.showAndWait().map(String::strip);
    }

    @Override
    public Optional<CloseRequest> askClose() {
        Dialog<CloseRequest> dialog = new Dialog<>();
        dialog.setTitle("Close case");
        dialog.setHeaderText("How should this case be closed?");
        ChoiceBox<String> resolution = new ChoiceBox<>(FXCollections.observableArrayList(
                "true_positive", "false_positive", "benign"));
        resolution.setValue("true_positive");
        TextArea comment = new TextArea();
        comment.setPromptText("What was done, or why this is not an incident (required)");
        comment.setPrefRowCount(4);
        GridPane grid = new GridPane();
        grid.setHgap(8);
        grid.setVgap(8);
        grid.addRow(0, new Label("Resolution:"), resolution);
        grid.addRow(1, new Label("Comment:"), comment);
        dialog.getDialogPane().setContent(grid);
        dialog.getDialogPane().getButtonTypes().addAll(ButtonType.OK, ButtonType.CANCEL);
        dialog.setResultConverter(b -> b == ButtonType.OK ? new CloseRequest(resolution.getValue(), comment.getText()) : null);
        owner(dialog);
        return dialog.showAndWait();
    }

    private void owner(Dialog<?> dialog) {
        if (root.getScene() != null) {
            dialog.initOwner(root.getScene().getWindow());
        }
    }

    @Override
    public void clearNoteInput() {
        noteInput.clear();
    }

    @Override
    public void setOnTriage(Runnable handler) {
        triageButton.setOnAction(e -> handler.run());
    }

    @Override
    public void setOnEnrich(Runnable handler) {
        enrichButton.setOnAction(e -> handler.run());
    }

    @Override
    public void setOnMapAttack(Consumer<Boolean> handler) {
        mapButton.setOnAction(e -> handler.accept(askAi.isSelected()));
    }

    @Override
    public void setOnChangeStatus(Consumer<String> handler) {
        startButton.setOnAction(e -> handler.accept(CaseActions.START));
        escalateButton.setOnAction(e -> handler.accept(CaseActions.ESCALATE));
        closeButton.setOnAction(e -> handler.accept(CaseActions.CLOSE));
        reopenButton.setOnAction(e -> handler.accept(CaseActions.REOPEN));
    }

    @Override
    public void setOnAddNote(Consumer<String> handler) {
        addNoteButton.setOnAction(e -> handler.accept(noteInput.getText()));
        noteInput.setOnAction(e -> handler.accept(noteInput.getText()));
    }

    @Override
    public void setOnRecommendResponse(Runnable handler) {
        respondButton.setOnAction(e -> handler.run());
    }

    @Override
    public void setOnStepDone(IntConsumer handler) {
        onStepDone = handler;
    }

    @Override
    public void setOnGenerateReport(Runnable handler) {
        reportButton.setOnAction(e -> handler.run());
    }
}
