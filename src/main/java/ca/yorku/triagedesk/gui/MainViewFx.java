package ca.yorku.triagedesk.gui;

import ca.yorku.triagedesk.domain.AgentResult;
import ca.yorku.triagedesk.domain.Case;
import java.io.File;
import java.nio.file.Path;
import java.util.List;
import java.util.function.Consumer;
import javafx.collections.FXCollections;
import javafx.geometry.Insets;
import javafx.geometry.Orientation;
import javafx.scene.Node;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.ListView;
import javafx.scene.control.ProgressIndicator;
import javafx.scene.control.SplitPane;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableRow;
import javafx.scene.control.TableView;
import javafx.scene.control.TextArea;
import javafx.scene.control.ToolBar;
import javafx.scene.control.Tooltip;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.Window;

/** JavaFX implementation of the main screen. */
public class MainViewFx implements MainView {

    private final BorderPane root = new BorderPane();
    private final Button importButton = new Button("Import files...");
    private final Button detectButton = new Button("Run detections");
    private final Button summarizeButton = new Button("Summarise with AI");
    private final ListView<String> files = new ListView<>();
    private final TableView<CaseRow> cases = new TableView<>();
    private final TextArea summary = new TextArea();
    private final ListView<String> summaryTrace = new ListView<>();
    private final Label summaryTitle = new Label("AI log summary");
    private final Label status = new Label("Ready.");
    private final ProgressIndicator busy = new ProgressIndicator();

    private Consumer<String> onSummarize = id -> { };
    private Consumer<String> onOpenCase = id -> { };

    public MainViewFx(String modelDescription) {
        importButton.setTooltip(new Tooltip("Wazuh alerts.json, Linux auth.log or Apache/Nginx access logs"));
        detectButton.setTooltip(new Tooltip("Run the detection rules and group the findings into cases"));
        Label model = new Label(modelDescription);
        model.getStyleClass().add("muted");
        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);
        root.setTop(new ToolBar(importButton, detectButton, spacer, model));

        files.setPlaceholder(new Label("No files imported yet."));
        files.setPrefWidth(230);
        summarizeButton.setMaxWidth(Double.MAX_VALUE);
        summarizeButton.setOnAction(e -> onSummarize.accept(files.getSelectionModel().getSelectedItem()));
        VBox left = box(heading("Imported files"), files, summarizeButton);
        VBox.setVgrow(files, Priority.ALWAYS);

        buildCaseTable();
        summary.setEditable(false);
        summary.setWrapText(true);
        summary.setPromptText("Select a file on the left and choose \"Summarise with AI\".");
        summaryTrace.setPrefHeight(110);
        summaryTrace.setPlaceholder(new Label("The agent's tool calls appear here."));
        VBox casesBox = box(heading("Cases (double-click to open)"), cases);
        VBox.setVgrow(cases, Priority.ALWAYS);
        summaryTitle.getStyleClass().add("heading");
        VBox summaryBox = box(summaryTitle, summary, new Label("Tool calls"), summaryTrace);
        VBox.setVgrow(summary, Priority.ALWAYS);

        SplitPane centre = new SplitPane(casesBox, summaryBox);
        centre.setOrientation(Orientation.VERTICAL);
        centre.setDividerPositions(0.55);
        SplitPane main = new SplitPane(left, centre);
        main.setDividerPositions(0.2);
        root.setCenter(main);

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

    private void buildCaseTable() {
        cases.getColumns().add(column("ID", "id", 90));
        cases.getColumns().add(column("State", "state", 110));
        cases.getColumns().add(column("Severity", "severity", 80));
        cases.getColumns().add(column("Priority", "priority", 65));
        cases.getColumns().add(column("Findings", "findings", 65));
        TableColumn<CaseRow, String> title = column("Title", "title", 520);
        cases.getColumns().add(title);
        cases.setPlaceholder(new Label("No cases yet. Import files, then run detections."));
        cases.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN);
        cases.setRowFactory(t -> {
            TableRow<CaseRow> row = new TableRow<>() {
                @Override
                protected void updateItem(CaseRow item, boolean empty) {
                    super.updateItem(item, empty);
                    getStyleClass().removeAll("sev-critical", "sev-high", "sev-medium", "sev-low", "closed");
                    if (item != null && !empty) {
                        getStyleClass().add(item.getState().equals("CLOSED") ? "closed" : "sev-" + item.getSeverity().toLowerCase());
                    }
                }
            };
            row.setOnMouseClicked(e -> {
                if (e.getClickCount() == 2 && !row.isEmpty()) {
                    onOpenCase.accept(row.getItem().getId());
                }
            });
            return row;
        });
    }

    private static <T> TableColumn<CaseRow, T> column(String title, String property, double width) {
        TableColumn<CaseRow, T> c = new TableColumn<>(title);
        c.setCellValueFactory(new PropertyValueFactory<>(property));
        c.setPrefWidth(width);
        return c;
    }

    static Label heading(String text) {
        Label l = new Label(text);
        l.getStyleClass().add("heading");
        return l;
    }

    static VBox box(Node... children) {
        VBox b = new VBox(6, children);
        b.setPadding(new Insets(8));
        return b;
    }

    @Override
    public List<Path> showImportDialog() {
        FileChooser chooser = new FileChooser();
        chooser.setTitle("Import log or alert files");
        chooser.getExtensionFilters().addAll(
                new FileChooser.ExtensionFilter("Logs and alerts (*.log, *.json, *.txt)", "*.log", "*.json", "*.txt", "*.log.*"),
                new FileChooser.ExtensionFilter("All files", "*.*"));
        File samples = new File("samples");
        if (samples.isDirectory()) {
            chooser.setInitialDirectory(samples.getAbsoluteFile());
        }
        Window owner = root.getScene() == null ? null : root.getScene().getWindow();
        List<File> chosen = chooser.showOpenMultipleDialog(owner);
        return chosen == null ? List.of() : chosen.stream().map(File::toPath).toList();
    }

    @Override
    public void showFiles(List<String> batchIds) {
        String selected = files.getSelectionModel().getSelectedItem();
        files.setItems(FXCollections.observableArrayList(batchIds));
        if (selected != null && batchIds.contains(selected)) {
            files.getSelectionModel().select(selected);
        }
    }

    @Override
    public void showCases(List<Case> list) {
        cases.setItems(FXCollections.observableArrayList(list.stream().map(CaseRow::new).toList()));
    }

    @Override
    public void showSummary(String batchId, AgentResult result) {
        summaryTitle.setText("AI log summary: " + batchId);
        summary.setText(result.text() + (result.stoppedEarly()
                ? "\n\n[Incomplete: the step limit was reached before the agent finished.]" : ""));
        summaryTrace.setItems(FXCollections.observableArrayList(result.toolTrace()));
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
        importButton.setDisable(isBusy);
        detectButton.setDisable(isBusy);
        summarizeButton.setDisable(isBusy);
        if (isBusy) {
            status.setText(what);
        }
    }

    @Override
    public void setOnImport(Runnable handler) {
        importButton.setOnAction(e -> handler.run());
    }

    @Override
    public void setOnRunDetections(Runnable handler) {
        detectButton.setOnAction(e -> handler.run());
    }

    @Override
    public void setOnSummarize(Consumer<String> handler) {
        onSummarize = handler;
    }

    @Override
    public void setOnOpenCase(Consumer<String> handler) {
        onOpenCase = handler;
    }
}
