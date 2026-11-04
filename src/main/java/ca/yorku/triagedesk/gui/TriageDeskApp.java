package ca.yorku.triagedesk.gui;

import ca.yorku.triagedesk.config.AppConfig;
import ca.yorku.triagedesk.domain.Case;
import ca.yorku.triagedesk.domain.Finding;
import ca.yorku.triagedesk.facade.SocAssistant;
import java.util.HashMap;
import java.util.Map;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.scene.control.Tab;
import javafx.scene.control.TabPane;
import javafx.scene.control.TextArea;
import javafx.stage.Stage;

/**
 * The JavaFX application: one window with a tab per screen. It creates the SocAssistant
 * facade (the model of MVC, shared with the CLI) and wires each view to its controller.
 */
public class TriageDeskApp extends Application {

    private final FxUiTasks tasks = new FxUiTasks();
    private final TabPane tabs = new TabPane();
    private final Map<String, Tab> caseTabs = new HashMap<>();
    private SocAssistant assistant;
    private MainController mainController;

    @Override
    public void start(Stage stage) {
        AppConfig config;
        try {
            config = AppConfig.load();
            assistant = SocAssistant.create(config);
        } catch (RuntimeException e) {
            Alert alert = new Alert(Alert.AlertType.ERROR, "TriageDesk could not start: " + MainController.message(e));
            alert.showAndWait();
            Platform.exit();
            return;
        }

        MainViewFx mainView = new MainViewFx("AI: " + modelDescription());
        mainController = new MainController(assistant, mainView, tasks, this::openCase);
        Tab mainTab = new Tab("Cases and imports", mainView.getRoot());
        mainTab.setClosable(false);
        mainTab.setOnSelectionChanged(e -> {
            if (mainTab.isSelected()) {
                mainController.refresh();
            }
        });
        tabs.getTabs().add(mainTab);

        Scene scene = new Scene(tabs, 1200, 760);
        scene.getStylesheets().add(TriageDeskApp.class.getResource("/gui/triagedesk.css").toExternalForm());
        stage.setTitle("TriageDesk - SOC alert triage (data: " + config.getDataDir().toAbsolutePath().normalize() + ")");
        stage.setScene(scene);
        stage.show();
        mainController.refresh();
    }

    @Override
    public void stop() {
        tasks.shutdown();
    }

    /** Which model the AI features use; creating the agent fails if no key is configured. */
    private String modelDescription() {
        try {
            return assistant.describeModel();
        } catch (RuntimeException e) {
            return "not configured (" + MainController.message(e) + ")";
        }
    }

    /** Opens (or brings forward) the tab of a case. */
    void openCase(String caseId) {
        Tab existing = caseTabs.get(caseId);
        if (existing != null) {
            tabs.getSelectionModel().select(existing);
            return;
        }
        Case c = assistant.getCase(caseId);
        TextArea details = new TextArea(describe(c));
        details.setEditable(false);
        details.getStyleClass().add("case-text");
        Tab tab = new Tab(c.getId(), details);
        tab.setOnClosed(e -> caseTabs.remove(caseId));
        caseTabs.put(caseId, tab);
        tabs.getTabs().add(tab);
        tabs.getSelectionModel().select(tab);
    }

    private static String describe(Case c) {
        StringBuilder sb = new StringBuilder();
        sb.append(c.getId()).append("  [").append(c.getState().name()).append("]  ").append(c.getSeverity())
                .append("  priority ").append(c.getPriority()).append('\n').append(c.getTitle()).append("\n\nFindings:\n");
        for (Finding f : c.getFindings()) {
            sb.append("  - [").append(f.detector()).append("] ").append(f.severity()).append(' ').append(f.title())
                    .append(" (").append(f.events().size()).append(" events, ").append(f.firstSeen()).append(" .. ")
                    .append(f.lastSeen()).append(")\n");
        }
        sb.append("\nHistory:\n");
        c.getHistory().forEach(h -> sb.append("  ").append(h).append('\n'));
        return sb.toString();
    }
}
