package ca.yorku.triagedesk.gui;

import ca.yorku.triagedesk.config.AppConfig;
import ca.yorku.triagedesk.facade.SocAssistant;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.scene.control.Tab;
import javafx.scene.control.TabPane;
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
        DashboardViewFx dashboardView = new DashboardViewFx();
        DashboardController dashboard = new DashboardController(assistant, dashboardView, tasks);
        Tab dashboardTab = new Tab("Dashboard", dashboardView.getRoot());
        dashboardTab.setClosable(false);
        dashboardTab.setOnSelectionChanged(e -> {
            if (dashboardTab.isSelected()) {
                dashboard.refresh();
            }
        });

        ChatViewFx chatView = new ChatViewFx();
        new ChatController(assistant, chatView, tasks);
        Tab chatTab = new Tab("Ask the Agent", chatView.getRoot());
        chatTab.setClosable(false);

        tabs.getTabs().addAll(dashboardTab, mainTab, chatTab);

        Scene scene = new Scene(tabs, 1200, 760);
        scene.getStylesheets().add(TriageDeskApp.class.getResource("/gui/triagedesk.css").toExternalForm());
        stage.setTitle("TriageDesk - SOC alert triage (data: " + config.getDataDir().toAbsolutePath().normalize() + ")");
        stage.setScene(scene);
        stage.show();
        mainController.refresh();
        dashboard.refresh();
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
        CaseViewFx view = new CaseViewFx(path -> getHostServices().showDocument(path.toAbsolutePath().toUri().toString()));
        CaseController controller = new CaseController(assistant, view, tasks, caseId, Path.of("reports"),
                mainController::refresh);
        Tab tab = new Tab(caseId, view.getRoot());
        tab.setOnClosed(e -> caseTabs.remove(caseId));
        caseTabs.put(caseId, tab);
        tabs.getTabs().add(tab);
        tabs.getSelectionModel().select(tab);
        controller.load();
    }
}
