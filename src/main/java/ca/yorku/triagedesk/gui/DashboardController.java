package ca.yorku.triagedesk.gui;

import ca.yorku.triagedesk.domain.DashboardStats;
import ca.yorku.triagedesk.facade.SocAssistant;
import java.util.List;

/** Controller of the dashboard (MVC): fetches the statistics from the facade and renders them. */
public class DashboardController {

    private final SocAssistant assistant;
    private final DashboardView view;
    private final UiTasks tasks;

    public DashboardController(SocAssistant assistant, DashboardView view, UiTasks tasks) {
        this.assistant = assistant;
        this.view = view;
        this.tasks = tasks;
        view.setOnRefresh(this::refresh);
    }

    // F13

    public void refresh() {
        tasks.run(() -> new Data(assistant.getDashboardStats(), assistant.listBatches()),
                d -> view.render(d.stats(), d.files()),
                e -> view.showError(MainController.message(e)));
    }

    private record Data(DashboardStats stats, List<String> files) {
    }
}
