package ca.yorku.triagedesk.gui;

import ca.yorku.triagedesk.domain.DashboardStats;
import java.util.List;

/** View of the dashboard (MVC): totals and charts for the imported data and the case queue. */
public interface DashboardView {

    /** @param files the imported files, shown next to the totals */
    void render(DashboardStats stats, List<String> files);

    void showError(String message);

    void setOnRefresh(Runnable handler);
}
