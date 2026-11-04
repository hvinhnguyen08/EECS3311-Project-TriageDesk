package ca.yorku.triagedesk.gui;

import ca.yorku.triagedesk.domain.DashboardStats;
import java.util.List;
import java.util.Map;
import javafx.collections.FXCollections;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.chart.BarChart;
import javafx.scene.chart.CategoryAxis;
import javafx.scene.chart.NumberAxis;
import javafx.scene.chart.PieChart;
import javafx.scene.chart.XYChart;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;

/** JavaFX implementation of the dashboard. */
public class DashboardViewFx implements DashboardView {

    private final BorderPane root = new BorderPane();
    private final Label totalEvents = tileValue();
    private final Label fileCount = tileValue();
    private final Label openCases = tileValue();
    private final Label closedCases = tileValue();
    private final Label files = new Label();
    private final BarChart<Number, String> topIps = barChart("Top source IPs", "events");
    private final BarChart<Number, String> topUsers = barChart("Top accounts", "events");
    private final PieChart casesByState = new PieChart();
    private final Label empty = new Label("No data yet. Import a file on the \"Cases and imports\" tab to begin.");
    private final StackPane centre = new StackPane();
    private final Button refresh = new Button("Refresh");

    public DashboardViewFx() {
        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);
        HBox tiles = new HBox(12, tile("Events", totalEvents), tile("Imported files", fileCount),
                tile("Open cases", openCases), tile("Closed cases", closedCases), spacer, refresh);
        tiles.setAlignment(Pos.CENTER_LEFT);
        files.getStyleClass().add("muted");
        files.setWrapText(true);
        VBox top = new VBox(6, tiles, files);
        top.setPadding(new Insets(12));
        root.setTop(top);

        casesByState.setTitle("Cases by state");
        casesByState.setAnimated(false);
        casesByState.setLegendVisible(true);
        GridPane charts = new GridPane();
        charts.setHgap(12);
        charts.setVgap(12);
        charts.setPadding(new Insets(0, 12, 12, 12));
        charts.add(topIps, 0, 0);
        charts.add(topUsers, 1, 0);
        charts.add(casesByState, 0, 1, 2, 1);
        for (Node n : List.of(topIps, topUsers, casesByState)) {
            GridPane.setHgrow(n, Priority.ALWAYS);
            GridPane.setVgrow(n, Priority.ALWAYS);
        }
        empty.getStyleClass().add("heading");
        centre.getChildren().addAll(charts, empty);
        root.setCenter(centre);
    }

    public Node getRoot() {
        return root;
    }

    private static Label tileValue() {
        Label l = new Label("0");
        l.getStyleClass().add("tile-value");
        return l;
    }

    private static VBox tile(String name, Label value) {
        Label caption = new Label(name);
        caption.getStyleClass().add("muted");
        VBox tile = new VBox(2, value, caption);
        tile.getStyleClass().add("tile");
        tile.setPadding(new Insets(8, 16, 8, 16));
        return tile;
    }

    private static BarChart<Number, String> barChart(String title, String unit) {
        NumberAxis x = new NumberAxis();
        x.setLabel(unit);
        x.setMinorTickVisible(false);
        CategoryAxis y = new CategoryAxis();
        BarChart<Number, String> chart = new BarChart<>(x, y);
        chart.setTitle(title);
        chart.setLegendVisible(false);
        chart.setAnimated(false);
        return chart;
    }

    @Override
    public void render(DashboardStats stats, List<String> fileNames) {
        boolean isEmpty = stats.isEmpty();
        empty.setVisible(isEmpty);
        centre.getChildren().get(0).setVisible(!isEmpty);
        totalEvents.setText(String.valueOf(stats.totalEvents()));
        fileCount.setText(String.valueOf(fileNames.size()));
        int closed = stats.casesByState().getOrDefault("CLOSED", 0);
        int all = stats.casesByState().values().stream().mapToInt(Integer::intValue).sum();
        openCases.setText(String.valueOf(all - closed));
        closedCases.setText(String.valueOf(closed));
        files.setText(fileNames.isEmpty() ? "" : "Files: " + String.join(", ", fileNames));

        fill(topIps, stats.topSourceIps());
        fill(topUsers, stats.topUsers());
        casesByState.setData(FXCollections.observableArrayList(stats.casesByState().entrySet().stream()
                .filter(e -> e.getValue() > 0)
                .map(e -> new PieChart.Data(e.getKey() + " (" + e.getValue() + ")", e.getValue()))
                .toList()));
    }

    /** Bars largest first from the top: the category axis lists them bottom-up, so they are added in reverse. */
    private static void fill(BarChart<Number, String> chart, Map<String, Integer> counts) {
        XYChart.Series<Number, String> series = new XYChart.Series<>();
        List<Map.Entry<String, Integer>> entries = List.copyOf(counts.entrySet());
        for (int i = entries.size() - 1; i >= 0; i--) {
            series.getData().add(new XYChart.Data<>(entries.get(i).getValue(), entries.get(i).getKey()));
        }
        chart.getData().setAll(List.of(series));
    }

    @Override
    public void showError(String message) {
        Alert alert = new Alert(Alert.AlertType.ERROR, message);
        alert.setHeaderText(null);
        alert.setTitle("TriageDesk");
        alert.show();
    }

    @Override
    public void setOnRefresh(Runnable handler) {
        refresh.setOnAction(e -> handler.run());
    }
}
