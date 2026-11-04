package ca.yorku.triagedesk.gui;

import ca.yorku.triagedesk.domain.AgentResult;
import java.util.List;
import java.util.function.Consumer;
import javafx.collections.FXCollections;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.Hyperlink;
import javafx.scene.control.Label;
import javafx.scene.control.ListView;
import javafx.scene.control.ProgressIndicator;
import javafx.scene.control.ScrollPane;
import javafx.scene.control.TextField;
import javafx.scene.control.TitledPane;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.FlowPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;

/** JavaFX implementation of "Ask the Agent". */
public class ChatViewFx implements ChatView {

    static final List<String> EXAMPLES = List.of(
            "Which IPs failed SSH login more than 10 times, and did any of them log in afterwards?",
            "What did 198.51.100.23 do on the web server?",
            "Which accounts used sudo, and was any attempt denied?");

    private final BorderPane root = new BorderPane();
    private final VBox conversation = new VBox(12);
    private final ScrollPane scroll = new ScrollPane(conversation);
    private final TextField question = new TextField();
    private final Button ask = new Button("Ask");
    private final ProgressIndicator busy = new ProgressIndicator();
    private final Label status = new Label("Answers come from tool calls on the imported data; each answer lists them.");
    private Consumer<String> onAsk = q -> { };

    public ChatViewFx() {
        conversation.setPadding(new Insets(12));
        scroll.setFitToWidth(true);
        root.setCenter(scroll);

        FlowPane examples = new FlowPane(8, 4);
        examples.getChildren().add(new Label("Try:"));
        for (String example : EXAMPLES) {
            Hyperlink link = new Hyperlink(example);
            link.setMnemonicParsing(false);
            link.setOnAction(e -> {
                question.setText(example);
                onAsk.accept(example);
            });
            examples.getChildren().add(link);
        }
        question.setPromptText("Ask a question about the imported events and press Enter");
        HBox.setHgrow(question, Priority.ALWAYS);
        question.setOnAction(e -> onAsk.accept(question.getText()));
        ask.setOnAction(e -> onAsk.accept(question.getText()));
        busy.setPrefSize(16, 16);
        busy.setVisible(false);
        HBox input = new HBox(8, question, ask, busy);
        input.setAlignment(Pos.CENTER_LEFT);
        status.getStyleClass().add("muted");
        VBox bottom = new VBox(6, examples, input, status);
        bottom.setPadding(new Insets(8, 12, 10, 12));
        bottom.getStyleClass().add("status-bar");
        root.setBottom(bottom);
    }

    public Node getRoot() {
        return root;
    }

    @Override
    public void showAnswer(String q, AgentResult answer, String usage) {
        Label you = new Label(q);
        you.setWrapText(true);
        you.getStyleClass().add("chat-question");
        Label reply = new Label(answer.text() + (answer.stoppedEarly()
                ? "\n\n[Incomplete: the step limit was reached before the agent finished.]" : ""));
        reply.setWrapText(true);
        reply.getStyleClass().add("chat-answer");
        ListView<String> calls = new ListView<>(FXCollections.observableArrayList(answer.toolTrace()));
        calls.setPrefHeight(Math.min(6, Math.max(1, answer.toolTrace().size())) * 26 + 4);
        TitledPane trace = new TitledPane("Tool calls (" + answer.toolTrace().size() + ") - " + usage, calls);
        trace.setExpanded(false);
        trace.setAnimated(false);
        conversation.getChildren().add(new VBox(6, you, reply, trace));
        scroll.layout();
        scroll.setVvalue(1.0);
        status.setText("Answered with " + answer.toolTrace().size() + " tool call(s).");
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
        ask.setDisable(isBusy);
        question.setDisable(isBusy);
        if (isBusy) {
            status.setText(what);
        }
    }

    @Override
    public void clearQuestion() {
        question.clear();
    }

    @Override
    public void setOnAsk(Consumer<String> handler) {
        onAsk = handler;
    }
}
