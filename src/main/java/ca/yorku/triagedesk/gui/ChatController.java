package ca.yorku.triagedesk.gui;

import ca.yorku.triagedesk.agent.TokenUsage;
import ca.yorku.triagedesk.facade.SocAssistant;

/** Controller of "Ask the Agent" (MVC): sends the question to the facade in the background. */
public class ChatController {

    private final SocAssistant assistant;
    private final ChatView view;
    private final UiTasks tasks;

    public ChatController(SocAssistant assistant, ChatView view, UiTasks tasks) {
        this.assistant = assistant;
        this.view = view;
        this.tasks = tasks;
        view.setOnAsk(this::onAsk);
    }

    // F12

    public void onAsk(String question) {
        if (question == null || question.isBlank()) {
            view.showError("Type a question about the imported data first.");
            return;
        }
        String q = question.strip();
        view.setBusy(true, "The AI agent is working on your question...");
        tasks.run(() -> assistant.ask(q), answer -> {
            view.setBusy(false, "");
            TokenUsage u = assistant.getLastUsage();
            view.showAnswer(q, answer, u.modelCalls() + " model call(s), " + u.promptTokens() + " + "
                    + u.completionTokens() + " tokens");
            view.clearQuestion();
        }, e -> {
            view.setBusy(false, "");
            view.showError(MainController.message(e));
        });
    }
}
