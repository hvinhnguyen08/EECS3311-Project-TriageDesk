package ca.yorku.triagedesk.gui;

import ca.yorku.triagedesk.domain.AgentResult;
import java.util.function.Consumer;

/** View of "Ask the Agent" (MVC): the conversation and the question box. */
public interface ChatView {

    /** Adds a question and the agent's answer, with its tool calls and token use, to the conversation. */
    void showAnswer(String question, AgentResult answer, String usage);

    void showError(String message);

    void setBusy(boolean busy, String what);

    void clearQuestion();

    void setOnAsk(Consumer<String> handler);
}
