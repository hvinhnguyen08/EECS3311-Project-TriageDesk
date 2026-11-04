package ca.yorku.triagedesk.agent;

/**
 * Command interface: an operation the model can ask for by name. Each tool is created with
 * its receiver (for example the EventStore), described to the model with a JSON Schema,
 * and executed by SocAgent with the JSON arguments the model chose.
 */
public interface Tool {

    /** The name the model uses, for example "search_events". */
    String name();

    /** What the tool does and when to use it, written for the model. */
    String description();

    /** JSON Schema of the arguments object. */
    String parameters();

    /**
     * Runs the tool. The result is text (usually JSON) that is sent back to the model.
     *
     * @throws IllegalArgumentException for invalid arguments; the agent returns the message to the model
     */
    String execute(String argsJson);
}
