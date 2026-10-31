package ca.yorku.triagedesk.domain;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Ordered checklist of containment and remediation steps. The analyst ticks steps off. */
public class ResponsePlan {

    private final List<String> steps;
    private final List<Boolean> done;

    public ResponsePlan(List<String> steps) {
        if (steps == null || steps.isEmpty()) {
            throw new IllegalArgumentException("A response plan needs at least one step");
        }
        for (String step : steps) {
            if (step == null || step.isBlank()) {
                throw new IllegalArgumentException("Response steps cannot be blank");
            }
        }
        this.steps = List.copyOf(steps);
        this.done = new ArrayList<>(Collections.nCopies(steps.size(), Boolean.FALSE));
    }

    public void markDone(int index) {
        if (index < 0 || index >= steps.size()) {
            throw new IndexOutOfBoundsException("No step " + (index + 1) + "; the plan has " + steps.size() + " steps");
        }
        done.set(index, Boolean.TRUE);
    }

    public boolean isDone(int index) {
        return done.get(index);
    }

    public boolean isComplete() {
        return !done.contains(Boolean.FALSE);
    }

    public List<String> getSteps() {
        return steps;
    }

    public List<Boolean> getDone() {
        return Collections.unmodifiableList(done);
    }
}
