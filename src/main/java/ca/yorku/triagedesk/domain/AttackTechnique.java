package ca.yorku.triagedesk.domain;

import java.util.Objects;

/** A MITRE ATT&CK technique, for example T1110.001 Password Guessing (Credential Access). */
public record AttackTechnique(String id, String name, String tactic) {

    public AttackTechnique {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(name, "name");
        if (!id.matches("T\\d{4}(\\.\\d{3})?")) {
            throw new IllegalArgumentException("Not an ATT&CK technique ID: " + id);
        }
    }
}
