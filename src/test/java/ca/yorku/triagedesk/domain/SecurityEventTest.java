package ca.yorku.triagedesk.domain;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class SecurityEventTest {

    private static final Instant T0 = Instant.parse("2026-10-30T12:00:00Z");

    @Test
    void builderFillsDefaults() {
        SecurityEvent e = SecurityEvent.builder("x:1", "x", T0).build();

        assertEquals("", e.message());
        assertEquals(SecurityEvent.OTHER, e.category());
        assertEquals(List.of(), e.mitreIds());
        assertEquals(Map.of(), e.attributes());
    }

    @Test
    void nullAttributeValuesAreDropped() {
        Map<String, String> attrs = new HashMap<>();
        attrs.put("status", "404");
        attrs.put("referrer", null);

        SecurityEvent e = new SecurityEvent("x:1", "x", T0, null, null, null, null, null, null, 0,
                null, null, attrs);

        assertEquals("404", e.attribute("status"));
        assertNull(e.attribute("referrer"));
        assertEquals(1, e.attributes().size());
    }

    @Test
    void attributesCannotBeModified() {
        SecurityEvent e = SecurityEvent.builder("x:1", "x", T0).attribute("status", "200").build();

        assertThrows(UnsupportedOperationException.class, () -> e.attributes().put("status", "500"));
    }

    @Test
    void requiredFieldsAreChecked() {
        assertThrows(NullPointerException.class, () -> SecurityEvent.builder(null, "x", T0).build());
        assertThrows(NullPointerException.class, () -> SecurityEvent.builder("x:1", "x", null).build());
    }
}
