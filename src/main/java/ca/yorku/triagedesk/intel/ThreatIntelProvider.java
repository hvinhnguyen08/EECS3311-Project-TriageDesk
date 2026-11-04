package ca.yorku.triagedesk.intel;

/**
 * Target interface of the Adapter pattern: the one way the application asks a
 * threat-intelligence service about an indicator, whatever the service's own API looks like.
 */
public interface ThreatIntelProvider {

    /** Display name, for example "AbuseIPDB". */
    String name();

    /** Whether this provider can rate indicators of the given type (Ioc.IP, Ioc.DOMAIN, Ioc.URL, Ioc.HASH). */
    boolean supports(String type);

    /** @throws ThreatIntelException if the service cannot answer */
    IntelResult lookup(String type, String value);
}
