package ca.yorku.triagedesk.intel;

import ca.yorku.triagedesk.domain.Ioc;
import ca.yorku.triagedesk.domain.SecurityEvent;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Finds indicators of compromise in events with regular expressions: IPv4 addresses,
 * http(s) URLs and their domains, and MD5/SHA-1/SHA-256 hashes. Domains are taken only
 * from URLs, because free text is full of names that look like domains (backup.zip, x.sh).
 */
public final class IocExtractor {

    private static final String OCTET = "(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)";
    static final Pattern IPV4 = Pattern.compile("(?<![\\d.])" + OCTET + "(?:\\." + OCTET + "){3}(?![\\d.]*\\d)");
    static final Pattern URL = Pattern.compile("https?://[^\\s\"'<>()\\[\\]{}]+", Pattern.CASE_INSENSITIVE);
    static final Pattern HASH = Pattern.compile("(?<![0-9a-fA-F])(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})(?![0-9a-fA-F])");
    private static final Pattern DOMAIN = Pattern.compile("(?i)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,24}");

    private IocExtractor() {
    }

    /** All distinct indicators in the events, in the order they first appear. */
    public static List<Ioc> extract(List<SecurityEvent> events) {
        Map<String, Ioc> found = new LinkedHashMap<>();
        for (SecurityEvent e : events) {
            if (e.srcIp() != null && IPV4.matcher(e.srcIp()).matches()) {
                add(found, Ioc.IP, e.srcIp());
            }
            for (String text : texts(e)) {
                Matcher m = IPV4.matcher(text);
                while (m.find()) {
                    add(found, Ioc.IP, m.group());
                }
                m = URL.matcher(text);
                while (m.find()) {
                    String url = trimPunctuation(m.group());
                    add(found, Ioc.URL, url);
                    String host = host(url);
                    if (host != null && !IPV4.matcher(host).matches()) {
                        add(found, Ioc.DOMAIN, host);
                    }
                }
                m = HASH.matcher(text);
                while (m.find()) {
                    add(found, Ioc.HASH, m.group().toLowerCase(Locale.ROOT));
                }
            }
        }
        return new ArrayList<>(found.values());
    }

    /**
     * The indicator type of a value typed by the analyst or the model.
     *
     * @throws IllegalArgumentException if the value is not an IPv4 address, URL, hash or domain
     */
    public static String classify(String value) {
        String v = value == null ? "" : value.strip();
        if (IPV4.matcher(v).matches()) {
            return Ioc.IP;
        }
        if (URL.matcher(v).matches()) {
            return Ioc.URL;
        }
        if (HASH.matcher(v).matches()) {
            return Ioc.HASH;
        }
        if (DOMAIN.matcher(v).matches()) {
            return Ioc.DOMAIN;
        }
        throw new IllegalArgumentException("Not an IPv4 address, URL, domain or MD5/SHA-1/SHA-256 hash: " + value);
    }

    /** Private, loopback, link-local and carrier-grade NAT addresses are never sent to external services. */
    public static boolean isPrivateIp(String ip) {
        if (!IPV4.matcher(ip).matches()) {
            return false;
        }
        try {
            InetAddress a = InetAddress.getByName(ip);  // a literal address: no DNS lookup
            byte[] b = a.getAddress();
            boolean cgnat = (b[0] & 0xff) == 100 && (b[1] & 0xc0) == 64;
            return a.isSiteLocalAddress() || a.isLoopbackAddress() || a.isLinkLocalAddress()
                    || a.isAnyLocalAddress() || a.isMulticastAddress() || cgnat;
        } catch (UnknownHostException e) {
            return false;
        }
    }

    private static List<String> texts(SecurityEvent e) {
        List<String> texts = new ArrayList<>();
        texts.add(e.message());
        for (String attr : List.of("fullLog", "command", "sha256")) {
            String v = e.attribute(attr);
            if (v != null) {
                texts.add(v);
            }
        }
        return texts;
    }

    private static void add(Map<String, Ioc> found, String type, String value) {
        found.putIfAbsent(type + ":" + value.toLowerCase(Locale.ROOT), Ioc.unscored(type, value));
    }

    private static String trimPunctuation(String url) {
        String u = url;
        while (!u.isEmpty() && ".,;:!?".indexOf(u.charAt(u.length() - 1)) >= 0) {
            u = u.substring(0, u.length() - 1);
        }
        return u;
    }

    private static String host(String url) {
        try {
            String h = URI.create(url).getHost();
            return h == null ? null : h.toLowerCase(Locale.ROOT);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
