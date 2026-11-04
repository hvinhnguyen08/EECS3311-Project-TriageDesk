package ca.yorku.triagedesk.intel;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ca.yorku.triagedesk.casemgmt.CaseManager;
import ca.yorku.triagedesk.config.AppConfig;
import ca.yorku.triagedesk.detect.DetectionEngine;
import ca.yorku.triagedesk.domain.Case;
import ca.yorku.triagedesk.domain.Ioc;
import ca.yorku.triagedesk.domain.SecurityEvent;
import ca.yorku.triagedesk.testutil.SampleData;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class IocExtractorTest {

    @TempDir
    Path dataDir;

    private static List<String> values(List<Ioc> iocs) {
        return iocs.stream().map(i -> i.type() + ":" + i.value()).toList();
    }

    private static SecurityEvent event(String message, String command) {
        return SecurityEvent.builder("e", "b", Instant.parse("2026-10-28T09:00:00Z"))
                .message(message).attribute("command", command).build();
    }

    @Test
    void indicatorsOfTheSampleCases() {
        CaseManager manager = new CaseManager(dataDir);
        manager.createCases(DetectionEngine.withStandardDetectors(AppConfig.load(null, Map.of())).runAll(SampleData.all()));
        Case ssh = manager.getCase("CASE-0001");
        Case web = manager.getCase("CASE-0002");
        Case rootkit = manager.getCase("CASE-0003");

        assertEquals(List.of("ip:203.0.113.7", "hash:9f2c4a0d7b1e3c5a8f6d2b4e0c1a3f5d7b9e2c4a6f8d0b1e3c5a7f9d2b4e6c8a"),
                values(IocExtractor.extract(ssh.getEvents())));
        assertEquals(List.of("ip:198.51.100.23", "url:https://sqlmap.org", "domain:sqlmap.org"),
                values(IocExtractor.extract(web.getEvents())));
        assertEquals(List.of(), IocExtractor.extract(rootkit.getEvents()));
    }

    @Test
    void urlsDomainsAndHashesInFreeText() {
        List<Ioc> iocs = IocExtractor.extract(List.of(
                event("download from http://dl.example.net/x.sh, then ran it", "/usr/bin/curl -s https://203.0.113.50/p"),
                event("md5 d41d8cd98f00b204e9800998ecf8427e and version 1.8.4 and backup.zip", null)));

        assertEquals(List.of(
                "url:http://dl.example.net/x.sh", "domain:dl.example.net",
                "ip:203.0.113.50", "url:https://203.0.113.50/p",
                "hash:d41d8cd98f00b204e9800998ecf8427e"), values(iocs));
    }

    @Test
    void ipBoundariesAreRespected() {
        List<Ioc> iocs = IocExtractor.extract(List.of(event("1.2.3.4.5 and 999.1.1.1 and 10.0.0.1. end", null)));

        assertEquals(List.of("ip:10.0.0.1"), values(iocs));
    }

    @Test
    void classifyAndPrivateAddresses() {
        assertEquals(Ioc.IP, IocExtractor.classify(" 203.0.113.7 "));
        assertEquals(Ioc.URL, IocExtractor.classify("https://sqlmap.org/x"));
        assertEquals(Ioc.DOMAIN, IocExtractor.classify("sqlmap.org"));
        assertEquals(Ioc.HASH, IocExtractor.classify("d41d8cd98f00b204e9800998ecf8427e"));
        assertThrows(IllegalArgumentException.class, () -> IocExtractor.classify("deploy"));

        for (String ip : List.of("10.0.0.11", "192.168.1.20", "172.16.5.4", "127.0.0.1", "169.254.1.1", "100.64.0.1")) {
            assertTrue(IocExtractor.isPrivateIp(ip), ip);
        }
        for (String ip : List.of("203.0.113.7", "8.8.8.8", "172.32.0.1", "100.128.0.1")) {
            assertFalse(IocExtractor.isPrivateIp(ip), ip);
        }
    }
}
