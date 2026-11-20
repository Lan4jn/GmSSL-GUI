package org.gmssl.gui.engine;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class EngineValidatorSanTest {
    final CatalogService catalog = new CatalogService(new ObjectMapper());
    final EngineValidator validator = new EngineValidator(new NetworkPolicy(null));
    final List<String> commands = List.of("certgen", "reqgen", "reqsign");

    EngineValidatorSanTest() throws Exception {}

    Map<String,Object> parameters() {
        return new LinkedHashMap<>(Map.of("days", 365, "cacert", "input:ca", "pass", "fixture"));
    }

    Map<String,List<String>> validate(String command, Map<String,Object> san) {
        var input = parameters();
        if (command.equals("reqgen")) input.remove("days");
        if (!command.equals("reqsign")) input.remove("cacert");
        input.putAll(san);
        return validator.validate(catalog.tool(command), input);
    }

    void invalid(String command, Map<String,Object> san) {
        var error = assertThrows(EngineException.class, () -> validate(command, san), command + ": " + san);
        assertEquals(400, error.status);
        assertEquals("INVALID_PARAMETERS", error.code);
    }

    @Test void consumesRealCatalogDnsAndIpRepeatableParameters() {
        var ips = List.of("192.168.1.50", "2001:db8::1", "::", "::1", "1:2:3:4:5:6:7:8",
            "::ffff:192.0.2.1", "1:2:3:4:5:6:192.0.2.1");
        for (String c : commands) {
            var result = validate(c, Map.of("subject_ip", ips, "subject_dns_name", List.of("example.test", "*.example.test")));
            assertEquals(ips, result.get("subject_ip"));
        }
    }

    @Test void rejectsMalformedIpLiteralsWithoutAcceptingNamesOrDecorations() {
        for (String c : commands) for (String ip : List.of("", "localhost", "example.test", "1.2.3",
            "256.1.1.1", "01.2.3.4", "1.2.3.4.5", "1.2.3.-1", "1.2.3.4/24", "[::1]",
            "fe80::1%en0", ":::1:2", ":::1", "1:::2", "1::2::3", ":1:2:3:4:5:6:7",
            "1:2:3:4:5:6:7:", "1:2:3:4:5:6:7", "1:2:3:4:5:6:7:8:9", "1:2:3:4:5:6:7::8",
            "12345::1", "gggg::1", "::ffff:192.00.2.1", "192.0.2.1::", " ::1", "::1 ")) {
            invalid(c, Map.of("subject_ip", ip));
        }
    }

    @Test void allows64SanEntriesAndRejects65CombinedEntries() {
        for (String c : commands) {
            assertEquals(64, validate(c, Map.of("subject_ip", Collections.nCopies(64, "::1"))).get("subject_ip").size());
            assertEquals(64, validate(c, Map.of("subject_dns_name", Collections.nCopies(64, "a.test"))).get("subject_dns_name").size());
            validate(c, Map.of("subject_dns_name", Collections.nCopies(32, "a.test"), "subject_ip", Collections.nCopies(32, "::1")));
            invalid(c, Map.of("subject_dns_name", Collections.nCopies(33, "a.test"), "subject_ip", Collections.nCopies(32, "::1")));
            invalid(c, Map.of("subject_ip", Collections.nCopies(65, "::1")));
        }
    }

    @Test void enforcesExactCombinedDerBudgetAt2048Bytes() {
        for (String c : commands) {
            var dns = new ArrayList<>(Collections.nCopies(8, "a".repeat(253)));
            validate(c, Map.of("subject_dns_name", dns)); // 8 * (tag + two-byte length + 253)
            invalid(c, Map.of("subject_dns_name", dns, "subject_ip", "127.0.0.1"));
            dns.set(7, "a".repeat(247));
            validate(c, Map.of("subject_dns_name", dns, "subject_ip", "127.0.0.1"));
            dns.set(7, "a".repeat(248));
            invalid(c, Map.of("subject_dns_name", dns, "subject_ip", "127.0.0.1"));
        }
    }

    @Test void countsIpv6AndMappedIpv6As16Octets() {
        for (String c : commands) {
            var dns = Collections.nCopies(8, "a".repeat(251)); // 2032 bytes, leaves 16
            validate(c, Map.of("subject_dns_name", dns, "subject_ip", "192.0.2.1"));
            invalid(c, Map.of("subject_dns_name", dns, "subject_ip", "::1"));
            invalid(c, Map.of("subject_dns_name", dns, "subject_ip", "::ffff:192.0.2.1"));
        }
    }

    @Test void enforcesDnsNativeAlphabetAndLength() {
        for (String c : commands) {
            validate(c, Map.of("subject_dns_name", "a".repeat(253)));
            for (String dns : List.of("", "a".repeat(254), "a b", "é.test", "a_test", "https://a.test", "a	.test")) {
                invalid(c, Map.of("subject_dns_name", dns));
            }
        }
    }

    @Test void retainsTypedAndEmptyListChecks() {
        for (String c : commands) {
            invalid(c, Map.of("subject_ip", List.of()));
            invalid(c, Map.of("subject_dns_name", List.of()));
            invalid(c, Map.of("subject_ip", 123));
            invalid(c, Map.of("subject_ip", List.of("::1", 123)));
            invalid(c, Map.of("subject_ip", "::1\n"));
        }
    }

    @Test void leavesOtherRepeatableParameterLimitsUnchanged() {
        invalid("certgen", Map.of("issuer_dns_name", Collections.nCopies(17, "a.test")));
        assertThrows(EngineException.class, () -> validator.validate(catalog.tool("sm3"), Map.of("subject_ip", "::1")));
    }
}
