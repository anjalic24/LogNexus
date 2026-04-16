package com.vulnuris.IngestionService.parser;

import com.vulnuris.IngestionService.model.CesEvent;
import com.vulnuris.IngestionService.service.severity.SyslogSeverityService;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

@Component
public class SyslogParser implements LogParser {

    private final SyslogSeverityService syslogSeverityService;

    public SyslogParser(SyslogSeverityService syslogSeverityService) {
        this.syslogSeverityService = syslogSeverityService;
    }

    private static final Pattern SYSLOG_PATTERN = Pattern.compile(
            "^<(?<pri>\\d+)>\\d+\\s+" +
                    "(?<ts>\\S+)\\s+" +
                    "(?<host>\\S+)\\s+" +
                    "(?<app>\\S+)\\s+" +
                    "(?<pid>\\S+)\\s+-\\s+-\\s+" +
                    "(?<msg>.*)$"
    );

    private static final Pattern IP_PATTERN =
            Pattern.compile("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b");

    private static final Pattern IP_PORT_PATTERN =
            Pattern.compile("(\\d+\\.\\d+\\.\\d+\\.\\d+):(\\d+)");

    private static final Pattern PORT_PATTERN =
            Pattern.compile("port\\s+(\\d+)");

    private static final Pattern USER_PATTERN =
            Pattern.compile("user\\s+(\\w+)");


    @Override
    public Stream<CesEvent> parseStream(InputStream input, String filename) {

        BufferedReader reader = new BufferedReader(new InputStreamReader(input));
        AtomicLong offsetCounter = new AtomicLong(0);

        return reader.lines()
                .map(line -> parseLine(line, filename, offsetCounter.getAndIncrement()))
                .filter(Objects::nonNull);
    }

    private CesEvent parseLine(String line, String file, long offset) {

        if (line == null || line.isBlank()) return null;

        try {
            Matcher m = SYSLOG_PATTERN.matcher(line);
            if (!m.find()) return null;

            String pri = m.group("pri");
            String ts = m.group("ts");
            String host = m.group("host");
            String app = m.group("app");
            String msg = m.group("msg");
            String pid = m.group("pid");

            Instant tsUtc = Instant.parse(ts);

            String srcIp = extractSrcIp(msg);
            String dstIp = extractDstIp(msg, host);

            Integer srcPort = extractSrcPort(msg);
            Integer dstPort = extractDstPort(msg);

            String user = extractUser(msg);
            String protocol = extractProtocol(msg);

            String action = detectAction(msg);
            String result = detectResult(msg);

            List<String> iocs = extractIOCs(msg);

            Map<String, String> correlationKeys = buildCorrelationKeys(host, user, srcIp, dstIp, action);

            Map<String, Object> extra = new HashMap<>();

            putIfNoNull(extra, "app", app);
            putIfNoNull(extra, "pid", pid);
            putIfNoNull(extra, "pri", pri);

            // ---------- SEVERITY ----------
            double severityScore = syslogSeverityService.calculateSeverity(line);
            String severity = syslogSeverityService.toSeverityLabel(severityScore);

            return CesEvent.builder()
                    .eventId(UUID.randomUUID().toString())
                    .tsUtc(tsUtc)
                    .tsOriginal(ts)
                    .tsOffset("Z")

                    .sourceType("syslog")

                    .host(host)
                    .user(user)

                    .srcIp(srcIp)
                    .dstIp(dstIp)

                    .srcPort(srcPort)
                    .dstPort(dstPort)

                    .protocol(protocol)

                    .action(action)
                    .object(app)
                    .result(result)
                    .severity(severityScore)
                    .severityLabel(severity)

                    .message(msg)

                    .iocs(iocs)
                    .correlationKeys(correlationKeys)
                    .extra(extra)

                    .rawRefFile(file)
                    .rawRefOffset(offset)

                    .build();

        } catch (Exception e) {

            return null;
        }
    }

    // ---------------- EXTRACTION ----------------

    private String extractSrcIp(String msg) {
        Matcher m = IP_PATTERN.matcher(msg);
        return m.find() ? m.group() : null;
    }

    private String extractDstIp(String msg, String host) {
        return host;
    }

    private Integer extractSrcPort(String msg) {
        Matcher m = IP_PORT_PATTERN.matcher(msg);
        if (m.find()) return safeInt(m.group(2));

        Matcher pm = PORT_PATTERN.matcher(msg);
        return pm.find() ? safeInt(pm.group(1)) : null;
    }

    private Integer extractDstPort(String msg) {
        Matcher m = Pattern.compile("port\\s+(\\d+)").matcher(msg);
        return m.find() ? safeInt(m.group(1)) : null;
    }

    private String extractUser(String msg) {
        Matcher m = USER_PATTERN.matcher(msg);
        return m.find() ? m.group(1) : null;
    }

    private String extractProtocol(String msg) {
        msg = msg.toLowerCase();

        if (msg.contains("ssh")) return "ssh";
        if (msg.contains("http")) return "http";
        if (msg.contains("https")) return "https";

        return null;
    }

    private List<String> extractIOCs(String msg) {

        if (msg == null || msg.isBlank()) {
            return Collections.emptyList();
        }

        List<String> list = new ArrayList<>();
        Matcher m = IP_PATTERN.matcher(msg);

        while (m.find()) {
            String ip = m.group();

            if (ip != null && !ip.isBlank()) {
                list.add(ip);
            }
        }

        return list;
    }

    // ---------------- DETECTION ----------------

    private String detectAction(String msg) {

        if (msg.contains("Failed password")) return "LOGIN_FAIL";
        if (msg.contains("Accepted publickey")) return "LOGIN_SUCCESS";
        if (msg.contains("session opened")) return "SESSION_OPEN";
        if (msg.contains("logged out")) return "LOGOUT";
        if (msg.contains("Connection from")) return "CONNECTION";
        if (msg.contains("Firewall rule")) return "FIREWALL_CHANGE";
        if (msg.contains("Disk")) return "RESOURCE_ALERT";
        if (msg.contains("Memory")) return "RESOURCE_ALERT";
        if (msg.contains("WARNING")) return "ALERT";
        if (msg.contains("ERROR")) return "ERROR";

        return "SYSTEM_EVENT";
    }

    private String detectResult(String msg) {

        msg = msg.toLowerCase();

        if (msg.contains("failed")) return "FAIL";
        if (msg.contains("accepted")) return "SUCCESS";

        return "UNKNOWN";
    }


    private Map<String, String> buildCorrelationKeys(String host, String user,
                                                     String srcIp, String dstIp,
                                                     String action) {

        Map<String, String> map = new HashMap<>();

        putIfNotNull(map, "host", host);
        putIfNotNull(map, "user", user);
        putIfNotNull(map, "srcIp", srcIp);
        putIfNotNull(map, "dstIp", dstIp);
        putIfNotNull(map, "action", action);

        return map;
    }
    private void putIfNoNull(Map<String, Object> map, String key, Object value) {
        if (value != null) {
            map.put(key, value);
        }
    }

    private void putIfNotNull(Map<String, String> map, String key, String value) {
        if (value != null) {
            map.put(key, value);
        }
    }



    private Integer safeInt(String val) {
        try { return Integer.parseInt(val); }
        catch (Exception e) { return null; }
    }

    private void put(Map<String, String> map, String key, String val) {
        if (val != null) map.put(key, val);
    }
}