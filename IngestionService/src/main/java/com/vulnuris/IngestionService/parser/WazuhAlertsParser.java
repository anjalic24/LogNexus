package com.vulnuris.IngestionService.parser;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.vulnuris.IngestionService.model.CesEvent;
import com.vulnuris.IngestionService.service.severity.WazuhSeverityService;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Stream;

@Component
public class WazuhAlertsParser implements LogParser{

    private final ObjectMapper mapper = new ObjectMapper();
    private final WazuhSeverityService  wazuhSeverityService;

    public WazuhAlertsParser(WazuhSeverityService wazuhSeverityService) {
        this.wazuhSeverityService = wazuhSeverityService;
    }

    @Override
    public Stream<CesEvent> parseStream(InputStream input, String filename) {
        BufferedReader reader = new BufferedReader(new InputStreamReader(input));
        AtomicLong offset = new AtomicLong(0);

        return reader.lines()
                .map(line -> convert(line, filename, offset.getAndIncrement()))
                .filter(Objects::nonNull);
    }

    private CesEvent convert(String line, String file, long offset) {
        try {
            if (line == null || line.isBlank()) return null;

            JsonNode root = mapper.readTree(line);

            // ---------- BASIC ----------
            String eventId = UUID.randomUUID().toString();

            String rule = getText(root, "rule", "id");

            String tsOriginal = getText(root, "timestamp");
            Instant tsUtc = parseTime(tsOriginal);

            String host = getText(root, "agent", "name");

            // ---------- USER ----------
            String user = extractUser(root);

            // ---------- IP ----------
            String srcIp = extractSrcIp(root);
            String dstIp = getNested(root, "data", "dstip");

            Integer srcPort = safeInt(getNested(root, "data", "srcport"));
            Integer dstPort = safeInt(getNested(root, "data", "dstport"));

            String protocol = getNested(root, "data", "protocol");

            // ---------- ACTION ----------
            String action = getNested(root, "data", "action");

            // ---------- OBJECT ----------
            String object = extractObject(root);

            // ---------- RESULT ----------
            String result = mapResult(action);

            // ---------- SEVERITY ----------
            double severityScore = wazuhSeverityService.calculateSeverity(root);
            String severity = wazuhSeverityService.toSeverityLabel(severityScore);

            // ---------- MESSAGE ----------
            String message = getText(root, "rule", "description");

            String mapppedAction = mapAction(action, message);

            // ---------- IOC ----------
            List<String> iocs = extractIocs(root, srcIp, dstIp);

            // ---------- CORRELATION ----------
            Map<String, String> correlation = new HashMap<>();
            putIfNotNull(correlation, "ruleId", rule);
            putIfNotNull(correlation, "host", host);
            putIfNotNull(correlation, "user", user);
            putIfNotNull(correlation, "srcIp", srcIp);
            putIfNotNull(correlation, "dstIp", dstIp);

            // ---------- EXTRA ----------
            Map<String, Object> extra = new HashMap<>();

            putIfNoNull(extra,"wazuhRuleId", rule);
            putIfNoNull(extra,"wazuhRuleLevel", severity);
            extra.put("data", root.get("data"));

            // Windows nested
            JsonNode win = root.path("data").path("win");
            if (!win.isMissingNode()) {
                extra.put("windowsEventId",
                        getText(win, "system", "eventID"));

                String winIp = getText(win, "eventData", "ipAddress");
                if (srcIp == null && winIp != null) {
                    srcIp = winIp;
                }
            }

            // ---------- BUILD ----------
            return CesEvent.builder()
                    .eventId(eventId)

                    .tsUtc(tsUtc)
                    .tsOriginal(tsOriginal)
                    .tsOffset("Z")

                    .sourceType("Wazuh")

                    .host(host)
                    .user(user)

                    .srcIp(srcIp)
                    .dstIp(dstIp)
                    .srcPort(srcPort)
                    .dstPort(dstPort)

                    .protocol(protocol)
                    .action(mapppedAction)

                    .object(object)
                    .result(result)
                    .severity(severityScore)
                    .severityLabel(severity)

                    .message(message)

                    .iocs(iocs)
                    .correlationKeys(correlation)
                    .extra(extra)

                    .rawRefFile(file)
                    .rawRefOffset(offset)

                    .build();

        } catch (Exception e) {
            return null;
        }
    }

    // ================= HELPERS =================

    private String getText(JsonNode node, String... path) {
        JsonNode current = node;
        for (String p : path) {
            if (current == null) return null;
            current = current.get(p);
        }
        return (current == null || current.isNull()) ? null : current.asText();
    }

    private String getNested(JsonNode node, String parent, String child) {
        return getText(node, parent, child);
    }

    private Integer safeInt(String val) {
        try {
            return val == null ? null : Integer.parseInt(val);
        } catch (Exception e) {
            return null;
        }
    }

    private Instant parseTime(String time) {
        try {
            return time == null ? Instant.now() : Instant.parse(time);
        } catch (Exception e) {
            return Instant.now();
        }
    }

    private void putIfNotNull(Map<String, String> map, String k, String v) {
        if (v != null) map.put(k, v);
    }

    private void putIfNoNull(Map<String, Object> map, String k, String v) {
        if (v != null) map.put(k, v);
    }

    // ---------- CUSTOM EXTRACTION ----------

    private String extractUser(JsonNode root) {

        String user = getNested(root, "data", "user");

        String srcUser = getNested(root, "data", "srcuser");

        String targetUser = getText(root, "data", "win", "eventdata", "targetUserName");

        String agent = getText(root, "agent", "name");

        String srcIP = extractSrcIp(root);

        if (user != null) return user;
        if (srcUser != null) return srcUser;
        if (targetUser != null) return targetUser;
        if (agent != null) return agent;

        return srcIP; // last fallback
    }

    private String extractSrcIp(JsonNode root) {
        String ip = getNested(root, "data", "srcip");

        // Windows fallback
        if (ip == null) {
            ip = getText(root, "data", "win", "eventdata", "ipAddress");
        }
        return ip;
    }

    private String extractObject(JsonNode root) {
        String path = getNested(root, "data", "path");
        String command = getNested(root, "data", "command");
        String url = getNested(root, "data", "url");

        if (path != null) return path;
        if (command != null) return command;
        if (url != null) return url;

        return null;
    }

    private String mapResult(String action) {
        if (action == null) return "UNKNOWN";
        if (action.equalsIgnoreCase("allowed") || action.equalsIgnoreCase("success"))
            return "SUCCESS";
        return "FAIL";
    }

    private List<String> extractIocs(JsonNode root, String srcIp, String dstIp) {
        List<String> iocs = new ArrayList<>();

        if (srcIp != null) iocs.add(srcIp);
        if (dstIp != null) iocs.add(dstIp);

        addIfPresent(iocs, getNested(root, "data", "md5_after"));
        addIfPresent(iocs, getNested(root, "data", "sha1_after"));
        addIfPresent(iocs, getNested(root, "data", "url"));
        addIfPresent(iocs, getNested(root, "agent", "ip"));

        return iocs;
    }

    private void addIfPresent(List<String> list, String val) {
        if (val != null && !val.isBlank()) list.add(val);
    }

    private String mapAction(String action, String message){

        if (action != null) return action;
        if (message != null) return message;
        return "UNKNOWN";
    }
}
