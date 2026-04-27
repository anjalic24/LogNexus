package com.vulnuris.IngestionService.parser;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.vulnuris.IngestionService.model.CesEvent;
import com.vulnuris.IngestionService.service.severity.PaloAltoSeverityService;
import org.springframework.stereotype.Component;

import java.io.InputStream;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Stream;

@Component
public class PaloAltoFirewallParser implements LogParser {

    private final ObjectMapper mapper = new ObjectMapper();
    private final PaloAltoSeverityService paloAltoSeverityService;

    public PaloAltoFirewallParser(PaloAltoSeverityService paloAltoSeverityService) {
        this.paloAltoSeverityService = paloAltoSeverityService;
    }

    private static final DateTimeFormatter PA_TIME =
            DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss")
                    .withZone(ZoneOffset.UTC);


    @Override
    public Stream<CesEvent> parseStream(InputStream input, String filename) {
        try {
            AtomicLong offsetCounter = new AtomicLong(0);

            List<Map<String, Object>> logs =
                    mapper.readValue(input, new TypeReference<>() {});

            if (logs == null || logs.isEmpty()) {
                return Stream.empty();
            }

            return logs.stream()
                    .map(log -> convert(log, filename, offsetCounter.getAndIncrement()))
                    .filter(Objects::nonNull);

        } catch (Exception e) {
            throw new RuntimeException("Palo Alto parsing error", e);
        }
    }

    private CesEvent convert(Map<String, Object> log, String file, long offset) {
        try {


            String eventId = UUID.randomUUID().toString();

            String tsOriginal = safeString(log.get("generated_time"));
            Instant tsUtc = parseTime(tsOriginal);

            String type = safeString(log.get("type"));


            String user = extractUser(safeString(log.get("src_user")));


            String src = safeString(log.get("src"));
            String dst = safeString(log.get("dst"));
            String natSrc = safeString(log.get("nat_src"));
            String natDst = safeString(log.get("nat_dst"));

            String srcIp = pickPublicIp(src, natSrc);
            String dstIp = pickPublicIp(dst, natDst);

            Integer srcPort = safeInt(log.get("sport"));
            Integer dstPort = safeInt(log.get("dport"));

            String protocol = safeString(log.get("protocol"));
            String action = safeString(log.get("action"));

            String threat = safeString(log.get("threat_name"));
            String category = safeString(log.get("category"));


            String result = mapResult(action);


            String message = threat != null && !threat.isBlank()
                    ? threat
                    : "PaloAlto " + action + " " + category;


            List<String> iocs = new ArrayList<>();
            addIfNotNull(iocs, srcIp);
            addIfNotNull(iocs, dstIp);
            addIfNotNull(iocs, threat);


            Map<String, String> correlation = new HashMap<>();
            putIfNotNull(correlation, "srcIp", srcIp);
            putIfNotNull(correlation, "dstIp", dstIp);
            putIfNotNull(correlation, "user", user);
            putIfNotNull(correlation, "rule", safeString(log.get("rule")));
            putIfNotNull(correlation, "app", safeString(log.get("app")));
            putIfNotNull(correlation, "sessionId", safeString(log.get("session_id")));


            boolean isInternalIp = isInternalIp(srcIp);

            Map<String, Object> extra = new HashMap<>();
            putIfNoNull(extra,"natSrcIp", natSrc);
            putIfNoNull(extra,"natDstIp", natDst);
            putIfNoNull(extra,"paloAltoType", type);
            putIfNoNull(extra,"subtype", safeString(log.get("subtype")));
            putIfNoNull(extra,"direction", safeString(log.get("direction")));
            putIfNoNull(extra,"bytes", log.get("bytes"));
            putIfNoNull(extra,"packets", log.get("packets"));

            putIfNoNull(extra, "isInternalIP", isInternalIp);


            double severityScore = paloAltoSeverityService.calculateSeverity(log);
            String severity = paloAltoSeverityService.toSeverityLabel(severityScore);



            return CesEvent.builder()
                    .eventId(eventId)

                    .tsUtc(tsUtc)
                    .tsOriginal(tsOriginal)
                    .tsOffset("Z")

                    .sourceType("PaloAlto")

                    .host(null)
                    .user(user)

                    .srcIp(srcIp)
                    .dstIp(dstIp)
                    .srcPort(srcPort)
                    .dstPort(dstPort)

                    .protocol(protocol)
                    .action(action)

                    .object(category)
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



    private String safeString(Object o) {
        return (o == null || o.toString().isBlank()) ? null : o.toString();
    }

    private Integer safeInt(Object o) {
        try {
            return (o == null) ? null : Integer.parseInt(o.toString());
        } catch (Exception e) {
            return null;
        }
    }

    private Instant parseTime(String time) {
        try {
            return (time == null) ? Instant.now() : Instant.from(PA_TIME.parse(time));
        } catch (Exception e) {
            return Instant.now();
        }
    }

    private String extractUser(String user) {
        if (user == null) return null;
        return user.contains("\\") ? user.split("\\\\")[1] : user;
    }

    private String mapResult(String action) {
        if (action == null) return "UNKNOWN";
        return action.equalsIgnoreCase("allow") ? "SUCCESS" : "FAIL";
    }

    private void addIfNotNull(List<String> list, String val) {
        if (val != null) list.add(val);
    }

    private void putIfNotNull(Map<String, String> map, String key, String val) {
        if (val != null) map.put(key, val);
    }

    private void putIfNoNull(Map<String, Object> map, String key, Object val) {
        if (val != null) map.put(key, val);
    }


    private String pickPublicIp(String original, String nat) {
        if (isPublicIp(nat)) return nat;
        return original;
    }

    private boolean isPublicIp(String ip) {
        if (ip == null) return false;

        return !(ip.startsWith("10.") ||
                ip.startsWith("192.168.") ||
                ip.startsWith("172.16.") ||
                ip.startsWith("172.17.") ||
                ip.startsWith("172.18.") ||
                ip.startsWith("172.19.") ||
                ip.startsWith("172.2"));
    }

    private boolean isInternalIp(String ip) {

        if (ip == null || ip.isBlank()) return false;

        return ip.startsWith("10.") ||
                ip.startsWith("192.168.") ||
                ip.matches("^172\\.(1[6-9]|2[0-9]|3[0-1])\\..*") ||
                ip.equals("127.0.0.1") ||
                ip.equalsIgnoreCase("localhost");
    }
}