package com.vulnuris.IngestionService.parser;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.vulnuris.IngestionService.model.CesEvent;
import com.vulnuris.IngestionService.service.severity.O365SeverityService;
import org.springframework.stereotype.Component;

import java.io.InputStream;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

@Component
public class O365Parser implements LogParser {

    private static final Pattern DOMAIN_PATTERN =
            Pattern.compile("\\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,}\\b");

    private static final Pattern MD5_PATTERN =
            Pattern.compile("\\b[a-f0-9]{32}\\b");

    private static final Pattern SHA1_PATTERN =
            Pattern.compile("\\b[a-f0-9]{40}\\b");

    private static final Pattern SHA256_PATTERN =
            Pattern.compile("\\b[a-f0-9]{64}\\b");

    private static final Pattern IP_PATTERN =
            Pattern.compile("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b");

    private final ObjectMapper mapper = new ObjectMapper();
    private final O365SeverityService o365SeverityService;

    public O365Parser(O365SeverityService o365SeverityService) {
        this.o365SeverityService = o365SeverityService;
    }

    @Override
    public Stream<CesEvent> parseStream(InputStream input, String filename) {

        try {
            AtomicLong offsetCounter = new AtomicLong(0);

            List<Map<String, Object>> logs =
                    mapper.readValue(input, new TypeReference<>() {});

            if (logs == null || logs.isEmpty()) return Stream.empty();

            return logs.stream()
                    .map(log -> convert(log, filename, offsetCounter.getAndIncrement()))
                    .filter(Objects::nonNull);

        } catch (Exception e) {
            throw new RuntimeException("O365 parsing error", e);
        }
    }

    private CesEvent convert(Map<String, Object> log, String file, long offset) {

        try {
            if (log == null) return null;


            String eventId = getOrGenerateId(log);
            String tsOriginal = safeString(log.get("CreationTime"));
            Instant tsUtc = parseTime(tsOriginal);

            String user = safeString(log.get("UserId"));
            String srcIp = extractIp(log);
            String action = safeString(log.get("Operation"));
            String workload = safeString(log.get("Workload"));
            String object = extractObject(log);


            String result = safeString(log.get("ResultStatus"));


            String message = buildMessage(log, user, action, srcIp);


            double severityScore = o365SeverityService.calculateSeverity(log);
            String severity = o365SeverityService.toSeverityLabel(severityScore);


            List<String> iocs = extractIocs(log, srcIp);


            Map<String, String> correlation = new HashMap<>();
            putIfNotNull(correlation, "user", user);
            putIfNotNull(correlation, "srcIp", srcIp);
            putIfNotNull(correlation, "operation", action);
            putIfNotNull(correlation, "workload", workload);


            boolean isInternalIp = isInternalIp(srcIp);
            Map<String, Object> extra = new HashMap<>();
            putIfNoNull(extra, "o365WorkLoad", workload);

            if (log.containsKey("OperationCount")) {
                extra.put("operationCount", log.get("OperationCount"));
            }

            if (log.containsKey("ExtendedProperties")) {

                Map<String, String> extProps =
                        parseExtendedProperties(log.get("ExtendedProperties"));

                if (!extProps.isEmpty()) {
                    extra.put("extendedProperties", extProps);
                }
            }

            putIfNoNull(extra, "isInternalIP", isInternalIp);


            return CesEvent.builder()
                    .eventId(eventId)


                    .tsUtc(tsUtc)
                    .tsOriginal(tsOriginal)
                    .tsOffset("Z")

                    .sourceType("O365")

                    .host(null)
                    .user(user)
                    .srcIp(srcIp)
                    .dstIp(null)
                    .srcPort(null)
                    .dstPort(null)
                    .protocol(null)

                    .action(action)
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



    private String getOrGenerateId(Map<String, Object> log) {
        String id = safeString(log.get("Id"));
        return id != null ? id : UUID.randomUUID().toString();
    }

    private String safeString(Object o) {
        return o == null ? null : String.valueOf(o);
    }

    private Instant parseTime(String time) {
        try {
            if (time == null) return Instant.now();
            return Instant.parse(time);
        } catch (Exception e) {
            return Instant.now();
        }
    }

    private String extractIp(Map<String, Object> log) {
        String ip = safeString(log.get("ClientIP"));
        if (ip == null) return null;


        if (ip.contains(":")) {
            return ip.split(":")[0];
        }
        return ip;
    }

    private String extractObject(Map<String, Object> log) {


        if (log.containsKey("Folders")) {
            return log.get("Folders").toString();
        }


        return safeString(log.get("ObjectId"));
    }

    private List<String> extractIocs(Map<String, Object> log, String srcIp) {

        Set<String> iocSet = new LinkedHashSet<>();


        String normalizedIp = normalizeIoc(srcIp);
        if (normalizedIp != null && !normalizedIp.isBlank()) {
            iocSet.add(normalizedIp);
        }


        String user = safeString(log.get("UserId"));
        String normalizedUser = normalizeIoc(user);
        if (normalizedUser != null && normalizedUser.contains("@")) {
            iocSet.add(normalizedUser);
        }


        String object = safeString(log.get("ObjectId"));
        String normalizedObject = normalizeIoc(object);
        if (normalizedObject != null) {

            if (normalizedObject.contains("@") || isUrl(normalizedObject)) {
                iocSet.add(normalizedObject);
            }
        }


        String siteUrl = safeString(log.get("SiteUrl"));
        String normalizedUrl = normalizeIoc(siteUrl);
        if (normalizedUrl != null && isUrl(normalizedUrl)) {
            iocSet.add(normalizedUrl);
        }


        Object ext = log.get("ExtendedProperties");

        if (ext instanceof List<?>) {
            for (Object item : (List<?>) ext) {

                if (item instanceof Map<?, ?> map) {

                    Object val = map.get("Value");

                    if (val != null) {
                        String normalizedVal = normalizeIoc(val.toString());

                        if (normalizedVal != null &&
                                !normalizedVal.isBlank() &&
                                (normalizedVal.contains("@") || isUrl(normalizedVal))) {

                            iocSet.add(normalizedVal);
                        }
                    }
                }
            }
        }

        for (Map.Entry<String, Object> entry : log.entrySet()) {

            String key = entry.getKey();


            if ("UserId".equalsIgnoreCase(key) ||
                    "ObjectId".equalsIgnoreCase(key) ||
                    "SiteUrl".equalsIgnoreCase(key) ||
                    "ClientIP".equalsIgnoreCase(key)) {
                continue;
            }

            Object value = entry.getValue();

            if (value instanceof String str) {
                extractFromText(str, iocSet);
            }

            if (value instanceof Map<?, ?> nestedMap) {
                for (Object v : nestedMap.values()) {
                    if (v instanceof String str) {
                        extractFromText(str, iocSet);
                    }
                }
            }

            if (value instanceof List<?> list) {
                for (Object item : list) {

                    if (item instanceof String str) {
                        extractFromText(str, iocSet);
                    }

                    if (item instanceof Map<?, ?> map) {
                        for (Object v : map.values()) {
                            if (v instanceof String str) {
                                extractFromText(str, iocSet);
                            }
                        }
                    }
                }
            }
        }


        return new ArrayList<>(iocSet);
    }


    private String normalizeIoc(String val) {
        return val == null ? null : val.trim().toLowerCase();
    }

    private boolean isUrl(String value) {

        if (value == null || value.isBlank()) {
            return false;
        }

        String val = value.trim().toLowerCase();

        try {

            if (!(val.startsWith("http://") || val.startsWith("https://"))) {
                return false;
            }


            java.net.URI uri = new java.net.URI(val);

            return uri.getHost() != null;

        } catch (Exception e) {
            return false;
        }
    }

    private String buildMessage(Map<String, Object> log,
                                String user,
                                String action,
                                String ip) {

        StringBuilder msg = new StringBuilder("O365 ");

        if (action != null) msg.append(action);

        if (user != null) msg.append(" by ").append(user);

        if (ip != null) msg.append(" from ").append(ip);

        if (log.containsKey("LogonError")) {
            msg.append(" | Error: ").append(log.get("LogonError"));
        }

        return msg.toString();
    }

    private void putIfNotNull(Map<String, String> map, String k, String v) {
        if (v != null) map.put(k, v);
    }

    private void putIfNoNull(Map<String, Object> map, String k, Object v) {
        if (v != null) map.put(k, v);
    }

    private Map<String, String> parseExtendedProperties(Object extObj) {

        Map<String, String> map = new HashMap<>();

        if (!(extObj instanceof List<?> list)) {
            return map;
        }

        for (Object item : list) {
            if (item instanceof Map<?, ?> entry) {

                Object nameObj = entry.get("Name");
                Object valueObj = entry.get("Value");

                if (nameObj != null && valueObj != null) {
                    String key = nameObj.toString();
                    String value = valueObj.toString();

                    map.put(key, value);
                }
            }
        }

        return map;
    }

    private boolean isInternalIp(String ip) {

        if (ip == null || ip.isBlank()) return false;

        return ip.startsWith("10.") ||
                ip.startsWith("192.168.") ||
                ip.matches("^172\\.(1[6-9]|2[0-9]|3[0-1])\\..*") ||
                ip.equals("127.0.0.1") ||
                ip.equalsIgnoreCase("localhost");
    }

    private void extractFromText(String text, Set<String> iocSet) {

        if (text == null || text.isBlank()) return;

        String normalized = text.toLowerCase();


        Matcher domainMatcher = DOMAIN_PATTERN.matcher(normalized);
        while (domainMatcher.find()) {
            addSafe(iocSet, domainMatcher.group());
        }


        Matcher ipMatcher = IP_PATTERN.matcher(normalized);
        while (ipMatcher.find()) {
            addSafe(iocSet, ipMatcher.group());
        }


        addMatches(normalized, MD5_PATTERN, iocSet);
        addMatches(normalized, SHA1_PATTERN, iocSet);
        addMatches(normalized, SHA256_PATTERN, iocSet);
    }

    private void addMatches(String text, Pattern pattern, Set<String> iocSet) {

        Matcher matcher = pattern.matcher(text);

        while (matcher.find()) {
            addSafe(iocSet, matcher.group());
        }
    }

    private void addSafe(Set<String> set, String val) {

        String normalized = normalizeIoc(val);

        if (normalized != null && !normalized.isBlank()) {
            set.add(normalized);
        }
    }

    private void addMatches(String text, String regex, Set<String> iocSet) {

        java.util.regex.Matcher matcher =
                java.util.regex.Pattern.compile(regex).matcher(text);

        while (matcher.find()) {
            String hash = normalizeIoc(matcher.group());
            if (hash != null && !hash.isBlank()) {
                iocSet.add(hash);
            }
        }
    }

}