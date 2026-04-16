package com.vulnuris.IngestionService.parser;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.vulnuris.IngestionService.model.CesEvent;
import com.vulnuris.IngestionService.service.severity.AwsSeverityService;
import org.springframework.stereotype.Component;

import java.io.InputStream;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Stream;

@Component
public class CloudTrailParser implements LogParser {

    private final ObjectMapper mapper = new ObjectMapper();
    private final AwsSeverityService awsSeverityService;

    public CloudTrailParser(AwsSeverityService awsSeverityService) {
        this.awsSeverityService = awsSeverityService;
    }

    @Override
    public Stream<CesEvent> parseStream(InputStream input, String filename) {
        try {
            AtomicLong offsetCounter = new AtomicLong(0);

            Map<String, Object> root = mapper.readValue(input, Map.class);

            List<Map<String, Object>> records = new ArrayList<>();

            if (root.containsKey("Records") && root.get("Records") instanceof List<?>) {
                records = (List<Map<String, Object>>) root.get("Records");
            } else {
                records.add(root);
            }

            return records.stream()
                    .filter(Objects::nonNull)
                    .map(record -> convert(record, filename, offsetCounter.getAndIncrement()))
                    .filter(Objects::nonNull);

        } catch (Exception e) {
            throw new RuntimeException("CloudTrail parsing error", e);
        }
    }

    private CesEvent convert(Map<String, Object> log, String file, long offset) {

        try {
            if (log == null || log.isEmpty()) return null;

            // ---------- TIMESTAMP ----------
            String eventTime = getString(log, "eventTime");
            Instant tsUtc = eventTime != null ? Instant.parse(eventTime) : Instant.now();

            // ---------- USER ----------
            Map<String, Object> userIdentity = getMap(log, "userIdentity");
            String userName = getString(userIdentity, "userName");
            String arn = getString(userIdentity, "arn");
            String accessKeyId = getString(userIdentity, "accessKeyId");


            // ---------- NETWORK ----------
            String srcIp = getString(log, "sourceIPAddress");

            // ---------- CORE FIELDS ----------
            String action = getString(log, "eventName");
            String object = getString(log, "eventSource");
            String awsRegion = getString(log, "awsRegion");
            String errorCode = getString(log, "errorCode");
            String userAgent = getString(log, "userAgent");
            String errorMessage = getString(log, "errorMessage");

            // ---------- EVENT ID ----------
            String eventId = getString(log, "eventID");
            if (eventId == null) {
                eventId = UUID.randomUUID().toString();
            }

            // ---------- RESULT ----------
            String result = detectResult(errorCode, errorMessage);

            // ---------- IOC EXTRACTION ----------
            List<String> iocs = new ArrayList<>();

            if (srcIp != null) iocs.add(srcIp);
            if (accessKeyId != null) iocs.add(accessKeyId);


            // ---------- CORRELATION KEYS ----------
            String readOnly = getString(log, "readOnly");
            String managementEvent =  getString(log, "managementEvent");
            Map<String, String> correlation = new HashMap<>();

            putIfNotNull(correlation, "userName", userName);
            putIfNotNull(correlation, "userArn", arn);
            putIfNotNull(correlation, "srcIp", srcIp);
            putIfNotNull(correlation, "accessKeyId", accessKeyId);
            putIfNotNull(correlation, "readOnly", readOnly);
            putIfNotNull(correlation, "managementEvent", managementEvent);

            // ---------- EXTRA ----------
            Map<String, Object> extra = new HashMap<>();

            putIfNotNull(extra, "userAgent", userAgent);
            putIfNotNull(extra, "awsRegion", awsRegion);
            putIfNotNull(extra, "awsErrorCode", errorCode);
            putIfNotNull(extra,"awsErrorMessage", errorMessage);


            // ---------- MESSAGE ----------
            String message = buildMessage(action, object, userName, srcIp);

            // ---------- SEVERITY ----------
            double severityScore = awsSeverityService.calculateSeverity(log);
            String severity = awsSeverityService.toSeverityLabel(severityScore);

            return CesEvent.builder()
                    .eventId(eventId)

                    .tsUtc(tsUtc)
                    .tsOriginal(eventTime)
                    .tsOffset("Z")

                    .sourceType("AWS")

                    .host(null)
                    .user(userName)

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
            System.err.println("Failed parsing log: " + log);
            return null;
        }
    }

    // ---------- HELPERS ----------

    private String getString(Map<String, Object> map, String key) {
        if (map == null || key == null) return null;
        Object val = map.get(key);
        return val != null ? val.toString() : null;
    }

    private Map<String, Object> getMap(Map<String, Object> map, String key) {
        if (map == null || key == null) return null;
        Object val = map.get(key);
        if (val instanceof Map<?, ?>) {
            return (Map<String, Object>) val;
        }
        return null;
    }

    private void putIfNotNull(Map<String, ?> map, String key, Object value) {
        if (value != null) {
            ((Map<String, Object>) map).put(key, value);
        }
    }

    private String buildMessage(String action, String object, String user, String ip) {
        return String.format("AWS event %s on %s by %s from %s",
                safe(action), safe(object), safe(user), safe(ip));
    }

    private String safe(String val) {
        return val == null ? "unknown" : val;
    }

    private String detectResult(String errorCode, String errorMessage){

        boolean hasErrorCode = errorCode != null && !errorCode.isBlank();
        boolean hasErrorMessage = errorMessage != null && !errorMessage.isBlank();

        boolean messageIndicatesFailure = hasErrorMessage &&
                errorMessage.toLowerCase().matches(".*(denied|unauthorized|not authorized|failed|error|forbidden).*");

        boolean isFailure = hasErrorCode || messageIndicatesFailure;

        String result = isFailure ? "FAILURE" : "SUCCESS";

        return result;
    }
}
