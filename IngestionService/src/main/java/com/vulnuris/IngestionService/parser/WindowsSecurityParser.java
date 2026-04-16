package com.vulnuris.IngestionService.parser;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.vulnuris.IngestionService.model.CesEvent;
import com.vulnuris.IngestionService.service.severity.WindowsSeverityService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.InputStream;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Stream;

@Slf4j
@Component
public class WindowsSecurityParser implements LogParser {

    private final ObjectMapper mapper = new ObjectMapper();
    private final WindowsSeverityService windowsSeverityService;

    public WindowsSecurityParser(WindowsSeverityService windowsSeverityService) {
        this.windowsSeverityService = windowsSeverityService;
    }

    private static final DateTimeFormatter FORMATTER =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");


    @Override
    public Stream<CesEvent> parseStream(InputStream input, String filename) {

        try {
            List<Map<String, Object>> events =
                    mapper.readValue(input, new TypeReference<List<Map<String, Object>>>() {});

            AtomicLong offset = new AtomicLong(0);

            return events.stream()
                    .map(e -> convert(e, filename, offset.getAndIncrement()))
                    .filter(Objects::nonNull);

        } catch (Exception e) {
            log.error("Windows parser failed", e);
            return Stream.empty();
        }
    }

    private CesEvent convert(Map<String, Object> logs, String file, long offset) {

        try {
            if (logs == null) return null;

            // -------- BASIC FIELDS --------
            String eventTime = safeString(logs.get("EventTime"));
            String hostname = safeString(logs.get("Hostname"));
            String message = safeString(logs.get("Message"));
            Integer eventId = safeInt(logs.get("EventID"));
            String severityStr = safeString(logs.get("Severity"));
            String severityValue = safeInt(logs.get("SeverityValue")).toString();

            Map<String, Object> eventData =
                    (Map<String, Object>) logs.getOrDefault("EventData", Collections.emptyMap());

            // -------- USER LOGIC --------
            String subjectUser = safeString(eventData.get("SubjectUserName"));
            String targetUser = safeString(eventData.get("TargetUserName"));

            String user = resolveUser(subjectUser, targetUser);

            // -------- NETWORK --------
            String srcIp = safeString(eventData.get("IpAddress"));
            Integer srcPort = safeInt(eventData.get("IpPort"));

            // -------- TIME --------
            Instant tsUtc = parseTime(eventTime);

            // -------- ACTION / RESULT --------
            String action = mapAction(eventId);
            String result = mapResult(logs.get("EventType"));

            // -------- IOCS --------
            List<String> iocs = new ArrayList<>();
            if (srcIp != null) iocs.add(srcIp);

            // -------- CORRELATION KEYS --------
            Map<String, String> correlationKeys = new HashMap<>();
            putIfNotNull(correlationKeys, "user", user);
            putIfNotNull(correlationKeys, "host", hostname);
            putIfNotNull(correlationKeys, "srcIp", srcIp);
            putIfNotNull(correlationKeys, "eventId", String.valueOf(eventId));
            putIfNotNull(correlationKeys, "severityMsg", severityStr);

            // -------- EXTRA --------
            Map<String, Object> extra = new HashMap<>();
            putIfNoNull(extra, "workstationName", safeString(eventData.get("WorkstationName")));
            putIfNoNull(extra, "windowsEventId", eventId);
            putIfNoNull(extra, "logonType", safeString(eventData.get("LogonType")));
            putIfNoNull(extra, "processName", safeString(eventData.get("LogonProcessName")));
            putIfNoNull(extra, "authPackage", safeString(eventData.get("AuthenticationPackageName")));

            // ---------- SEVERITY ----------
            double severityScore = windowsSeverityService.calculateSeverity(logs);
            String severity = windowsSeverityService.toSeverityLabel(severityScore);

            return CesEvent.builder()
                    .eventId(UUID.randomUUID().toString())

                    .tsUtc(tsUtc)
                    .tsOriginal(eventTime)
                    .tsOffset("Z")

                    .sourceType("WINDOWS")

                    .host(hostname)
                    .user(user)

                    .srcIp(srcIp)
                    .srcPort(srcPort)

                    .dstIp(null)
                    .dstPort(null)

                    .protocol("windows")

                    .action(action)
                    .object(eventId != null ? "event_" + eventId : null)

                    .result(result)
                    .severity(severityScore)
                    .severityLabel(severity)

                    .message(message)

                    .iocs(iocs)

                    .correlationKeys(correlationKeys)

                    .extra(extra)

                    .rawRefFile(file)
                    .rawRefOffset(offset)

                    .build();

        } catch (Exception e) {
            log.error("Failed parsing windows event: {}", e.getMessage(), e);
            return null;
        }
    }

    // ---------------- HELPERS ----------------

    private String resolveUser(String subject, String target) {

        if (target != null && !"SYSTEM".equalsIgnoreCase(target)) {
            return target;
        }

        if (subject != null && !"SYSTEM".equalsIgnoreCase(subject)) {
            return subject;
        }

        return target != null ? target : subject;
    }

    private Instant parseTime(String time) {
        try {
            if (time == null) return Instant.now();
            LocalDateTime ldt = LocalDateTime.parse(time, FORMATTER);
            return ldt.toInstant(ZoneOffset.UTC);
        } catch (Exception e) {
            return Instant.now();
        }
    }

    private String mapAction(Integer eventId) {

        if (eventId == null) return "WINDOWS_EVENT";

        switch (eventId) {
            // ---------------- AUTHENTICATION ----------------
            case 4624: return "LOGIN_SUCCESS";
            case 4625: return "LOGIN_FAIL";
            case 4634: return "LOGOUT";
            case 4647: return "USER_INITIATED_LOGOUT";
            case 4648: return "EXPLICIT_LOGIN";
            case 4675: return "SID_FILTERING";

            // ---------------- PRIVILEGES ----------------
            case 4672: return "ADMIN_PRIVILEGES_ASSIGNED";
            case 4673: return "PRIVILEGED_SERVICE_CALLED";
            case 4674: return "PRIVILEGED_OPERATION";

            // ---------------- PROCESS ----------------
            case 4688: return "PROCESS_CREATE";
            case 4689: return "PROCESS_EXIT";

            // ---------------- ACCOUNT MANAGEMENT ----------------
            case 4720: return "USER_CREATE";
            case 4722: return "USER_ENABLE";
            case 4723: return "PASSWORD_CHANGE";
            case 4724: return "PASSWORD_RESET";
            case 4725: return "USER_DISABLE";
            case 4726: return "USER_DELETE";
            case 4738: return "USER_MODIFY";

            // ---------------- GROUP MANAGEMENT ----------------
            case 4732: return "LOCAL_GROUP_MEMBER_ADD";
            case 4733: return "LOCAL_GROUP_MEMBER_REMOVE";

            case 4756: return "GLOBAL_GROUP_MEMBER_ADD";
            case 4757: return "GLOBAL_GROUP_MEMBER_REMOVE";

            case 4728: return "SECURITY_GROUP_MEMBER_ADD";
            case 4729: return "SECURITY_GROUP_MEMBER_REMOVE";

            // ---------------- POLICY / SYSTEM ----------------
            case 4719: return "AUDIT_POLICY_CHANGE";
            case 4616: return "SYSTEM_TIME_CHANGED";
            case 4608: return "SYSTEM_START";
            case 4609: return "SYSTEM_SHUTDOWN";

            // ---------------- NETWORK / SHARE ----------------
            case 5140: return "FILE_SHARE_ACCESS";
            case 5145: return "FILE_SHARE_PERMISSION_CHECK";

            // ---------------- TASK / SCHEDULER ----------------
            case 4698: return "TASK_CREATE";
            case 4699: return "TASK_DELETE";
            case 4700: return "TASK_ENABLE";
            case 4701: return "TASK_DISABLE";

            // ---------------- OBJECT ACCESS ----------------
            case 4663: return "OBJECT_ACCESS";
            case 4656: return "HANDLE_REQUEST";

            // ---------------- LOG CLEAR ----------------
            case 1102: return "AUDIT_LOG_CLEARED";

            // ---------------- DEFAULT ----------------
            default: return "WINDOWS_EVENT";
        }
    }

    private String mapResult(Object eventType) {

        if (eventType == null) return "UNKNOWN";

        String val = eventType.toString().toLowerCase();

        if (val.contains("success")) return "SUCCESS";
        if (val.contains("failure") || val.contains("fail")) return "FAIL";

        return "UNKNOWN";
    }

    private void putIfNotNull(Map<String, String> map, String key, String value) {
        if (value != null) map.put(key, value);
    }

    private void putIfNoNull(Map<String, Object> map, String key, Object value) {
        if (value != null) {
            map.put(key, value);
        }
    }

    private String safeString(Object obj) {
        return obj != null ? obj.toString() : null;
    }

    private Integer safeInt(Object obj) {
        try {
            return obj != null ? Integer.parseInt(obj.toString()) : null;
        } catch (Exception e) {
            return null;
        }
    }
}