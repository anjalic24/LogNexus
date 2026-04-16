package com.vulnuris.IngestionService.parser;


import com.vulnuris.IngestionService.model.CesEvent;
import com.vulnuris.IngestionService.service.severity.WebServerSeverityService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.*;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.*;
import java.util.stream.Stream;


@Slf4j
@Component
public class WebAccessLogParser implements LogParser {

    private final WebServerSeverityService webServerSeverityService;

    public WebAccessLogParser(WebServerSeverityService webServerSeverityService) {
        this.webServerSeverityService = webServerSeverityService;
    }

    private static final Pattern LOG_PATTERN = Pattern.compile(
            "^(\\S+) - - \\[(.*?)\\] \"(\\S+) (.*?) (\\S+)\" (\\d{3}) (\\d+) \"(.*?)\" \"(.*?)\"$"
    );

    private static final DateTimeFormatter FORMATTER =
            DateTimeFormatter.ofPattern("dd/MMM/yyyy:HH:mm:ss Z", Locale.ENGLISH);


    @Override
    public Stream<CesEvent> parseStream(InputStream input, String filename) {

        AtomicLong offset = new AtomicLong(0);

        BufferedReader reader = new BufferedReader(new InputStreamReader(input));

        return reader.lines()
                .map(line -> parseLine(line, filename, offset.getAndIncrement()))
                .filter(Objects::nonNull);
    }

    private CesEvent parseLine(String line, String file, long offset) {

        try {

            if (line == null || line.isBlank())
                return null;

            Matcher m = LOG_PATTERN.matcher(line);

            if (!m.matches()) {
                log.debug("Unmatched line: {}", line);
                return null;
            }

            String srcIp = m.group(1);
            String tsOriginal = m.group(2);
            String method = m.group(3);
            String url = m.group(4);
            String protocol = m.group(5);
            Integer status = parseInt(m.group(6));
            Integer bytes = parseInt(m.group(7));
            String referrer = m.group(8);
            String userAgent = m.group(9);

            ZonedDateTime zdt = ZonedDateTime.parse(tsOriginal, FORMATTER);
            Instant tsUtc = zdt.toInstant();
            String tsOffset = zdt.getOffset().toString();

            String action = detectAction(method, url);
            String result = mapResult(status);

            List<String> iocs = extractIocs(srcIp, url);

            Map<String, String> correlationKeys = new HashMap<>();
            putIfNotNull(correlationKeys, "srcIp", srcIp);
            putIfNotNull(correlationKeys, "url", url);
            putIfNotNull(correlationKeys, "method", method);
            putIfNotNull(correlationKeys, "status", String.valueOf(status));

            Map<String, Object> extra = new HashMap<>();
            putIfNoNull(extra, "bytes", bytes);
            putIfNoNull(extra, "referrer", referrer);
            putIfNoNull(extra, "userAgent", userAgent);

            // ---------- SEVERITY ----------
            double severityScore = webServerSeverityService.calculateSeverity(line);
            String severity = webServerSeverityService.toSeverityLabel(severityScore);

            return CesEvent.builder()
                    .eventId(UUID.randomUUID().toString())
                    .tsUtc(tsUtc)
                    .tsOriginal(tsOriginal)
                    .tsOffset(tsOffset)

                    .sourceType("WEB")

                    .host(null)
                    .user(null)

                    .srcIp(srcIp)
                    .dstIp(null)

                    .srcPort(null)
                    .dstPort(null)

                    .protocol(protocol)

                    .action(action)
                    .object(url)

                    .result(result)
                    .severity(severityScore)
                    .severityLabel(severity)

                    .message(method + " " + url + " -> " + status)

                    .iocs(iocs)

                    .correlationKeys(correlationKeys)
                    .extra(extra)

                    .rawRefFile(file)
                    .rawRefOffset(offset)

                    .build();

        } catch (Exception e) {
            log.error("Parsing failed at offset {} : {}", offset, e.getMessage());
            return null;
        }
    }

    // ---------------- HELPERS ----------------

    private Integer parseInt(String val) {
        try {
            return val != null ? Integer.parseInt(val) : null;
        } catch (Exception e) {
            return null;
        }
    }

    private String mapResult(Integer status) {
        if (status == null) return "UNKNOWN";
        if (status >= 200 && status < 300) return "SUCCESS";
        if (status >= 400) return "FAIL";
        return "UNKNOWN";
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

    private String detectAction(String method, String url) {

        if (url == null) return method;

        String u = url.toLowerCase();

        if (u.contains("<script>"))
            return "XSS_ATTEMPT";

        if (u.contains("../"))
            return "PATH_TRAVERSAL";

        if (u.contains("' or '1'='1"))
            return "SQL_INJECTION";

        if (u.contains("cmd="))
            return "COMMAND_INJECTION";

        if (u.contains("wp-admin"))
            return "WORDPRESS_PROBE";

        return method;
    }

    private List<String> extractIocs(String ip, String url) {

        List<String> list = new ArrayList<>();

        if (ip != null)
            list.add(ip);

        if (url != null)
            list.add(url);

        return list;
    }


}