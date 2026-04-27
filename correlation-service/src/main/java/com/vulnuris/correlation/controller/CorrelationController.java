package com.vulnuris.correlation.controller;

import com.vulnuris.correlation.dto.CesEventDto;
import com.vulnuris.correlation.dto.FilteredIngestRequest;
import com.vulnuris.correlation.ingestion.IngestionContext;
import com.vulnuris.correlation.model.EventNode;
import com.vulnuris.correlation.repository.EventRepository;
import com.vulnuris.correlation.service.AttackStoryService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.neo4j.core.Neo4jClient;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@RestController
@RequestMapping("/api/correlation")
@RequiredArgsConstructor
public class CorrelationController {

    private final IngestionContext ingestionContext;
    private final AttackStoryService attackStoryService;
    private final EventRepository eventRepository;
    private final Neo4jClient neo4jClient;

    @PostMapping("/manual-ingest")
    public ResponseEntity<String> manualIngest(@RequestBody List<CesEventDto> events) {
        if (events == null || events.isEmpty()) {
            return ResponseEntity.badRequest().body("No events provided");
        }

        String bundleId = events.get(0).getBundleId();
        if (bundleId == null || bundleId.isBlank()) {
            return ResponseEntity.badRequest().body("First event must have a valid bundleId");
        }

        boolean allSameBundle = events.stream()
                .allMatch(e -> bundleId.equals(e.getBundleId()));
        if (!allSameBundle) {
            return ResponseEntity.badRequest().body("All events must share the same bundleId");
        }

        log.info("Manual ingest: bundleId={}, eventCount={}", bundleId, events.size());
        ingestionContext.ingest("MANUAL", bundleId, events);
        return ResponseEntity.ok("Bundle processed: " + bundleId);
    }

    @PostMapping("/filtered-ingest")
    public ResponseEntity<Map<String, Object>> filteredIngest(@RequestBody FilteredIngestRequest request) {
        if (request.getEvents() == null || request.getEvents().isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "No events provided"));
        }

        List<CesEventDto> filtered = request.getEvents().stream()
                .filter(e -> e.getEventId() != null)
                .filter(e -> {
                    if (request.getMinSeverity() != null) {
                        double minSev = severityToScore(request.getMinSeverity());
                        return e.getSeverity() >= minSev;
                    }
                    return true;
                })
                .filter(e -> {
                    if (request.getTimeFrom() != null && e.getTsUtc().getEpochSecond() < request.getTimeFrom()) return false;
                    if (request.getTimeTo() != null && e.getTsUtc().getEpochSecond() > request.getTimeTo()) return false;
                    return true;
                })
                .toList();

        if (filtered.isEmpty()) {
            return ResponseEntity.ok(Map.of(
                    "status", "NO_MATCH",
                    "message", "No events matched the filters",
                    "originalCount", request.getEvents().size(),
                    "filteredCount", 0
            ));
        }

        String bundleId = filtered.get(0).getBundleId();
        log.info("Filtered ingest: bundleId={}, original={}, afterFilter={}",
                bundleId, request.getEvents().size(), filtered.size());

        ingestionContext.ingest("MANUAL", bundleId, filtered);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("status", "SUCCESS");
        result.put("bundleId", bundleId);
        result.put("originalCount", request.getEvents().size());
        result.put("filteredCount", filtered.size());
        result.put("minSeverity", request.getMinSeverity());
        return ResponseEntity.ok(result);
    }

    @GetMapping("/attack-sessions/{bundleId}")
    public ResponseEntity<List<Map<String, Object>>> getAttackSessions(@PathVariable String bundleId) {
        if (bundleId == null || bundleId.isBlank()) {
            return ResponseEntity.badRequest().build();
        }
        List<Map<String, Object>> sessions = attackStoryService.buildAttackSessions(bundleId);
        return ResponseEntity.ok(sessions);
    }

    @GetMapping("/events/{bundleId}")
    public ResponseEntity<List<Map<String, Object>>> getEvents(
            @PathVariable String bundleId,
            @RequestParam(defaultValue = "0")   int page,
            @RequestParam(defaultValue = "100")  int size) {

        if (bundleId == null || bundleId.isBlank()) {
            return ResponseEntity.badRequest().build();
        }
        int cappedSize = Math.min(size, 500);
        int skip = page * cappedSize;

        Collection<Map<String, Object>> rows = neo4jClient.query("""
            MATCH (e:Event {bundleId: $bundleId})
            RETURN e.eventId AS id,
                   toString(e.tsUtc) AS tsUtc,
                   e.severity AS severity,
                   e.severityLabel AS severityLabel,
                   e.sourceType AS eventType,
                   e.srcIp AS sourceIp,
                   e.host AS sourceHost,
                   e.action AS action,
                   e.attckTtp AS attckTtp,
                   e.message AS message
            ORDER BY e.tsUtc DESC
            SKIP $skip LIMIT $limit
        """)
                .bind(bundleId).to("bundleId")
                .bind(skip).to("skip")
                .bind(cappedSize).to("limit")
                .fetch().all();

        return ResponseEntity.ok(new ArrayList<>(rows));
    }

    @GetMapping("/graph/{bundleId}")
    public ResponseEntity<Map<String, Object>> getGraphData(@PathVariable String bundleId) {

        Collection<Map<String, Object>> eventNodes = neo4jClient.query("""
            MATCH (e:Event {bundleId: $bundleId})
            RETURN e.eventId AS id, 'Event' AS type, e.action AS label,
                   e.severity AS severity, e.severityLabel AS severityLabel,
                   e.user AS user, e.srcIp AS srcIp, e.host AS host,
                   e.dstIp AS dstIp, e.nodeRisk AS nodeRisk,
                   e.killChainStage AS killChainStage, e.attckTtp AS attckTtp,
                   e.geoCountry AS geoCountry, e.sourceType AS sourceType,
                   e.message AS message, toString(e.tsUtc) AS tsUtc
        """).bind(bundleId).to("bundleId").fetch().all();

        Collection<Map<String, Object>> userNodes = neo4jClient.query("""
            MATCH (e:Event {bundleId: $bundleId})-[:HAS_USER]->(u:User)
            RETURN DISTINCT u.userId AS id, 'User' AS type, u.userId AS label,
                   u.riskScore AS riskScore
        """).bind(bundleId).to("bundleId").fetch().all();

        Collection<Map<String, Object>> ipNodes = neo4jClient.query("""
            MATCH (e:Event {bundleId: $bundleId})-[:HAS_SRC_IP]->(ip:IP)
            RETURN DISTINCT ip.ipAddress AS id, 'IP' AS type, ip.ipAddress AS label,
                   ip.country AS country, ip.threatScore AS threatScore
        """).bind(bundleId).to("bundleId").fetch().all();

        Collection<Map<String, Object>> hostNodes = neo4jClient.query("""
            MATCH (e:Event {bundleId: $bundleId})-[:ON_HOST]->(h:Host)
            RETURN DISTINCT h.hostname AS id, 'Host' AS type, h.hostname AS label,
                   h.riskScore AS riskScore
        """).bind(bundleId).to("bundleId").fetch().all();

        Collection<Map<String, Object>> iocNodes = neo4jClient.query("""
            MATCH (e:Event {bundleId: $bundleId})-[:HAS_IOC]->(ioc:IOC)
            RETURN DISTINCT ioc.iocValue AS id, 'IOC' AS type, ioc.iocValue AS label
        """).bind(bundleId).to("bundleId").fetch().all();

        Collection<Map<String, Object>> linkedEdges = neo4jClient.query("""
            MATCH (s:Event {bundleId: $bundleId})-[r:LINKED]->(t:Event {bundleId: $bundleId})
            RETURN s.eventId AS source, t.eventId AS target,
                   r.confidence AS confidence, r.edgeType AS edgeType,
                   r.reasons AS reasons, r.timeDiffMs AS timeDiffMs,
                   'LINKED' AS type
        """).bind(bundleId).to("bundleId").fetch().all();

        Collection<Map<String, Object>> entityEdges = neo4jClient.query("""
            MATCH (e:Event {bundleId: $bundleId})-[r]->(n)
            WHERE type(r) IN ['HAS_USER', 'HAS_SRC_IP', 'ON_HOST', 'HAS_IOC']
            RETURN e.eventId AS source,
                   CASE type(r)
                     WHEN 'HAS_USER' THEN n.userId
                     WHEN 'HAS_SRC_IP' THEN n.ipAddress
                     WHEN 'ON_HOST' THEN n.hostname
                     WHEN 'HAS_IOC' THEN n.iocValue
                   END AS target,
                   type(r) AS type, 0.0 AS confidence
        """).bind(bundleId).to("bundleId").fetch().all();

        List<Map<String, Object>> allNodes = new ArrayList<>();
        allNodes.addAll(eventNodes);
        allNodes.addAll(userNodes);
        allNodes.addAll(ipNodes);
        allNodes.addAll(hostNodes);
        allNodes.addAll(iocNodes);

        List<Map<String, Object>> allEdges = new ArrayList<>();
        allEdges.addAll(linkedEdges);
        allEdges.addAll(entityEdges);

        return ResponseEntity.ok(Map.of(
                "nodes", allNodes,
                "edges", allEdges,
                "bundleId", bundleId
        ));
    }

    @GetMapping("/rca/{bundleId}")
    public ResponseEntity<Map<String, Object>> getRcaReport(@PathVariable String bundleId) {
        List<Map<String, Object>> sessions = attackStoryService.buildAttackSessions(bundleId);

        final int timelineLimit = 2000;
        Collection<Map<String, Object>> events = neo4jClient.query("""
            MATCH (e:Event {bundleId: $bundleId})
            RETURN e.eventId AS eventId, e.action AS action, e.severity AS severity,
                   e.severityLabel AS severityLabel, e.user AS user, e.srcIp AS srcIp,
                   e.host AS host, e.dstIp AS dstIp, e.message AS message,
                   e.sourceType AS sourceType, e.killChainStage AS killChainStage,
                   e.attckTtp AS attckTtp, e.geoCountry AS geoCountry,
                   e.nodeRisk AS nodeRisk, e.threatScore AS threatScore,
                   e.iocs AS iocs, toString(e.tsUtc) AS tsUtc
            ORDER BY e.tsUtc
            LIMIT $limit
        """)
                .bind(bundleId).to("bundleId")
                .bind(timelineLimit).to("limit")
                .fetch().all();

        Long totalEventsAll = neo4jClient.query("""
            MATCH (e:Event {bundleId: $bundleId})
            RETURN count(e) AS c
        """).bind(bundleId).to("bundleId").fetch().one()
                .map(m -> (m.get("c") instanceof Number n) ? n.longValue() : 0L)
                .orElse(0L);

        Collection<Map<String, Object>> affectedUsers = neo4jClient.query("""
            MATCH (e:Event {bundleId: $bundleId})-[:HAS_USER]->(u:User)
            RETURN DISTINCT u.userId AS userId, u.riskScore AS riskScore
        """).bind(bundleId).to("bundleId").fetch().all();

        Collection<Map<String, Object>> affectedHosts = neo4jClient.query("""
            MATCH (e:Event {bundleId: $bundleId})-[:ON_HOST]->(h:Host)
            RETURN DISTINCT h.hostname AS hostname, h.riskScore AS riskScore
        """).bind(bundleId).to("bundleId").fetch().all();

        Collection<Map<String, Object>> affectedIps = neo4jClient.query("""
            MATCH (e:Event {bundleId: $bundleId})-[:HAS_SRC_IP]->(ip:IP)
            RETURN DISTINCT ip.ipAddress AS ipAddress, ip.country AS country,
                   ip.threatScore AS threatScore
        """).bind(bundleId).to("bundleId").fetch().all();

        Collection<Map<String, Object>> iocs = neo4jClient.query("""
            MATCH (e:Event {bundleId: $bundleId})-[:HAS_IOC]->(ioc:IOC)
            RETURN DISTINCT ioc.iocValue AS iocValue
        """).bind(bundleId).to("bundleId").fetch().all();

        Collection<Map<String, Object>> causalChain = neo4jClient.query("""
            MATCH (s:Event {bundleId: $bundleId})-[r:LINKED]->(t:Event {bundleId: $bundleId})
            WHERE r.confidence >= 0.6
            RETURN s.eventId AS sourceId, s.action AS sourceAction,
                   t.eventId AS targetId, t.action AS targetAction,
                   r.confidence AS confidence, r.reasons AS reasons,
                   r.edgeType AS edgeType
            ORDER BY r.confidence DESC
        """).bind(bundleId).to("bundleId").fetch().all();

        Map<String, Object> rca = new LinkedHashMap<>();
        rca.put("bundleId", bundleId);
        rca.put("generatedAt", java.time.Instant.now().toString());
        rca.put("attackSessions", sessions);
        rca.put("timeline", events);
        rca.put("timelineLimit", timelineLimit);
        rca.put("timelineTruncated", totalEventsAll > events.size());
        rca.put("affectedUsers", affectedUsers);
        rca.put("affectedHosts", affectedHosts);
        rca.put("affectedIps", affectedIps);
        rca.put("iocs", iocs);
        rca.put("causalChain", causalChain);
        rca.put("totalEvents", totalEventsAll);
        rca.put("totalSessions", sessions.size());

        return ResponseEntity.ok(rca);
    }

    @GetMapping("/bundles")
    public ResponseEntity<List<Map<String, Object>>> listBundles() {
        Collection<Map<String, Object>> bundles = neo4jClient.query("""
            MATCH (e:Event)
            WITH e.bundleId AS bundleId, count(e) AS eventCount,
                 max(e.severity) AS maxSeverity, min(toString(e.tsUtc)) AS firstEvent,
                 max(toString(e.tsUtc)) AS lastEvent
            RETURN bundleId, eventCount, maxSeverity, firstEvent, lastEvent
            ORDER BY lastEvent DESC
        """).fetch().all();

        return ResponseEntity.ok(new ArrayList<>(bundles));
    }

    @GetMapping("/bundles/{bundleId}/status")
    public ResponseEntity<Map<String, Object>> getBundleStatus(@PathVariable String bundleId) {
        if (bundleId == null || bundleId.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("status", "ERROR", "message", "bundleId is required"));
        }

        Map<String, Object> row = neo4jClient.query("""
            MATCH (e:Event {bundleId: $bundleId})
            RETURN count(e) AS eventCount,
                   max(e.severity) AS maxSeverity,
                   min(toString(e.tsUtc)) AS firstEvent,
                   max(toString(e.tsUtc)) AS lastEvent
        """).bind(bundleId).to("bundleId").fetch().one().orElseGet(() -> {
            Map<String, Object> fallback = new HashMap<>();
            fallback.put("eventCount", 0L);
            fallback.put("maxSeverity", null);
            fallback.put("firstEvent", null);
            fallback.put("lastEvent", null);
            return fallback;
        });

        long eventCount = 0L;
        Object countObj = row.get("eventCount");
        if (countObj instanceof Number n) eventCount = n.longValue();

        String phase = eventCount > 0 ? "PERSISTED" : "WAITING";

        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("bundleId", bundleId);
        resp.put("phase", phase);
        resp.putAll(row);
        resp.put("timestamp", java.time.Instant.now().toString());
        return ResponseEntity.ok(resp);
    }

    @DeleteMapping("/bundles")
    public ResponseEntity<Map<String, Object>> deleteAllBundles() {
        log.warn("DELETE ALL: Purging all bundles from Neo4j");
        neo4jClient.query("MATCH (n) DETACH DELETE n").run();
        return ResponseEntity.ok(Map.of("status", "DELETED", "message", "All bundles and nodes purged"));
    }

    @DeleteMapping("/bundles/{bundleId}")
    public ResponseEntity<Map<String, Object>> deleteBundle(@PathVariable String bundleId) {
        log.warn("DELETE bundle: {}", bundleId);

        neo4jClient.query("""
            MATCH (e:Event {bundleId: $bundleId})
            DETACH DELETE e
        """).bind(bundleId).to("bundleId").run();

        neo4jClient.query("""
            MATCH (n)
            WHERE NOT n:Event
              AND NOT (n)--()          
            DELETE n
        """).run();

        return ResponseEntity.ok(Map.of("status", "DELETED", "bundleId", bundleId));
    }

    @GetMapping("/status")
    public ResponseEntity<Map<String, Object>> status() {
        return ResponseEntity.ok(Map.of(
                "status", "UP",
                "service", "correlation-service",
                "mode", "manual",
                "timestamp", java.time.Instant.now().toString()
        ));
    }

    private double severityToScore(String label) {
        if (label == null) return 0.0;
        return switch (label.toUpperCase()) {
            case "LOW" -> 2.0;
            case "MEDIUM" -> 4.0;
            case "HIGH" -> 7.0;
            case "CRITICAL" -> 9.0;
            default -> 0.0;
        };
    }
}