package com.vulnuris.correlation.service;

import com.vulnuris.correlation.model.EventNode;
import com.vulnuris.correlation.repository.EventRepository;
import com.vulnuris.correlation.utils.Constants;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.neo4j.core.Neo4jClient;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Service
public class AttackStoryService {

    private final EventRepository eventRepository;
    private final Neo4jClient neo4jClient;

    public AttackStoryService(EventRepository eventRepository, Neo4jClient neo4jClient) {
        this.eventRepository = eventRepository;
        this.neo4jClient = neo4jClient;
    }


    public List<Map<String, Object>> buildAttackSessions(String bundleId) {
        log.info("Building attack sessions for bundle: {}", bundleId);

        propagateRisk(bundleId);

        List<Set<String>> components = findConnectedComponents(bundleId);

        log.info("Found {} attack sessions in bundle {}", components.size(), bundleId);

        List<Map<String, Object>> sessions = new ArrayList<>();
        int index = 1;

        for (Set<String> componentEventIds : components) {
            if (componentEventIds.isEmpty()) continue;
            sessions.add(buildSessionFromComponent(bundleId, componentEventIds, index++));
        }

        return sessions;
    }


    private List<Set<String>> findConnectedComponents(String bundleId) {


        Collection<Map<String, Object>> results = neo4jClient.query("""
            MATCH (e:Event {bundleId: $bundleId})
            OPTIONAL MATCH (e)-[:LINKED*1..20]-(connected:Event {bundleId: $bundleId})
            WITH e.eventId AS root, collect(DISTINCT connected.eventId) + [e.eventId] AS component
            RETURN component
        """)
        .bind(bundleId).to("bundleId")
        .fetch()
        .all();

        List<Set<String>> allSets = new ArrayList<>();
        for (Map<String, Object> row : results) {
            Object comp = row.get("component");
            if (comp instanceof List<?> idList) {
                Set<String> set = new HashSet<>();
                for (Object id : idList) {
                    if (id != null) set.add(id.toString());
                }
                if (!set.isEmpty()) allSets.add(set);
            }
        }

        return mergeOverlapping(allSets);
    }

    private List<Set<String>> mergeOverlapping(List<Set<String>> sets) {
        List<String> allIds = new ArrayList<>();
        for (Set<String> s : sets) allIds.addAll(s);


        List<String> unique = allIds.stream().distinct().collect(java.util.stream.Collectors.toList());
        Map<String, Integer> index = new HashMap<>();
        for (int i = 0; i < unique.size(); i++) index.put(unique.get(i), i);

        int n = unique.size();
        int[] parent = new int[n];
        int[] rank   = new int[n];
        for (int i = 0; i < n; i++) parent[i] = i;


        for (Set<String> s : sets) {
            if (s.isEmpty()) continue;
            String first = s.iterator().next();
            int rootIdx = index.get(first);
            for (String id : s) {
                union(parent, rank, rootIdx, index.get(id));
            }
        }


        Map<Integer, Set<String>> components = new HashMap<>();
        for (String id : unique) {
            int root = find(parent, index.get(id));
            components.computeIfAbsent(root, k -> new HashSet<>()).add(id);
        }

        return new ArrayList<>(components.values());
    }



    private int find(int[] parent, int i) {
        if (parent[i] != i) parent[i] = find(parent, parent[i]);
        return parent[i];
    }

    private void union(int[] parent, int[] rank, int a, int b) {
        int ra = find(parent, a);
        int rb = find(parent, b);
        if (ra == rb) return;
        if (rank[ra] < rank[rb])      { parent[ra] = rb; }
        else if (rank[ra] > rank[rb]) { parent[rb] = ra; }
        else                          { parent[rb] = ra; rank[ra]++; }
    }


    private Map<String, Object> buildSessionFromComponent(String bundleId, Set<String> eventIds, int index) {

        List<EventNode> nodes = eventRepository.findAllByEventIdIn(eventIds);

        if (nodes.isEmpty()) {
            return Map.of("attack_id", "ATK-" + bundleId.substring(0, 8) + "-" + index, "status", "EMPTY");
        }

        nodes.sort(Comparator.comparing(EventNode::getTsUtc, Comparator.nullsLast(Comparator.naturalOrder())));

        String attackId = "ATK-" + bundleId.substring(0, 8).toUpperCase() + "-" + String.format("%03d", index);
        Instant timelineStart = nodes.get(0).getTsUtc();
        Instant timelineEnd = nodes.get(nodes.size() - 1).getTsUtc();

        double maxRisk = nodes.stream().mapToDouble(EventNode::getNodeRisk).max().orElse(0.0);
        double avgSeverity = nodes.stream().mapToDouble(EventNode::getSeverity).average().orElse(0.0);

        Set<String> sourceTypes = extractNonNull(nodes, EventNode::getSourceType);
        Set<String> killChainStages = extractNonNull(nodes, EventNode::getKillChainStage);
        Set<String> attackTtps = extractNonNull(nodes, EventNode::getAttckTtp);
        Set<String> involvedUsers = extractNonNull(nodes, EventNode::getUser);
        Set<String> involvedIps = extractNonNull(nodes, EventNode::getSrcIp);
        Set<String> involvedHosts = extractNonNull(nodes, EventNode::getHost);

        String narrative = buildNarrative(nodes, involvedUsers, involvedIps, sourceTypes, attackTtps);

        String overallSeverity;
        if (maxRisk >= 0.8) overallSeverity = "CRITICAL";
        else if (maxRisk >= 0.6) overallSeverity = "HIGH";
        else if (maxRisk >= 0.4) overallSeverity = "MEDIUM";
        else overallSeverity = "LOW";

        Map<String, Object> session = new LinkedHashMap<>();
        session.put("attack_id", attackId);
        session.put("bundleId", bundleId);
        session.put("event_count", nodes.size());
        session.put("timeline_start", timelineStart != null ? timelineStart.toString() : null);
        session.put("timeline_end", timelineEnd != null ? timelineEnd.toString() : null);
        session.put("duration_seconds", timelineStart != null && timelineEnd != null
                ? java.time.Duration.between(timelineStart, timelineEnd).getSeconds() : 0);
        session.put("max_risk_score", Math.round(maxRisk * 1000.0) / 1000.0);
        session.put("avg_severity", Math.round(avgSeverity * 100.0) / 100.0);
        session.put("overall_severity", overallSeverity);
        session.put("source_types", sourceTypes);
        session.put("kill_chain_stages", killChainStages);
        session.put("mitre_ttps", attackTtps);
        session.put("involved_users", involvedUsers);
        session.put("involved_ips", involvedIps);
        session.put("involved_hosts", involvedHosts);
        session.put("narrative", narrative);
        session.put("event_ids", eventIds);

        log.info("Attack session {}: {} events, risk={}, severity={}",
                attackId, nodes.size(), maxRisk, overallSeverity);

        return session;
    }

    private <T> Set<String> extractNonNull(List<EventNode> nodes, java.util.function.Function<EventNode, String> getter) {
        return nodes.stream()
                .map(getter)
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());
    }

    private String buildNarrative(List<EventNode> nodes, Set<String> users,
                                  Set<String> ips, Set<String> sourceTypes, Set<String> ttps) {
        StringBuilder sb = new StringBuilder();
        sb.append("Attack session detected spanning ").append(nodes.size()).append(" events");
        sb.append(" across ").append(sourceTypes.size()).append(" source type(s): ");
        sb.append(String.join(", ", sourceTypes)).append(". ");

        if (!users.isEmpty()) sb.append("Involved user(s): ").append(String.join(", ", users)).append(". ");
        if (!ips.isEmpty()) sb.append("Involved IP(s): ").append(String.join(", ", ips)).append(". ");
        if (!ttps.isEmpty()) sb.append("MITRE ATT&CK technique(s): ").append(String.join(", ", ttps)).append(". ");

        List<String> criticalActions = nodes.stream()
                .filter(n -> n.getSeverity() >= 8.0)
                .map(EventNode::getAction)
                .filter(Objects::nonNull)
                .distinct()
                .toList();

        if (!criticalActions.isEmpty()) {
            sb.append("Critical actions observed: ").append(String.join(", ", criticalActions)).append(".");
        }

        return sb.toString();
    }

    public void propagateRisk(String bundleId) {
        log.info("Starting risk propagation for bundle: {}", bundleId);


        neo4jClient.query("""
            MATCH (e:Event {bundleId: $bundleId})
            SET e.baseRisk = e.nodeRisk
        """)
        .bind(bundleId).to("bundleId")
        .run();

        for (int round = 0; round < Constants.RISK_PROPAGATION_ROUNDS; round++) {
            neo4jClient.query("""
                MATCH (target:Event {bundleId: $bundleId})
                OPTIONAL MATCH (source:Event {bundleId: $bundleId})-[r:LINKED]->(target)
                WITH target,
                     target.baseRisk AS base,
                     collect({risk: source.baseRisk, conf: r.confidence}) AS edges
                WITH target, base,
                     reduce(acc = 0.0, e IN edges |
                         CASE WHEN e.risk IS NOT NULL AND e.conf IS NOT NULL
                              THEN acc + (e.risk * e.conf * $dampingFactor)
                              ELSE acc
                         END
                     ) AS propagated
                SET target.nodeRisk = CASE
                    WHEN base + propagated > 1.0 THEN 1.0
                    ELSE base + propagated
                END
            """)
            .bind(bundleId).to("bundleId")
            .bind(Constants.RISK_DAMPING_FACTOR).to("dampingFactor")
            .run();
        }

        log.info("Risk propagation completed for bundle: {}", bundleId);
    }
}