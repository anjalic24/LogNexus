package com.vulnuris.correlation.repository;

import com.vulnuris.correlation.model.EventNode;
import org.springframework.data.neo4j.repository.Neo4jRepository;
import org.springframework.data.neo4j.repository.query.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Collection;
import java.util.List;

public interface EventRepository extends Neo4jRepository<EventNode, String> {


    @Query("""
        MATCH (e:Event)
        WHERE e.eventId IN $eventIds
        RETURN e
    """)
    List<EventNode> findAllByEventIdIn(@Param("eventIds") Collection<String> eventIds);

    @Query("""
        MATCH (e:Event {bundleId: $bundleId})
        RETURN count(e)
    """)
    long countByBundleId(@Param("bundleId") String bundleId);

    @Query("""
        MATCH (e:Event)
        WHERE e.bundleId = $bundleId
          AND e.tsUtc >= $windowStart
          AND (
            ($user IS NOT NULL AND e.user = $user)
            OR ($srcIp IS NOT NULL AND e.srcIp = $srcIp)
            OR ($host IS NOT NULL AND e.host = $host)
            OR ($srcIp IS NOT NULL AND e.dstIp = $srcIp)
            OR ($dstIp IS NOT NULL AND e.srcIp = $dstIp)
          )
        RETURN e LIMIT $limit
    """)
    List<EventNode> findCandidates(
            @Param("bundleId") String bundleId,
            @Param("windowStart") Instant windowStart,
            @Param("user") String user,
            @Param("srcIp") String srcIp,
            @Param("host") String host,
            @Param("dstIp") String dstIp,
            @Param("limit") int limit
    );


    @Query("""
        MATCH (source:Event {eventId: $sourceId})
        MATCH (target:Event {eventId: $targetId})
        MERGE (source)-[r:LINKED]->(target)
        SET r.confidence = $confidence,
            r.reasons = $reasons,
            r.edgeType = $edgeType,
            r.timeDiffMs = $timeDiff
    """)
    void createLinkedEdge(
            @Param("sourceId") String sourceId,
            @Param("targetId") String targetId,
            @Param("confidence") double confidence,
            @Param("reasons") List<String> reasons,
            @Param("edgeType") String edgeType,
            @Param("timeDiff") long timeDiff
    );

    @Query("""
        UNWIND $edges AS edge
        MATCH (source:Event {eventId: edge.sourceId})
        MATCH (target:Event {eventId: edge.targetId})
        MERGE (source)-[r:LINKED]->(target)
        SET r.confidence = edge.confidence,
            r.reasons = edge.reasons,
            r.edgeType = edge.edgeType,
            r.timeDiffMs = edge.timeDiff
    """)
    void bulkCreateEdges(@Param("edges") List<java.util.Map<String, Object>> edges);




    @Query("""
        MATCH (e:Event {eventId: $eventId})
        MERGE (u:User {userId: $userId})
        MERGE (e)-[:HAS_USER]->(u)
    """)
    void linkUser(@Param("eventId") String eventId, @Param("userId") String userId);

    @Query("""
        MATCH (e:Event {eventId: $eventId})
        MERGE (ip:IP {ipAddress: $ipAddress})
        MERGE (e)-[:HAS_SRC_IP]->(ip)
    """)
    void linkIp(@Param("eventId") String eventId, @Param("ipAddress") String ipAddress);

    @Query("""
        MATCH (e:Event {eventId: $eventId})
        MERGE (h:Host {hostname: $hostname})
        MERGE (e)-[:ON_HOST]->(h)
    """)
    void linkHost(@Param("eventId") String eventId, @Param("hostname") String hostname);

    @Query("""
        MATCH (e:Event {eventId: $eventId})
        MERGE (ioc:IOC {iocValue: $iocValue})
        MERGE (e)-[:HAS_IOC]->(ioc)
    """)
    void linkIoc(@Param("eventId") String eventId, @Param("iocValue") String iocValue);



    @Query("""
        MATCH (e:Event {bundleId: $bundleId})-[:HAS_SRC_IP]->(ip:IP)
        WITH ip, max(e.threatScore) AS maxThreat,
             collect(DISTINCT e.geoCountry)[0] AS country
        SET ip.threatScore = COALESCE(maxThreat, 0.0),
            ip.country = COALESCE(country, ip.country)
    """)
    void propagateIpEnrichment(@Param("bundleId") String bundleId);

    @Query("""
        MATCH (e:Event {bundleId: $bundleId})-[:HAS_USER]->(u:User)
        WITH u, max(e.nodeRisk) AS maxRisk
        SET u.riskScore = COALESCE(maxRisk, 0.0)
    """)
    void propagateUserRisk(@Param("bundleId") String bundleId);

    @Query("""
        MATCH (e:Event {bundleId: $bundleId})-[:ON_HOST]->(h:Host)
        WITH h, max(e.nodeRisk) AS maxRisk
        SET h.riskScore = COALESCE(maxRisk, 0.0)
    """)
    void propagateHostRisk(@Param("bundleId") String bundleId);
}