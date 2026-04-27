package com.vulnuris.correlation.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.data.neo4j.core.Neo4jClient;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class Neo4jIndexConfig {

    private final Neo4jClient neo4jClient;

    public Neo4jIndexConfig(Neo4jClient neo4jClient) {
        this.neo4jClient = neo4jClient;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void createIndexes() {
        log.info("Creating Neo4j indexes...");


        createIndex("CREATE INDEX event_bundleId IF NOT EXISTS FOR (e:Event) ON (e.bundleId)");
        createIndex("CREATE INDEX event_eventId IF NOT EXISTS FOR (e:Event) ON (e.eventId)");
        createIndex("CREATE INDEX event_tsUtc IF NOT EXISTS FOR (e:Event) ON (e.tsUtc)");
        createIndex("CREATE INDEX event_user IF NOT EXISTS FOR (e:Event) ON (e.user)");
        createIndex("CREATE INDEX event_srcIp IF NOT EXISTS FOR (e:Event) ON (e.srcIp)");
        createIndex("CREATE INDEX event_host IF NOT EXISTS FOR (e:Event) ON (e.host)");
        createIndex("CREATE INDEX event_dstIp IF NOT EXISTS FOR (e:Event) ON (e.dstIp)");


        createIndex("CREATE INDEX event_bundle_ts IF NOT EXISTS FOR (e:Event) ON (e.bundleId, e.tsUtc)");


        createIndex("CREATE INDEX user_id IF NOT EXISTS FOR (u:User) ON (u.userId)");
        createIndex("CREATE INDEX ip_address IF NOT EXISTS FOR (ip:IP) ON (ip.ipAddress)");
        createIndex("CREATE INDEX host_name IF NOT EXISTS FOR (h:Host) ON (h.hostname)");
        createIndex("CREATE INDEX ioc_value IF NOT EXISTS FOR (i:IOC) ON (i.iocValue)");

        log.info("Neo4j indexes created successfully.");
    }

    private void createIndex(String cypher) {
        try {
            neo4jClient.query(cypher).run();
        } catch (Exception e) {
            log.warn("Index creation skipped (may already exist): {}", e.getMessage());
        }
    }
}
