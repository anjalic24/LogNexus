package com.vulnuris.IngestionService.config;

import org.apache.kafka.clients.admin.AdminClientConfig;
import org.apache.kafka.clients.admin.NewTopic;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.config.TopicBuilder;
import org.springframework.kafka.core.KafkaAdmin;

import java.util.HashMap;
import java.util.Map;

@Configuration
public class KafkaTopicConfig {

    private static final int NORMALIZED_EVENTS_PARTITIONS = 12;
    private static final int BUNDLE_SIGNALS_PARTITIONS    = 3;
    private static final int REPLICATION_FACTOR           = 3;

    private static final String RETENTION_MS            = String.valueOf(7L * 24 * 60 * 60 * 1_000);
    private static final String RETENTION_BYTES_EVENTS  = String.valueOf(10L * 1024 * 1024 * 1024);
    private static final String RETENTION_BYTES_SIGNALS = String.valueOf(1024L * 1024 * 1024);

    @Value("${spring.kafka.bootstrap-servers}")
    private String bootstrapServers;

    @Bean
    public KafkaAdmin kafkaAdmin() {
        Map<String, Object> configs = new HashMap<>();
        configs.put(AdminClientConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        configs.put(AdminClientConfig.REQUEST_TIMEOUT_MS_CONFIG, 10_000);
        configs.put(AdminClientConfig.DEFAULT_API_TIMEOUT_MS_CONFIG, 30_000);
        KafkaAdmin admin = new KafkaAdmin(configs);
        admin.setFatalIfBrokerNotAvailable(false);
        admin.setAutoCreate(true);
        return admin;
    }

    @Bean
    public NewTopic normalizedEventsTopic() {
        return TopicBuilder.name("normalized-events")
                .partitions(NORMALIZED_EVENTS_PARTITIONS)
                .replicas(REPLICATION_FACTOR)
                .config("retention.ms", RETENTION_MS)
                .config("retention.bytes", RETENTION_BYTES_EVENTS)
                .config("segment.bytes", String.valueOf(512 * 1024 * 1024))
                .config("compression.type", "snappy")
                .config("min.insync.replicas", "2")
                .build();
    }

    @Bean
    public NewTopic bundleSignalsTopic() {
        return TopicBuilder.name("bundle-signals")
                .partitions(BUNDLE_SIGNALS_PARTITIONS)
                .replicas(REPLICATION_FACTOR)
                .config("retention.ms", RETENTION_MS)
                .config("retention.bytes", RETENTION_BYTES_SIGNALS)
                .config("min.insync.replicas", "2")
                .build();
    }
}
