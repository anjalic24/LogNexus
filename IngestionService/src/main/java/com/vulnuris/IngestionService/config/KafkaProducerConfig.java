package com.vulnuris.IngestionService.config;

import com.vulnuris.IngestionService.model.CesEvent;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.serialization.StringSerializer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.core.DefaultKafkaProducerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.core.ProducerFactory;
import org.springframework.kafka.support.serializer.JsonSerializer;

import java.util.HashMap;
import java.util.Map;

@Configuration
public class KafkaProducerConfig {

    @Value("${spring.kafka.bootstrap-servers}")
    private String bootstrapServers;

    private Map<String, Object> baseProducerProps() {
        Map<String, Object> props = new HashMap<>();
        props.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        props.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class);

        props.put(ProducerConfig.BATCH_SIZE_CONFIG, 65_536);
        props.put(ProducerConfig.LINGER_MS_CONFIG, 5);
        props.put(ProducerConfig.COMPRESSION_TYPE_CONFIG, "snappy");
        props.put(ProducerConfig.BUFFER_MEMORY_CONFIG, 67_108_864L);

        props.put(ProducerConfig.ACKS_CONFIG, "all");
        props.put(ProducerConfig.ENABLE_IDEMPOTENCE_CONFIG, true);
        props.put(ProducerConfig.MAX_IN_FLIGHT_REQUESTS_PER_CONNECTION, 5);

        props.put(ProducerConfig.RETRIES_CONFIG, 5);
        props.put(ProducerConfig.RETRY_BACKOFF_MS_CONFIG, 1_000);
        props.put(ProducerConfig.REQUEST_TIMEOUT_MS_CONFIG, 30_000);
        props.put(ProducerConfig.DELIVERY_TIMEOUT_MS_CONFIG, 120_000);

        return props;
    }

    @Bean
    public ProducerFactory<String, CesEvent> cesEventProducerFactory() {
        Map<String, Object> props = baseProducerProps();
        JsonSerializer<CesEvent> valueSerializer = new JsonSerializer<>();
        valueSerializer.setAddTypeInfo(false);
        return new DefaultKafkaProducerFactory<>(props, new StringSerializer(), valueSerializer);
    }

    @Bean
    public KafkaTemplate<String, CesEvent> cesEventKafkaTemplate() {
        return new KafkaTemplate<>(cesEventProducerFactory());
    }

    @Bean
    public ProducerFactory<String, String> bundleSignalProducerFactory() {
        Map<String, Object> props = baseProducerProps();
        props.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, StringSerializer.class);
        return new DefaultKafkaProducerFactory<>(props);
    }

    @Bean
    public KafkaTemplate<String, String> bundleSignalKafkaTemplate() {
        return new KafkaTemplate<>(bundleSignalProducerFactory());
    }
}
