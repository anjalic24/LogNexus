package com.vulnuris.correlation.consumer;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.vulnuris.correlation.dto.CesEventDto;
import com.vulnuris.correlation.ingestion.IngestionContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.support.KafkaHeaders;
import org.springframework.messaging.handler.annotation.Header;
import org.springframework.messaging.handler.annotation.Payload;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class EventConsumer {

    private static final String KEY_PREFIX = "bundle:";
    private static final String KEY_SUFFIX = ":events";
    private static final Duration BUNDLE_TTL = Duration.ofHours(2);
    private static final int PAGE_SIZE = 1_000;

    private final IngestionContext ingestionContext;
    private final StringRedisTemplate stringRedisTemplate;
    private final ObjectMapper objectMapper;

    @KafkaListener(
            topics = "normalized-events",
            groupId = "corr-grp",
            containerFactory = "kafkaListenerContainerFactory"
    )
    public void consumeEvent(
            @Payload CesEventDto event,
            @Header(value = KafkaHeaders.RECEIVED_KEY, required = false) String key
    ) {
        String bundleId = event.getBundleId() != null ? event.getBundleId() : key;
        if (bundleId == null || bundleId.isBlank()) {
            log.warn("[EventConsumer] Dropping event with no bundleId. eventId={}", event.getEventId());
            return;
        }

        String redisKey = KEY_PREFIX + bundleId + KEY_SUFFIX;

        try {
            String json = objectMapper.writeValueAsString(event);
            stringRedisTemplate.opsForList().rightPush(redisKey, json);
            stringRedisTemplate.expire(redisKey, BUNDLE_TTL);
        } catch (JsonProcessingException e) {
            log.error("[EventConsumer] Serialization failed, event dropped. eventId={} error={}",
                    event.getEventId(), e.getMessage());
        }

        log.debug("[EventConsumer] Event buffered. bundleId={} redisKey={}", bundleId, redisKey);
    }

    @KafkaListener(
            topics = "bundle-signals",
            groupId = "corr-grp",
            containerFactory = "kafkaStringListenerContainerFactory"
    )
    public void handleBundleComplete(
            @Payload String bundleId,
            @Header(value = KafkaHeaders.RECEIVED_KEY, required = false) String key
    ) {
        String effectiveId = bundleId != null ? bundleId : key;
        if (effectiveId == null || effectiveId.isBlank()) {
            log.warn("[EventConsumer] Bundle-signal received with no bundleId; ignoring.");
            return;
        }

        String redisKey = KEY_PREFIX + effectiveId + KEY_SUFFIX;

        Long totalEvents = stringRedisTemplate.opsForList().size(redisKey);
        if (totalEvents == null || totalEvents == 0L) {
            log.warn("[EventConsumer] Bundle-signal for '{}' but Redis buffer is empty.", effectiveId);
            return;
        }

        log.info("[EventConsumer] Bundle '{}' complete — {} events in Redis buffer.", effectiveId, totalEvents);

        long readStart = System.currentTimeMillis();
        List<CesEventDto> allEvents = new ArrayList<>((int) Math.min(totalEvents, Integer.MAX_VALUE));

        try {
            for (long offset = 0; offset < totalEvents; offset += PAGE_SIZE) {
                List<String> page = stringRedisTemplate
                        .opsForList()
                        .range(redisKey, offset, offset + PAGE_SIZE - 1);

                if (page == null || page.isEmpty()) {
                    log.warn("[EventConsumer] Unexpected empty page at offset {} for bundle '{}'.",
                            offset, effectiveId);
                    break;
                }

                for (String json : page) {
                    try {
                        allEvents.add(objectMapper.readValue(json, CesEventDto.class));
                    } catch (JsonProcessingException e) {
                        log.warn("[EventConsumer] Deserialization failed for event in bundle '{}'; "
                                + "skipping. error={}", effectiveId, e.getMessage());
                    }
                }
            }

        } finally {
            Boolean deleted = stringRedisTemplate.delete(redisKey);
            log.info("[EventConsumer] Redis buffer cleared for bundle '{}'. deleted={} readMs={}",
                    effectiveId, deleted, System.currentTimeMillis() - readStart);
        }

        if (allEvents.isEmpty()) {
            log.warn("[EventConsumer] No events could be deserialized for bundle '{}'; "
                    + "skipping correlation.", effectiveId);
            return;
        }

        log.info("[EventConsumer] Handing {} events to correlation engine for bundle '{}'.",
                allEvents.size(), effectiveId);
        ingestionContext.ingest("KAFKA", effectiveId, allEvents);
    }
}