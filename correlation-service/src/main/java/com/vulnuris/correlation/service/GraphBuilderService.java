package com.vulnuris.correlation.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.vulnuris.correlation.dto.CesEventDto;
import com.vulnuris.correlation.model.EventNode;
import com.vulnuris.correlation.repository.EventRepository;
import com.vulnuris.correlation.utils.Constants;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;

@Slf4j
@Service
public class GraphBuilderService {

    private static final int ENRICHMENT_BATCH_SIZE = 500;

    private final EventRepository eventRepository;
    private final NoiseGateService noiseGateService;
    private final FeatureExtractor featureExtractor;
    private final EdgeScorer edgeScorer;
    private final ThreatEnrichmentService threatEnrichmentService;
    private final ImpossibleTravelDetector impossibleTravelDetector;
    private final KillChainMapper killChainMapper;
    private final ObjectMapper objectMapper;
    private final Executor enrichmentExecutor;

    private static final long CLOCK_SKEW_TOLERANCE_MS = 2000;

    public GraphBuilderService(EventRepository eventRepository,
                               NoiseGateService noiseGateService,
                               FeatureExtractor featureExtractor,
                               EdgeScorer edgeScorer,
                               ThreatEnrichmentService threatEnrichmentService,
                               ImpossibleTravelDetector impossibleTravelDetector,
                               KillChainMapper killChainMapper,
                               ObjectMapper objectMapper,
                               @Qualifier("enrichmentExecutor") Executor enrichmentExecutor) {
        this.eventRepository = eventRepository;
        this.noiseGateService = noiseGateService;
        this.featureExtractor = featureExtractor;
        this.edgeScorer = edgeScorer;
        this.threatEnrichmentService = threatEnrichmentService;
        this.impossibleTravelDetector = impossibleTravelDetector;
        this.killChainMapper = killChainMapper;
        this.objectMapper = objectMapper;
        this.enrichmentExecutor = enrichmentExecutor;
    }

    @Transactional
    public void buildGraph(String bundleId, List<CesEventDto> rawEvents) {
        long startMs = System.currentTimeMillis();

        long existingCount = eventRepository.countByBundleId(bundleId);
        if (existingCount > 0) {
            log.warn("Bundle {} already has {} events in graph. Skipping to avoid duplicates.", bundleId, existingCount);
            return;
        }

        List<CesEventDto> validEvents = rawEvents.stream()
                .filter(e -> e.getEventId() != null)
                .filter(e -> e.getTsUtc() != null)
                .filter(e -> !noiseGateService.isNoise(e))
                .toList();

        log.info("[GraphBuilder] bundle={} noiseFilter: {}/{} events passed",
                bundleId, validEvents.size(), rawEvents.size());
        if (validEvents.isEmpty()) return;

        List<EventNode> unsavedNodes = validEvents.stream()
                .map(dto -> convertToNode(dto, bundleId))
                .toList();


        List<EventNode> savedNodes = new ArrayList<>(
                eventRepository.saveAll(unsavedNodes)
        );
        log.info("[GraphBuilder] bundle={} bulkSave: {} nodes written in {}ms",
                bundleId, savedNodes.size(), System.currentTimeMillis() - startMs);


        for (EventNode node : savedNodes) {
            if (node.getUser() != null && !node.getUser().isBlank()) {
                eventRepository.linkUser(node.getEventId(), node.getUser());
            }
            if (node.getSrcIp() != null && !node.getSrcIp().isBlank()) {
                eventRepository.linkIp(node.getEventId(), node.getSrcIp());
            }
            if (node.getHost() != null && !node.getHost().isBlank()) {
                eventRepository.linkHost(node.getEventId(), node.getHost());
            }
            if (node.getIocs() != null) {
                for (String ioc : node.getIocs()) {
                    if (ioc != null && !ioc.isBlank()) {
                        eventRepository.linkIoc(node.getEventId(), ioc);
                    }
                }
            }
        }


        long enrichStart = System.currentTimeMillis();
        List<List<EventNode>> batches = partition(savedNodes, ENRICHMENT_BATCH_SIZE);

        for (List<EventNode> batch : batches) {
            List<CompletableFuture<Void>> futures = batch.stream()
                    .map(node -> CompletableFuture.runAsync(
                            () -> threatEnrichmentService.enrichSync(node),
                            enrichmentExecutor
                    ))
                    .toList();

            CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();
        }
        log.info("[GraphBuilder] bundle={} parallelEnrich: {} events enriched in {}ms",
                bundleId, savedNodes.size(), System.currentTimeMillis() - enrichStart);


        eventRepository.propagateIpEnrichment(bundleId);
        eventRepository.propagateUserRisk(bundleId);
        eventRepository.propagateHostRisk(bundleId);


        long edgeStartMs = System.currentTimeMillis();
        List<Map<String, Object>> edgesToCreate = Collections.synchronizedList(new ArrayList<>());

        savedNodes.parallelStream().forEach(newerEvent -> {
            long windowMinutes = newerEvent.getSeverity() >= Constants.SEVERITY_CRITICAL_THRESHOLD
                    ? Constants.TIME_WINDOW_CRITICAL_MINUTES
                    : Constants.TIME_WINDOW_LOW_MINUTES;
            Instant windowStart = newerEvent.getTsUtc()
                    .minus(windowMinutes, ChronoUnit.MINUTES);


            List<EventNode> candidates = savedNodes.stream()
                .filter(olderEvent -> !olderEvent.getEventId().equals(newerEvent.getEventId()))
                .filter(olderEvent -> !olderEvent.getTsUtc().isBefore(windowStart))
                .filter(olderEvent -> (newerEvent.getTsUtc().toEpochMilli() - olderEvent.getTsUtc().toEpochMilli()) >= -CLOCK_SKEW_TOLERANCE_MS)
                .filter(olderEvent -> {
                    boolean userMatch = newerEvent.getUser() != null && newerEvent.getUser().equals(olderEvent.getUser());
                    boolean srcIpMatch = newerEvent.getSrcIp() != null && newerEvent.getSrcIp().equals(olderEvent.getSrcIp());
                    boolean hostMatch = newerEvent.getHost() != null && newerEvent.getHost().equals(olderEvent.getHost());
                    boolean crossIp1 = newerEvent.getSrcIp() != null && newerEvent.getSrcIp().equals(olderEvent.getDstIp());
                    boolean crossIp2 = newerEvent.getDstIp() != null && newerEvent.getDstIp().equals(olderEvent.getSrcIp());
                    return userMatch || srcIpMatch || hostMatch || crossIp1 || crossIp2;
                })
                .limit(100)
                .toList();

            for (EventNode olderEvent : candidates) {
                long timeDiffMs = Math.abs(newerEvent.getTsUtc().toEpochMilli() - olderEvent.getTsUtc().toEpochMilli());
                
                var features = featureExtractor.extract(olderEvent, newerEvent, windowMinutes);
                var scoreResult = edgeScorer.score(features, olderEvent, newerEvent);

                if (scoreResult.confidence() >= Constants.EDGE_THRESHOLD
                        && killChainMapper.isForwardProgress(
                        olderEvent.getKillChainStage(),
                        newerEvent.getKillChainStage())) {

                    double travelMultiplier = impossibleTravelDetector.getMultiplier(olderEvent, newerEvent);
                    double finalConfidence = Math.min(1.0, scoreResult.confidence() * travelMultiplier);

                    Map<String, Object> edgeParams = new HashMap<>();
                    edgeParams.put("sourceId", olderEvent.getEventId());
                    edgeParams.put("targetId", newerEvent.getEventId());
                    edgeParams.put("confidence", finalConfidence);
                    edgeParams.put("reasons", scoreResult.reasons());
                    edgeParams.put("edgeType", scoreResult.edgeType());
                    edgeParams.put("timeDiff", timeDiffMs);
                    edgesToCreate.add(edgeParams);
                }
            }
        });

        long computeEnd = System.currentTimeMillis();
        if (!edgesToCreate.isEmpty()) {

            List<List<Map<String, Object>>> edgeBatches = partition(edgesToCreate, 10_000);
            for (List<Map<String, Object>> batch : edgeBatches) {
                eventRepository.bulkCreateEdges(batch);
            }
        }

        log.info("[GraphBuilder] bundle={} EDGE PHASE: {} edges computed in {}ms, saved in {}ms. TOTAL GRAPH TIME: {}ms",
                bundleId, edgesToCreate.size(), computeEnd - edgeStartMs, System.currentTimeMillis() - computeEnd, System.currentTimeMillis() - startMs);
    }


    private <T> List<List<T>> partition(List<T> list, int size) {
        List<List<T>> partitions = new ArrayList<>();
        for (int i = 0; i < list.size(); i += size) {
            partitions.add(list.subList(i, Math.min(i + size, list.size())));
        }
        return partitions;
    }

    private EventNode convertToNode(CesEventDto dto, String bundleId) {
        EventNode node = new EventNode();

        node.setEventId(dto.getEventId());
        node.setBundleId(bundleId);
        node.setTsUtc(dto.getTsUtc());
        node.setSourceType(dto.getSourceType());
        node.setHost(dto.getHost());
        node.setUser(dto.getUser());
        node.setSrcIp(dto.getSrcIp());
        node.setDstIp(dto.getDstIp());
        node.setAction(dto.getAction());
        node.setMessage(dto.getMessage());
        node.setIocs(dto.getIocs());
        node.setSeverity(dto.getSeverity());
        node.setSeverityLabel(dto.getSeverityLabel());


        try {
            if (dto.getExtra() != null) {
                node.setExtra(objectMapper.writeValueAsString(dto.getExtra()));
            }
        } catch (Exception e) {
            log.warn("Failed to serialize extra field for event {}: {}", dto.getEventId(), e.getMessage());
            node.setExtra("{}");
        }


        node.setWazuhRuleId(dto.getWazuhRuleId());
        node.setWindowsEventId(dto.getWindowsEventId());


        if (dto.getCorrelationKeys() != null) {
            if (node.getWazuhRuleId() == null) {
                node.setWazuhRuleId(dto.getCorrelationKeys().get("ruleId"));
            }
            if (node.getWindowsEventId() == null) {
                node.setWindowsEventId(dto.getCorrelationKeys().get("eventId"));
            }
        }

        node.setRawRefFile(dto.getRawRefFile());
        node.setRawRefOffset(dto.getRawRefOffset());


        node.setKillChainStage(killChainMapper.mapActionToStage(dto.getAction()));

        return node;
    }
}