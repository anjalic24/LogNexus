package com.vulnuris.correlation.service;

import com.vulnuris.correlation.model.EventNode;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Slf4j
@Service
public class ImpossibleTravelDetector {

    private static final long IMPOSSIBLE_TRAVEL_THRESHOLD_MINUTES = 60;

    public double getMultiplier(EventNode source, EventNode target) {
        if (source.getGeoCountry() == null || target.getGeoCountry() == null) {
            return 1.0;
        }

        if ("Unknown".equals(source.getGeoCountry()) || "Unknown".equals(target.getGeoCountry())) {
            return 1.0;
        }

        if (!source.getGeoCountry().equals(target.getGeoCountry())) {
            if (source.getTsUtc() != null && target.getTsUtc() != null) {
                long minutesDiff = Math.abs(Duration.between(source.getTsUtc(), target.getTsUtc()).toMinutes());

                if (minutesDiff <= IMPOSSIBLE_TRAVEL_THRESHOLD_MINUTES) {
                    log.warn("IMPOSSIBLE TRAVEL detected: {} ({}) -> {} ({}) within {} minutes",
                            source.getSrcIp(), source.getGeoCountry(),
                            target.getSrcIp(), target.getGeoCountry(),
                            minutesDiff);
                    return 1.8;
                } else {
                    return 1.3;
                }
            }
            return 1.5;
        }

        return 1.0;
    }
}