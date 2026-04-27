package com.vulnuris.correlation.service;

import com.vulnuris.correlation.model.EventNode;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.*;

@Service
public class FeatureExtractor {


    public FeatureResult extract(EventNode source, EventNode target, long windowMinutes) {

        List<String> reasons = new ArrayList<>();
        double[] features = new double[12];


        if (source.getUser() != null && target.getUser() != null
                && source.getUser().equals(target.getUser())) {
            features[0] = 1.0;
            reasons.add("same_user:" + source.getUser());
        }


        if (source.getSrcIp() != null && target.getSrcIp() != null
                && source.getSrcIp().equals(target.getSrcIp())) {
            features[1] = 1.0;
            reasons.add("same_src_ip:" + source.getSrcIp());
        }


        if (source.getHost() != null && target.getHost() != null
                && source.getHost().equals(target.getHost())) {
            features[2] = 1.0;
            reasons.add("same_host:" + source.getHost());
        }


        if (source.getAction() != null && target.getAction() != null
                && source.getAction().equals(target.getAction())) {
            features[3] = 1.0;
            reasons.add("same_action");
        }


        if (source.getTsUtc() != null && target.getTsUtc() != null) {
            long diffMs = Math.abs(Duration.between(source.getTsUtc(), target.getTsUtc()).toMillis());

            double decayConstantMs = windowMinutes * 60.0 * 1000.0;
            double timeScore = Math.exp(-diffMs / decayConstantMs);
            features[4] = timeScore;
            if (timeScore > 0.3) reasons.add("time_proximity");
        }


        int overlap = 0;
        if (source.getIocs() != null && target.getIocs() != null) {
            overlap = (int) source.getIocs().stream()
                    .filter(ioc -> isRealIoc(ioc))
                    .filter(target.getIocs()::contains)
                    .count();
        }
        features[5] = Math.min(overlap, 5) / 5.0;
        if (overlap > 0) reasons.add("ioc_overlap:" + overlap);


        if (source.getSourceType() != null && target.getSourceType() != null
                && !source.getSourceType().equals(target.getSourceType())) {
            features[6] = 0.5;
            reasons.add("cross_source:" + source.getSourceType() + "->" + target.getSourceType());
        }


        if (source.getSrcIp() != null && target.getSrcIp() != null
                && source.getSrcIp().equals(target.getSrcIp())
                && source.getUser() != null && target.getUser() != null
                && !source.getUser().equals(target.getUser())) {
            features[7] = 0.8;
            reasons.add("multi_user_same_ip");
        }


        if (source.getSrcIp() != null && target.getDstIp() != null
                && source.getSrcIp().equals(target.getDstIp())) {
            features[8] = 0.9;
            reasons.add("src_to_dst_ip:" + source.getSrcIp());
        }
        if (source.getDstIp() != null && target.getSrcIp() != null
                && source.getDstIp().equals(target.getSrcIp())) {
            features[8] = Math.max(features[8], 0.9);
            if (!reasons.contains("src_to_dst_ip:" + source.getDstIp())) {
                reasons.add("dst_to_src_ip:" + source.getDstIp());
            }
        }


        if (target.getSeverity() > source.getSeverity()) {
            features[9] = Math.min(1.0, (target.getSeverity() - source.getSeverity()) / 5.0);
            reasons.add("severity_escalation");
        }

        double ckScore = computeCorrelationKeyOverlap(source, target);
        features[10] = ckScore;
        if (ckScore > 0) reasons.add("correlation_key_match");


        if (source.getGeoCountry() != null && target.getGeoCountry() != null
                && !"Unknown".equals(source.getGeoCountry())
                && !"Unknown".equals(target.getGeoCountry())
                && source.getGeoCountry().equals(target.getGeoCountry())) {
            features[11] = 0.3;
            reasons.add("same_country:" + source.getGeoCountry());
        }

        return new FeatureResult(features, reasons);
    }

    private boolean isRealIoc(String ioc) {
        if (ioc == null || ioc.isBlank()) return false;

        if (ioc.matches("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$")) return false;

        if (ioc.contains("@")) return false;

        if (ioc.startsWith("/api/") || ioc.startsWith("/static/")) return false;
        return true;
    }

    private double computeCorrelationKeyOverlap(EventNode source, EventNode target) {
        int matches = 0;
        int totalChecks = 0;


        if (source.getWazuhRuleId() != null && target.getWazuhRuleId() != null) {
            totalChecks++;
            if (source.getWazuhRuleId().equals(target.getWazuhRuleId())) matches++;
        }


        if (source.getWindowsEventId() != null && target.getWindowsEventId() != null) {
            totalChecks++;
            if (source.getWindowsEventId().equals(target.getWindowsEventId())) matches++;
        }


        if (source.getDstIp() != null && target.getDstIp() != null) {
            totalChecks++;
            if (source.getDstIp().equals(target.getDstIp())) matches++;
        }

        if (totalChecks == 0) return 0.0;
        return (double) matches / totalChecks;
    }

    public record FeatureResult(double[] features, List<String> reasons) {}
}