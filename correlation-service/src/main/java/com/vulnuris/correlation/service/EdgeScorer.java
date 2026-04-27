package com.vulnuris.correlation.service;

import com.vulnuris.correlation.model.EventNode;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@Slf4j
public class EdgeScorer {

    private static final double[] WEIGHTS =
            {0.15, 0.15, 0.08, 0.05, 0.15, 0.10, 0.05, 0.04, 0.10, 0.03, 0.08, 0.02};

    public ScoreResult score(FeatureExtractor.FeatureResult f, EventNode s, EventNode t) {

        double score = 0.0;

        for (int i = 0; i < Math.min(WEIGHTS.length, f.features().length); i++) {
            score += f.features()[i] * WEIGHTS[i];
        }

        double avgSeverity = (s.getSeverity() + t.getSeverity()) / 2.0;
        if (avgSeverity >= 8.0) {
            score *= 1.15;
        } else if (avgSeverity >= 6.0) {
            score *= 1.05;
        }

        score = Math.min(score, 1.0);

        String type = score >= 0.65 ? "caused_by" : "follows";

        return new ScoreResult(score, f.reasons(), type);
    }

    public record ScoreResult(double confidence, List<String> reasons, String edgeType) {}
}