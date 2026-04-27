package com.vulnuris.correlation.model;

import lombok.Data;
import org.springframework.data.neo4j.core.schema.Id;
import org.springframework.data.neo4j.core.schema.Node;

@Node("Host")
@Data
public class HostNode {
    @Id
    private String hostname;
    private double riskScore = 0.0;
}
