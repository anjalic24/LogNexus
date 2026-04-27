package com.vulnuris.correlation.model;

import lombok.Data;
import org.springframework.data.neo4j.core.schema.Id;
import org.springframework.data.neo4j.core.schema.Node;

@Node("User")
@Data
public class UserNode {
    @Id
    private String userId;
    private double riskScore = 0.0;
}
