package com.vulnuris.correlation.model;

import lombok.Data;
import org.springframework.data.neo4j.core.schema.Id;
import org.springframework.data.neo4j.core.schema.Node;

@Node("IP")
@Data
public class IpNode {
    @Id
    private String ipAddress;
    private String country;
    private double threatScore = 0.0;
}
