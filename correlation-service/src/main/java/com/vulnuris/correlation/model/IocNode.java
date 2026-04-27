package com.vulnuris.correlation.model;

import lombok.Data;
import org.springframework.data.neo4j.core.schema.Id;
import org.springframework.data.neo4j.core.schema.Node;

@Node("IOC")
@Data
public class IocNode {
    @Id
    private String iocValue;
}
