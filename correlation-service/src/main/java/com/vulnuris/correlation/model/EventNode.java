package com.vulnuris.correlation.model;

import org.springframework.data.neo4j.core.schema.*;
import lombok.Data;
import java.time.Instant;
import java.util.List;
import org.springframework.data.neo4j.core.schema.Relationship;

@Node("Event")
@Data
public class EventNode {

    @Id
    private String eventId;

    private String bundleId;
    private Instant tsUtc;
    private String sourceType;
    private String host;
    private String user;
    private String srcIp;
    private String dstIp;
    private String action;
    private String message;
    private List<String> iocs;
    private double severity;
    private String severityLabel;
    private double nodeRisk = 0.0;
    private double threatScore = 0.0;
    private String attckTtp;
    private String geoCountry;
    private String killChainStage;

    private String extra;

    // Fields from logs
    private String wazuhRuleId;
    private Integer wazuhRuleLevel;
    private String windowsEventId;
    private String rawRefFile;
    private Long rawRefOffset;

    @Relationship(type = "HAS_USER", direction = Relationship.Direction.OUTGOING)
    private UserNode userNode;

    @Relationship(type = "HAS_SRC_IP", direction = Relationship.Direction.OUTGOING)
    private IpNode srcIpNode;

    @Relationship(type = "ON_HOST", direction = Relationship.Direction.OUTGOING)
    private HostNode hostNode;

    @Relationship(type = "HAS_IOC", direction = Relationship.Direction.OUTGOING)
    private List<IocNode> iocNodes;
}