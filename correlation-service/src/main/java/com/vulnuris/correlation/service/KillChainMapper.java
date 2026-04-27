package com.vulnuris.correlation.service;

import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class KillChainMapper {


    private static final Map<String, Integer> STAGE_ORDER = Map.ofEntries(
            Map.entry("RECONNAISSANCE", 1),
            Map.entry("WEAPONIZATION", 2),
            Map.entry("DELIVERY", 3),
            Map.entry("EXPLOITATION", 4),
            Map.entry("INSTALLATION", 5),
            Map.entry("COMMAND_AND_CONTROL", 6),
            Map.entry("ACTIONS_ON_OBJECTIVES", 7),

            Map.entry("INITIAL_ACCESS", 3),
            Map.entry("EXECUTION", 4),
            Map.entry("PERSISTENCE", 5),
            Map.entry("PRIVILEGE_ESCALATION", 5),
            Map.entry("DEFENSE_EVASION", 5),
            Map.entry("CREDENTIAL_ACCESS", 5),
            Map.entry("DISCOVERY", 6),
            Map.entry("LATERAL_MOVEMENT", 6),
            Map.entry("COLLECTION", 7),
            Map.entry("EXFILTRATION", 7),
            Map.entry("IMPACT", 7)
    );

    public boolean isForwardProgress(String sourceStage, String targetStage) {
        if (sourceStage == null || targetStage == null) return true;

        Integer sourceOrder = STAGE_ORDER.getOrDefault(sourceStage.toUpperCase(), 0);
        Integer targetOrder = STAGE_ORDER.getOrDefault(targetStage.toUpperCase(), 0);

        return targetOrder >= sourceOrder;
    }

    public String mapActionToStage(String action) {
        if (action == null) return null;
        String upper = action.toUpperCase();
        return switch (upper) {
            case "PORT_SCAN", "WORDPRESS_PROBE" -> "RECONNAISSANCE";
            case "SQL_INJECTION", "RCE_ATTACK", "LFI_ATTACK",
                 "COMMAND_INJECTION", "FILE_UPLOAD_ATTACK", "POST" -> "INITIAL_ACCESS";
            case "LOGIN_SUCCESS", "EXPLICIT_LOGIN", "SSH_LOGIN",
                 "USERLOGGEDIN", "PASSWORD_RESET" -> "CREDENTIAL_ACCESS";
            case "USER_CREATE", "USER_ENABLE", "PERSISTENCE" -> "PERSISTENCE";
            case "PRIV_ESC",
                 "SUCCESSFUL SUDO TO ROOT EXECUTED." -> "PRIVILEGE_ESCALATION";
            case "FIREWALL_CHANGE", "GPO_CHANGE",
                 "FIREWALL DROP EVENT." -> "DEFENSE_EVASION";
            case "RDP_HIJACK", "REMOTE_EXEC" -> "LATERAL_MOVEMENT";
            case "FILEACCESSED", "FILEMODIFIED", "GETOBJECT" -> "COLLECTION";
            case "DNS_TUNNELING" -> "COMMAND_AND_CONTROL";
            case "DATA_EXFILTRATION" -> "EXFILTRATION";
            case "DELETESNAPSHOT", "DELETEOBJECT" -> "IMPACT";
            case "RUNINSTANCES", "CREATESECURITYGROUP" -> "EXECUTION";
            case "MALWARE DETECTED." -> "EXPLOITATION";
            case "BOT_ATTACK" -> "COMMAND_AND_CONTROL";
            case "DENY", "RESET-BOTH", "RESET-SERVER",
                 "RESET-CLIENT", "DROP", "ALLOW" -> "DEFENSE_EVASION";
            default -> null;
        };
    }
}