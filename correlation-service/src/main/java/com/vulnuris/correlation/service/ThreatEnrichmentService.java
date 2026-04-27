package com.vulnuris.correlation.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.vulnuris.correlation.model.EventNode;
import com.vulnuris.correlation.repository.EventRepository;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import io.github.resilience4j.retry.annotation.Retry;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.time.Duration;
import java.util.concurrent.Semaphore;


@Slf4j
@Service
public class ThreatEnrichmentService {

    private final RedisTemplate<String, Object> redisTemplate;
    private final EventRepository eventRepository;
    private final ObjectMapper objectMapper;
    private final WebClient webClient;

    @Value("${correlation.geoip-url:http://ip-api.com/json/}")
    private String geoipBaseUrl;


    private final Semaphore geoIpRateLimiter = new Semaphore(40);

    public ThreatEnrichmentService(RedisTemplate<String, Object> redisTemplate,
                                   EventRepository eventRepository,
                                   ObjectMapper objectMapper) {
        this.redisTemplate = redisTemplate;
        this.eventRepository = eventRepository;
        this.objectMapper = objectMapper;
        this.webClient = WebClient.builder()
                .codecs(configurer -> configurer.defaultCodecs().maxInMemorySize(2 * 1024 * 1024))
                .build();
    }

    public void enrichSync(EventNode node) {
        if (node == null) return;

        try {
            enrichGeoIP(node);
            enrichCisaKevFromCache(node);
            enrichMitreAttack(node);
            calculateNodeRisk(node);
            eventRepository.save(node);
        } catch (Exception e) {
            log.warn("Enrichment failed for event {}: {}", node.getEventId(), e.getMessage());
        }
    }

    @CircuitBreaker(name = "geoipBreaker", fallbackMethod = "geoipFallback")
    @Retry(name = "geoipRetry")
    public void enrichGeoIP(EventNode node) {
        if (node.getSrcIp() == null) return;


        if (isPrivateIp(node.getSrcIp())) {
            node.setGeoCountry("Internal");
            return;
        }

        String cacheKey = "geo:" + node.getSrcIp();
        String country = (String) redisTemplate.opsForValue().get(cacheKey);

        if (country != null) {
            node.setGeoCountry(country);
            return;
        }


        boolean acquired = geoIpRateLimiter.tryAcquire();
        if (!acquired) {
            log.warn("GeoIP rate limit reached, skipping lookup for {}", node.getSrcIp());
            node.setGeoCountry("Unknown");
            return;
        }

        try {
            String response = webClient.get()
                    .uri(geoipBaseUrl + node.getSrcIp() + "?fields=status,country,countryCode,isp,org,query")
                    .retrieve()
                    .bodyToMono(String.class)
                    .block(Duration.ofSeconds(5));

            JsonNode json = objectMapper.readTree(response);

            if ("success".equals(json.path("status").asText())) {
                country = json.path("country").asText("Unknown");
            } else {
                country = "Unknown";
            }

            redisTemplate.opsForValue().set(cacheKey, country, Duration.ofHours(24));

        } catch (Exception e) {
            log.warn("GeoIP lookup failed for {}: {}", node.getSrcIp(), e.getMessage());
            country = "Unknown";
        } finally {
            geoIpRateLimiter.release();
        }

        node.setGeoCountry(country);
    }

    public void geoipFallback(EventNode node, Throwable t) {
        log.warn("GeoIP circuit breaker OPEN for {}: {}", node.getSrcIp(), t.getMessage());
        node.setGeoCountry("Unknown");
    }



    public void enrichCisaKevFromCache(EventNode node) {
        if (node.getIocs() == null || node.getIocs().isEmpty()) return;

        for (String ioc : node.getIocs()) {
            if (ioc == null || !ioc.startsWith("CVE-")) continue;

            String kevKey = "cisa_kev:cve:" + ioc;
            Object cached = redisTemplate.opsForValue().get(kevKey);

            if (cached != null) {
                String kevData = cached.toString();
                boolean isRansomware = kevData.contains("Known");
                double boost = isRansomware ? 0.25 : 0.15;
                node.setThreatScore(Math.min(1.0, node.getThreatScore() + boost));
                log.info("CISA KEV match: {} for event {} (ransomware={})", ioc, node.getEventId(), isRansomware);
            }
        }
    }



    public void enrichMitreAttack(EventNode node) {
        if (node.getAction() == null) return;

        String cacheKey = "mitre:ttp:" + node.getAction().toLowerCase();
        String cachedTtp = (String) redisTemplate.opsForValue().get(cacheKey);

        if (cachedTtp != null) {
            node.setAttckTtp(cachedTtp);
            return;
        }

        String ttp = mapActionToAttackTtp(node.getAction());

        if (ttp != null) {
            node.setAttckTtp(ttp);
            redisTemplate.opsForValue().set(cacheKey, ttp, Duration.ofHours(48));
        }
    }

    private String mapActionToAttackTtp(String action) {
        if (action == null) return null;
        String upper = action.toUpperCase();


        String exact = switch (upper) {
            case "SQL_INJECTION", "RCE_ATTACK", "LFI_ATTACK",
                 "COMMAND_INJECTION", "FILE_UPLOAD_ATTACK" -> "T1190";
            case "PASSWORD_RESET"                          -> "T1110";
            case "LOGIN_SUCCESS", "EXPLICIT_LOGIN",
                 "USERLOGGEDIN"                            -> "T1078";
            case "SSH_LOGIN"                               -> "T1078.004";
            case "USER_CREATE", "USER_ENABLE"              -> "T1136";
            case "PERSISTENCE"                             -> "T1547";
            case "PRIV_ESC"                                -> "T1068";
            case "SUCCESSFUL SUDO TO ROOT EXECUTED."       -> "T1548.003";
            case "FIREWALL_CHANGE"                         -> "T1562.004";
            case "GPO_CHANGE"                              -> "T1484.001";
            case "PORT_SCAN"                               -> "T1046";
            case "WORDPRESS_PROBE"                         -> "T1595.002";
            case "RDP_HIJACK"                              -> "T1563.002";
            case "REMOTE_EXEC"                             -> "T1021";
            case "FILEACCESSED"                            -> "T1005";
            case "FILEMODIFIED"                            -> "T1565.001";
            case "DNS_TUNNELING"                           -> "T1071.004";
            case "DATA_EXFILTRATION"                       -> "T1041";
            case "GETOBJECT"                               -> "T1530";
            case "DELETEOBJECT", "DELETESNAPSHOT"          -> "T1485";
            case "FIREWALL DROP EVENT."                    -> "T1562.004";
            case "DENY", "RESET-BOTH", "RESET-SERVER",
                 "RESET-CLIENT", "DROP"                   -> "T1562.004";
            case "RUNINSTANCES"                            -> "T1204";
            case "CREATESECURITYGROUP"                     -> "T1562.007";
            case "MALWARE DETECTED."                       -> "T1204.002";
            case "BOT_ATTACK"                              -> "T1583.005";
            case "POST"                                    -> "T1071.001";
            case "ALLOW"                                   -> null;
            default                                        -> null;
        };
        if (exact != null) return exact;


        return mapActionFuzzy(upper);
    }

    private String mapActionFuzzy(String upper) {

        if (upper.contains("POWERSHELL") || upper.contains("CMD.EXE")
                || upper.contains("WSCRIPT") || upper.contains("CSCRIPT")
                || upper.contains("BASH") || upper.contains("SH "))    return "T1059";
        if (upper.contains("SCHEDULED") && upper.contains("TASK"))     return "T1053.005";
        if (upper.contains("CRON"))                                     return "T1053.003";
        if (upper.contains("SERVICE") && upper.contains("CREAT"))      return "T1543.003";
        if (upper.contains("WMIC"))                                     return "T1047";
        if (upper.contains("MSHTA") || upper.contains("REGSVR"))       return "T1218";

        if (upper.contains("PHISH"))                                    return "T1566";
        if (upper.contains("BRUTE") || upper.contains("SPRAY"))        return "T1110";
        if (upper.contains("EXPLOIT"))                                  return "T1190";
        if (upper.contains("SPEAR"))                                    return "T1566.001";
        if (upper.contains("VPN") && upper.contains("FAIL"))           return "T1133";

        if (upper.contains("PASS") && (upper.contains("FAIL")
                || upper.contains("WRONG") || upper.contains("INVALID")
                || upper.contains("INCORRECT")))                        return "T1110.001";
        if (upper.contains("MIMIKATZ") || upper.contains("LSASS"))     return "T1003.001";
        if (upper.contains("KERBEROS") || upper.contains("KERBEROAST")) return "T1558.003";
        if (upper.contains("SECRETSDUMP"))                              return "T1003";
        if (upper.contains("CREDENTIAL") || upper.contains("CRED"))    return "T1552";
        if (upper.contains("TOKEN") && upper.contains("STEAL"))        return "T1134";
        if (upper.contains("MFA") && (upper.contains("BYPASS")
                || upper.contains("PUSH") || upper.contains("FATIGUE"))) return "T1621";

        if (upper.contains("SUDO") || upper.contains("RUNAS"))         return "T1548";
        if (upper.contains("PRIV") || upper.contains("ESCALAT"))       return "T1068";
        if (upper.contains("BECOME") || upper.contains("SETUID"))      return "T1548.001";
        if (upper.contains("TOKEN") && upper.contains("IMPERSON"))     return "T1134.001";

        if (upper.contains("REGISTRY") && (upper.contains("RUN")
                || upper.contains("SET") || upper.contains("ADD")))    return "T1547.001";
        if (upper.contains("AUTORUN") || upper.contains("STARTUP"))    return "T1547";
        if (upper.contains("BACKDOOR"))                                 return "T1505";
        if (upper.contains("WEBSHELL"))                                 return "T1505.003";
        if (upper.contains("ADDUSER") || upper.contains("ADD_USER")
                || upper.contains("NEWUSER"))                           return "T1136.001";

        if (upper.contains("LOGCLEAR") || upper.contains("LOG_CLEAR")
                || upper.contains("CLEARLOG") || upper.contains("WINEVENT")
                || (upper.contains("CLEAR") && upper.contains("LOG"))) return "T1070.001";
        if (upper.contains("ANTIVIRUS") && upper.contains("DISABLE"))  return "T1562.001";
        if (upper.contains("OBFUSCAT") || upper.contains("BASE64")
                || upper.contains("ENCODE"))                            return "T1027";
        if (upper.contains("MASQUERAD"))                                return "T1036";
        if (upper.contains("TIMESTOMP"))                                return "T1070.006";

        if (upper.contains("SMB") || (upper.contains("ADMIN$")
                || upper.contains("IPC$")))                             return "T1021.002";
        if (upper.contains("RDPLOGIN") || upper.contains("RDP_LOGIN")
                || (upper.contains("RDP") && upper.contains("LOGIN"))) return "T1021.001";
        if (upper.contains("PSEXEC"))                                   return "T1569.002";
        if (upper.contains("WINRM") || upper.contains("REMOTE_MGMT")) return "T1021.006";
        if (upper.contains("PASS-THE-HASH") || upper.contains("PTH")
                || upper.contains("PASSTHEHASH"))                       return "T1550.002";

        if (upper.contains("NMAP") || (upper.contains("SCAN")
                && upper.contains("PORT")))                             return "T1046";
        if (upper.contains("WHOAMI") || upper.contains("IPCONFIG")
                || upper.contains("SYSTEMINFO"))                        return "T1082";
        if (upper.contains("NETDISCOVER") || upper.contains("ARP_SCAN")) return "T1018";
        if (upper.contains("DIR ") || upper.contains("LS ")
                || upper.contains("LISTDIR"))                           return "T1083";

        if (upper.contains("SCREENSHOT"))                               return "T1113";
        if (upper.contains("KEYLOG"))                                   return "T1056.001";
        if (upper.contains("CLIPBOARD"))                                return "T1115";
        if (upper.contains("ARCHIVE") || upper.contains("COMPRESS")
                || upper.contains("ZIP"))                               return "T1560";

        if (upper.contains("EXFIL") || upper.contains("EXFILTRAT"))    return "T1041";
        if (upper.contains("FTP") || upper.contains("SFTP"))           return "T1048.003";
        if (upper.contains("UPLOAD") && (upper.contains("C2")
                || upper.contains("C&C") || upper.contains("DROPBOX")
                || upper.contains("S3")))                               return "T1567";
        if (upper.contains("EMAIL") && upper.contains("SEND"))         return "T1048";

        if (upper.contains("BEACON") || upper.contains("COBALT")
                || upper.contains("COBALTSTRIKE"))                      return "T1071";
        if (upper.contains("DNS") && (upper.contains("TXT")
                || upper.contains("FLOOD") || upper.contains("QUERY"))) return "T1071.004";
        if (upper.contains("HTTP") && (upper.contains("C2")
                || upper.contains("COVERT")))                           return "T1071.001";
        if (upper.contains("TOR") || upper.contains("DARKNET"))        return "T1090.003";
        if (upper.contains("PROXY"))                                    return "T1090";

        if (upper.contains("ASSUMEROLESUCCESS")
                || upper.contains("ASSUMEROLE"))                        return "T1548.005";
        if (upper.contains("PUTBUCKETPOLICY") || upper.contains("S3_ACL")) return "T1530";
        if (upper.contains("DESCRIBEINSTANCES")
                || upper.contains("LISTBUCKETS"))                       return "T1580";
        if (upper.contains("CREATEACCESSKEY")
                || upper.contains("CREATE_KEY"))                        return "T1098.001";
        if (upper.contains("CONSOLELOGIN")
                || upper.contains("CONSOLE_LOGIN"))                     return "T1078.004";
        if (upper.contains("SECURITYHUB")
                || upper.contains("GUARDDUTY_DISABLE"))                 return "T1562.008";

        if (upper.contains("RANSOM") || upper.contains("ENCRYPT")
                || upper.contains(".LOCKED") || upper.contains("WANNACRY")) return "T1486";
        if (upper.contains("WIPE") || upper.contains("FORMAT")
                || upper.contains("SHRED"))                             return "T1485";
        if (upper.contains("DEFAC") || upper.contains("DEFACE"))       return "T1491.001";
        if (upper.contains("DDOS") || upper.contains("FLOOD"))         return "T1498";

        return null;
    }


    private void calculateNodeRisk(EventNode node) {
        double severityComponent = (node.getSeverity() / 10.0) * 0.6;
        double threatComponent = node.getThreatScore() * 0.2;
        double iocComponent = (node.getIocs() != null ? Math.min(node.getIocs().size(), 5) / 5.0 : 0.0) * 0.1;
        double geoComponent = (node.getGeoCountry() != null
                && !"Unknown".equals(node.getGeoCountry())
                && !"Internal".equals(node.getGeoCountry())) ? 0.1 : 0.0;

        double risk = Math.min(1.0, severityComponent + threatComponent + iocComponent + geoComponent);
        node.setNodeRisk(risk);
    }



    private boolean isPrivateIp(String ip) {
        if (ip == null) return false;
        if (ip.startsWith("10.") || ip.startsWith("192.168.") || ip.startsWith("127.")
                || ip.startsWith("169.254.") || ip.equals("0.0.0.0")) {
            return true;
        }

        if (ip.startsWith("172.")) {
            try {
                int secondOctet = Integer.parseInt(ip.split("\\.")[1]);
                return secondOctet >= 16 && secondOctet <= 31;
            } catch (NumberFormatException | ArrayIndexOutOfBoundsException e) {
                return false;
            }
        }
        return false;
    }
}