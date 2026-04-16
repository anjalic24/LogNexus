package com.vulnuris.IngestionService.parser;

import com.vulnuris.IngestionService.context.IngestionContext;
import com.vulnuris.IngestionService.service.LogStreamService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.multipart.MultipartFile;

@Component
@RequiredArgsConstructor
public class ParserFactory {

    private final CloudTrailParser cloudTrail;
    private final O365Parser o365;
    private final PaloAltoFirewallParser paloAlto;
    private final SyslogParser syslog;
    private final WindowsSecurityParser windowsSecurity;
    private final WebAccessLogParser webAccessLog;
    private final WazuhAlertsParser wazuhAlerts;
    private final LogStreamService logStreamService;

    public LogParser getParser(String file, IngestionContext ingestionContext) throws InterruptedException {

        String fileName = file.toLowerCase();

        if (fileName.contains("cloudtrail") || fileName.contains("aws")) {
            logStreamService.send(ingestionContext.getBundleId(), "✅ AWS parser selected");
            Thread.sleep(700);
            return cloudTrail;
        }

        if (fileName.contains("o365")) {
            logStreamService.send(ingestionContext.getBundleId(), "✅ O365 parser selected");
            Thread.sleep(700);
            return o365;
        }

        if (fileName.contains("paloalto")) {
            logStreamService.send(ingestionContext.getBundleId(), "✅ Palo Alto Firewall parser selected");
            Thread.sleep(700);
            return paloAlto;
        }

        if (fileName.contains("linux") || fileName.contains("syslog")) {
            logStreamService.send(ingestionContext.getBundleId(), "✅ Syslog parser selected");
            Thread.sleep(700);
            return syslog;
        }

        if (fileName.contains("windows")) {
            logStreamService.send(ingestionContext.getBundleId(), "✅ Windows Security parser selected");
            Thread.sleep(700);
            return windowsSecurity;
        }

        if (fileName.contains("web")) {
            logStreamService.send(ingestionContext.getBundleId(), "✅ Webserver Access parser selected");
            Thread.sleep(700);
            return webAccessLog;
        }

        if (fileName.contains("wazuh")) {
            logStreamService.send(ingestionContext.getBundleId(), "✅ Wazuh Alerts parser selected");
            Thread.sleep(700);
            return wazuhAlerts;
        }

        throw new RuntimeException("Unsupported file type: " + fileName);
    }
}
