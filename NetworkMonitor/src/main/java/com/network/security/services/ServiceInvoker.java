// src/main/java/com/network/security/services/ServiceInvoker.java
package com.network.security.services;

import java.util.Map;

import com.network.security.PacketSniffing.PacketParserBuffer;
import com.network.security.services.Detection.BruteForceService;
import com.network.security.services.Detection.DNSWebFilterService;
import com.network.security.services.Detection.DosService;
import com.network.security.services.Detection.DpiService;
import com.network.security.services.Detection.ExtICMPService;
import com.network.security.services.Detection.SusUserAgentService;

/**
 * Utility class to invoke all service‑layer functions as-is.
 */
public class ServiceInvoker {

    public static void invokeAllServices() throws Exception {
        // 1) AlertService usage
        AlertService alertService = new AlertService();
        // Trigger a sample alert
        alertService.triggerAlert(
                "192.168.0.1", "10.0.0.5",
                "TCP", 101,
                "HIGH", "Sample alert message"
        );
        // Display all alerts
        alertService.showAllAlerts();

        // 2) PacketPipelineService: start the full capture pipeline
        new Thread(() -> PacketPipelineService.main(new String[0])).start();

        // 3) Manually parse a dummy packet and send through detection services
        byte[] dummyPacket = new byte[]{ /* raw packet bytes */};
        Map<String, Object> parsed = PacketParserBuffer.parsePacket(dummyPacket);
        if (parsed != null && !parsed.isEmpty()) {
            new BruteForceService().loadBruteForce(parsed);
            new DNSWebFilterService().loadDnsWebFilterRules(parsed);
            new DosService().loadDosService(parsed);
            new DpiService().loadDpiDetectorKeywords(parsed);
            new ExtICMPService().loadICMPRules(parsed);
            new SusUserAgentService().loadSuspiciousUserAgent(parsed);
        }
    }

    public static void main(String[] args) throws Exception {
        invokeAllServices();
    }
}
