package com.network.security.PacketSniffing; 

import org.pcap4j.core.*;
import org.pcap4j.util.NifSelector;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

public class PacketSnifferService {
    private static final Logger LOGGER = Logger.getLogger(PacketSnifferService.class.getName());
    public PcapNetworkInterface getDevice() {
        try {
            return new NifSelector().selectNetworkInterface();
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    public void DeviceStatus(PcapNetworkInterface device) {
        if (device == null) {
            LOGGER.log(Level.SEVERE, "No network device selected!");
        }
        else {
            System.out.println("[INFO] Selected Interface: " + (device != null ? device.getName() : "None"));
        }
    }
}
