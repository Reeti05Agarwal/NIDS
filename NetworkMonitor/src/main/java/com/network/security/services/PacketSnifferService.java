package com.network.security.services;

import org.pcap4j.core.*;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.util.NifSelector;

import java.io.IOException;

public class PacketSnifferService {
    public PcapNetworkInterface getDevice() {
        try {
            return new NifSelector().selectNetworkInterface();
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    public PcapHandle startCapture(PcapNetworkInterface device, PacketListener listener) throws PcapNativeException, NotOpenException, InterruptedException {
        if (device == null) {
            throw new IllegalArgumentException("No network device selected!");
        }
        PcapHandle handle = device.openLive(65536, PromiscuousMode.PROMISCUOUS, 50);
        
        return handle;
    }
}
