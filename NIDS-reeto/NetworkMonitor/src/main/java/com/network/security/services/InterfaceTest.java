package com.network.security.services;

import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;

public class InterfaceTest {
    public static void main(String[] args) throws PcapNativeException {
        for (PcapNetworkInterface dev : Pcaps.findAllDevs()) {
            System.out.println("Found interface: " + dev.getName() + " - " + dev.getDescription());
        }
    }
}