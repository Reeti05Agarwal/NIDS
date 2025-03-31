package com.network.security.packetTesters;

import org.pcap4j.core.*;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
// import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IpV4Packet;
// import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.NifSelector;
//import java.util.List;
import java.io.IOException;
 

public class Normal {

    public static void main(String[] args) throws PcapNativeException, NotOpenException {
        try {
            PcapNetworkInterface device = getDevice();
            System.out.println("You chose: " + device);

            // New code below here
            if (device == null) {
                System.out.println("No device chosen.");
                System.exit(1);
            }
 
            System.out.println("Selected Interface: " + device.getName());

            int snapshotLength = 65536; // in bytes   
            int readTimeout = 50; // in milliseconds 
            final PcapHandle handle;
            handle = device.openLive(snapshotLength, PromiscuousMode.PROMISCUOUS, readTimeout);

            // Create a listener that defines what to do with the received packets
            PacketListener listener = new PacketListener() {
                @Override
                public void gotPacket(Packet packet) {
                    System.out.println("[DEBUG] Packet received...");
                    System.out.print(packet);
                    processPacket(packet, handle.getTimestamp());
                }
            };

            // Tell the handle to loop using the listener we created
            try {
                int maxPackets = 50;
                handle.loop(maxPackets, listener);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            // Cleanup when complete
            handle.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    static PcapNetworkInterface getDevice() {
        PcapNetworkInterface device = null;

        try {
            device = new NifSelector().selectNetworkInterface();
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
        return device;
    }

    static void processPacket(Packet packet, java.sql.Timestamp timestamp) {

        IpV4Packet ipv4Packet = packet.get(IpV4Packet.class);

        if (ipv4Packet != null) {
            IpV4Packet.IpV4Header ipHeader = ipv4Packet.getHeader();

            System.out.println("[DEBUG] Processing IPv4 Packet: " + ipHeader.getSrcAddr() + " -> " + ipHeader.getDstAddr());

            String srcIP = ipHeader.getSrcAddr().toString();
            String destIP = ipHeader.getDstAddr().toString();
            //String protocolID = String.valueOf(ipHeader.getProtocol().value());
            //String totalLength = String.valueOf(ipHeader.getTotalLengthAsInt());
            //String ttl = String.valueOf(ipHeader.getTtlAsInt());
            //String flags = Integer.toBinaryString(ipHeader.getReservedFlag() ? 1 : 0) +
            //               Integer.toBinaryString(ipHeader.getDontFragmentFlag() ? 1 : 0) +
            //               Integer.toBinaryString(ipHeader.getMoreFragmentFlag() ? 1 : 0);
            //String fragmentOffset = String.valueOf(ipHeader.getFragmentOffset());
            // String checksum = Integer.toHexString(ipHeader.getChecksum()); // Method does not exist
            String payload = (ipv4Packet.getPayload() != null) ? ipv4Packet.getPayload().toString() : "";
            System.out.println("Source IP" + srcIP);
            System.out.println("Destination IP" + destIP);
            System.out.println("Payload" + payload);
        }

    }
}
