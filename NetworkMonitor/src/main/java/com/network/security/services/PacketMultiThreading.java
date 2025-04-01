package com.network.security.services;

import java.nio.ByteBuffer;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;

import com.network.security.packetTesters.PacketParserMain;

public class PacketMultiThreading {
    private static final Logger LOGGER = Logger.getLogger(PacketParserMain.class.getName());


    public static void main(String[] args) {
        BlockingQueue<ByteBuffer> queue = new LinkedBlockingQueue<>();  

        PacketSnifferService packetSnifferService = new PacketSnifferService();
        PacketParcerBuffer packetParser = new PacketParcerBuffer();
        // PacketStoring packetStoring = new PacketStoring();

        PcapNetworkInterface  device = packetSnifferService.getDevice();
        if (device == null) {
            LOGGER.log(Level.SEVERE, "No network device selected!");
            return;
        }

        PacketListener listener = packet -> {
            try {
                System.out.println("[DEBUG] Packet received...");
                queue.put(ByteBuffer.wrap(packet.getRawData())); // Add raw data to queue
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        };

        new Thread(() -> {
            try (PcapHandle handle = packetSnifferService.startCapture(device, listener)) {
                handle.loop(-1, listener); // Capture indefinitely
            } catch (PcapNativeException | NotOpenException | InterruptedException e) {
                LOGGER.log(Level.SEVERE, "Error during packet capture: ", e);
            }
        }).start();

        // Producer : Packet Sniffing
        // PacketSnifferService.java
        // PacketParcerBuffer.java
        Thread producerThread = new Thread(new PacketProducer(queue, packetParser)); 
        // Consumer : Packet Storing in Mysql
        // PacketStoring.java
        Thread consumerThread = new Thread(new PacketConsumer(queue, packetParser));

        producerThread.start();
        consumerThread.start();
    }


}

class PacketProducer implements Runnable {
    private BlockingQueue<ByteBuffer> queue;
    private PacketParcerBuffer packetParser;

    public PacketProducer(BlockingQueue<ByteBuffer> queue, PacketParcerBuffer packetParser) {
        this.queue = queue;
        this.packetParser = packetParser;
    }

    @Override
    public void run() {
        try {
            while (true) {
                ByteBuffer buffer = queue.take(); // Fetch from queue
                byte[] packetData = new byte[buffer.remaining()];
                buffer.get(packetData); // Convert ByteBuffer to byte[]
                PacketParcerBuffer.parsePacket(packetData); // Parse it
                System.out.println("Produced packet of size: " + packetData.length);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}


class PacketConsumer implements Runnable {
    private BlockingQueue<ByteBuffer> queue;
    private PacketParcerBuffer packetParser;

    public PacketConsumer(BlockingQueue<ByteBuffer> queue, PacketParcerBuffer packetParser) {
        this.queue = queue;
        this.packetParser = packetParser;
    }

    @Override
    public void run() {
        try {
            while (true) {
                ByteBuffer buffer = queue.take();
                byte[] packetData = new byte[buffer.remaining()];
                buffer.get(packetData);
                processPacket(packetData);
                System.out.println("Consumed packet of size: " + packetData.length);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private void processPacket(byte[] packetData) {
        System.out.println("Processing packet: " + packetData.length + " bytes");
    }
}

 