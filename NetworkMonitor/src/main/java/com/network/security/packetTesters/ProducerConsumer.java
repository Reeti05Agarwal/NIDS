package com.network.security.packetTesters;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public class ProducerConsumer {
    public static void main(String[] args) {
        // Create a queue with capacity 5
        BlockingQueue<String> queue = new LinkedBlockingQueue<>(5);

        // Create producer and consumer threads
        Thread producer = new Thread(new PacketProducer(queue));
        Thread consumer = new Thread(new PacketConsumer(queue));

        // Start both threads
        producer.start();
        consumer.start();
    }
}

// Producer: Simulates capturing packets and adding them to the queue
class PacketProducer implements Runnable {
    private BlockingQueue<String> queue;

    public PacketProducer(BlockingQueue<String> queue) {
        this.queue = queue;
    }

    @Override
    public void run() {
        try {
            for (int i = 1; i <= 10; i++) {
                String packet = "Packet " + i;
                queue.put(packet); // Adds to queue (blocks if full)
                System.out.println("Captured: " + packet);
                Thread.sleep(500); // Simulates delay in packet arrival
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}

// Consumer: Fetches packets from the queue and "processes" them (DB insertion)
class PacketConsumer implements Runnable {
    private BlockingQueue<String> queue;

    public PacketConsumer(BlockingQueue<String> queue) {
        this.queue = queue;
    }

    @Override
    public void run() {
        try {
            while (true) {
                String packet = queue.take(); // Takes from queue (blocks if empty)
                System.out.println("Processing: " + packet);
                Thread.sleep(1000); // Simulates database insertion time
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
