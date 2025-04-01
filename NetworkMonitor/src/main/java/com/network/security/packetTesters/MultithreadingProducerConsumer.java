package com.network.security.packetTesters;

import java.util.concurrent.*;

public class MultithreadingProducerConsumer {
    public static void main(String[] args) {
        // Create a BlockingQueue with a capacity of 10 packets
        BlockingQueue<String> queue = new LinkedBlockingQueue<>(10);

        // Start the producer (simulates packet capture)
        new Thread(new PacketProducer(queue)).start();

        // Start 3 consumer threads to process packets in parallel
        ExecutorService executor = Executors.newFixedThreadPool(3); // 3 threads
        for (int i = 0; i < 3; i++) {
            executor.execute(new PacketConsumer(queue, i + 1)); // Different worker IDs
        }
    }
}

// Producer: Captures packets and adds them to the queue
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
                queue.put(packet); // Adds packet to the queue (blocks if full)
                System.out.println("Captured: " + packet);
                Thread.sleep(500); // Simulates delay in packet arrival
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}

// Consumer: Processes packets from the queue (simulates database insert)
class PacketConsumer implements Runnable {
    private BlockingQueue<String> queue;
    private int workerId;

    public PacketConsumer(BlockingQueue<String> queue, int workerId) {
        this.queue = queue;
        this.workerId = workerId;
    }

    @Override
    public void run() {
        try {
            while (true) {
                String packet = queue.take(); // Takes packet from queue (blocks if empty)
                System.out.println("Worker " + workerId + " processing: " + packet);
                Thread.sleep(1000); // Simulates database insertion time
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
