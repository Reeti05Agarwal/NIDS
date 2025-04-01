package com.network.security.packetTesters;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public class BlockingQueueExample {
    public static void main(String[] args) {
        BlockingQueue<Integer> queue = new LinkedBlockingQueue<>(3); // Max size = 3

        // Producer thread
        new Thread(() -> {
            try {
                for (int i = 1; i <= 5; i++) {
                    System.out.println("[Producer] Trying to put item: " + i);
                    queue.put(i);  // Blocks if queue is full
                    System.out.println("[Producer] Produced: " + i);
                    System.out.println("[Producer] Queue size after production: " + queue.size());
                    Thread.sleep(1000); // Simulate delay
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }).start();

        // Consumer thread
        new Thread(() -> {
            try {
                while (true) {
                    System.out.println("[Consumer] Waiting to take item...");
                    Integer item = queue.take();  // Blocks if queue is empty
                    System.out.println("[Consumer] Consumed: " + item);
                    System.out.println("[Consumer] Queue size after consumption: " + queue.size());
                    Thread.sleep(2000); // Simulate processing delay
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }).start();
    }
}
