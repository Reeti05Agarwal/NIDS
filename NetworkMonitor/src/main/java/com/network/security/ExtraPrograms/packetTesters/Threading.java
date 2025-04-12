package com.network.security.ExtraPrograms.packetTesters;

import java.time.temporal.Temporal;

public class Threading extends Thread {
    public void run() {
        // id is always in long data type
        long id = Thread.currentThread().threadId();   
        String name = Thread.currentThread().getName();  
        
        System.out.println("Thread ID: " + id);
        System.out.println("Thread Name: " + name);
    }

    public static void main(String[] args) {
        Threading t1 = new Threading();
        Threading t2 = new Threading();
        Threading t3 = new Threading();
        t1.start(); // will call run() automatically
        t2.start(); // will call run() automatically
        t3.start(); // will call run() automatically
        t1.run();

        for (int i = 5; i < 10; i++) {
            System.out.println("Creating Thread: " + i);
            Threading t = new Threading();
            t.start();
        }
    }
}
