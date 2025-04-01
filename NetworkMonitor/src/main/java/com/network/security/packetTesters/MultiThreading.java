package com.network.security.packetTesters;


public class MultiThreading extends Thread{
    public static int amount = 0;
    public static void main(String[] args){
        MultiThreading thread = new MultiThreading(); // Create a new thread object
        thread.start(); // Start the new thread (runs run() automatically)

        // Simulate delay in main thread
        try{
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            System.out.println(e);
        }

        System.out.println("Main Thread: " + amount);
        amount++;
        System.out.println("Main Thread (after increment): " + amount);

    }    

    public void run(){
        // Simulate delay in main thread
        try{
            Thread.sleep(500);
        } catch (InterruptedException e) {
            System.out.println(e);
        }

        amount++;
        System.out.println("New Thread: " + amount);

    }
}

//The new thread sleeps for 50ms, then increments amount to 1 and prints it.
// The main thread wakes up after 100ms, sees amount = 1, prints it,
//  then increments amount to 2.
