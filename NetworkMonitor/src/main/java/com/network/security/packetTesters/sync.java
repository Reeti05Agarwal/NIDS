package com.network.security.packetTesters;

import javax.print.attribute.standard.PrinterName;

public class sync {
    
    public static void main(String[] args) {
        PrintName printerNameTask = new PrintName("Printer1");
        PrintPrimeNumber primeNumberTask = new PrintPrimeNumber(100);

        Thread printerNameThread = new Thread(printerNameTask);
        Thread primeNumberThread = new Thread(primeNumberTask);

        printerNameThread.start();
        primeNumberThread.start();
    }
}

class PrintName implements Runnable {
    private String name;
    
    public PrintName(String name) {
        this.name = name;
    }
    
    @Override
    public void run() {
        for (int i = 0; i < 10; i++) {

            System.out.println("Hello, " + name + "!");
        }
    }
}

class PrintPrimeNumber implements Runnable{
    private int number;
    
    public PrintPrimeNumber(int number) {
        this.number = number;
    }
    
    @Override
    public void run() {
        for (int i = 2; i <= number; i++) {
            if (isPrime(i)) {
                System.out.println(i + " is a prime number.");
            }
        }
    }
    
    private boolean isPrime(int num) {
        if (num <= 1) return false;
        for (int i = 2; i <= Math.sqrt(num); i++) {
            if (num % i == 0) return false;
        }
        return true;
    }
}