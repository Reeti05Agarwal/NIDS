package com.network.security.packetTesters;

import java.io.BufferedReader;
import java.io.InputStreamReader;

public class TsharkPS {
    public static void main(String[] args) {
        try {
            // Command to capture packets from interface eth0 (change as per your system)
            ProcessBuilder processBuilder1  = new ProcessBuilder(
                "tshark", "-D"
            );
            processBuilder1.redirectErrorStream(true);
            Process process1 = processBuilder1.start();
            BufferedReader reader1 = new BufferedReader(new InputStreamReader(process1.getInputStream()));
            String line1;
            while ((line1 = reader1.readLine()) != null) {
                System.out.println("Output (Interfaces): " + line1);
            }
            process1.waitFor();


            ProcessBuilder processBuilder = new ProcessBuilder(
                "tshark", "-i", "eth0", "-c", "10", "-T", "fields", "-e", "ip.src", "-e", "ip.dst"
            );

            processBuilder.redirectErrorStream(true); // Merge error and output streams
            Process process = processBuilder.start();

            // Read output from TShark
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    System.out.println("Captured Packet: " + line);
                }
            }

            // Wait for process to complete
            int exitCode = process.waitFor();
            System.out.println("TShark exited with code: " + exitCode);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
