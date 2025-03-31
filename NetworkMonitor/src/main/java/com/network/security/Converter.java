package com.network.security;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class Converter {
    public static void main(String[] args) {
        String hexString = "b8 1e a4 ba 89 75 20 0c 86 a6 62 10 08 00 45 b8 00 36 00 00 40 00 3c 11 a6 ed 8e fa 46 6a c0 a8 01 05 01 bb fe 9a 00 22 a8 1a 43 d1 72 26 b3 fa ba 5a 10 0a 3c 0b 7f a9 74 0a 0d 8d 1b 10 3c 55 00 63 f6 bb";

        // Remove spaces and split hex into bytes
        String[] hexBytes = hexString.split(" ");
        byte[] bytes = new byte[hexBytes.length];

        for (int i = 0; i < hexBytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(hexBytes[i], 16);
        }

        // Debug: Print raw byte array
        System.out.println("Raw bytes: " + Arrays.toString(bytes));

        // Try converting to text with UTF-8
        String utf8Text = new String(bytes, StandardCharsets.UTF_8);
        System.out.println("Converted String (UTF-8): " + utf8Text);

        // Try converting with ISO-8859-1 encoding
        String isoText = new String(bytes, StandardCharsets.ISO_8859_1);
        System.out.println("Converted String (ISO-8859-1): " + isoText);

        // Print as Hex Dump (if binary)
        System.out.print("Hex Dump: ");
        for (byte b : bytes) {
            System.out.printf("%02X ", b);
        }
        System.out.println();
    }
}
