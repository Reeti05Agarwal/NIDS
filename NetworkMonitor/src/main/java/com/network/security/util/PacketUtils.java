package com.network.security.util;

import java.nio.ByteBuffer;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class PacketUtils {
    public static String getMacAddress(ByteBuffer buffer, int start) {
        buffer.position(start);
        byte[] mac = new byte[6];
        buffer.get(mac);
        return String.format("%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }

    public static String getIpAddress(ByteBuffer buffer, int offset) {
        byte[] ip = new byte[4];
        buffer.position(offset);
        buffer.get(ip);
        try {
            return InetAddress.getByAddress(ip).getHostAddress();
        } catch (UnknownHostException e) {
            return "Invalid IP";
        }
    }

    public static String getIpAddress(byte[] ip, int offset) {
        try {
            return InetAddress.getByAddress(ip).getHostAddress();
        } catch (UnknownHostException e) {
            return "Invalid IP";
        }
    }

    public static Map<String, Boolean> parseTCPFlags(int flags) {
        Map<String, Boolean> flagMap = new HashMap<>();
        flagMap.put("URG", (flags & 0x20) != 0);
        flagMap.put("ACK", (flags & 0x10) != 0);
        flagMap.put("PSH", (flags & 0x08) != 0);
        flagMap.put("RST", (flags & 0x04) != 0);
        flagMap.put("SYN", (flags & 0x02) != 0);
        flagMap.put("FIN", (flags & 0x01) != 0);
        return flagMap;
    }

    public static String parceProtocol(int protocol) {
        Map<Integer, String> protocolMap = new HashMap<>();
        protocolMap.put(1, "ICMP");
        protocolMap.put(6, "TCP");
        protocolMap.put(17, "UDP");
        return protocolMap.get(protocol);
    }

    public static String bytesToMac(byte[] macBytes) {
        StringBuilder mac = new StringBuilder();
        for (byte b : macBytes) {
            mac.append(String.format("%02X", b));
            mac.append(":");
        }
        return mac.substring(0, mac.length() - 1);
    }
    
    public static String parseProtocol(int protocol) {
        Map<Integer, String> protocolMap = new HashMap<>();
        protocolMap.put(1, "ICMP");
        protocolMap.put(6, "TCP");
        protocolMap.put(17, "UDP");
        // Extend with other protocols as needed.
        return protocolMap.getOrDefault(protocol, "UNKNOWN");

    } 

    public static String parseHttpMethods(String packetStr) {
        String[] methods = { "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH" };
        for (String method : methods) {
            if (packetStr.contains(method)) {
                return method;
            }
        }
        return null;
    }

    public static String parseHttpStatus(int status) {
        Map<Integer, String> httpStatusMap = new HashMap<>();
        httpStatusMap.put(200, "OK");
        httpStatusMap.put(404, "Not Found");
        httpStatusMap.put(500, "Internal Server Error");
        return httpStatusMap.getOrDefault(status, "UNKNOWN_STATUS");
    }

    public static String extractHeader(String packetStr, String headerName) {
        int start = packetStr.indexOf(headerName); 
        if (start == -1) return null;
        start += headerName.length();
        int end = packetStr.indexOf("\r\n", start);
        return packetStr.substring(start, end).trim();
    }

    public static boolean isExtensionHeader(int nextHeader) {
        return nextHeader == 0  || nextHeader == 43 || nextHeader == 44 || nextHeader == 50 || 
               nextHeader == 51 || nextHeader == 60 || nextHeader == 135;
    }
    
    
    public static List<Integer> parseExtensionHeaders(ByteBuffer buffer, int offset, int nextHeader, Map<String, Object> packetData) {
        List<Integer> extensionHeaders = new ArrayList<>();
        
        while (isExtensionHeader(nextHeader)) {
            if (offset + 2 > buffer.limit()) return extensionHeaders;
            
            extensionHeaders.add(nextHeader);
            int newNextHeader = buffer.get(offset) & 0xFF;
            int hdrExtLen = buffer.get(offset + 1) & 0xFF;
    
            int headerLength = (hdrExtLen + 1) * 8;
            offset += headerLength;
            nextHeader = newNextHeader;
        }
        
        return extensionHeaders;
    }

    public static String decodePayload(byte[] tcpPayload) {
        StringBuilder decoded = new StringBuilder();

        for (byte b : tcpPayload) {
            int unsignedByte = b & 0xFF;

            // Accept only printable ASCII characters (32 = space to 126 = ~)
            if (unsignedByte >= 32 && unsignedByte <= 126) {
                decoded.append((char) unsignedByte);
            }
        }

        return decoded.toString();
    }
    

}