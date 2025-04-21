package com.network.security.util;

import java.util.HashMap;
import java.util.Map;

public class PacketTracker {
    static class TrafficStats {
        int packetCount;
        long startTimeMillis;
    }

    private final int timeWindowSec;
    private final Map<String, TrafficStats> trafficMap = new HashMap<>();

    public PacketTracker(int timeWindowSec) {
        this.timeWindowSec = timeWindowSec;
    }

    public int incrementAndGetPacketCount(String sourceIP) {
        long currentTime = System.currentTimeMillis();
        TrafficStats stats = trafficMap.getOrDefault(sourceIP, new TrafficStats());

        // If time window has passed, reset
        if ((currentTime - stats.startTimeMillis) > timeWindowSec * 1000L) {
            stats.packetCount = 1;
            stats.startTimeMillis = currentTime;
        } else {
            stats.packetCount++;
        }

        trafficMap.put(sourceIP, stats);
        return stats.packetCount;
    }

    public int getTimeElapsedSec(String sourceIP) {
        TrafficStats stats = trafficMap.getOrDefault(sourceIP, null);
        if (stats == null) return 0;
        return (int) ((System.currentTimeMillis() - stats.startTimeMillis) / 1000L);
    }
}

