package com.network.security.ExtraPrograms.DetectionTest;

public class RulesSet {
    //public static final Set<String> BLACKLISTED_IPS = Set.of("192.168.1.100", "10.0.0.5");
    //public static final Set<Integer> BLACKLISTED_PORTS = Set.of(23, 445, 135);
    //Blacklisted IP addresses and ports Table Inserted in the code

    // DNS and Web Filtering
    public static final String DNS_FILTERING_PATTERN = ".*(malicious|phishing|spam).*";  // regex pattern for DNS filtering
    public static final String WEB_FILTERING_PATTERN = ".*(malicious|phishing|spam).*";  // regex pattern for web filtering


}
