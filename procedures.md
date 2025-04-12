-- 🔐 PROCEDURE 1: Detect SYN Flood (DoS)
DELIMITER //
CREATE PROCEDURE DetectSynFlood()
BEGIN
    INSERT INTO Alerts (PacketID, RuleMatched, Severity, Description)
    SELECT TCP.PacketID, 'SYN_FLOOD', 'High', CONCAT('High number of SYN packets from ', Layer3_IP.SrcIP)
    FROM TCP
    JOIN Layer3_IP ON TCP.PacketID = Layer3_IP.PacketID
    WHERE TCP.Flags = 'SYN'
    GROUP BY Layer3_IP.SrcIP
    HAVING COUNT(*) > (SELECT syn_flood_threshold FROM thresholds);
END;//
DELIMITER ;

-- 🔐 PROCEDURE 2: Detect Port Scanning
DELIMITER //
CREATE PROCEDURE DetectPortScan()
BEGIN
    INSERT INTO Alerts (PacketID, RuleMatched, Severity, Description)
    SELECT TCP.PacketID, 'PORT_SCAN', 'Medium', CONCAT('Multiple port accesses by ', Layer3_IP.SrcIP)
    FROM TCP
    JOIN Layer3_IP ON TCP.PacketID = Layer3_IP.PacketID
    GROUP BY Layer3_IP.SrcIP, TCP.DstPort
    HAVING COUNT(DISTINCT TCP.DstPort) > (SELECT port_flood_threshold FROM thresholds);
END;//
DELIMITER ;

-- 🔐 PROCEDURE 3: Detect Brute Force (HTTP/SSH/FTP)
DELIMITER //
CREATE PROCEDURE DetectBruteForce()
BEGIN
    INSERT INTO Alerts (PacketID, RuleMatched, Severity, Description)
    SELECT PacketID, 'BRUTE_FORCE_ATTACK', 'High', 'Multiple failed login attempts detected'
    FROM AuthenticationLogs
    WHERE AttemptStatus = 'FAIL'
    GROUP BY SrcIP
    HAVING COUNT(*) > (SELECT http_auth_brute_force_threshold FROM thresholds);
END;//
DELIMITER ;

-- 🔐 PROCEDURE 4: Detect DNS Tunneling
DELIMITER //
CREATE PROCEDURE DetectDNSTunneling()
BEGIN
    INSERT INTO Alerts (PacketID, RuleMatched, Severity, Description)
    SELECT PacketID, 'DNS_TUNNELING', 'High', 'Suspicious DNS query patterns detected'
    FROM DNSLogs
    GROUP BY SrcIP
    HAVING COUNT(*) > (SELECT dns_tunneling_threshold FROM thresholds);
END;//
DELIMITER ;

-- 🔐 PROCEDURE 5: Detect Typosquatting Domains
DELIMITER //
CREATE PROCEDURE DetectTyposquatting()
BEGIN
    INSERT INTO Alerts (PacketID, RuleMatched, Severity, Description)
    SELECT PacketID, 'TYPOSQUATTING', 'Medium', 'Request to suspected typosquatting domain'
    FROM DNSLogs
    WHERE Domain IN (SELECT domain FROM typosquatting_detection);
END;//
DELIMITER ;

-- 🔐 PROCEDURE 6: Detect Data Exfiltration (Insider Threat)
DELIMITER //
CREATE PROCEDURE DetectDataExfiltration()
BEGIN
    INSERT INTO Alerts (PacketID, RuleMatched, Severity, Description)
    SELECT PacketID, 'DATA_EXFIL', 'High', 'Possible data exfiltration via large data transfers'
    FROM Packets
    WHERE PayloadSize > (SELECT data_exfil_threshold FROM thresholds);
END;//
DELIMITER ;

-- 🔐 PROCEDURE 7: Detect UDP Flood (DoS/DDoS)
DELIMITER //
CREATE PROCEDURE DetectUDPFlood()
BEGIN
    INSERT INTO Alerts (PacketID, RuleMatched, Severity, Description)
    SELECT UDP.PacketID, 'UDP_FLOOD', 'High', CONCAT('Excessive UDP traffic from ', Layer3_IP.SrcIP)
    FROM UDP
    JOIN Layer3_IP ON UDP.PacketID = Layer3_IP.PacketID
    GROUP BY Layer3_IP.SrcIP
    HAVING COUNT(*) > (SELECT udp_flood_threshold FROM thresholds);
END;//
DELIMITER ;

-- 🔐 PROCEDURE 8: Detect ICMP Flood (DoS/DDoS)
DELIMITER //
CREATE PROCEDURE DetectICMPFlood()
BEGIN
    INSERT INTO Alerts (PacketID, RuleMatched, Severity, Description)
    SELECT ICMP.PacketID, 'ICMP_FLOOD', 'High', CONCAT('Excessive ICMP traffic from ', Layer3_IP.SrcIP)
    FROM ICMP
    JOIN Layer3_IP ON ICMP.PacketID = Layer3_IP.PacketID
    GROUP BY Layer3_IP.SrcIP
    HAVING COUNT(*) > (SELECT icmp_flood_threshold FROM thresholds);
END;//
DELIMITER ;

-- 🔐 PROCEDURE 9: Detect HTTP Flood (DoS/DDoS)
DELIMITER //
CREATE PROCEDURE DetectHTTPFlood()
BEGIN
    INSERT INTO Alerts (PacketID, RuleMatched, Severity, Description)
    SELECT HTTP.PacketID, 'HTTP_FLOOD', 'High', CONCAT('High frequency of HTTP requests from ', Layer3_IP.SrcIP)
    FROM HTTP
    JOIN Layer3_IP ON HTTP.PacketID = Layer3_IP.PacketID
    GROUP BY Layer3_IP.SrcIP
    HAVING COUNT(*) > (SELECT http_flood_threshold FROM thresholds);
END;//
DELIMITER ;


//alerts and logging config
-- 📋 ALERTS TABLE (Logging)
CREATE TABLE IF NOT EXISTS Alerts (
    AlertID INT AUTO_INCREMENT PRIMARY KEY,
    PacketID INT,
    RuleMatched VARCHAR(100),
    Severity VARCHAR(20),
    Description TEXT,
    Timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
