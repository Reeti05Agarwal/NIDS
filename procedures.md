-- Table for logging anomalies
CREATE TABLE anomaly_logs (
    log_id SERIAL PRIMARY KEY,
    packetid INT NOT NULL,
    reason TEXT NOT NULL,
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table for storing detection rule config in JSON
CREATE TABLE detection_config (
    config_name TEXT PRIMARY KEY,
    rules JSONB
);

-- 1. Blacklist Rules
CREATE OR REPLACE FUNCTION detect_blacklist(packetid INT) RETURNS VOID AS $$
DECLARE
    config JSONB;
    pkt RECORD;
    black_ip TEXT;
    black_port TEXT;
BEGIN
    SELECT * INTO pkt FROM packet_metadata WHERE packetid = detect_blacklist.packetid;
    SELECT rules INTO config FROM detection_config WHERE config_name = 'default_config';

    FOR black_ip IN SELECT jsonb_array_elements_text(config->'blacklisted_ips') LOOP
        IF pkt.srcip = black_ip OR pkt.destip = black_ip THEN
            INSERT INTO anomaly_logs (packetid, reason) VALUES (packetid, 'Blacklisted IP');
            RETURN;
        END IF;
    END LOOP;

    FOR black_port IN SELECT jsonb_array_elements_text(config->'blacklisted_ports') LOOP
        IF EXISTS (
            SELECT 1 FROM transport_layer
            WHERE packetid = pkt.packetid
              AND (srcport = black_port::INT OR destport = black_port::INT)
        ) THEN
            INSERT INTO anomaly_logs (packetid, reason) VALUES (packetid, 'Blacklisted Port');
            RETURN;
        END IF;
    END LOOP;
END;
$$ LANGUAGE plpgsql;

-- 2. Port Scanning Detection
CREATE OR REPLACE FUNCTION detect_port_scan(packetid INT) RETURNS VOID AS $$
DECLARE
    config JSONB;
    pkt RECORD;
BEGIN
    SELECT * INTO pkt FROM packet_metadata WHERE packetid = detect_port_scan.packetid;
    SELECT rules INTO config FROM detection_config WHERE config_name = 'default_config';

    IF EXISTS (
        SELECT 1 FROM tcp_header t
        JOIN transport_layer tr ON t.packetid = tr.packetid
        WHERE tr.packetid = pkt.packetid
          AND t.flags LIKE '%SYN%'
    ) THEN
        INSERT INTO anomaly_logs (packetid, reason) VALUES (packetid, 'SYN flood/Port scan');
    END IF;
END;
$$ LANGUAGE plpgsql;

-- 3. Protocol Violation
CREATE OR REPLACE FUNCTION detect_protocol_violations(packetid INT) RETURNS VOID AS $$
DECLARE
    config JSONB;
    pkt RECORD;
    proto TEXT;
BEGIN
    SELECT * INTO pkt FROM packet_metadata WHERE packetid = detect_protocol_violations.packetid;
    SELECT rules INTO config FROM detection_config WHERE config_name = 'default_config';

    proto := pkt.protocol_type;
    IF proto IS NOT NULL AND proto = ANY (SELECT jsonb_array_elements_text(config->'restricted_protocols')) THEN
        INSERT INTO anomaly_logs (packetid, reason) VALUES (packetid, 'Restricted Protocol');
    END IF;
END;
$$ LANGUAGE plpgsql;

-- 4. DoS/DDoS Attack
CREATE OR REPLACE FUNCTION detect_dos_attacks(packetid INT) RETURNS VOID AS $$
DECLARE
    config JSONB;
    pkt RECORD;
BEGIN
    SELECT * INTO pkt FROM packet_metadata WHERE packetid = detect_dos_attacks.packetid;
    SELECT rules INTO config FROM detection_config WHERE config_name = 'default_config';

    IF pkt.payloadsize > 100000 THEN
        INSERT INTO anomaly_logs (packetid, reason) VALUES (packetid, 'Potential DoS attack - Payload size high');
    END IF;
END;
$$ LANGUAGE plpgsql;

-- 5. Packet Inspection
CREATE OR REPLACE FUNCTION detect_packet_inspection(packetid INT) RETURNS VOID AS $$
DECLARE
    config JSONB;
    keyword TEXT;
    payload TEXT; -- assume extracted payload is in plaintext (for demo)
BEGIN
    SELECT rules INTO config FROM detection_config WHERE config_name = 'default_config';
    SELECT pkt.payloadsize::TEXT INTO payload FROM packet_metadata pkt WHERE packetid = detect_packet_inspection.packetid;

    FOR keyword IN SELECT jsonb_array_elements_text(config->'dpi_keywords') LOOP
        IF position(lower(keyword) in lower(payload)) > 0 THEN
            INSERT INTO anomaly_logs (packetid, reason) VALUES (packetid, 'DPI Keyword Match');
            RETURN;
        END IF;
    END LOOP;
END;
$$ LANGUAGE plpgsql;

-- 6. Brute-Force Attack Detection
CREATE OR REPLACE FUNCTION detect_brute_force(packetid INT) RETURNS VOID AS $$
DECLARE
    config JSONB;
    pkt RECORD;
BEGIN
    SELECT * INTO pkt FROM packet_metadata WHERE packetid = detect_brute_force.packetid;
    SELECT rules INTO config FROM detection_config WHERE config_name = 'default_config';

    IF EXISTS (
        SELECT 1 FROM http_header h
        WHERE h.packetid = pkt.packetid AND h.auth IS NOT NULL
    ) THEN
        INSERT INTO anomaly_logs (packetid, reason) VALUES (packetid, 'HTTP Auth Brute Force Suspicion');
    END IF;
END;
$$ LANGUAGE plpgsql;

-- 7. Insider Threat Detection
CREATE OR REPLACE FUNCTION detect_insider_threat(packetid INT) RETURNS VOID AS $$
DECLARE
    pkt RECORD;
BEGIN
    SELECT * INTO pkt FROM packet_metadata WHERE packetid = detect_insider_threat.packetid;

    IF pkt.srcip LIKE '10.%' AND pkt.destip NOT LIKE '10.%' THEN
        INSERT INTO anomaly_logs (packetid, reason) VALUES (packetid, 'Potential Data Exfiltration');
    END IF;
END;
$$ LANGUAGE plpgsql;

-- 8. DNS & Web Filtering
CREATE OR REPLACE FUNCTION detect_dns_web_filtering(packetid INT) RETURNS VOID AS $$
DECLARE
    config JSONB;
    domain TEXT;
BEGIN
    SELECT rules INTO config FROM detection_config WHERE config_name = 'default_config';

    SELECT d.question INTO domain FROM dns_header d WHERE d.packetid = detect_dns_web_filtering.packetid;

    IF domain IS NOT NULL AND domain = ANY (SELECT jsonb_array_elements_text(config->'blacklisted_domains')) THEN
        INSERT INTO anomaly_logs (packetid, reason) VALUES (packetid, 'Blacklisted Domain Access');
    END IF;
END;
$$ LANGUAGE plpgsql;

-- Trigger function
CREATE OR REPLACE FUNCTION detect_all_anomalies() RETURNS TRIGGER AS $$
BEGIN
    PERFORM detect_blacklist(NEW.packetid);
    PERFORM detect_port_scan(NEW.packetid);
    PERFORM detect_protocol_violations(NEW.packetid);
    PERFORM detect_dos_attacks(NEW.packetid);
    PERFORM detect_packet_inspection(NEW.packetid);
    PERFORM detect_brute_force(NEW.packetid);
    PERFORM detect_insider_threat(NEW.packetid);
    PERFORM detect_dns_web_filtering(NEW.packetid);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger
CREATE TRIGGER trigger_detect_all_anomalies
AFTER INSERT ON packet_metadata
FOR EACH ROW
EXECUTE FUNCTION detect_all_anomalies();
