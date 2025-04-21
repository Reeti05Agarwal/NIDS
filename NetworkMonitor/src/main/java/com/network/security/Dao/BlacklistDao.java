// src/main/java/com/network/security/Dao/BlacklistDao.java
package com.network.security.Dao;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import com.network.security.util.DBConnection;

public class BlacklistDao {

    private static final String SELECT_SQL
            = "SELECT ip_address, reason FROM blacklist_ip";

    public List<String> getAllBlockedIPs() {
        List<String> ips = new ArrayList<>();
        try (
                Connection conn = DBConnection.getConnection(); 
                Statement stmt = conn.createStatement(); 
                ResultSet rs = stmt.executeQuery(SELECT_SQL)) {
            while (rs.next()) {
                String ip = rs.getString("ip_address");
                String reason = rs.getString("reason");
                ips.add(ip + (reason != null ? " — " + reason : ""));
            }
        } catch (Exception e) {
            // print full stack so you see if something goes wrong
            e.printStackTrace();
            // return a one‐item list so the UI won’t be empty
            ips.clear();
            ips.add("Error loading IPs: " + e.getMessage());
        }
        return ips;
    }
}
