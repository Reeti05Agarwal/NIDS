package com.network.security.Dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;

import com.network.security.util.DBConnection;

/**
 * DAO for fetching all blocked IP addresses from the Blacklist_ip table.
 */
public class BlacklistDao {

    /**
     * Returns a list of all blocked IPs.
     */
    public List<String> getAllBlockedIPs() {
        List<String> ips = new ArrayList<>();
        String sql = "SELECT ip_address FROM Blacklist_ip";

        try (Connection conn = DBConnection.getConnection(); PreparedStatement ps = conn.prepareStatement(sql); ResultSet rs = ps.executeQuery()) {

            while (rs.next()) {
                ips.add(rs.getString("ip_address"));
            }
        } catch (Exception e) {
            ips.clear();
            ips.add("[ERROR] " + e.getMessage());
        }

        return ips;
    }
}
