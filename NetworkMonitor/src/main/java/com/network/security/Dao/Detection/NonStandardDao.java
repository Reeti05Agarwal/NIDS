// package com.network.security.Dao.Detection;

// import java.sql.Connection;
// import java.sql.PreparedStatement;
// import java.sql.ResultSet;
// import java.sql.SQLException;

// import com.network.security.Intrusion_detection.NonStandardPorts;

// public class NonStandardDao {
//     private NonStandardPorts nonStandardPorts;

//     // Insert a new brute force detection rule into the database

//     // Load the brute force detection thresholds from the database
//     public void loadNonStandardPorts(Connection conn) {
//         String sql = "SELECT protocol_name, expected_port, actual_port FROM non_standard_ports";
//         try (PreparedStatement stmt = conn.prepareStatement(sql);
//              ResultSet rs = stmt.executeQuery()) {

//             while (rs.next()) {
//                 nonStandardPorts.setNSPProtocolName(rs.getString("protocol_name"));
//                 nonStandardPorts.setNSPExpectedPort(rs.getInt("expected_port"));
//                 nonStandardPorts.setNSPActaulPort(rs.getInt("actual_port"));
//             }

//         } catch (SQLException e) {
//             System.err.println("[ERROR] Failed to load brute force thresholds");
//             e.printStackTrace();
//         }
//     }

//     // update 


//     // delete
// }
