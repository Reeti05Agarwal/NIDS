// package com.network.security.Dao.Detection;

// import java.sql.Connection;
// import java.sql.PreparedStatement;
// import java.sql.ResultSet;
// import java.sql.SQLException;

// import com.network.security.Intrusion_detection.ProtocolViolationDetection;

// public class ProtocolViolationDao {
//     private ProtocolViolationDetection protocolViolationDetection;

//     // Insert a new protocol violation rule into the database
//     private void insertProtocolViolationRule(Connection conn, String protocolName, int expectedPort, int actualPort) {
//         String sql = "INSERT INTO non_standard_ports (protocol_name, expected_port, actual_port) VALUES (?, ?, ?)";
//         try (PreparedStatement stmt = conn.prepareStatement(sql)) {
//             stmt.setString(1, protocolName);
//             stmt.setInt(2, expectedPort);
//             stmt.setInt(3, actualPort);
//             stmt.executeUpdate();
//         } catch (SQLException e) {
//             System.err.println("[ERROR] Failed to insert protocol violation rule");
//             e.printStackTrace();
//         }
//     }

//     // Load protocol violation thresholds from the database
//     private void loadProtocolViolationThresholds(Connection conn) {
//         String sql = "SELECT protocol_name, expected_port, actual_port FROM non_standard_ports";
//         try (PreparedStatement stmt = conn.prepareStatement(sql);
//              ResultSet rs = stmt.executeQuery()) {

//             while (rs.next()) {
//                 protocolViolationDetection.setProtocolName(rs.getString("protocol_name"));
//                 protocolViolationDetection.setExpectedPort(rs.getInt("expected_port"));
//                 protocolViolationDetection.setActualPort(rs.getInt("actual_port"));
//             }

//         } catch (SQLException e) {
//             System.err.println("[ERROR] Failed to load protocol violation rules");
//             e.printStackTrace();
//         }
//     }

//     // Update expected port
//     private void updateExpectedPort(Connection conn, int newExpectedPort, int id) {
//         String sql = "UPDATE non_standard_ports SET expected_port = ? WHERE id = ?";
//         try (PreparedStatement stmt = conn.prepareStatement(sql)) {
//             stmt.setInt(1, newExpectedPort);
//             stmt.setInt(2, id);
//             stmt.executeUpdate();
//         } catch (SQLException e) {
//             System.err.println("[ERROR] Failed to update expected port");
//             e.printStackTrace();
//         }
//     }

//     // Update actual port
//     private void updateActualPort(Connection conn, int newActualPort, int id) {
//         String sql = "UPDATE non_standard_ports SET actual_port = ? WHERE id = ?";
//         try (PreparedStatement stmt = conn.prepareStatement(sql)) {
//             stmt.setInt(1, newActualPort);
//             stmt.setInt(2, id);
//             stmt.executeUpdate();
//         } catch (SQLException e) {
//             System.err.println("[ERROR] Failed to update actual port");
//             e.printStackTrace();
//         }
//     }

//     // Delete protocol violation rule
//     private void deleteProtocolViolationRule(Connection conn, int id) {
//         String sql = "DELETE FROM non_standard_ports WHERE id = ?";
//         try (PreparedStatement stmt = conn.prepareStatement(sql)) {
//             stmt.setInt(1, id);
//             stmt.executeUpdate();
//         } catch (SQLException e) {
//             System.err.println("[ERROR] Failed to delete protocol violation rule");
//             e.printStackTrace();
//         }
//     }

// }
