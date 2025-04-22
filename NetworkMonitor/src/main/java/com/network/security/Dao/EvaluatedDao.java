package com.network.security.Dao;

import com.network.security.util.DBConnection;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class EvaluatedDao {
    
    public static void evaluated(Long packetID){
        if (packetID == null){
            return;
        }
        Connection conn = null;
        try{
            conn = DBConnection.getConnection();
            String query = "UPDATE Packet_Metadata SET evaluate=1 where PacketID=?";
            try(PreparedStatement stmt = conn.prepareStatement(query)){
                stmt.setLong(1, packetID);
                stmt.executeUpdate();
            
            }
        } catch (SQLException e){
            if (conn != null) {
                try {
                    conn.rollback();  // Rollback the transaction in case of an error
                } catch (SQLException ex) {
                    ex.printStackTrace();
                }
            }
            e.printStackTrace();
            System.err.println("[ERROR] SQL Exception: " + e.getMessage());
            throw new RuntimeException("Database error occurred", e); 
        }
    }
}
