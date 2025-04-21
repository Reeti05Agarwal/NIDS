// package com.network.security.Dao;

// import java.util.Properties;

// import com.network.security.entity.User;

// import java.io.FileInputStream;
// import java.io.IOException;
// import java.sql.Connection;
// import java.sql.DriverManager;
// import java.sql.PreparedStatement;
// import java.sql.SQLException;
// import java.util.Map;
 
// /*
//  * Mapping alerts when anomalies are detected.
//  * This class will be used to store and retrieve alerts from the database.
//  * It will also be used to send alerts to the user.
//  * Recieves alerts from the AnomalyDetection class and stores them in the database.
//  *  
//  */

// public class AlertDao {
//     static Properties config = loadConfig("NetworkMonitor\\src\\main\\resources\\config.properties");
//     private static final String DB_URL = config.getProperty("db.url");
//     private static final String DB_USER = config.getProperty("db.user");
//     private static final String DB_PASSWORD = config.getProperty("db.password");

//     public static Properties loadConfig(String filePath) {
//         Properties properties = new Properties();
//         try (FileInputStream input = new FileInputStream(filePath)) {
//             properties.load(input);
//         } catch (IOException e) {
//             System.err.println("[ERROR] Could not load config file: " + filePath);
//             e.printStackTrace();
//         }
//         return properties;
//     }

    

// }
