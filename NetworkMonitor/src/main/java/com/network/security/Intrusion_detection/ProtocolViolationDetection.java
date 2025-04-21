// package com.network.security.Intrusion_detection;

// public class ProtocolViolationDetection {
 
//     private int violationThreshold;
//     private int violationTimeWindow;
//     private String protocolType;
//     private String severity;

//     // Detection logic
//     public boolean detect(int violationCount, int secondsElapsed) {
//         if (violationCount > violationThreshold && secondsElapsed <= violationTimeWindow) {
//             System.out.println("Protocol violation detected for protocol: " + protocolType);
//             return true;
//         }
//         return false;
//     }

//     // Getter for violationThreshold
//     public int getViolationThreshold() {
//         return violationThreshold;
//     }

//     // Setter for violationThreshold
//     public void setViolationThreshold(int violationThreshold) {
//         this.violationThreshold = violationThreshold;
//     }

//     // Getter for violationTimeWindow
//     public int getViolationTimeWindow() {
//         return violationTimeWindow;
//     }

//     // Setter for violationTimeWindow
//     public void setViolationTimeWindow(int violationTimeWindow) {
//         this.violationTimeWindow = violationTimeWindow;
//     }

//     // Getter for protocolType
//     public String getProtocolType() {
//         return protocolType;
//     }

//     // Setter for protocolType
//     public void setProtocolType(String protocolType) {
//         this.protocolType = protocolType;
//     }
// }
