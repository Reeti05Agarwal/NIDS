package com.network.security.Intrusion_detection;

public class DpiDetector {
    private String keyword;

    public DpiDetector(String keyword) {
        this.keyword = keyword.toLowerCase();
    }

    public String getKeyword() {
        return keyword;
    }

    public void setKeyword(String keyword) {
        this.keyword = keyword.toLowerCase();
    }

    public boolean detect(String content) {
        if (content != null && content.toLowerCase().contains(keyword)) {
            System.out.println("DPI violation detected.");
            return true;
        }
        return false;
    }
}
