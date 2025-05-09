package com.network.security.Intrusion_detection;

import java.util.List;

public class DpiDetector {
    private List<String> keyword;
    private String severity;

    public DpiDetector(List<String> keyword) {
        this.keyword = keyword;
    }

    public List<String> getKeyword() {
        return keyword;
    }

    public void setKeyword(List<String> keyword) {
        this.keyword = keyword;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public boolean detect(String content) {
        for (String keyword : this.keyword) {
            if (isDpiViolation(content, keyword)) {
                return true;
            }   
        }
        return false;
    }

    private boolean isDpiViolation(String content, String keyword) {
        return content != null && content.toLowerCase().contains(keyword.toLowerCase());
    }
}
