package com.network.security.services;

import com.network.security.Dao.DetectionDao;

// contains the threshold and stuff
import com.network.security.models.DetectionRule;

import java.util.List;

public class DetectionServices {

    private final DetectionDao detectionDao;

    public DetectionServices() {
        this.detectionDao = new DetectionDao();
    }

    // 1. Display detection rules table
    public List<DetectionRule> getAllDetectionRules() {
        return DetectionDao.getAllRules();
    }

    // 2. Update threshold/time_interval/severity
    public boolean updateDetectionRule(int ruleId, int threshold, int timeInterval, String severity) {
        return DetectionDao.updateRule(ruleId, threshold, timeInterval, severity);
    }

    // 3. Delete a rule
    public boolean deleteDetectionRule(int ruleId) {
        return DetectionDao.deleteRule(ruleId);
    }

    // 4. Add a new rule
    public boolean addDetectionRule(DetectionRule newRule) {
        return DetectionDao.insertRule(newRule);
    }
}
