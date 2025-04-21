package com.network.security.services;

import java.util.List;

import com.network.security.Dao.BlacklistDao;

/**
 * Service layer for blacklist operations.
 */
public class BlacklistService {

    private final BlacklistDao dao = new BlacklistDao();

    /**
     * Fetches all blocked IPs.
     */
    public List<String> getAllBlockedIPs() {
        return dao.getAllBlockedIPs();
    }
}
