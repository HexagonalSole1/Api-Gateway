package com.vallhallatech.apiGateway.security.domain;

import java.time.LocalDateTime;

public class TokenInfo {
    private final String userId;
    private final String username;
    private final String roles;
    private final LocalDateTime expiration;
    private final boolean valid;

    public TokenInfo(String userId, String username, String roles, LocalDateTime expiration, boolean valid) {
        this.userId = userId;
        this.username = username;
        this.roles = roles;
        this.expiration = expiration;
        this.valid = valid;
    }

    public static TokenInfo invalid() {
        return new TokenInfo(null, null, null, null, false);
    }

    public static TokenInfo valid(String userId, String username, String roles, LocalDateTime expiration) {
        return new TokenInfo(userId, username, roles, expiration, true);
    }

    public boolean isExpired() {
        return expiration != null && LocalDateTime.now().isAfter(expiration);
    }

    public boolean isValidAndNotExpired() {
        return valid && !isExpired();
    }

    // Getters
    public String getUserId() { return userId; }
    public String getUsername() { return username; }
    public String getRoles() { return roles; }
    public LocalDateTime getExpiration() { return expiration; }
    public boolean isValid() { return valid; }
}