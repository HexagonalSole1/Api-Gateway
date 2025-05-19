package com.vallhallatech.apiGateway.security.entities;

/**
 * Principal personalizado que contiene la información del usuario extraída del JWT
 */
public class JwtUserPrincipal {
    private final String userId;
    private final String username;
    private final String roles;

    public JwtUserPrincipal(String userId, String username, String roles) {
        this.userId = userId;
        this.username = username;
        this.roles = roles;
    }

    public String getUserId() {
        return userId;
    }

    public String getUsername() {
        return username;
    }

    public String getRoles() {
        return roles;
    }

    @Override
    public String toString() {
        return "JwtUserPrincipal{" +
                "userId='" + userId + '\'' +
                ", username='" + username + '\'' +
                ", roles='" + roles + '\'' +
                '}';
    }
}