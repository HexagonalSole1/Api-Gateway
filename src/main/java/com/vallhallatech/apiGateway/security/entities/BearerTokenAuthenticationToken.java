package com.vallhallatech.apiGateway.security.entities;

import org.springframework.security.authentication.AbstractAuthenticationToken;

/**
 * Token temporal usado durante el proceso de autenticación
 * Contiene solo el JWT token crudo antes de ser validado
 */
public class BearerTokenAuthenticationToken extends AbstractAuthenticationToken {

    private final String token;

    public BearerTokenAuthenticationToken(String token) {
        super(null);
        this.token = token;
        setAuthenticated(false); // Aún no está autenticado
    }

    @Override
    public Object getCredentials() {
        return token;
    }

    @Override
    public Object getPrincipal() {
        return token;
    }
}