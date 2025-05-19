package com.vallhallatech.apiGateway.security.entities;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

/**
 * Token de autenticación exitosa que contiene la información del usuario
 * y sus autoridades (roles)
 */
public class JwtAuthenticationToken extends AbstractAuthenticationToken {

    private final JwtUserPrincipal principal;
    private final String token;

    public JwtAuthenticationToken(JwtUserPrincipal principal, String token,
                                  Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        this.token = token;
        setAuthenticated(true); // Marca como autenticado exitosamente
    }

    @Override
    public Object getCredentials() {
        return token;
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }
}