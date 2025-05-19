package com.vallhallatech.apiGateway.security.application;


import com.vallhallatech.apiGateway.security.domain.TokenInfo;
import com.vallhallatech.apiGateway.security.infrastructure.JwtValidator;
import org.springframework.stereotype.Service;

@Service
public class TokenValidationService {

    private final JwtValidator jwtValidator;

    public TokenValidationService(JwtValidator jwtValidator) {
        this.jwtValidator = jwtValidator;
    }

    /**
     * Valida un token JWT (firma y expiración)
     */
    public TokenInfo validateToken(String token) {
        if (token == null || token.trim().isEmpty()) {
            return TokenInfo.invalid();
        }

        return jwtValidator.validate(token);
    }

    /**
     * Extrae el token del header Authorization
     */
    public String extractTokenFromHeader(String authorizationHeader) {
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            return authorizationHeader.substring(7);
        }
        return null;
    }
}