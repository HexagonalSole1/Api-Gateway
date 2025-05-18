package com.vallhallatech.apiGateway.authentication.application;

import com.vallhallatech.apiGateway.authentication.domain.TokenInfo;
import com.vallhallatech.apiGateway.authentication.infrastructure.JwtValidator;
import org.springframework.stereotype.Service;

@Service
public class TokenValidationService {

    private final JwtValidator jwtValidator;

    public TokenValidationService(JwtValidator jwtValidator) {
        this.jwtValidator = jwtValidator;
    }

    /**
     * Valida un token JWT básicamente (firma y expiración)
     * NO hace validaciones de autorización complejas
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
