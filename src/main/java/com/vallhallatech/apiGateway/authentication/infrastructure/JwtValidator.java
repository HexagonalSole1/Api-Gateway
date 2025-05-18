package com.vallhallatech.apiGateway.authentication.infrastructure;


import com.vallhallatech.apiGateway.authentication.domain.TokenInfo;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.JwtException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

@Component
public class JwtValidator {

    @Value("${jwt.secret}")
    private String jwtSecret;

    /**
     * Validación JWT simple: firma y expiración
     * No valida reglas de negocio complejas
     */
    public TokenInfo validate(String token) {
        try {
            Claims claims = Jwts.parser()
                    .setSigningKey(jwtSecret.getBytes())
                    .parseClaimsJws(token)
                    .getBody();

            String userId = claims.getSubject();
            String username = claims.get("username", String.class);
            String roles = claims.get("roles", String.class); // Como string simple

            Date expiration = claims.getExpiration();
            LocalDateTime expirationTime = expiration.toInstant()
                    .atZone(ZoneId.systemDefault())
                    .toLocalDateTime();

            return TokenInfo.valid(userId, username, roles, expirationTime);

        } catch (JwtException | IllegalArgumentException e) {
            // Token inválido o malformado
            return TokenInfo.invalid();
        }
    }
}