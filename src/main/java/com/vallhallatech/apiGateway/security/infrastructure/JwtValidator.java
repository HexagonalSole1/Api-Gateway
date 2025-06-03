package com.vallhallatech.apiGateway.security.infrastructure;
import com.vallhallatech.apiGateway.security.domain.TokenInfo;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

@Component
public class JwtValidator {

    @Value("${jwt.access-token-secret-key:TuClaveSecretaSuperSeguraDeAlMenos256BitsParaJWTTokensQueDebeSerLaMismaEnTodosLosMicroserviciosParaQueElGatewayPuedaValidarLosTokensCorrectamente}")
    private String jwtSecret;

    @PostConstruct
    public void logJwtConfig() {
        System.out.println("🔑 [API-GATEWAY] JWT Config Loaded:");
        System.out.println("🔑 [API-GATEWAY] Secret Key: " + jwtSecret.substring(0, Math.min(20, jwtSecret.length())) + "...");
        System.out.println("🔑 [API-GATEWAY] Secret Length: " + jwtSecret.length());
        System.out.println("🔑 [API-GATEWAY] Secret Hash: " + jwtSecret.hashCode());
    }

    public TokenInfo validate(String token) {
        System.out.println("🟡 [API-GATEWAY] Validating token...");
        System.out.println("🟡 [API-GATEWAY] Token preview: " + token.substring(0, Math.min(50, token.length())) + "...");
        System.out.println("🟡 [API-GATEWAY] Using secret: " + jwtSecret.substring(0, Math.min(20, jwtSecret.length())) + "...");
        System.out.println("🟡 [API-GATEWAY] Secret hash: " + jwtSecret.hashCode());

        try {
            // Verificar que tenemos el mismo formato exacto
            Claims claims = Jwts.parser()
                    .verifyWith(Keys.hmacShaKeyFor(jwtSecret.getBytes()))
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            System.out.println("✅ [API-GATEWAY] JWT parsed successfully!");
            System.out.println("✅ [API-GATEWAY] All claims: " + claims);
            System.out.println("✅ [API-GATEWAY] Subject: " + claims.getSubject());

            // Extraer información del token
            String userId = claims.getSubject();
            String username = claims.get("username", String.class);
            String roles = claims.get("roles", String.class);

            // Si el subject es null, buscar en los claims
            if (userId == null) {
                Object idClaim = claims.get("id");
                if (idClaim != null) {
                    userId = idClaim.toString();
                    System.out.println("✅ [API-GATEWAY] Found userId in claims: " + userId);
                }
            }

            // También buscar email si no hay subject
            if (userId == null) {
                Object emailClaim = claims.get("email");
                if (emailClaim != null) {
                    userId = emailClaim.toString();
                    System.out.println("✅ [API-GATEWAY] Using email as userId: " + userId);
                }
            }

            Date expiration = claims.getExpiration();
            LocalDateTime expirationTime = null;
            if (expiration != null) {
                expirationTime = expiration.toInstant()
                        .atZone(ZoneId.systemDefault())
                        .toLocalDateTime();
            }

            System.out.println("🟢 [API-GATEWAY] JWT válido - userId: " + userId + ", username: " + username + ", roles: " + roles);
            return TokenInfo.valid(userId, username, roles, expirationTime);

        } catch (JwtException e) {
            System.err.println("🔴 [API-GATEWAY] JWT validation error: " + e.getMessage());
            System.err.println("🔴 [API-GATEWAY] Error type: " + e.getClass().getSimpleName());

            // Intentar decodificar el header para más información
            try {
                String[] parts = token.split("\\.");
                if (parts.length >= 2) {
                    System.err.println("🔴 [API-GATEWAY] Token parts count: " + parts.length);
                    System.err.println("🔴 [API-GATEWAY] Header: " + parts[0]);
                }
            } catch (Exception ex) {
                System.err.println("🔴 [API-GATEWAY] Cannot decode token parts: " + ex.getMessage());
            }

            return TokenInfo.invalid();
        } catch (Exception e) {
            System.err.println("🔴 [API-GATEWAY] Unexpected error during JWT validation: " + e.getMessage());
            e.printStackTrace();
            return TokenInfo.invalid();
        }
    }
}