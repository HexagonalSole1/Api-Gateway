package com.vallhallatech.apiGateway.security.authentication;

import com.vallhallatech.apiGateway.security.application.TokenValidationService;
import com.vallhallatech.apiGateway.security.entities.BearerTokenAuthenticationToken;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Convierte las requests HTTP con JWT en objetos Authentication
 */
@Component
public class JwtServerAuthenticationConverter implements ServerAuthenticationConverter {

    private final TokenValidationService tokenValidationService;

    public JwtServerAuthenticationConverter(TokenValidationService tokenValidationService) {
        this.tokenValidationService = tokenValidationService;
    }

    @Override
    public Mono<Authentication> convert(ServerWebExchange exchange) {
        // 1. Extraer header Authorization
        String authHeader = exchange.getRequest()
                .getHeaders()
                .getFirst(HttpHeaders.AUTHORIZATION);

        // 2. Extraer token del header
        String token = tokenValidationService.extractTokenFromHeader(authHeader);

        // 3. Si no hay token, retornar Mono vacío
        if (token == null) {
            System.out.println("⚪ No JWT token found in request");
            return Mono.empty();
        }

        // 4. ✅ SOLUCIÓN: Cast explícito y uso de Mono.just()
        System.out.println("🟡 JWT Token found, sending to authentication manager");
        Authentication bearerToken = new BearerTokenAuthenticationToken(token);
        return Mono.just(bearerToken);
    }
}