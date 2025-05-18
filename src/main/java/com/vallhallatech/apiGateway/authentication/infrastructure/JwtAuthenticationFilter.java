package com.vallhallatech.apiGateway.authentication.infrastructure;


import com.vallhallatech.apiGateway.authentication.application.TokenValidationService;
import com.vallhallatech.apiGateway.authentication.domain.TokenInfo;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class JwtAuthenticationFilter extends AbstractGatewayFilterFactory<JwtAuthenticationFilter.Config> {

    private final TokenValidationService tokenValidationService;

    public JwtAuthenticationFilter(TokenValidationService tokenValidationService) {
        super(Config.class);
        this.tokenValidationService = tokenValidationService;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {

            // Omitir rutas públicas
            if (shouldSkipAuthentication(exchange)) {
                return chain.filter(exchange);
            }

            // Extraer token
            String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
            String token = tokenValidationService.extractTokenFromHeader(authHeader);

            if (token == null) {
                return handleUnauthorized(exchange, "Token no proporcionado");
            }

            // Validar token (solo firma y expiración)
            TokenInfo tokenInfo = tokenValidationService.validateToken(token);

            if (!tokenInfo.isValidAndNotExpired()) {
                return handleUnauthorized(exchange, "Token inválido o expirado");
            }

            // Agregar headers para el microservicio destino
            ServerWebExchange modifiedExchange = exchange.mutate()
                    .request(r -> r.header("X-User-Id", tokenInfo.getUserId())
                            .header("X-Username", tokenInfo.getUsername())
                            .header("X-User-Roles", tokenInfo.getRoles()))
                    .build();

            return chain.filter(modifiedExchange);
        };
    }

    private boolean shouldSkipAuthentication(ServerWebExchange exchange) {
        String path = exchange.getRequest().getPath().value();

        // Rutas que NO necesitan autenticación
        return path.startsWith("/auth/login") ||
                path.startsWith("/auth/register") ||
                path.startsWith("/actuator/health") ||
                path.startsWith("/actuator/info");
    }

    private Mono<Void> handleUnauthorized(ServerWebExchange exchange, String message) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        exchange.getResponse().getHeaders().add("Content-Type", "application/json");

        String body = String.format("{\"error\":\"%s\",\"timestamp\":\"%s\"}",
                message, java.time.Instant.now());

        org.springframework.core.io.buffer.DataBuffer buffer =
                exchange.getResponse().bufferFactory().wrap(body.getBytes());
        return exchange.getResponse().writeWith(Mono.just(buffer));
    }

    public static class Config {
        // Configuración si es necesaria en el futuro
    }
}