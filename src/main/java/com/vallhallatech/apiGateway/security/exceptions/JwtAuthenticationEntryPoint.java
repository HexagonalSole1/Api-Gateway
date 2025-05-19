package com.vallhallatech.apiGateway.security.exceptions;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Maneja errores 401 (Unauthorized) cuando no hay token o es inválido
 */
@Component
public class JwtAuthenticationEntryPoint implements ServerAuthenticationEntryPoint {

    @Override
    public Mono<Void> commence(ServerWebExchange exchange, AuthenticationException ex) {

        System.out.println("🔴 Authentication failed: " + ex.getMessage());

        // Configurar response
        var response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        response.getHeaders().add("Content-Type", MediaType.APPLICATION_JSON_VALUE);

        // Crear mensaje de error JSON
        String body = """
            {
                "error": "Unauthorized",
                "message": "Token requerido para acceder a este recurso",
                "details": "%s",
                "timestamp": "%s",
                "path": "%s"
            }
            """.formatted(
                ex.getMessage(),
                Instant.now(),
                exchange.getRequest().getPath().value()
        );

        // Escribir response
        DataBuffer buffer = response.bufferFactory().wrap(body.getBytes());
        return response.writeWith(Mono.just(buffer));
    }
}
