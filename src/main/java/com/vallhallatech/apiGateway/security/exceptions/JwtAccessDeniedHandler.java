package com.vallhallatech.apiGateway.security.exceptions;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Maneja errores 403 (Forbidden) cuando el usuario no tiene permisos
 */
@Component
public class JwtAccessDeniedHandler implements ServerAccessDeniedHandler {

    @Override
    public Mono<Void> handle(ServerWebExchange exchange, AccessDeniedException denied) {

        System.out.println("🔴 Access denied: " + denied.getMessage());

        // Configurar response
        var response = exchange.getResponse();
        response.setStatusCode(HttpStatus.FORBIDDEN);
        response.getHeaders().add("Content-Type", MediaType.APPLICATION_JSON_VALUE);

        // Crear mensaje de error JSON
        String body = """
            {
                "error": "Access Denied",
                "message": "No tienes permisos para acceder a este recurso",
                "details": "%s",
                "timestamp": "%s",
                "path": "%s"
            }
            """.formatted(
                denied.getMessage(),
                Instant.now(),
                exchange.getRequest().getPath().value()
        );

        // Escribir response
        DataBuffer buffer = response.bufferFactory().wrap(body.getBytes());
        return response.writeWith(Mono.just(buffer));
    }
}