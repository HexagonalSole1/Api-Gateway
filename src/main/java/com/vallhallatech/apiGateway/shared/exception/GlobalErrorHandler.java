package com.vallhallatech.apiGateway.shared.exception;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.web.reactive.error.ErrorWebExceptionHandler;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@Component
@Order(-1)
public class GlobalErrorHandler implements ErrorWebExceptionHandler {

    private static final Logger logger = LoggerFactory.getLogger(GlobalErrorHandler.class);
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public Mono<Void> handle(ServerWebExchange exchange, Throwable ex) {

        logger.error("Error en API Gateway: {}", ex.getMessage(), ex);

        // Determinar status code basado en el tipo de excepción
        HttpStatus status = determineHttpStatus(ex);

        // Crear respuesta de error
        ErrorResponse errorResponse = createErrorResponse(ex, status, exchange);

        // Configurar response
        exchange.getResponse().setStatusCode(status);
        exchange.getResponse().getHeaders().add("Content-Type", MediaType.APPLICATION_JSON_VALUE);

        // Convertir a JSON
        try {
            String jsonResponse = objectMapper.writeValueAsString(errorResponse);
            org.springframework.core.io.buffer.DataBufferFactory bufferFactory = exchange.getResponse().bufferFactory();
            org.springframework.core.io.buffer.DataBuffer buffer = bufferFactory.wrap(jsonResponse.getBytes());
            return exchange.getResponse().writeWith(Mono.just(buffer));
        } catch (JsonProcessingException e) {
            logger.error("Error al serializar respuesta de error", e);
            return exchange.getResponse().setComplete();
        }
    }

    private HttpStatus determineHttpStatus(Throwable ex) {
        if (ex instanceof IllegalArgumentException) {
            return HttpStatus.BAD_REQUEST;
        } else if (ex instanceof SecurityException) {
            return HttpStatus.UNAUTHORIZED;
        } else if (ex instanceof RuntimeException) {
            return HttpStatus.INTERNAL_SERVER_ERROR;
        } else {
            return HttpStatus.INTERNAL_SERVER_ERROR;
        }
    }

    private ErrorResponse createErrorResponse(Throwable ex, HttpStatus status, ServerWebExchange exchange) {
        String requestId = (String) exchange.getAttributes().get("requestId");
        String path = exchange.getRequest().getPath().value();

        return new ErrorResponse(
                status.value(),
                status.getReasonPhrase(),
                ex.getMessage(),
                path,
                requestId,
                LocalDateTime.now()
        );
    }

    private static class ErrorResponse {
        private final int status;
        private final String error;
        private final String message;
        private final String path;
        private final String requestId;
        private final LocalDateTime timestamp;

        public ErrorResponse(int status, String error, String message, String path, String requestId, LocalDateTime timestamp) {
            this.status = status;
            this.error = error;
            this.message = message;
            this.path = path;
            this.requestId = requestId;
            this.timestamp = timestamp;
        }

        // Getters para Jackson
        public int getStatus() { return status; }
        public String getError() { return error; }
        public String getMessage() { return message; }
        public String getPath() { return path; }
        public String getRequestId() { return requestId; }
        public LocalDateTime getTimestamp() { return timestamp; }
    }
}