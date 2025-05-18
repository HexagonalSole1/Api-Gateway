package com.vallhallatech.apiGateway.logging.infrastructure;

import com.vallhallatech.apiGateway.logging.application.RequestLoggingService;
import com.vallhallatech.apiGateway.logging.domain.RequestLog;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Component
public class GlobalLoggingFilter implements GlobalFilter, Ordered {

    private final RequestLoggingService loggingService;

    public GlobalLoggingFilter(RequestLoggingService loggingService) {
        this.loggingService = loggingService;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        // Generar ID único para la petición
        String requestId = UUID.randomUUID().toString().substring(0, 8);

        // Extraer información de la petición
        ServerHttpRequest request = exchange.getRequest();
        String method = request.getMethod() != null ? request.getMethod().name() : "UNKNOWN";
        String path = request.getPath().value();
        String clientIp = getClientIp(request);
        String userId = request.getHeaders().getFirst("X-User-Id");

        // Headers relevantes para logging (sin información sensible)
        Map<String, String> relevantHeaders = extractRelevantHeaders(request);

        // Crear log de entrada
        RequestLog requestLog = new RequestLog(requestId, method, path, clientIp, relevantHeaders, userId);

        // Log de entrada
        loggingService.logIncomingRequest(requestLog);

        // Agregar requestId al exchange para uso posterior
        exchange.getAttributes().put("requestId", requestId);

        // Tiempo de inicio
        long startTime = System.currentTimeMillis();

        // CORRECCIÓN: Usar doOnSuccess() y doOnError() en lugar de then() y onErrorResume()
        return chain.filter(exchange)
                .doOnSuccess(aVoid -> {
                    // Log de salida exitosa
                    long endTime = System.currentTimeMillis();
                    int statusCode = exchange.getResponse().getStatusCode() != null ?
                            exchange.getResponse().getStatusCode().value() : 0;

                    String targetService = extractTargetService(path);
                    loggingService.logOutgoingResponse(requestId, statusCode, endTime - startTime, targetService);
                })
                .doOnError(throwable -> {
                    // Log de error
                    loggingService.logError(requestId, "Gateway processing error", throwable);
                });
    }

    private String getClientIp(ServerHttpRequest request) {
        String xForwardedFor = request.getHeaders().getFirst("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }

        String xRealIp = request.getHeaders().getFirst("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }

        return request.getRemoteAddress() != null ?
                request.getRemoteAddress().getAddress().getHostAddress() : "unknown";
    }

    private Map<String, String> extractRelevantHeaders(ServerHttpRequest request) {
        Map<String, String> headers = new HashMap<>();

        // Solo headers relevantes, no sensibles
        String userAgent = request.getHeaders().getFirst("User-Agent");
        String contentType = request.getHeaders().getFirst("Content-Type");
        String accept = request.getHeaders().getFirst("Accept");

        if (userAgent != null) headers.put("User-Agent", userAgent);
        if (contentType != null) headers.put("Content-Type", contentType);
        if (accept != null) headers.put("Accept", accept);

        return headers;
    }

    private String extractTargetService(String path) {
        if (path.startsWith("/auth")) return "auth-service";
        if (path.startsWith("/api/users")) return "user-service";
        if (path.startsWith("/api/products")) return "product-service";
        return "unknown";
    }

    @Override
    public int getOrder() {
        return -1; // Ejecutar antes que otros filtros
    }
}