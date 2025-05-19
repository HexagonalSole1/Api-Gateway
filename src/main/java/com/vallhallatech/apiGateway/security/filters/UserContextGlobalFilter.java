package com.vallhallatech.apiGateway.security.filters;

import com.vallhallatech.apiGateway.security.entities.JwtAuthenticationToken;
import com.vallhallatech.apiGateway.security.entities.JwtUserPrincipal;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Filtro global que agrega headers de usuario autenticado para microservicios downstream
 * Se ejecuta DESPUÉS de la autenticación exitosa
 */
@Component
public class UserContextGlobalFilter implements GlobalFilter, Ordered {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        // Obtener el contexto de seguridad
        return ReactiveSecurityContextHolder.getContext()
                .map(securityContext -> securityContext.getAuthentication())
                .cast(JwtAuthenticationToken.class)
                .map(authentication -> {
                    // Extraer información del usuario autenticado
                    JwtUserPrincipal principal = (JwtUserPrincipal) authentication.getPrincipal();

                    System.out.println("🟢 Adding user headers for: " + principal.getUsername());

                    // Crear exchange modificado con headers adicionales
                    ServerWebExchange modifiedExchange = exchange.mutate()
                            .request(request -> request
                                    .header("X-User-Id", principal.getUserId())
                                    .header("X-Username", principal.getUsername())
                                    .header("X-User-Roles", principal.getRoles())
                                    .header("X-Authenticated", "true")
                            )
                            .build();

                    return modifiedExchange;
                })
                .defaultIfEmpty(exchange) // Si no hay autenticación, usar exchange original
                .flatMap(chain::filter);
    }

    @Override
    public int getOrder() {
        // Ejecutar DESPUÉS de la autenticación (orden positivo)
        return 0;
    }
}
