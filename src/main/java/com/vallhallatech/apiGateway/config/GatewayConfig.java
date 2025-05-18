package com.vallhallatech.apiGateway.config;


import com.vallhallatech.apiGateway.authentication.infrastructure.JwtAuthenticationFilter;
import com.vallhallatech.apiGateway.logging.infrastructure.GlobalLoggingFilter;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class GatewayConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    public GatewayConfig(JwtAuthenticationFilter jwtAuthenticationFilter) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
    }

    @Bean
    public RouteLocator customRouteLocator(RouteLocatorBuilder builder) {
        return builder.routes()
                // Rutas públicas
                .route("auth-public", r -> r.path("/auth/login", "/auth/register")
                        .uri("lb://auth-service"))

                // Rutas protegidas del auth-service
                .route("auth-protected", r -> r.path("/auth/**")
                        .filters(f -> f.stripPrefix(1)
                                .filter(jwtAuthenticationFilter.apply(new JwtAuthenticationFilter.Config())))
                        .uri("lb://auth-service"))

                // Microservicio de usuarios
                .route("user-service", r -> r.path("/api/users/**")
                        .filters(f -> f.stripPrefix(2)
                                .filter(jwtAuthenticationFilter.apply(new JwtAuthenticationFilter.Config())))
                        .uri("lb://user-service"))

                // Actuator endpoints
                .route("actuator", r -> r.path("/actuator/**")
                        .uri("lb://api-gateway"))

                .build();
    }
}