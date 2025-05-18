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
    private final GlobalLoggingFilter globalLoggingFilter;

    public GatewayConfig(JwtAuthenticationFilter jwtAuthenticationFilter,
                         GlobalLoggingFilter globalLoggingFilter) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.globalLoggingFilter = globalLoggingFilter;
    }

//    @Bean
//    public RouteLocator customRouteLocator(RouteLocatorBuilder builder) {
//        return builder.routes()
//                // ✅ RUTAS PÚBLICAS con rewrite
//                .route("auth-public", r -> r
//                        .path("/auth/login", "/auth/register", "/auth/authenticate")
//                        .filters(f -> f.rewritePath("/auth/(.*)", "/api/auth/$1"))  // ✅ Clave!
//                        .uri("lb://auth-service"))  // ✅ Nombre correcto
//
//                // ✅ RUTAS PROTEGIDAS con rewrite
//                .route("auth-protected", r -> r
//                        .path("/auth/**")
//                        .filters(f -> f
//                                .rewritePath("/auth/(.*)", "/api/auth/$1")  // ✅ Reescribir
//                                .filter(jwtAuthenticationFilter.apply(new JwtAuthenticationFilter.Config())))
//                        .uri("lb://auth-service"))
//
//                .build();
//    }
}