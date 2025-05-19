package com.vallhallatech.apiGateway.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import org.springframework.web.cors.reactive.CorsConfigurationSource;

import java.util.List;

@Configuration
public class SecurityConfig {

    private static final String ALLOWED_ORIGINS = "*";

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        http
                // 1. Deshabilitar CSRF
                .csrf(ServerHttpSecurity.CsrfSpec::disable)

                // 2. CORS reactivo
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))

                // 3. No almacenar contexto de seguridad en sesión
                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())

                // 4. Configurar autenticación/autorización
                .authorizeExchange(exchanges -> exchanges
                        // permitir preflight CORS
                        .pathMatchers(HttpMethod.OPTIONS).permitAll()
                        // rutas públicas
                        .pathMatchers("/auth/**", "/public/**","auth-service/**").permitAll()
                        .pathMatchers("/actuator/health", "/actuator/info","/actuator/**").permitAll()
                        // el resto requiere autenticación
                        .anyExchange().authenticated()
                );

        return http.build();
    }

    private CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(List.of(ALLOWED_ORIGINS.split(",")));
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"));
        config.setAllowedHeaders(List.of("Authorization", "Cache-Control", "Content-Type", "X-Requested-With"));
        config.setExposedHeaders(List.of("Authorization"));
        config.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}
