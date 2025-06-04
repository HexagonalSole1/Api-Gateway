package com.vallhallatech.apiGateway.security;

import com.vallhallatech.apiGateway.security.authentication.JwtServerAuthenticationConverter;
import com.vallhallatech.apiGateway.security.exceptions.JwtAccessDeniedHandler;
import com.vallhallatech.apiGateway.security.exceptions.JwtAuthenticationEntryPoint;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.security.web.server.util.matcher.NegatedServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.OrServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import org.springframework.web.cors.reactive.CorsConfigurationSource;

import java.util.List;


@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    private static final String ALLOWED_ORIGINS = "*";

    private final JwtAuthenticationManager jwtAuthenticationManager;
    private final JwtServerAuthenticationConverter jwtAuthenticationConverter;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;

    public SecurityConfig(JwtAuthenticationManager jwtAuthenticationManager,
                          JwtServerAuthenticationConverter jwtAuthenticationConverter,
                          JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint,
                          JwtAccessDeniedHandler jwtAccessDeniedHandler) {
        this.jwtAuthenticationManager = jwtAuthenticationManager;
        this.jwtAuthenticationConverter = jwtAuthenticationConverter;
        this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
        this.jwtAccessDeniedHandler = jwtAccessDeniedHandler;
    }

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        return http
                // 1. Deshabilitar CSRF y configuraciones innecesarias
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .logout(ServerHttpSecurity.LogoutSpec::disable)

                // 2. CORS reactivo
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))

                // 3. No almacenar contexto en sesión (stateless)
                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())

                // 4. ✅ Configurar Authentication Manager
                .authenticationManager(jwtAuthenticationManager)

                // 5. ✅ Configurar autorización por rutas y roles
                .authorizeExchange(exchanges -> exchanges
                        // 🟢 Rutas públicas (permitir sin autenticación)
                        .pathMatchers(HttpMethod.OPTIONS).permitAll()
                        .pathMatchers("/auth-service/auth/**", "/public/**").permitAll()
                        .pathMatchers("/auth-service/users/**", "/public/**").permitAll()
                        .pathMatchers("/actuator/health", "/actuator/info", "/actuator/**").permitAll()
                        .pathMatchers(HttpMethod.GET,"/product-service/products/**").permitAll()

                        // 🔒 Rutas que requieren roles específicos
                        .pathMatchers("/api/admin/**").hasRole("ADMIN")
                        .pathMatchers("/api/tasks/**").hasRole("ADMIN")
                        .pathMatchers("/roles/**").hasRole("ADMIN")

                        // 🔒 Rutas que requieren cualquier usuario autenticado
                        .pathMatchers("/profile/**").hasAnyRole("USER", "ADMIN")
                        .pathMatchers("/users/**").hasAnyRole("USER", "ADMIN")
                        .pathMatchers("/notifications/**").authenticated()

                        //profile-service
                        .pathMatchers("/profile-service/**").authenticated()

                        // 🔒 Todo lo demás requiere autenticación
                        .anyExchange().authenticated()
                )

                // 6. ✅ Agregar filtro de autenticación JWT
                .addFilterBefore(jwtAuthenticationWebFilter(), SecurityWebFiltersOrder.AUTHENTICATION)

                // 7. ✅ Configurar manejo de excepciones
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                        .accessDeniedHandler(jwtAccessDeniedHandler)
                )

                .build();
    }

    /**
     * ✅ CORREGIDO: Configurar el filtro de autenticación JWT sin negate()
     */
    @Bean
    public AuthenticationWebFilter jwtAuthenticationWebFilter() {
        AuthenticationWebFilter authenticationWebFilter =
                new AuthenticationWebFilter(jwtAuthenticationManager);

        // Configurar el convertidor que extrae JWT del header
        authenticationWebFilter.setServerAuthenticationConverter(jwtAuthenticationConverter);

        // ✅ SOLUCIÓN: Usar NegatedServerWebExchangeMatcher en lugar de negate()
        authenticationWebFilter.setRequiresAuthenticationMatcher(
                new NegatedServerWebExchangeMatcher(
                        new OrServerWebExchangeMatcher(
                                ServerWebExchangeMatchers.pathMatchers("/auth/**"),
                                ServerWebExchangeMatchers.pathMatchers("/public/**"),
                                ServerWebExchangeMatchers.pathMatchers("/actuator/**"),
                                ServerWebExchangeMatchers.pathMatchers(HttpMethod.OPTIONS, "/**")
                        )
                )
        );

        return authenticationWebFilter;
    }

    /**
     * Configuración CORS (mantenida igual)
     */
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