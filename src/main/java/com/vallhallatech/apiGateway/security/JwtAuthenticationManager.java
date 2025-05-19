package com.vallhallatech.apiGateway.security;


import com.vallhallatech.apiGateway.security.application.TokenValidationService;
import com.vallhallatech.apiGateway.security.domain.TokenInfo;
import com.vallhallatech.apiGateway.security.entities.JwtAuthenticationToken;
import com.vallhallatech.apiGateway.security.entities.JwtUserPrincipal;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Manager que valida los tokens JWT y crea objetos Authentication
 */
@Component
public class JwtAuthenticationManager implements ReactiveAuthenticationManager {

    private final TokenValidationService tokenValidationService;

    public JwtAuthenticationManager(TokenValidationService tokenValidationService) {
        this.tokenValidationService = tokenValidationService;
    }

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        String token = authentication.getCredentials().toString();

        try {
            // 1. Validar el token
            TokenInfo tokenInfo = tokenValidationService.validateToken(token);

            if (!tokenInfo.isValidAndNotExpired()) {
                return Mono.error(new BadCredentialsException("Token inválido o expirado"));
            }

            // 2. Extraer información del usuario
            String userId = tokenInfo.getUserId();
            String username = tokenInfo.getUsername();
            String roles = tokenInfo.getRoles();

            // 3. Convertir roles a authorities
            List<GrantedAuthority> authorities = parseRoles(roles);

            // 4. Crear principal
            JwtUserPrincipal principal = new JwtUserPrincipal(userId, username, roles);

            // 5. ✅ Cast super explícito
            JwtAuthenticationToken jwtToken = new JwtAuthenticationToken(principal, token, authorities);
            Authentication authResult = (Authentication) jwtToken;

            System.out.println("🟢 Authentication successful for user: " + principal.getUsername());

            return Mono.just(authResult);

        } catch (Exception ex) {
            System.out.println("🔴 Authentication failed: " + ex.getMessage());
            return Mono.error(new BadCredentialsException("Error validando token", ex));
        }
    }
    /**
     * Convierte la cadena de roles en GrantedAuthority de Spring Security
     */
    private List<GrantedAuthority> parseRoles(String rolesString) {
        if (rolesString == null || rolesString.trim().isEmpty()) {
            return new ArrayList<>();
        }

        return Arrays.stream(rolesString.split(","))
                .map(String::trim)
                .filter(role -> !role.isEmpty())
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                .collect(Collectors.toList());
    }
}