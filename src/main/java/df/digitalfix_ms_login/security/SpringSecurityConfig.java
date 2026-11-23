package df.digitalfix_ms_login.security;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;
import java.util.Set;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SpringSecurityConfig {

        public static final String API_SCOPE = "SCOPE_access_as_user";

        private final EntraJwtAuthenticationConverter jwtAuthenticationConverter;
        private final TokenIssuedAfterLogoutValidator tokenIssuedAfterLogoutValidator;
        private final JsonSecurityErrorHandler jsonSecurityErrorHandler;

        @Value("${AZURE_TENANT_ID:3fb8463e-0e33-4b7d-adc1-2a47c707831e}")
        private String tenantId;

        @Value("${AZURE_CLIENT_ID:9494b59c-9c6e-4a0f-91ae-ae90212882e7}")
        private String clientId;

        @Value("${CORS_ALLOWED_ORIGINS:http://localhost:4200}")
        private List<String> corsAllowedOrigins;

        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
                return http
                                .csrf(AbstractHttpConfigurer::disable)
                                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                                .sessionManagement(session -> session
                                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                                .authorizeHttpRequests(auth -> auth
                                                .requestMatchers("/v3/api-docs/**", "/swagger-ui/**",
                                                                "/swagger-ui.html")
                                                .permitAll()
                                                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                                                .requestMatchers(HttpMethod.GET, "/api/v1/login/status")
                                                .hasAuthority(API_SCOPE)
                                                .requestMatchers(HttpMethod.GET, "/api/v1/login/me")
                                                .hasAuthority(API_SCOPE)
                                                .requestMatchers(HttpMethod.POST, "/api/v1/login/logout")
                                                .hasAuthority(API_SCOPE)
                                                .requestMatchers(HttpMethod.POST, "/api/v1/audit/login")
                                                .hasAuthority(API_SCOPE)
                                                .requestMatchers(HttpMethod.GET, "/api/v1/audit/**")
                                                .hasAnyRole("ADMIN", "AUDITOR")
                                                .anyRequest().authenticated())
                                .oauth2ResourceServer(oauth2 -> oauth2
                                                .jwt(jwt -> jwt
                                                                .decoder(jwtDecoder())
                                                                .jwtAuthenticationConverter(jwtAuthenticationConverter))
                                                .authenticationEntryPoint(jsonSecurityErrorHandler)
                                                .accessDeniedHandler(jsonSecurityErrorHandler))
                                .exceptionHandling(ex -> ex
                                                .authenticationEntryPoint(jsonSecurityErrorHandler)
                                                .accessDeniedHandler(jsonSecurityErrorHandler))
                                .build();
        }

        @Bean
        static RoleHierarchy roleHierarchy() {
                return RoleHierarchyImpl.withDefaultRolePrefix()
                                .role("SUPERADMIN").implies("ADMIN", "SUPERVISOR", "TECNICO", "CLIENTE", "AUDITOR")
                                .build();
        }

        @Bean
        public CorsConfigurationSource corsConfigurationSource() {
                CorsConfiguration configuration = new CorsConfiguration();
                configuration.setAllowedOrigins(corsAllowedOrigins);
                configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
                configuration.setAllowedHeaders(List.of("Authorization", "Content-Type"));
                configuration.setAllowCredentials(true);

                UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
                source.registerCorsConfiguration("/**", configuration);
                return source;
        }

        @Bean
        public JwtDecoder jwtDecoder() {
                String issuerV2 = "https://login.microsoftonline.com/" + tenantId + "/v2.0";
                String issuerV1 = "https://sts.windows.net/" + tenantId + "/";

                NimbusJwtDecoder jwtDecoder = JwtDecoders.fromIssuerLocation(issuerV2);

                Set<String> allowedIssuers = Set.of(issuerV2, issuerV1);
                OAuth2TokenValidator<Jwt> issuerValidator = new JwtClaimValidator<Object>(
                                JwtClaimNames.ISS, iss -> iss != null && allowedIssuers.contains(iss.toString()));

                OAuth2TokenValidator<Jwt> audienceValidator = new JwtClaimValidator<Object>(
                                "aud", aud -> {
                                        if (aud instanceof String s) {
                                                return s.equals(clientId) || s.equals("api://" + clientId);
                                        }
                                        if (aud instanceof List<?> list) {
                                                return list.contains(clientId) || list.contains("api://" + clientId);
                                        }
                                        return false;
                                });

                // JwtValidators.createDefaultWithIssuer(...) no se usa aquí porque soportamos
                // v1 y v2;
                // combinamos timestamp validator (exp + nbf), issuer, audience y validación
                // post-logout.
                OAuth2TokenValidator<Jwt> defaultTimestampValidator = new JwtTimestampValidator();
                jwtDecoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                                defaultTimestampValidator,
                                issuerValidator,
                                audienceValidator,
                                tokenIssuedAfterLogoutValidator));
                return jwtDecoder;
        }
}