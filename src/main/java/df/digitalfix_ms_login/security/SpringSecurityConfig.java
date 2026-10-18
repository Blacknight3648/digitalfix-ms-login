package df.digitalfix_ms_login.security;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
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

// Seguridad de ms-login con el mismo modelo RBAC del backend de referencia
// (reglas por ruta + roles "ROLE_*"), pero sin emitir tokens propios: quien
// autentica es Microsoft Entra ID (IDaaS) y aquí solo se valida su JWT.
//
// Validación del token (JwtDecoder):
//   - Firma: con las claves públicas (JWKS) del tenant, descubiertas desde el issuer.
//   - Vigencia: "exp" y "nbf" (JwtValidators.createDefault).
//   - Issuer: el del tenant, en formato v2 (https://login.microsoftonline.com/<tenant>/v2.0)
//     o v1 (https://sts.windows.net/<tenant>/), según la versión de token que emita la API.
//   - Audience: el client ID de la API (o api://<client ID>).
// ms-user valida exactamente igual (misma App Registration y tenant).
//   - Punto limpio: tokens emitidos antes del último logout se rechazan.
//
// Autorización (EntraJwtAuthenticationConverter):
//   - SCOPE_<scp>: scopes delegados del token (access_as_user).
//   - ROLE_<rol>: App Roles del claim "roles" y el rol del usuario en ms-user.
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SpringSecurityConfig {

    // Scope que expone la App Registration de la API y que pide el frontend.
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
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                .authorizeHttpRequests(auth -> auth

                        /** SWAGGER */
                        .requestMatchers("/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html").permitAll()

                        /** PREFLIGHT CORS */
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()

                        /** LOGIN – cualquier usuario autenticado con el scope de la API */
                        .requestMatchers(HttpMethod.GET, "/api/v1/login/status").hasAuthority(API_SCOPE)
                        .requestMatchers(HttpMethod.GET, "/api/v1/login/me").hasAuthority(API_SCOPE)
                        .requestMatchers(HttpMethod.POST, "/api/v1/login/logout").hasAuthority(API_SCOPE)

                        /** AUDITORÍA – registrar es de cualquier usuario; consultar, solo admin/auditor */
                        .requestMatchers(HttpMethod.POST, "/api/v1/audit/login").hasAuthority(API_SCOPE)
                        .requestMatchers(HttpMethod.GET, "/api/v1/audit/**").hasAnyRole("ADMIN", "AUDITOR")

                        /** RESTO */
                        .anyRequest().authenticated()
                )

                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt
                                .decoder(jwtDecoder())
                                .jwtAuthenticationConverter(jwtAuthenticationConverter))
                        // 401 con JSON cuando el token falta, es inválido, expiró o es anterior al logout
                        .authenticationEntryPoint(jsonSecurityErrorHandler)
                        // 403 con JSON cuando el token es válido pero falta el scope o el rol
                        .accessDeniedHandler(jsonSecurityErrorHandler))
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(jsonSecurityErrorHandler)
                        .accessDeniedHandler(jsonSecurityErrorHandler))
                .build();
    }

    // El frontend Angular corre en un origen distinto (ej. http://localhost:4200),
    // así que el navegador exige que este backend declare explícitamente qué
    // orígenes puede llamar antes de aceptar la respuesta con el Bearer token.
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

        // fromIssuerLocation descubre el jwks_uri del tenant: la firma se verifica
        // con las claves públicas de Entra ID (RS256), no con un secreto local.
        // Las claves son las mismas para tokens v1 y v2 del tenant.
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
        jwtDecoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefault(), issuerValidator, audienceValidator, tokenIssuedAfterLogoutValidator));
        return jwtDecoder;
    }

}
