package df.digitalfix_ms_login.controller;


import df.digitalfix_ms_login.dto.UserSessionResponse;
import df.digitalfix_ms_login.security.EntraJwtAuthenticationConverter;
import df.digitalfix_ms_login.security.EntraTokenClaims;
import df.digitalfix_ms_login.service.LoginAuditSevice;
import df.digitalfix_ms_login.service.UserRoleClient;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

// Las reglas de acceso de cada ruta están centralizadas en SpringSecurityConfig
// (como en el backend de referencia): aquí todas exigen el scope access_as_user.
@RestController
@RequestMapping("api/v1/login")
@RequiredArgsConstructor
public class LoginController {

    private final LoginAuditSevice auditSevice;
    private final UserRoleClient userRoleClient;

    @GetMapping("/status")
    public ResponseEntity<String> checkStatus() {

        return ResponseEntity.ok("Autenticación exitosa. \n Bienvenido a digitalfix");

    }

    // Identidad, roles y scopes del usuario según el token validado.
    @GetMapping("/me")
    public ResponseEntity<UserSessionResponse> me(JwtAuthenticationToken authentication) {
        Jwt jwt = authentication.getToken();

        return ResponseEntity.ok(UserSessionResponse.builder()
                .userEntraId(EntraTokenClaims.userEntraId(jwt))
                .email(EntraTokenClaims.email(jwt))
                .name(jwt.getClaimAsString("name"))
                .roles(EntraJwtAuthenticationConverter.rolesOf(authentication.getAuthorities()))
                .scopes(EntraJwtAuthenticationConverter.scopesOf(authentication.getAuthorities()))
                .tokenExpiresAt(jwt.getExpiresAt())
                .build());
    }

    // Lo llama el frontend al cerrar sesión. Desde este momento el backend
    // rechaza los tokens del usuario emitidos antes (TokenIssuedAfterLogoutValidator),
    // así que para volver a entrar hay que iniciar sesión de nuevo.
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(JwtAuthenticationToken authentication, HttpServletRequest request) {
        String userEntraId = EntraTokenClaims.userEntraId(authentication.getToken());
        auditSevice.recordLogout(userEntraId, request.getRemoteAddr(), request.getHeader(HttpHeaders.USER_AGENT));
        userRoleClient.evict(userEntraId);
        return ResponseEntity.noContent().build();
    }

}
