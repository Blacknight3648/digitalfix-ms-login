package df.digitalfix_ms_login.security;

import df.digitalfix_ms_login.controller.LoginAuditController;
import df.digitalfix_ms_login.controller.LoginController;
import df.digitalfix_ms_login.service.LoginAuditSevice;
import df.digitalfix_ms_login.service.UserRoleClient;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasItem;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

// Verifica las reglas de SpringSecurityConfig y las respuestas de error en JSON.
// El JwtDecoder real (firma/issuer/audience/vigencia contra Entra ID) se
// reemplaza por un mock: jwt() entrega un token ya validado con las autoridades
// indicadas, y el mock simula un token rechazado por el decoder.
@WebMvcTest(controllers = {LoginController.class, LoginAuditController.class})
@Import({SpringSecurityConfig.class, EntraJwtAuthenticationConverter.class, JsonSecurityErrorHandler.class})
@TestPropertySource(properties = {
        "spring.security.oauth2.resourceserver.jwt.issuer-uri=https://login.microsoftonline.com/test-tenant/v2.0",
        "AZURE_CLIENT_ID=test-client"
})
class SecurityRulesTest {

    private static final String OID = "11111111-2222-3333-4444-555555555555";
    private static final SimpleGrantedAuthority API_SCOPE = new SimpleGrantedAuthority("SCOPE_access_as_user");

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private JwtDecoder jwtDecoder;
    @MockitoBean
    private TokenIssuedAfterLogoutValidator tokenIssuedAfterLogoutValidator;
    @MockitoBean
    private UserRoleClient userRoleClient;
    @MockitoBean
    private LoginAuditSevice auditSevice;

    @Test
    void sinTokenResponde401EnJson() throws Exception {
        mockMvc.perform(get("/api/v1/login/me"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.message").value("Token inválido o ausente"));
    }

    @Test
    void tokenRechazadoPorElDecoderResponde401ConElMotivo() throws Exception {
        when(jwtDecoder.decode(anyString())).thenThrow(new BadJwtException("Jwt expired at 2026-10-18T19:00:00Z"));

        mockMvc.perform(get("/api/v1/login/me").header("Authorization", "Bearer token-vencido"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.errors[0]", containsString("expired")));
    }

    @Test
    void tokenValidoSinElScopeDeLaApiResponde403EnJson() throws Exception {
        mockMvc.perform(get("/api/v1/login/me").with(jwt()))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.status").value(403));
    }

    @Test
    void meDevuelveRolesYScopesDelToken() throws Exception {
        mockMvc.perform(get("/api/v1/login/me").with(jwt()
                        .jwt(token -> token.claim("oid", OID).claim("name", "Usuario Prueba")
                                .claim("preferred_username", "prueba@duocuc.cl"))
                        .authorities(API_SCOPE, new SimpleGrantedAuthority("ROLE_ADMIN"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.userEntraId").value(OID))
                .andExpect(jsonPath("$.email").value("prueba@duocuc.cl"))
                .andExpect(jsonPath("$.roles", hasItem("ADMIN")))
                .andExpect(jsonPath("$.scopes", hasItem("access_as_user")));
    }

    @Test
    void consultarAuditoriaSinRolAdminOAuditorResponde403() throws Exception {
        mockMvc.perform(get("/api/v1/audit/login").with(jwt()
                        .authorities(API_SCOPE, new SimpleGrantedAuthority("ROLE_CLIENTE"))))
                .andExpect(status().isForbidden());
    }

    @Test
    void consultarAuditoriaConRolAdminResponde200() throws Exception {
        when(auditSevice.findRecentEvents()).thenReturn(List.of());

        mockMvc.perform(get("/api/v1/audit/login").with(jwt()
                        .authorities(API_SCOPE, new SimpleGrantedAuthority("ROLE_ADMIN"))))
                .andExpect(status().isOk());
    }

    @Test
    void logoutRegistraElEventoYResponde204() throws Exception {
        mockMvc.perform(post("/api/v1/login/logout").with(jwt()
                        .jwt(token -> token.claim("oid", OID))
                        .authorities(API_SCOPE)))
                .andExpect(status().isNoContent());

        verify(auditSevice).recordLogout(eq(OID), anyString(), org.mockito.ArgumentMatchers.any());
        verify(userRoleClient).evict(OID);
    }
}
