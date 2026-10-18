package df.digitalfix_ms_login.security;

import df.digitalfix_ms_login.service.UserRoleClient;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class EntraJwtAuthenticationConverterTest {

    private static final String OID = "11111111-2222-3333-4444-555555555555";

    private final UserRoleClient userRoleClient = mock(UserRoleClient.class);
    private final EntraJwtAuthenticationConverter converter = new EntraJwtAuthenticationConverter(userRoleClient);

    private static Jwt token(String scp, List<String> roles) {
        Jwt.Builder builder = Jwt.withTokenValue("token")
                .header("alg", "RS256")
                .claim("oid", OID)
                .claim("scp", scp)
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(3600));
        if (roles != null) {
            builder.claim("roles", roles);
        }
        return builder.build();
    }

    @Test
    void combinaScopesRolesDelTokenYRolDeMsUser() {
        when(userRoleClient.findRoleCode(anyString(), anyString())).thenReturn(Optional.of("ADMIN"));

        AbstractAuthenticationToken auth = converter.convert(token("access_as_user offline_access", List.of("auditor")));

        assertThat(auth.getName()).isEqualTo(OID);
        assertThat(EntraJwtAuthenticationConverter.scopesOf(auth.getAuthorities()))
                .containsExactlyInAnyOrder("access_as_user", "offline_access");
        assertThat(EntraJwtAuthenticationConverter.rolesOf(auth.getAuthorities()))
                .containsExactlyInAnyOrder("AUDITOR", "ADMIN");
    }

    @Test
    void sinRolEnTokenNiEnMsUserSoloQuedanLosScopes() {
        when(userRoleClient.findRoleCode(anyString(), anyString())).thenReturn(Optional.empty());

        AbstractAuthenticationToken auth = converter.convert(token("access_as_user", null));

        assertThat(EntraJwtAuthenticationConverter.rolesOf(auth.getAuthorities())).isEmpty();
        assertThat(EntraJwtAuthenticationConverter.scopesOf(auth.getAuthorities())).containsExactly("access_as_user");
    }
}
