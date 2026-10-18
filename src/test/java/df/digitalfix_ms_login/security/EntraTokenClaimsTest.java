package df.digitalfix_ms_login.security;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

// Misma prueba en ms-user: ambos servicios deben identificar al usuario igual.
class EntraTokenClaimsTest {

    private static Jwt.Builder token() {
        return Jwt.withTokenValue("token").header("alg", "RS256")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600));
    }

    @Test
    void tokenV2UsaOidYPreferredUsername() {
        Jwt jwt = token().subject("sub-por-app").claim("oid", "oid-1")
                .claim("preferred_username", "ana@duocuc.cl").claim("name", "Ana Pérez Soto").build();

        assertThat(EntraTokenClaims.userEntraId(jwt)).isEqualTo("oid-1");
        assertThat(EntraTokenClaims.email(jwt)).isEqualTo("ana@duocuc.cl");
        assertThat(EntraTokenClaims.givenName(jwt)).isEqualTo("Ana");
        assertThat(EntraTokenClaims.familyName(jwt)).isEqualTo("Pérez Soto");
    }

    @Test
    void tokenV1UsaOidUpnYNombresSeparados() {
        Jwt jwt = token().subject("sub-por-app").claim("oid", "oid-1").claim("upn", "ana@duocuc.cl")
                .claim("given_name", "Ana").claim("family_name", "Pérez").build();

        assertThat(EntraTokenClaims.userEntraId(jwt)).isEqualTo("oid-1");
        assertThat(EntraTokenClaims.email(jwt)).isEqualTo("ana@duocuc.cl");
        assertThat(EntraTokenClaims.givenName(jwt)).isEqualTo("Ana");
        assertThat(EntraTokenClaims.familyName(jwt)).isEqualTo("Pérez");
    }

    @Test
    void sinOidUsaSubComoRespaldo() {
        assertThat(EntraTokenClaims.userEntraId(token().subject("sub-1").build())).isEqualTo("sub-1");
    }
}
