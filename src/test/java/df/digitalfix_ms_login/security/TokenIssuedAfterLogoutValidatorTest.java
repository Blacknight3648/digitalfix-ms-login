package df.digitalfix_ms_login.security;

import df.digitalfix_ms_login.service.LoginAuditSevice;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class TokenIssuedAfterLogoutValidatorTest {

    private static final String OID = "11111111-2222-3333-4444-555555555555";
    // Entra ID emite "iat" 5 minutos en el pasado (margen de reloj).
    private static final long ENTRA_BACKDATE_SECONDS = 300;

    private final LoginAuditSevice auditSevice = mock(LoginAuditSevice.class);
    private final TokenIssuedAfterLogoutValidator validator = new TokenIssuedAfterLogoutValidator(auditSevice);

    private static Jwt tokenIssuedAt(Instant issuedAt) {
        return Jwt.withTokenValue("token")
                .header("alg", "none")
                .claim("oid", OID)
                .issuedAt(issuedAt)
                .expiresAt(issuedAt.plusSeconds(3600))
                .build();
    }

    private static LocalDateTime toLocal(Instant instant) {
        return LocalDateTime.ofInstant(instant, ZoneId.systemDefault());
    }

    @Test
    void aceptaTokenSiElUsuarioNuncaCerroSesion() {
        when(auditSevice.findLastLogout(OID)).thenReturn(Optional.empty());

        assertFalse(validator.validate(tokenIssuedAt(Instant.now())).hasErrors());
    }

    @Test
    void rechazaTokenEmitidoAntesDelUltimoLogout() {
        Instant logoutAt = Instant.now();
        when(auditSevice.findLastLogout(OID)).thenReturn(Optional.of(toLocal(logoutAt)));

        // Emitido en realidad 60 s antes del logout.
        Instant iat = logoutAt.minusSeconds(60 + ENTRA_BACKDATE_SECONDS);
        assertTrue(validator.validate(tokenIssuedAt(iat)).hasErrors());
    }

    @Test
    void aceptaNuevoLoginPocosMinutosDespuesDelLogoutAunqueEntraAtraseElIat() {
        // Login real 60 s después del logout: su "iat" queda 4 min antes del logout.
        Instant logoutAt = Instant.parse("2026-10-20T19:15:14Z");
        when(auditSevice.findLastLogout(OID)).thenReturn(Optional.of(toLocal(logoutAt)));

        Instant iat = logoutAt.plusSeconds(60 - ENTRA_BACKDATE_SECONDS);
        assertFalse(validator.validate(tokenIssuedAt(iat)).hasErrors());
    }

    @Test
    void aceptaTokenDeUnNuevoLoginPosteriorAlLogout() {
        Instant logoutAt = Instant.now().minusSeconds(120);
        when(auditSevice.findLastLogout(OID)).thenReturn(Optional.of(toLocal(logoutAt)));

        assertFalse(validator.validate(tokenIssuedAt(Instant.now())).hasErrors());
    }

    @Test
    void aceptaTokenEmitidoEnElMismoSegundoDelLogout() {
        // "iat" no tiene milisegundos: un login en el mismo segundo no debe rechazarse.
        Instant logoutAt = Instant.parse("2026-10-18T19:00:00.750Z");
        when(auditSevice.findLastLogout(OID)).thenReturn(Optional.of(toLocal(logoutAt)));

        assertFalse(validator.validate(tokenIssuedAt(Instant.parse("2026-10-18T19:00:00Z"))).hasErrors());
    }
}
