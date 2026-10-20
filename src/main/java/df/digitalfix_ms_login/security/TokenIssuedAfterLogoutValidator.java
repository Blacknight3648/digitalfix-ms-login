package df.digitalfix_ms_login.security;

import df.digitalfix_ms_login.service.LoginAuditSevice;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;

// Un access token de Entra ID sigue siendo válido hasta que expira (~1 hora),
// aunque el usuario ya haya cerrado sesión. Este validador obliga a partir
// desde un punto limpio: tras un LOGOUT registrado, solo se aceptan tokens
// emitidos después, es decir, obtenidos con un nuevo inicio de sesión.
@Component
@RequiredArgsConstructor
public class TokenIssuedAfterLogoutValidator implements OAuth2TokenValidator<Jwt> {

    private static final OAuth2Error TOKEN_BEFORE_LOGOUT = new OAuth2Error(
            OAuth2ErrorCodes.INVALID_TOKEN,
            "El token fue emitido antes del ultimo cierre de sesion; inicia sesion nuevamente.",
            null);

    private static final Duration ENTRA_IAT_BACKDATE = Duration.ofMinutes(5);

    private final LoginAuditSevice auditSevice;

    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        String userEntraId = EntraTokenClaims.userEntraId(jwt);
        Instant issuedAt = jwt.getIssuedAt();
        if (userEntraId == null || issuedAt == null) {
            return OAuth2TokenValidatorResult.success();
        }

        // Entra ID emite "iat" con ENTRA_IAT_BACKDATE de atraso (margen de reloj),
        // así que se compara la hora real de emisión. Sin esto, un login hecho
        // pocos minutos después del logout queda rechazado (401) y el usuario
        // entra sin su rol. "iat" viene en segundos: el logout se trunca al segundo.
        Instant realIssuedAt = issuedAt.plus(ENTRA_IAT_BACKDATE);
        boolean issuedBeforeLogout = auditSevice.findLastLogout(userEntraId)
                .map(logoutAt -> logoutAt.atZone(ZoneId.systemDefault()).toInstant().truncatedTo(ChronoUnit.SECONDS))
                .map(realIssuedAt::isBefore)
                .orElse(false);

        return issuedBeforeLogout
                ? OAuth2TokenValidatorResult.failure(TOKEN_BEFORE_LOGOUT)
                : OAuth2TokenValidatorResult.success();
    }
}
