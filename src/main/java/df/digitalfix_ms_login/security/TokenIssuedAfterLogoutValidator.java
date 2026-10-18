package df.digitalfix_ms_login.security;

import df.digitalfix_ms_login.service.LoginAuditSevice;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

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

    private final LoginAuditSevice auditSevice;

    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        String userEntraId = EntraTokenClaims.userEntraId(jwt);
        Instant issuedAt = jwt.getIssuedAt();
        if (userEntraId == null || issuedAt == null) {
            return OAuth2TokenValidatorResult.success();
        }

        // "iat" viene en segundos: se trunca el logout al segundo para no
        // rechazar un token emitido en el mismo segundo del nuevo login.
        boolean issuedBeforeLogout = auditSevice.findLastLogout(userEntraId)
                .map(logoutAt -> logoutAt.atZone(ZoneId.systemDefault()).toInstant().truncatedTo(ChronoUnit.SECONDS))
                .map(issuedAt::isBefore)
                .orElse(false);

        return issuedBeforeLogout
                ? OAuth2TokenValidatorResult.failure(TOKEN_BEFORE_LOGOUT)
                : OAuth2TokenValidatorResult.success();
    }
}
