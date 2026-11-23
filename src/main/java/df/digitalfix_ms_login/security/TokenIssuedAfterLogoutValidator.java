package df.digitalfix_ms_login.security;

import df.digitalfix_ms_login.service.LoginAuditSevice;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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

@Slf4j
@Component
@RequiredArgsConstructor
public class TokenIssuedAfterLogoutValidator implements OAuth2TokenValidator<Jwt> {

    private static final OAuth2Error TOKEN_BEFORE_LOGOUT = new OAuth2Error(
            OAuth2ErrorCodes.INVALID_TOKEN,
            "El token fue emitido antes del ultimo cierre de sesion; inicia sesion nuevamente.",
            null);

    // Entra ID emite "iat" (y "nbf") con 5 minutos de atraso respecto de la hora
    // real de emisión. Sin compensarlo, un login hecho menos de 5 minutos después
    // del logout se rechaza con 401 y el usuario entra sin su rol (ej. SUPERADMIN).
    private static final Duration ENTRA_IAT_BACKDATE = Duration.ofMinutes(5);

    private final LoginAuditSevice auditSevice;

    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        String userEntraId = EntraTokenClaims.userEntraId(jwt);
        Instant issuedAt = jwt.getIssuedAt();
        if (userEntraId == null || issuedAt == null) {
            return OAuth2TokenValidatorResult.success();
        }

        // El logout se guarda con LocalDateTime.now() (zona del JVM), así que se
        // interpreta con esa misma zona; usar UTC lo desplaza 3 horas en Chile.
        Instant effectiveIssuedAt = issuedAt.plus(ENTRA_IAT_BACKDATE);
        boolean issuedBeforeLogout = auditSevice.findLastLogout(userEntraId)
                .map(logoutAt -> logoutAt.atZone(ZoneId.systemDefault()).toInstant().truncatedTo(ChronoUnit.SECONDS))
                .map(logoutInstant -> {
                    boolean before = effectiveIssuedAt.isBefore(logoutInstant);
                    if (before) {
                        log.debug("Token rechazado por logout previo: user={}, issuedAt={}, logoutAt={}",
                                userEntraId, issuedAt, logoutInstant);
                    }
                    return before;
                })
                .orElse(false);

        return issuedBeforeLogout
                ? OAuth2TokenValidatorResult.failure(TOKEN_BEFORE_LOGOUT)
                : OAuth2TokenValidatorResult.success();
    }
}