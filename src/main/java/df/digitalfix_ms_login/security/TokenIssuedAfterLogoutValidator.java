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
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;

@Slf4j
@Component
@RequiredArgsConstructor
public class TokenIssuedAfterLogoutValidator implements OAuth2TokenValidator<Jwt> {

    private static final OAuth2Error TOKEN_BEFORE_LOGOUT = new OAuth2Error(
            OAuth2ErrorCodes.INVALID_TOKEN,
            "El token fue emitido antes del ultimo cierre de sesion; inicia sesion nuevamente.",
            null);

    // Pequeño margen de tolerancia de reloj (clock skew), no 5 minutos hacia
    // adelante
    private static final Duration CLOCK_SKEW = Duration.ofSeconds(30);

    private final LoginAuditSevice auditSevice;

    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        String userEntraId = EntraTokenClaims.userEntraId(jwt);
        Instant issuedAt = jwt.getIssuedAt();
        if (userEntraId == null || issuedAt == null) {
            return OAuth2TokenValidatorResult.success();
        }

        // Si el logout se guarda en UTC (lo estándar en backend/BD), convertimos a
        // Instant en UTC.
        // Si tu BD guarda en hora local de Chile, cambia ZoneOffset.UTC por
        // ZoneId.of("America/Santiago").
        Instant effectiveIssuedAt = issuedAt.plus(CLOCK_SKEW);
        boolean issuedBeforeLogout = auditSevice.findLastLogout(userEntraId)
                .map(logoutAt -> logoutAt.toInstant(ZoneOffset.UTC).truncatedTo(ChronoUnit.SECONDS))
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