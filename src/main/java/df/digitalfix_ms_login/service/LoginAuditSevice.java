package df.digitalfix_ms_login.service;

import df.digitalfix_ms_login.dto.LoginAuditRequest;
import df.digitalfix_ms_login.entity.LoginAudit;
import df.digitalfix_ms_login.enums.AuditEventType;
import df.digitalfix_ms_login.repository.LoginAuditRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Locale;

@Slf4j
@Service
@RequiredArgsConstructor
public class LoginAuditSevice {

    private final LoginAuditRepository auditRepository;

    @Transactional
    public void recordLoginAttempt(LoginAuditRequest request) {
        log.info("registrando intento de autenticacion para el usuario: '{}' - Exito: '{}'", request.getUsername(), request.getSuccess());

        String evento = resolverTipoEvento(request);

        LoginAudit audit= LoginAudit.builder()
                .userEntryId(request.getUsername())
                .direccionIp(request.getIpAddress())
                .event(evento)
                .userAgent(request.getUserAgent())
                .motivoFallo(request.getFailureReason())
                .build();

        auditRepository.save(audit);
        log.debug("Evento de auditoria guardado con exito en la base de datos.");
    }

    private String resolverTipoEvento(LoginAuditRequest request) {

        if (Boolean.TRUE.equals(request.getSuccess())) {
            return AuditEventType.LOGIN_SUCCESS.toString();
        }
        String motivo = request.getFailureReason();

        if (motivo != null && motivo.toLowerCase().contains("bloqueada")) {
            return AuditEventType.ACCOUNT_BLOCKED.toString();

        }

        return AuditEventType.LOGIN_FAILURE.toString();

    }

}
