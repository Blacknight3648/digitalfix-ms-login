package df.digitalfix_ms_login.service;

import df.digitalfix_ms_login.dto.LoginAuditRequest;
import df.digitalfix_ms_login.entity.LoginAudit;
import df.digitalfix_ms_login.repository.LoginAuditRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class LoginAuditSevice {

    private final LoginAuditRepository auditRepository;

    @Transactional
    public void recordLoginAttempt(LoginAuditRequest request) {
        log.info("registrando intento de autenticacion para el usuario: '{}' - Exito: '{}'", request.getUsername(), request.getSuccess());

        String evento = Boolean.TRUE.equals(request.getSuccess()) ? "Login exitoso" : "Login fallido";

        LoginAudit audit= LoginAudit.builder()
                .userEntryId(request.getUsername())
                .direccionIp(request.getIpAddress())
                .userAgent(request.getUserAgent())
                .motivoFallo(request.getFailureReason())
                .build();

        auditRepository.save(audit);
        log.debug("Evento de auditoria guardado con exito en la base de datos.");
    }

}
