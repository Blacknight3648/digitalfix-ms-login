package df.digitalfix_ms_login.service;

import df.digitalfix_ms_login.dto.LoginAuditRequest;
import df.digitalfix_ms_login.dto.LoginAuditResponse;
import df.digitalfix_ms_login.model.LoginAudit;
import df.digitalfix_ms_login.enums.AuditEventType;
import df.digitalfix_ms_login.repository.LoginAuditRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

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

    // El LOGOUT marca el punto limpio: TokenIssuedAfterLogoutValidator rechaza
    // desde este momento cualquier token del usuario emitido antes.
    @Transactional
    public void recordLogout(String userEntraId, String ipAddress, String userAgent) {
        log.info("registrando cierre de sesion para el usuario: '{}'", userEntraId);

        LoginAudit audit = LoginAudit.builder()
                .userEntryId(userEntraId)
                .direccionIp(ipAddress)
                .event(AuditEventType.LOGOUT.toString())
                .userAgent(userAgent)
                .fechaRegistro(LocalDateTime.now())
                .build();

        auditRepository.save(audit);
    }

    @Transactional(readOnly = true)
    public List<LoginAuditResponse> findRecentEvents() {
        return auditRepository.findTop50ByOrderByFechaRegistroDesc().stream()
                .map(audit -> LoginAuditResponse.builder()
                        .id(audit.getId())
                        .userEntraId(audit.getUserEntryId())
                        .event(audit.getEvent())
                        .ipAddress(audit.getDireccionIp())
                        .failureReason(audit.getMotivoFallo())
                        .registeredAt(audit.getFechaRegistro())
                        .build())
                .toList();
    }

    @Transactional(readOnly = true)
    public Optional<LocalDateTime> findLastLogout(String userEntraId) {
        return auditRepository
                .findFirstByUserEntryIdAndEventOrderByFechaRegistroDesc(userEntraId, AuditEventType.LOGOUT.toString())
                .map(LoginAudit::getFechaRegistro);
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
