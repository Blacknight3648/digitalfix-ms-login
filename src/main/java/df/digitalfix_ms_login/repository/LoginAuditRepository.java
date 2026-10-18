package df.digitalfix_ms_login.repository;

import df.digitalfix_ms_login.model.LoginAudit;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;


@Repository
public interface LoginAuditRepository extends JpaRepository<LoginAudit, Long>{

    // Último evento de un tipo para el usuario (usa IDX_AUDITORIA_USER).
    Optional<LoginAudit> findFirstByUserEntryIdAndEventOrderByFechaRegistroDesc(String userEntryId, String event);

    List<LoginAudit> findTop50ByOrderByFechaRegistroDesc();

}
