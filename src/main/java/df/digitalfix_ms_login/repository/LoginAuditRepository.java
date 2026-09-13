package df.digitalfix_ms_login.repository;

import df.digitalfix_ms_login.entity.LoginAudit;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;


@Repository
public interface LoginAuditRepository extends JpaRepository<LoginAudit, Long>{

}
