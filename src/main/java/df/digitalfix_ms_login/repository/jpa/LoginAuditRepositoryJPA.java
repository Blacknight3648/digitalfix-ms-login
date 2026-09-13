package df.digitalfix_ms_login.repository.jpa;

import df.digitalfix_ms_login.entity.LoginAuditJPA;
import org.springframework.stereotype.Repository;
import org.springframework.data.jpa.repository.JpaRepository;


@Repository
public interface LoginAuditRepositoryJPA extends JpaRepository<LoginAuditJPA, Long>{

}
