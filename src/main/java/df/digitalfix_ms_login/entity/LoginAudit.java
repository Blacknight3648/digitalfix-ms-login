package df.digitalfix_ms_login.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "LOG_AUDITORIA_ACCESO")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class LoginAudit {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "USER_ENTRA_ID", nullable = false, length = 100)
    private String userEntryId;

    @Column(name = "EVENTO", nullable = false, length = 50)
    private String event;

    @Column(name = "DIRECCION_IP", length = 45)
    private String direccionIp;

    @Column(name = "USER_AGENT", length = 500)
    private String userAgent;

    @Column(name = "MOTIVO_FALLO")
    private String motivoFallo;

    @Column(name = "FECHA_REGISTRO", nullable = false, updatable = false)
    private LocalDateTime fechaRegistro;

    @PrePersist
    public void prePersist() {
        if(this.fechaRegistro == null) {
            this.fechaRegistro = LocalDateTime.now();
        }
    }

}
