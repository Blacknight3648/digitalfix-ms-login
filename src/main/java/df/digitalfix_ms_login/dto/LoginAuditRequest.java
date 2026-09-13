package df.digitalfix_ms_login.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class LoginAuditRequest {

    @NotBlank(message = "El nombre de usuario es obligatorio")
    private String username;

    @NotNull(message = "El estado de exito/fallo es obligatorio")
    private Boolean success;

    @NotBlank(message = "La direccion IP es obligatoria")
    private String ipAddress;

    private String userAgent;

    private  String failureReason;

}
