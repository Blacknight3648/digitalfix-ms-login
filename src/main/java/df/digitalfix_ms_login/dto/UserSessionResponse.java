package df.digitalfix_ms_login.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.util.List;

// Sesión del usuario según el JWT validado: identidad, roles y scopes ya
// resueltos por EntraJwtAuthenticationConverter. El frontend la usa para armar
// el menú y las vistas por rol.
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserSessionResponse {
    private String userEntraId;
    private String email;
    private String name;
    private List<String> roles;
    private List<String> scopes;
    private Instant tokenExpiresAt;
}
