package df.digitalfix_ms_login.controller;


import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/v1/login")
public class LoginController {

    @GetMapping("/status")
    // El scope expuesto en Azure AD (App Registration de la API > Expose an
    // API) se llama "access_as_user" (el nombre por defecto que sugiere
    // Azure). SecurityConfig mapea el claim "scp" del token con prefijo
    // "SCP_", por eso se valida como "SCP_access_as_user".
    @PreAuthorize("hasAuthority('SCP_access_as_user')")
    public ResponseEntity<String> checkStatus() {

        return ResponseEntity.ok("Autenticación exitosa. \n Bienvenido a digitalfix");

    }

}
