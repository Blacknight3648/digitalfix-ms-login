package df.digitalfix_ms_login.controller;


import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/login")
public class LoginController {

    @GetMapping("/status")
    @PreAuthorize("hasAuthority('SCP_Auth.Access')")
    public ResponseEntity<String> checkStatus() {

        return ResponseEntity.ok("Autenticación exitosa. \n Bienvenido a digitalfix");

    }

}
