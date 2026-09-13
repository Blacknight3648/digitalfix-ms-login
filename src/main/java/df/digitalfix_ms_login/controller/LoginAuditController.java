package df.digitalfix_ms_login.controller;

import df.digitalfix_ms_login.dto.LoginAuditRequest;
import df.digitalfix_ms_login.service.LoginAuditSevice;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("api/v1/audit")
@RequiredArgsConstructor
public class LoginAuditController {

    private final LoginAuditSevice auditSevice;

    @PostMapping("/login")
    public ResponseEntity<Void> registerLogin(@Valid @RequestBody LoginAuditRequest request) {
        auditSevice.recordLoginAttempt(request);
        return ResponseEntity.status(HttpStatus.CREATED).build();

    }

}
