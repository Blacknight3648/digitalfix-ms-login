package df.digitalfix_ms_login.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LoginAuditResponse {
    private Long id;
    private String userEntraId;
    private String event;
    private String ipAddress;
    private String failureReason;
    private LocalDateTime registeredAt;
}
