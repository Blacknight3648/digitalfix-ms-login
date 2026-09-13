package df.digitalfix_ms_login.dto;

import lombok.*;

import java.time.LocalDateTime;
import java.util.List;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor

public class ErrorResponse {

    private int status;
    private String message;
    private LocalDateTime timestamp;
    private List<String> errors;

}
