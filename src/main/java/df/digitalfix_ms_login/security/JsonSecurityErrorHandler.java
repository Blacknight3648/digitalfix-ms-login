package df.digitalfix_ms_login.security;

import df.digitalfix_ms_login.dto.ErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.List;

// Respuestas de error de seguridad en JSON, igual que los filtros del backend
// de referencia, con el mismo formato que GlobalExceptionHandler (ErrorResponse):
//   401 -> falta el token, la firma no es válida, expiró, issuer/audience
//          incorrectos o fue emitido antes del último logout.
//   403 -> el token es válido pero no tiene el scope o el rol que pide la ruta.
@Component
@RequiredArgsConstructor
public class JsonSecurityErrorHandler implements AuthenticationEntryPoint, AccessDeniedHandler {

    private final JsonMapper jsonMapper;

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException {
        // Estándar OAuth 2.0 (RFC 6750): indica al cliente que debe enviar/renovar el Bearer token.
        response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer error=\"invalid_token\"");
        write(response, HttpStatus.UNAUTHORIZED, "Token inválido o ausente", authException.getMessage());
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException {
        write(response, HttpStatus.FORBIDDEN, "No tienes permisos para acceder a este recurso",
                "Se requiere un scope o rol que el token no incluye");
    }

    private void write(HttpServletResponse response, HttpStatus status, String message, String detail)
            throws IOException {
        ErrorResponse body = ErrorResponse.builder()
                .status(status.value())
                .message(message)
                .timestamp(LocalDateTime.now())
                .errors(List.of(detail))
                .build();

        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write(jsonMapper.writeValueAsString(body));
    }
}
