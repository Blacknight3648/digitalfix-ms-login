package df.digitalfix_ms_login.security;

import df.digitalfix_ms_login.service.UserRoleClient;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

@Slf4j
@Component
@RequiredArgsConstructor
public class EntraJwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private final UserRoleClient userRoleClient;

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        Set<GrantedAuthority> authorities = new LinkedHashSet<>();

        String scopes = jwt.getClaimAsString("scp");
        if (scopes != null) {
            for (String scope : scopes.split(" ")) {
                if (!scope.isBlank()) {
                    authorities.add(new SimpleGrantedAuthority("SCOPE_" + scope));
                }
            }
        }

        List<String> tokenRoles = jwt.getClaimAsStringList("roles");
        if (tokenRoles != null) {
            tokenRoles.forEach(role -> authorities.add(toRoleAuthority(role)));
        }

        String userEntraId = EntraTokenClaims.userEntraId(jwt);
        if (userEntraId != null) {
            try {
                userRoleClient.findRoleCode(userEntraId, jwt.getTokenValue())
                        .ifPresent(role -> authorities.add(toRoleAuthority(role)));
            } catch (Exception ex) {
                log.warn("No se pudo consultar el rol en ms-user para {}: {}", userEntraId, ex.getMessage());
            }
        }

        return new JwtAuthenticationToken(jwt, authorities, userEntraId);
    }

    public static List<String> rolesOf(Collection<? extends GrantedAuthority> authorities) {
        return authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .filter(authority -> authority.startsWith("ROLE_"))
                .map(authority -> authority.substring("ROLE_".length()))
                .toList();
    }

    public static List<String> scopesOf(Collection<? extends GrantedAuthority> authorities) {
        return authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .filter(authority -> authority.startsWith("SCOPE_"))
                .map(authority -> authority.substring("SCOPE_".length()))
                .toList();
    }

    private static GrantedAuthority toRoleAuthority(String role) {
        return new SimpleGrantedAuthority("ROLE_" + role.toUpperCase());
    }
}