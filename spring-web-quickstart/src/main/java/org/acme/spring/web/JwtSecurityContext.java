package org.acme.spring.web;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;

import javax.ws.rs.core.SecurityContext;
import java.security.Principal;

@Getter
@EqualsAndHashCode
@ToString
public class JwtSecurityContext implements SecurityContext {

    private final String jwtToken;
    private final Principal principal;

    JwtSecurityContext(String jwtToken, Principal principal) {
        this.jwtToken = jwtToken;
        this.principal = principal;
    }

    @Override
    public Principal getUserPrincipal() {
        return principal;
    }

    @Override
    public boolean isUserInRole(String role) {
        return true;
    }

    @Override
    public boolean isSecure() {
        return false;
    }

    @Override
    public String getAuthenticationScheme() {
        return BASIC_AUTH;
    }
}
