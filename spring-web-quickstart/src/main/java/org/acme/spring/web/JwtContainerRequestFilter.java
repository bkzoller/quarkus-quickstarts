package org.acme.spring.web;

import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import io.quarkus.security.runtime.QuarkusPrincipal;

import javax.enterprise.context.ApplicationScoped;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.PreMatching;
import javax.ws.rs.core.Cookie;
import javax.ws.rs.ext.Provider;
import java.security.Principal;
import java.util.Optional;

import static org.springframework.http.HttpHeaders.*;

@Provider
@PreMatching
@ApplicationScoped
public class JwtContainerRequestFilter implements ContainerRequestFilter {

    private static final String BEARER_PREFIX = "Bearer ";
    private static final String COOKIE_NAME = "JWTCookie";
    private static final String USER_CLAIM_KEY = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name";
    private static final JwtSecurityContext EMPTY_SECURITY_CONTEXT = new JwtSecurityContext(null, null);

    @Override
    public void filter(ContainerRequestContext requestContext) {
        try {
            setAuthentication(requestContext);
        } catch (TokenExpiredException e) {
            requestContext.setSecurityContext(EMPTY_SECURITY_CONTEXT);
        }
    }

    private Optional<String> fromHeader(ContainerRequestContext requestContext) {
        String header = requestContext.getHeaderString(AUTHORIZATION);

        if (authorizationIsBearerToken(header)) {
            return Optional.of(header.substring(BEARER_PREFIX.length()));
        }
        return Optional.empty();
    }

    private String fromCookie(ContainerRequestContext requestContext) {
        return requestContext.getCookies()
                .entrySet().stream()
                .filter(entry -> entry.getKey().equals(COOKIE_NAME))
                .findFirst()
                .map(Entry::getValue)
                .map(Cookie::getValue)
                .orElse(null);
    }

    private boolean authorizationIsBearerToken(String header) {
        return header != null && header.startsWith(BEARER_PREFIX);
    }

    private void setAuthentication(ContainerRequestContext requestContext) {
        String token = fromHeader(requestContext).orElse(fromCookie(requestContext));
        if (token == null) {
            requestContext.setSecurityContext(EMPTY_SECURITY_CONTEXT);
        } else {
            DecodedJWT decoded;
            try {
                decoded = JWT.decode(token);
            } catch (JWTDecodeException | IllegalArgumentException e) {
                requestContext.setSecurityContext(EMPTY_SECURITY_CONTEXT);
                return;
            }

            String user = decoded.getClaim(USER_CLAIM_KEY).asString();
            Principal principal = new QuarkusPrincipal(user);
            requestContext.setSecurityContext(new JwtSecurityContext(token, principal));
        }
    }
}
