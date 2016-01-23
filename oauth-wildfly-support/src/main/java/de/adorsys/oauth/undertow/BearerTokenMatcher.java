package de.adorsys.oauth.undertow;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;

import io.undertow.security.api.SecurityContext;
import io.undertow.server.HttpServerExchange;

/**
 * BearerTokenMatcher
 */
public class BearerTokenMatcher implements AuthenicatorMatcher {

    @Override
    public void initialize(ServletContext servletContext) {

    }

    @Override
    public boolean match(HttpServerExchange exchange, HttpServletRequest request) {
        String authorization = request.getHeader("Authorization");
        if (authorization == null) {
            authorization = request.getHeader("authorization");
        }
        return authorization != null && authorization.startsWith("Bearer");
    }

    @Override
    public AuthenticationMechanismOutcome authenticate(HttpServerExchange exchange, SecurityContext securityContext) {
        // real token validation is done in the endpoint
        return AuthenticationMechanismOutcome.AUTHENTICATED;
    }

    @Override
    public ChallengeResult sendChallenge(HttpServerExchange exchange, SecurityContext securityContext) {
        return new ChallengeResult(false);
    }
}
