package de.adorsys.oauth.undertow;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;

import java.util.Collections;

import io.undertow.security.api.AuthenticationMechanism;
import io.undertow.security.api.SecurityContext;
import io.undertow.security.impl.BasicAuthenticationMechanism;
import io.undertow.server.HttpServerExchange;

/**
 * PasswordCredentialFlowAuthenticatorMatcher
 */
@SuppressWarnings("unused")
public class BasicAuthenticatorMatcher implements AuthenicatorMatcher {

    private static final Logger LOG = LoggerFactory.getLogger(BasicAuthenticatorMatcher.class);

    private AuthenticationMechanism baseAuthenticationMechanism;

    @Override
    public void initialize(ServletContext servletContext) {
        baseAuthenticationMechanism = new BasicAuthenticationMechanism(servletContext.getServletContextName(), "BASIC");
    }

    @Override
    public AuthenticationMechanismOutcome authenticate(HttpServerExchange exchange, SecurityContext securityContext) {
        return baseAuthenticationMechanism.authenticate(exchange, securityContext);
    }

    @Override
    public ChallengeResult sendChallenge(HttpServerExchange exchange, SecurityContext securityContext) {
        return baseAuthenticationMechanism.sendChallenge(exchange, securityContext);
    }

    @Override
    public boolean match(HttpServerExchange exchange, HttpServletRequest request) {
        for (String name : Collections.list(request.getHeaderNames())) {
            if ("authorization".equalsIgnoreCase(name)) {
                return request.getHeader(name).substring(0, 5).equalsIgnoreCase("Basic");
            }
        }

        return false;
    }
}
