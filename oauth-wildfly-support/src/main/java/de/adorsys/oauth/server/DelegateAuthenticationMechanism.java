package de.adorsys.oauth.server;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;

import java.util.ArrayList;
import java.util.List;

import io.undertow.security.api.AuthenticationMechanism;
import io.undertow.security.api.SecurityContext;
import io.undertow.server.HttpServerExchange;
import io.undertow.servlet.handlers.ServletRequestContext;
import io.undertow.util.AttachmentKey;

/**
 * DelegateAuthenticationMechanism
 */
@SuppressWarnings("unused")
public class DelegateAuthenticationMechanism implements AuthenticationMechanism {

    private static final Logger LOG = LoggerFactory.getLogger(DelegateAuthenticationMechanism.class);

    private static final AttachmentKey<AuthenticationMechanism> AUTHENTICATION_MECHANISM_ATTACHMENT_KEY = AttachmentKey.create(AuthenticationMechanism.class);

    private List<AuthenticatorMatcher> authenticatioMatchers;

    public DelegateAuthenticationMechanism(ServletContext servletContext) {
        authenticatioMatchers = new ArrayList<>();
        // insert PasswordFlowAuthenticatorMatcher first !
        authenticatioMatchers.add(new PasswordFlowAuthenticatorMatcher());
        authenticatioMatchers.add(new BasicAuthenticatorMatcher());
        authenticatioMatchers.add(new BearerTokenMatcher());

        for (AuthenticatorMatcher authenticatioMatcher : authenticatioMatchers) {
            authenticatioMatcher.initialize(servletContext);
        }
    }

    @Override @SuppressWarnings("ReplaceAllDot")
    public AuthenticationMechanismOutcome authenticate(HttpServerExchange exchange, SecurityContext securityContext) {

        ServletRequestContext servletRequestContext = exchange.getAttachment(ServletRequestContext.ATTACHMENT_KEY);
        HttpServletRequest request = servletRequestContext.getOriginalRequest();

        for (AuthenticatorMatcher authenicatorMatcher : authenticatioMatchers) {
            if (authenicatorMatcher.match(exchange, request)) {
                LOG.debug("use {}", authenicatorMatcher.getClass().getSimpleName());
                exchange.putAttachment(AUTHENTICATION_MECHANISM_ATTACHMENT_KEY, authenicatorMatcher);
                return authenicatorMatcher.authenticate(exchange, securityContext);
            }
        }

        LOG.debug("no authenicatorMatcher found for {}", exchange);
        return AuthenticationMechanismOutcome.NOT_AUTHENTICATED;
    }

    @Override
    public ChallengeResult sendChallenge(HttpServerExchange exchange, SecurityContext securityContext) {
        AuthenticationMechanism authenticationMechanism = exchange.getAttachment(AUTHENTICATION_MECHANISM_ATTACHMENT_KEY);
        return authenticationMechanism == null ? new ChallengeResult(false, 401) : authenticationMechanism.sendChallenge(exchange, securityContext);

    }


}
