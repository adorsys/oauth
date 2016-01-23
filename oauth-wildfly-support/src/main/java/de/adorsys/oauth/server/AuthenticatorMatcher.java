package de.adorsys.oauth.server;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;

import io.undertow.security.api.AuthenticationMechanism;
import io.undertow.server.HttpServerExchange;

/**
 * AuthenicatorMatcher
 */
public interface AuthenticatorMatcher extends AuthenticationMechanism {

    void initialize(ServletContext servletContext);

    boolean match(HttpServerExchange exchange, HttpServletRequest request);
}
