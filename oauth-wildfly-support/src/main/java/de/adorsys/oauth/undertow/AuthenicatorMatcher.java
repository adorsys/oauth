package de.adorsys.oauth.undertow;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;

import io.undertow.security.api.AuthenticationMechanism;
import io.undertow.server.HttpServerExchange;

/**
 * AuthenicatorMatcher
 */
public interface AuthenicatorMatcher extends AuthenticationMechanism {

    void initialize(ServletContext servletContext);

    boolean match(HttpServerExchange exchange, HttpServletRequest request);
}
