package de.adorsys.oauth.server;

import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.jacc.PolicyContext;
import javax.security.jacc.PolicyContextException;
import javax.security.jacc.PolicyContextHandler;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import io.undertow.security.api.AuthenticationMechanism;
import io.undertow.security.api.SecurityContext;
import io.undertow.server.HttpServerExchange;
import io.undertow.servlet.handlers.ServletRequestContext;
import io.undertow.util.AttachmentKey;

/**
 * DelegateAuthenticationMechanism
 */
@SuppressWarnings("unused")
public class DelegateAuthenticationMechanism implements AuthenticationMechanism, PolicyContextHandler {

    private static final Logger LOG = LoggerFactory.getLogger(DelegateAuthenticationMechanism.class);

    private static final String[] SUPPORTED_CONTEXT = {
            HttpServletRequest.class.getName(),
            HttpServletResponse.class.getName(),
            AuthorizationRequest.class.getName(),
            TokenRequest.class.getName()
    };

    private static ThreadLocal<Map<String, Object>> contextData = new ThreadLocal<Map<String, Object>>() {
        @Override
        protected Map<String, Object> initialValue() {
            return new HashMap<>();
        }
    };


    private static final AttachmentKey<AuthenticationMechanism> AUTHENTICATION_MECHANISM_ATTACHMENT_KEY = AttachmentKey.create(AuthenticationMechanism.class);

    private List<AuthenticatorMatcher> authenticatioMatchers;

    public DelegateAuthenticationMechanism(ServletContext servletContext) {
        authenticatioMatchers = new ArrayList<>();
        // insert PasswordFlowAuthenticatorMatcher first !
        authenticatioMatchers.add(new TokenEndpointMatcher());
        authenticatioMatchers.add(new RememberMeMatcher());
        authenticatioMatchers.add(new FormAuthenticationMatcher());
        authenticatioMatchers.add(new BasicAuthenticatorMatcher());
        authenticatioMatchers.add(new BearerTokenMatcher());

        for (AuthenticatorMatcher authenticatioMatcher : authenticatioMatchers) {
            authenticatioMatcher.initialize(servletContext);
        }

        for (String key : SUPPORTED_CONTEXT) {
            try {
                PolicyContext.registerHandler(key, this, false);
            } catch (Exception e) {
                LOG.debug(e.getClass().getSimpleName() + " " + e.getMessage());
            }
        }

    }

    @Override @SuppressWarnings("ReplaceAllDot")
    public AuthenticationMechanismOutcome authenticate(HttpServerExchange exchange, SecurityContext securityContext) {

        ServletRequestContext servletRequestContext = exchange.getAttachment(ServletRequestContext.ATTACHMENT_KEY);
        HttpServletRequest request = servletRequestContext.getOriginalRequest();

        HTTPRequest httpRequest = FixedServletUtils.createHTTPRequest(request);
        AuthorizationRequest authorizationRequest = resolveAuthorizationRequest(httpRequest);
        TokenRequest tokenRequest = resolveTokenRequest(httpRequest);

        store(HttpServletRequest.class.getName(), request)
                .store(HttpServletResponse.class.getName(), servletRequestContext.getOriginalResponse())
                .store(AuthorizationRequest.class.getName(), authorizationRequest)
                .store(TokenRequest.class.getName(), tokenRequest);

        try {
            for (AuthenticatorMatcher authenicatorMatcher : authenticatioMatchers) {
                if (authenicatorMatcher.match(exchange, request)) {
                    LOG.debug("use {}", authenicatorMatcher.getClass().getSimpleName());
                    exchange.putAttachment(AUTHENTICATION_MECHANISM_ATTACHMENT_KEY, authenicatorMatcher);
                    return authenicatorMatcher.authenticate(exchange, securityContext);
                }
            }
        } finally {
            for (String key : SUPPORTED_CONTEXT) {
                contextData.get().remove(key);
            }
        }

        LOG.debug("no authenicatorMatcher found for {}", exchange);
        return AuthenticationMechanismOutcome.NOT_ATTEMPTED;
    }

    @Override
    public ChallengeResult sendChallenge(HttpServerExchange exchange, SecurityContext securityContext) {
        AuthenticationMechanism authenticationMechanism = exchange.getAttachment(AUTHENTICATION_MECHANISM_ATTACHMENT_KEY);
        return authenticationMechanism == null ? new ChallengeResult(false, 401) : authenticationMechanism.sendChallenge(exchange, securityContext);

    }

    private void debugRequest(HttpServletRequest request) {
        if (!LOG.isDebugEnabled()) {
            return;
        }
        String method = request.getMethod();

        StringBuilder sb = new StringBuilder(method).append(' ');
        sb.append(request.getScheme()).append("://")
                .append(request.getServerName()).append(":")
                .append(request.getServerPort())
                .append(request.getRequestURI());

        if (method.equals("GET")) {
            sb.append(request.getQueryString());
        } else {
            Enumeration<String> parameterNames = request.getParameterNames();
            while (parameterNames.hasMoreElements()) {
                String param = parameterNames.nextElement();
                sb.append("\n ").append(param).append("=");
                String value = request.getParameter(param);
                try {
                    sb.append(URLDecoder.decode(value, "UTF-8"));
                } catch (UnsupportedEncodingException e) {
                    sb.append(value);
                }
            }
        }

        LOG.debug(sb.toString());

    }

    private DelegateAuthenticationMechanism store(String key, Object value) {
        if (value != null) {
            contextData.get().put(key, value);
        }
        return this;
    }

    private AuthorizationRequest resolveAuthorizationRequest(HTTPRequest httpRequest)  {
        try {
            return AuthorizationRequest.parse(httpRequest);
        } catch (Exception e) {
            // ignore
        }

        // sometimes during some redirections or idp chaining we get an POST with query string
        try {
            return AuthorizationRequest.parse(httpRequest.getQuery());
        } catch (Exception e) {
            // ignore
        }

        return null;
    }

    private TokenRequest resolveTokenRequest(HTTPRequest httpRequest) {
        try {
            return TokenRequest.parse(httpRequest);
        } catch (Exception e) {
            //
        }
        return null;
    }

    /// PolicyContextHandler

    @Override
    public Object getContext(String key, Object data) throws PolicyContextException {
        return contextData.get().get(key);
    }

    @Override
    public String[] getKeys() throws PolicyContextException {
        return new String[] { HttpServletRequest.class.getName(), HttpServletResponse.class.getName()};
    }

    @Override
    public boolean supports(String key) throws PolicyContextException {
        for (String supported : SUPPORTED_CONTEXT) {
            if (supported.equals(key)) {
                return true;
            }
        }
        return false;
    }
}
