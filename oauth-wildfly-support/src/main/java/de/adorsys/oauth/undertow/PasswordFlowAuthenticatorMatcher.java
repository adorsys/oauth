package de.adorsys.oauth.undertow;

import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ResourceOwnerPasswordCredentialsGrant;
import com.nimbusds.oauth2.sdk.TokenRequest;

import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;

import io.undertow.security.api.SecurityContext;
import io.undertow.security.idm.Account;
import io.undertow.security.idm.IdentityManager;
import io.undertow.security.idm.PasswordCredential;
import io.undertow.server.HttpServerExchange;
import io.undertow.servlet.handlers.ServletRequestContext;
import io.undertow.util.AttachmentKey;

/**
 * PasswordCredentialFlowAuthenticatorMatcher
 */
@SuppressWarnings("unused")
public class PasswordFlowAuthenticatorMatcher implements AuthenicatorMatcher {

    private static final Logger LOG = LoggerFactory.getLogger(PasswordFlowAuthenticatorMatcher.class);

    private static final AttachmentKey<TokenRequest> TOKEN_REQUEST_ATTACHMENT_KEY = AttachmentKey.create(TokenRequest.class);

    private String clientSecurityDomain;
    private String mechanismName;

    @Override @SuppressWarnings("ReplaceAllDot")
    public AuthenticationMechanismOutcome authenticate(HttpServerExchange exchange, SecurityContext securityContext) {

        ServletRequestContext servletRequestContext = exchange.getAttachment(ServletRequestContext.ATTACHMENT_KEY);
        HttpServletRequest request = servletRequestContext.getOriginalRequest();
        HttpServletResponse response = servletRequestContext.getOriginalResponse();

        TokenRequest tokenRequest = exchange.getAttachment(TOKEN_REQUEST_ATTACHMENT_KEY);
        if (tokenRequest == null) {
            return AuthenticationMechanismOutcome.NOT_ATTEMPTED;
        }

        AuthorizationGrant authorizationGrant = tokenRequest.getAuthorizationGrant();
        if (authorizationGrant.getType() != GrantType.PASSWORD) {
            return AuthenticationMechanismOutcome.NOT_ATTEMPTED;
        }

        if (!verifyClientCredentials(request)) try {
            response.setStatus(403);
            response.getWriter().write("client authentification failed");
            return AuthenticationMechanismOutcome.NOT_ATTEMPTED;
        } catch (Exception e) {
            // ignore
        }

        ResourceOwnerPasswordCredentialsGrant grant = (ResourceOwnerPasswordCredentialsGrant) authorizationGrant;
        String userName = grant.getUsername();
        String password = grant.getPassword().getValue() == null ? "" : grant.getPassword().getValue();

        LOG.debug("PasswordFlow - login {} {}", userName, password.replaceAll(".", "x"));

        IdentityManager identityManager = securityContext.getIdentityManager();

        Account account = identityManager.verify(userName, new PasswordCredential(password.toCharArray()));
        if (account == null) {
            return AuthenticationMechanismOutcome.NOT_AUTHENTICATED;
        }

        securityContext.authenticationComplete(account, mechanismName, true); // cachingRequired ???
        return AuthenticationMechanismOutcome.AUTHENTICATED;
    }

    @Override
    public ChallengeResult sendChallenge(HttpServerExchange exchange, SecurityContext securityContext) {
        return new ChallengeResult(true, 401);
    }

    /**
     * Check client credentials
     * We expect the credentials as BASIC-Auth header
     */
    @SuppressWarnings("Duplicates")
    private boolean verifyClientCredentials(HttpServletRequest httpRequest) {

        if (clientSecurityDomain == null) {
            // ignore auth if no security domain is configured
            return true;
        }

        String authValue = httpRequest.getHeader("Authorization");
        if (authValue == null || !authValue.startsWith("Basic ")) {
            return false;
        }

        String encodedValue = authValue.substring(6);
        String decodedValue= new String(Base64.decodeBase64(encodedValue));
        final String[] namePassword = decodedValue.contains(":") ? decodedValue.split(":") : new String[] { decodedValue, "" };

        CallbackHandler callbackHandler = new CallbackHandler() {
            @Override
            public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                for (Callback callback : callbacks) {
                    if (callback instanceof NameCallback) {
                        ((NameCallback) callback).setName(namePassword[0]);
                        continue;
                    }
                    if (callback instanceof PasswordCallback) {
                        ((PasswordCallback) callback).setPassword(namePassword[1].toCharArray());
                    }
                }
            }
        };

        Subject subject = new Subject();
        try {
            LoginContext loginContext = new LoginContext(clientSecurityDomain, subject, callbackHandler);
            loginContext.login();
            loginContext.logout();
        } catch (LoginException e) {
            LOG.error("call securitydomain " + callbackHandler, e);
            return false;
        }

        return true;

    }

    /**
     * resolveTokenRequest
     */
    private TokenRequest resolveTokenRequest(HttpServletRequest httpRequest) {
        try {
            return TokenRequest.parse(FixedServletUtils.createHTTPRequest(httpRequest));
        } catch (Exception e) {
            // ignore
        }
        return null;
    }


    @Override
    public void initialize(ServletContext servletContext) {
        clientSecurityDomain = servletContext.getInitParameter("clientSecurityDomain");
        mechanismName = "OAUTH_PASSWORD";
    }

    @Override
    public boolean match(HttpServerExchange exchange, HttpServletRequest request) {
        TokenRequest tokenRequest = resolveTokenRequest(request);
        if (tokenRequest == null) {
            return false;
        }

        exchange.putAttachment(TOKEN_REQUEST_ATTACHMENT_KEY, tokenRequest);
        return true;
    }
}
