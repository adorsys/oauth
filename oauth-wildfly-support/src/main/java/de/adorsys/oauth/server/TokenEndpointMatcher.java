package de.adorsys.oauth.server;

import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ResourceOwnerPasswordCredentialsGrant;
import com.nimbusds.oauth2.sdk.TokenRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.jacc.PolicyContext;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import io.undertow.security.api.SecurityContext;
import io.undertow.security.idm.Account;
import io.undertow.security.idm.IdentityManager;
import io.undertow.security.idm.PasswordCredential;
import io.undertow.server.HttpServerExchange;
import io.undertow.servlet.handlers.ServletRequestContext;

/**
 * TokenEndpointMatcher
 */
@SuppressWarnings("unused")
public class TokenEndpointMatcher implements AuthenticatorMatcher {

    private static final Logger LOG = LoggerFactory.getLogger(TokenEndpointMatcher.class);

    @Override @SuppressWarnings("ReplaceAllDot")
    public AuthenticationMechanismOutcome authenticate(HttpServerExchange exchange, SecurityContext securityContext) {

        ServletRequestContext servletRequestContext = exchange.getAttachment(ServletRequestContext.ATTACHMENT_KEY);
        HttpServletRequest request = servletRequestContext.getOriginalRequest();
        HttpServletResponse response = servletRequestContext.getOriginalResponse();

        TokenRequest tokenRequest = resolveTokenRequest();
        if (tokenRequest == null) {
            return AuthenticationMechanismOutcome.NOT_ATTEMPTED;
        }

        AuthorizationGrant authorizationGrant = tokenRequest.getAuthorizationGrant();

        // authorize auth code and refresh token request
        if (authorizationGrant.getType() == GrantType.AUTHORIZATION_CODE || authorizationGrant.getType() == GrantType.REFRESH_TOKEN) {
            securityContext.authenticationComplete(OAuhtAccount.INSTANCE, OAuthServletExtension.MECHANISM_NAME, false);
            return AuthenticationMechanismOutcome.AUTHENTICATED;
        }

        if (authorizationGrant.getType() != GrantType.PASSWORD) {
            return AuthenticationMechanismOutcome.NOT_ATTEMPTED;
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

        securityContext.authenticationComplete(account, OAuthServletExtension.MECHANISM_NAME, false);
        return AuthenticationMechanismOutcome.AUTHENTICATED;
    }

    @Override
    public ChallengeResult sendChallenge(HttpServerExchange exchange, SecurityContext securityContext) {
        return new ChallengeResult(true, 403);
    }

    private TokenRequest resolveTokenRequest() {
        try {
            return (TokenRequest) PolicyContext.getContext(TokenRequest.class.getName());
        } catch (Exception e) {
            // ignore
        }
        return null;
    }


    @Override
    public void initialize(ServletContext servletContext) {
    }

    @Override
    public boolean match(HttpServerExchange exchange, HttpServletRequest request) {
        TokenRequest tokenRequest = resolveTokenRequest();
        return tokenRequest != null;
    }
}
