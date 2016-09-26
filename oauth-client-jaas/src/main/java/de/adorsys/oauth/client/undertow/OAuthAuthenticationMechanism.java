package de.adorsys.oauth.client.undertow;

import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import de.adorsys.oauth.client.protocol.OAuthProtocol;
import de.adorsys.oauth.client.protocol.UserInfoResolver;
import io.undertow.security.api.AuthenticationMechanism;
import io.undertow.security.api.AuthenticationMechanismFactory;
import io.undertow.security.api.SecurityContext;
import io.undertow.security.idm.Account;
import io.undertow.security.idm.IdentityManager;
import io.undertow.security.idm.PasswordCredential;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.handlers.form.FormParserFactory;
import io.undertow.servlet.handlers.ServletRequestContext;
import io.undertow.util.StatusCodes;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.URI;
import java.security.Principal;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

/**
 * OAuthAuthenticationMechanism
 */
@SuppressWarnings("unused")
public class OAuthAuthenticationMechanism implements AuthenticationMechanism {

    private static final Logger LOG = LoggerFactory.getLogger(OAuthAuthenticationMechanism.class);

    private OAuthProtocol oauthProtocol;
    private UserInfoResolver userInfoResolver;
    private boolean supportAuthCode;
    private boolean supportGuest;
    private boolean treatInvalidTokenAsGuest;
    private boolean supportHttpSession;
    private String mechanismName;

    public OAuthAuthenticationMechanism(String mechanismName, Map<String, String> properties) {
        this.mechanismName = mechanismName;
        oauthProtocol = OAuthProtocol.from(properties);
        userInfoResolver = UserInfoResolver.from(properties);

        supportAuthCode = extract(properties, "supportAuthCode", true);
        supportGuest = extract(properties, "supportGuest", false);
        supportHttpSession = extract(properties, "supportHttpSession", false);
        treatInvalidTokenAsGuest = extract(properties, "treatInvalidTokenAsGuest", false);

        LOG.info("use {} {}", oauthProtocol, userInfoResolver);
    }

    private boolean extract(Map<String, String> properties, String key, boolean defaultValue) {
        return properties.containsKey(key) ? Boolean.valueOf(properties.get(key)) : defaultValue;
    }

    @Override
    public AuthenticationMechanismOutcome authenticate(HttpServerExchange exchange, SecurityContext securityContext) {

        ServletRequestContext servletRequestContext = exchange.getAttachment(ServletRequestContext.ATTACHMENT_KEY);
        HttpServletRequest request = servletRequestContext.getOriginalRequest();
        HttpServletResponse response = servletRequestContext.getOriginalResponse();

        Principal principal = request.getUserPrincipal();
        if (principal != null) {
            return AuthenticationMechanismOutcome.AUTHENTICATED;
        }

        URI requestURI = oauthProtocol.extractURI(request);
        LOG.debug("Request " + requestURI);

        // 1. check for token
        AccessToken accessToken = oauthProtocol.resolveAccessToken(request);

        // 1.1 no accessToken and guest allowed
        if (accessToken == null && supportGuest) {
            return authenticateAsGuest(securityContext);
        }

        // try to authenticate with accessToken
        if (authenticate(securityContext, accessToken, request, response)) {
            return AuthenticationMechanismOutcome.AUTHENTICATED;
        }

        // Authenticate as guest if invalid token supplied
        if(treatInvalidTokenAsGuest) {
            return authenticateAsGuest(securityContext);
        }

        // return 401 if AuthorizationCodeFlow disallowed
        if (!supportAuthCode) {
            response.setStatus(401);
            return AuthenticationMechanismOutcome.NOT_AUTHENTICATED;
        }

        // 2. run AuthorizationCodeFlow
        AccessTokenResponse accessTokenResponse = oauthProtocol.runAuthorizationCodeFlow(requestURI);
        if (accessTokenResponse != null && accessTokenResponse.getTokens() != null) {
            Tokens tokens = accessTokenResponse.getTokens();
            accessToken = tokens.getAccessToken(); //TODO refresh_token, login_session "supportHttpSession"
            if (authenticate(securityContext, accessToken, request, response)) {
                return AuthenticationMechanismOutcome.AUTHENTICATED;
            }
        }

        // 3. redirect to authEndpoint to gain authCode
        oauthProtocol.doAuthorizationRequest(response, requestURI);

        return AuthenticationMechanismOutcome.NOT_ATTEMPTED;
    }

    private AuthenticationMechanismOutcome authenticateAsGuest(SecurityContext securityContext) {
        Account account = securityContext.getIdentityManager().verify("guest", new PasswordCredential("NONE".toCharArray()));
        securityContext.authenticationComplete(account, mechanismName, false);
        return AuthenticationMechanismOutcome.AUTHENTICATED;
    }

    /**
     * authenticate with accessToken
     */
    private boolean authenticate(SecurityContext securityContext, AccessToken accessToken, HttpServletRequest request, HttpServletResponse response) {

        if (accessToken == null) {
            return false;
        }

        LOG.debug("authenticate with accessToken {}", accessToken);

        UserInfo userInfo = userInfoResolver.resolve(accessToken);
        if (userInfo == null) {
            LOG.trace("no userInfo available for {}", accessToken.getValue());
            return false;
        }

        IdentityManager identityManager = securityContext.getIdentityManager();
        // use the request to provide userinfo in loginmodules
        request.setAttribute(UserInfo.class.getName(), userInfo);

        Account account = identityManager.verify(userInfo.getSubject().getValue(), new PasswordCredential(accessToken.getValue().toCharArray()));

        if (account == null) {
            if (!supportGuest) {
                LOG.error("no account created for {} {}, OAuthLoginModule configured correctly ?", userInfo.getSubject().getValue(), accessToken.getValue());
            }
            return false;
        }

        securityContext.authenticationComplete(account, mechanismName, supportHttpSession);

        response.setHeader("Authorization", accessToken.toAuthorizationHeader());

        return true;
    }

    @Override
    public ChallengeResult sendChallenge(HttpServerExchange exchange, SecurityContext securityContext) {
        return new ChallengeResult(true, StatusCodes.UNAUTHORIZED);
    }


    /**
     * Factory
     */
    public static final class Factory implements AuthenticationMechanismFactory {

        private Map<String, String> contextProperties;

        public Factory(ServletContext servletContext) {
            contextProperties = new HashMap<>();
            Enumeration<String> attrNames = servletContext.getInitParameterNames();
            while (attrNames.hasMoreElements()) {
                String key = attrNames.nextElement();
                contextProperties.put(key, servletContext.getInitParameter(key));
            }

            LOG.info("initialize OAuthAuthenticationMechanism for {}", servletContext.getContextPath());
        }

        @Override
        public AuthenticationMechanism create(String mechanismName, FormParserFactory formParserFactory, Map<String, String> properties) {
            properties.putAll(contextProperties);
            return new OAuthAuthenticationMechanism(mechanismName, properties);
        }
    }

}
