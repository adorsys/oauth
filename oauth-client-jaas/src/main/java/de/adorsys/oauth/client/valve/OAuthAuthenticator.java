/**
 * Copyright (C) 2015 Daniel Straub, Sandro Sonntag, Christian Brandenstein, Francis Pouatcha (sso@adorsys.de, dst@adorsys.de, cbr@adorsys.de, fpo@adorsys.de)
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.adorsys.oauth.client.valve;

import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;

import de.adorsys.oauth.client.protocol.OAuthProtocol;
import de.adorsys.oauth.client.protocol.UserInfoResolver;

import org.apache.catalina.LifecycleException;
import org.apache.catalina.Session;
import org.apache.catalina.authenticator.AuthenticatorBase;
import org.apache.catalina.connector.Request;
import org.apache.catalina.deploy.LoginConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import java.io.IOException;
import java.net.URI;
import java.security.Principal;

/**
 * OAuthAuthenticator
 */
@SuppressWarnings({ "UnusedParameters", "unused" })
public class OAuthAuthenticator extends AuthenticatorBase {

    private static final Logger LOG = LoggerFactory.getLogger(OAuthAuthenticator.class);

    private boolean supportHttpSession;

    private boolean supportAuthCode;

    private boolean supportGuest;

    private OAuthProtocol oauthProtocol;

    private UserInfoResolver userInfoResolver;

    /**
     * Initializing
     */
    public OAuthAuthenticator() {
        oauthProtocol = new OAuthProtocol();
        userInfoResolver = new UserInfoResolver();
        // authcode is default enabled
        supportAuthCode = true;
        supportHttpSession = false;
    }

    @Override
    protected boolean authenticate(Request request, HttpServletResponse response, LoginConfig loginConfig) throws IOException {

        Principal principal = request.getUserPrincipal();
        if (principal != null) {
            return true;
        }

        URI requestURI = oauthProtocol.extractURI(request);
        LOG.debug("Request " + requestURI);

        // 1. check for token
        AccessToken accessToken = oauthProtocol.resolveAccessToken(request);

        // 1.1 kein accessToken and guest allowed
        if (accessToken == null && supportGuest) {
            principal = context.getRealm().authenticate("guest", "NONE");
            request.setUserPrincipal(principal);
            return true;
        }

        // try to authenticate with accessToken
        if (authenticate(accessToken, request, response, null, null)) {
            return true;
        }

        // return 401 if AuthorizationCodeFlow disallowed
        if (!isAuthCodeRequest(request)) {
            response.setStatus(401);
            return false;
        }

        // 2. run AuthorizationCodeFlow
        AccessTokenResponse accessTokenResponse = oauthProtocol.runAuthorizationCodeFlow(requestURI);
        if (accessTokenResponse != null && accessTokenResponse.getTokens() != null) {
            Tokens tokens = accessTokenResponse.getTokens();
            accessToken = tokens.getAccessToken();
            RefreshToken refreshToken = tokens.getRefreshToken();
            Object sessionId = accessTokenResponse.getCustomParameters().get("login_session");
            if (authenticate(accessToken, request, response, refreshToken, sessionId)) {
                return true;
            }
        }

        // 3. redirect to authEndpoint to gain authCode
        oauthProtocol.doAuthorizationRequest(response, requestURI);

        return false;
    }

    /**
     * If true, the module will redirect to configured "authEndpoint"
     * otherwise return 401. This method is usefull to override in case of mixed auth flow webapps.
     * @param request
     * @return true for redirect false for 401
     */
    protected boolean isAuthCodeRequest(Request request) {
        return supportAuthCode;
    }

    /**
     * authenticate with accessToken
     */
    @SuppressWarnings("unchecked")
    private boolean authenticate(
        AccessToken accessToken,
        Request request,
        HttpServletResponse response,
        RefreshToken refreshToken,
        Object sessionId
    ) {

        if (accessToken == null) {
            return false;
        }

        LOG.debug("authenticate with accessToken {}", accessToken);

        UserInfo userInfo = userInfoResolver.resolve(accessToken);
        if (userInfo == null) {
            LOG.trace("no userInfo available for {}", accessToken.getValue());
            return false;
        }

        // use the request to provide userinfo in loginmodules
        request.setAttribute(UserInfo.class.getName(), userInfo);

        Principal principal = context.getRealm().authenticate(userInfo.getSubject().getValue(), accessToken.getValue());
        if (supportHttpSession) {
            Session session = request.getSessionInternal(); // force to create http-session

            HttpSession httpSession = session.getSession();
            httpSession.setAttribute("access_token", accessToken.getValue());
            if (refreshToken != null) {
                httpSession.setAttribute("refresh_token", refreshToken.getValue());
            }
            if (sessionId != null) {
                httpSession.setAttribute("login_session", sessionId);
            }
        }
        request.setUserPrincipal(principal);
        response.setHeader("Authorization", accessToken.toAuthorizationHeader());
        register(request, response, principal, "OAUTH", userInfo.getSubject().getValue(), accessToken.getValue());

        return true;
    }

    @Override
    @SuppressWarnings("unchecked")
    public void start() throws LifecycleException {
        oauthProtocol.initialize();
        userInfoResolver.initialize(System.getProperties());
        super.start();
        LOG.info("OAuthAuthenticator initialized {} {}", oauthProtocol, userInfoResolver);
    }

    public void setAuthEndpoint(String authEndpoint) {
        oauthProtocol.setAuthEndpoint(authEndpoint);
    }

    public void setTokenEndpoint(String tokenEndpoint) {
        oauthProtocol.setTokenEndpoint(tokenEndpoint);
    }

    public void setUserInfoEndpoint(String userInfoEndpoint) {
        userInfoResolver.setUserInfoEndpoint(userInfoEndpoint);
    }

    public void setClientSecret(String clientSecret) {
        oauthProtocol.setClientSecretValue(clientSecret);
    }

    public void setClientId(String clientId) {
        oauthProtocol.setClientId(clientId);
    }

    public void setSupportHttpSession(boolean supportHttpSession) {
        this.supportHttpSession = supportHttpSession;
    }

    public void setSupportAuthCode(boolean supportAuthCode) {
        this.supportAuthCode = supportAuthCode;
    }

    public void setSupportGuest(boolean supportGuest) {
        this.supportGuest = supportGuest;
    }
}
