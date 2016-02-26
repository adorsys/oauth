/**
 * Copyright (C) 2015 Daniel Straub, Sandro Sonntag, Christian Brandenstein, Francis Pouatcha (sso@adorsys.de, dst@adorsys.de, cbr@adorsys.de, fpo@adorsys.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.adorsys.oauth.server;

import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.RefreshTokenGrant;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.core.Context;

/**
 * TokenResource
 */
@Path("token")
@ApplicationScoped
@SuppressWarnings("unused")
public class TokenResource {

    private static final Logger LOG = LoggerFactory.getLogger(TokenResource.class);

    @Context
    private HttpServletRequest servletRequest;

    @Context
    private HttpServletResponse servletResponse;

    @Context
    private ServletContext servletContext;

    @Inject
    private UserInfoFactory userInfoFactory;

    @Inject
    private TokenStore tokenStore;

    private long tokenLifetime;

    @PostConstruct
    public void postConstruct() {
        try {
            tokenLifetime = Long.valueOf(servletContext.getInitParameter("lifetime"));
        } catch (Exception e) {
            tokenLifetime = 8 * 3600;
        }

        LOG.info("token lifetime {}", tokenLifetime);
    }

    @POST
    @Consumes("application/x-www-form-urlencoded")
    public void token() throws Exception {
        TokenRequest request;
		try {
			request = TokenRequest.parse(FixedServletUtils.createHTTPRequest(servletRequest));
		} catch (ParseException e) {
			ServletUtils.applyHTTPResponse(
                    new TokenErrorResponse(OAuth2Error.UNSUPPORTED_GRANT_TYPE).toHTTPResponse(), servletResponse);
			return;
		}
        LOG.info("tokenRequest {}", request);

        AuthorizationGrant authorizationGrant = request.getAuthorizationGrant();

        if (authorizationGrant.getType() == GrantType.AUTHORIZATION_CODE) {
            doAuthorizationCodeGrantFlow(request);
            return;
        }

        if (authorizationGrant.getType() == GrantType.PASSWORD) {
            doResourceOwnerPasswordCredentialFlow(request);
            return;
        }
        
        if (authorizationGrant.getType() == GrantType.REFRESH_TOKEN) {
            doRefreshTokenGrantFlow(request);
            return;
        }

         ServletUtils.applyHTTPResponse(
                    new TokenErrorResponse(OAuth2Error.UNSUPPORTED_GRANT_TYPE).toHTTPResponse(), servletResponse);
    }

    private void doRefreshTokenGrantFlow(TokenRequest request) throws IOException {
    	RefreshTokenGrant refreshTokenGrant = (RefreshTokenGrant) request.getAuthorizationGrant();
    	
    	RefreshTokenAndMetadata refreshTokeMetadata = tokenStore.findRefreshToken(refreshTokenGrant.getRefreshToken());
    	if (refreshTokeMetadata == null || !refreshTokeMetadata.getClientId().equals(request.getClientAuthentication().getClientID())) {
    		ServletUtils.applyHTTPResponse(
                    new TokenErrorResponse(OAuth2Error.INVALID_GRANT).toHTTPResponse(),
                    servletResponse);
    	}
    	
    	BearerAccessToken accessToken = new BearerAccessToken(tokenLifetime, request.getScope());
    	tokenStore.remove(refreshTokeMetadata.getRefreshToken().getValue(), refreshTokeMetadata.getClientId());
		tokenStore.addAccessToken(accessToken, refreshTokeMetadata.getUserInfo(), refreshTokeMetadata.getClientId(), refreshTokeMetadata.getRefreshToken());
		RefreshToken refreshToken = new RefreshToken();
		tokenStore.addRefreshToken(refreshToken,  refreshTokeMetadata.getUserInfo(), refreshTokeMetadata.getClientId(), refreshTokeMetadata.getLoginSession());

		ServletUtils.applyHTTPResponse(
                new AccessTokenResponse(new Tokens(accessToken, refreshToken)).toHTTPResponse(),
                servletResponse);
	}

	private void doAuthorizationCodeGrantFlow(TokenRequest request) throws Exception  {
        AuthorizationCodeGrant authorizationCodeGrant = (AuthorizationCodeGrant) request.getAuthorizationGrant();

        AuthCodeAndMetadata authCodeMetadata = tokenStore.consumeAuthCode(authorizationCodeGrant.getAuthorizationCode());

        if (authCodeMetadata == null ||
        		!authCodeMetadata.getClientId().equals(request.getClientAuthentication().getClientID()) ||
        		!authCodeMetadata.getRedirectURI().equals(servletRequest.getParameter("redirect_uri"))
        		) {
            LOG.info("tokenRequest: invalid grant {}", authorizationCodeGrant.getAuthorizationCode());
            ServletUtils.applyHTTPResponse(
                    new TokenErrorResponse(OAuth2Error.INVALID_GRANT).toHTTPResponse(),
                    servletResponse);
            return;
        }

        //Every auth flow must create new refresh token
//        RefreshToken refreshToken = tokenStore.findRefreshToken(authCodeMetadata.getLoginSession());
//        if (refreshToken == null) {
//        	refreshToken = new RefreshToken();
//			tokenStore.addRefreshToken(refreshToken, authCodeMetadata.getUserInfo(), authCodeMetadata.getClientId(), authCodeMetadata.getLoginSession());
//        }

        RefreshToken refreshToken = new RefreshToken();
        tokenStore.addRefreshToken(refreshToken, authCodeMetadata.getUserInfo(), authCodeMetadata.getClientId(), authCodeMetadata.getLoginSession());

        BearerAccessToken accessToken = new BearerAccessToken(tokenLifetime, request.getScope());

        tokenStore.addAccessToken(accessToken, authCodeMetadata.getUserInfo(), authCodeMetadata.getClientId(), refreshToken);

        LOG.info("accessToken {}", accessToken.toJSONString());

        Map<String, Object> customParameters = new HashMap<>();
        customParameters.put("login_session", authCodeMetadata.getLoginSession().getValue());
		ServletUtils.applyHTTPResponse(
                new AccessTokenResponse(new Tokens(accessToken, refreshToken), customParameters).toHTTPResponse(),
                servletResponse);
    }

    private void doResourceOwnerPasswordCredentialFlow(TokenRequest request) throws Exception {
        UserInfo userInfo = userInfoFactory.createUserInfo(servletRequest);
        LOG.debug(userInfo.toJSONObject().toJSONString());

        RefreshToken refreshToken = new RefreshToken();
        LOG.info("request.getClientAuthentication() {}", request.getClientAuthentication());
		tokenStore.addRefreshToken(refreshToken, userInfo, request.getClientAuthentication().getClientID(), null);

        BearerAccessToken accessToken = new BearerAccessToken(tokenLifetime, request.getScope());

        LOG.info("resourceOwnerPasswordCredentialFlow {}", accessToken.toJSONString());

        tokenStore.addAccessToken(accessToken, userInfo, request.getClientAuthentication().getClientID(), refreshToken);

        LOG.info("accessToken {}", accessToken.toJSONString());

        ServletUtils.applyHTTPResponse(
                new AccessTokenResponse(new Tokens(accessToken, refreshToken)).toHTTPResponse(),
                servletResponse);
    }

}
