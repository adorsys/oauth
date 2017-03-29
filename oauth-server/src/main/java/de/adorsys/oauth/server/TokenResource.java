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
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * TokenResource
 */
@WebServlet("/api/token")
@ApplicationScoped
@SuppressWarnings("unused")
public class TokenResource extends HttpServlet {

    private static final Logger LOG = LoggerFactory.getLogger(TokenResource.class);

    @Inject
    private UserInfoFactory userInfoFactory;

    @Inject
    private TokenStore tokenStore;

    private long tokenLifetime;
    private long refreshTokenLifetime;
    
    @Override
    public void init(ServletConfig config) throws ServletException {
	   try {
           tokenLifetime = Long.valueOf(config.getServletContext().getInitParameter("lifetime"));
           refreshTokenLifetime = Long.valueOf(config.getServletContext().getInitParameter("refreshlifetime"));
       } catch (Exception e) {
           tokenLifetime = 8 * 3600;
           refreshTokenLifetime = 0L;
       }

       LOG.info("token lifetime {}", tokenLifetime);
    }
    
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
    	token(req, resp);
    }

    public void token(HttpServletRequest servletRequest, HttpServletResponse servletResponse) throws IOException {
        TokenRequest request;
		try {
			request = TokenRequest.parse(FixedServletUtils.createHTTPRequest(servletRequest));
		} catch (ParseException e) {
			ServletUtils.applyHTTPResponse(
                    new TokenErrorResponse(OAuth2Error.UNSUPPORTED_GRANT_TYPE).toHTTPResponse(), servletResponse);
			return;
		}
        LOG.debug("tokenRequest {}", request);

        AuthorizationGrant authorizationGrant = request.getAuthorizationGrant();

        if (authorizationGrant.getType() == GrantType.AUTHORIZATION_CODE) {
            doAuthorizationCodeGrantFlow(request, servletRequest, servletResponse);
            return;
        }

        if (authorizationGrant.getType() == GrantType.PASSWORD) {
            doResourceOwnerPasswordCredentialFlow(request, servletRequest, servletResponse);
            return;
        }
        
        if (authorizationGrant.getType() == GrantType.REFRESH_TOKEN) {
            doRefreshTokenGrantFlow(request, servletRequest, servletResponse);
            return;
        }

         ServletUtils.applyHTTPResponse(
                    new TokenErrorResponse(OAuth2Error.UNSUPPORTED_GRANT_TYPE).toHTTPResponse(), servletResponse);
    }

    private void doRefreshTokenGrantFlow(TokenRequest request, HttpServletRequest servletRequest, HttpServletResponse servletResponse) throws IOException {

        RefreshTokenGrant refreshTokenGrant = (RefreshTokenGrant) request.getAuthorizationGrant();
    	
    	RefreshTokenAndMetadata refreshTokeMetadata = tokenStore.findRefreshToken(refreshTokenGrant.getRefreshToken());

    	if (refreshTokeMetadata == null || !refreshTokeMetadata.getClientId().equals(request.getClientAuthentication().getClientID())) {
    		ServletUtils.applyHTTPResponse(
                    new TokenErrorResponse(OAuth2Error.INVALID_GRANT).toHTTPResponse(),
                    servletResponse);
            return;
    	}
    	RefreshToken refreshToken = new RefreshToken();
    	tokenStore.addRefreshToken(refreshToken,  refreshTokeMetadata.getUserInfo(), refreshTokeMetadata.getClientId(), refreshTokeMetadata.getLoginSession(), refreshTokenLifetime);
    	BearerAccessToken accessToken = new BearerAccessToken(tokenLifetime, request.getScope());
    	tokenStore.addAccessToken(accessToken, refreshTokeMetadata.getUserInfo(), refreshTokeMetadata.getClientId(), refreshToken);
    	
    	tokenStore.remove(refreshTokeMetadata.getRefreshToken().getValue(), refreshTokeMetadata.getClientId());
		ServletUtils.applyHTTPResponse(
                new AccessTokenResponse(new Tokens(accessToken, refreshToken)).toHTTPResponse(),
                servletResponse);
	}

	private void doAuthorizationCodeGrantFlow(TokenRequest request, HttpServletRequest servletRequest, HttpServletResponse servletResponse) throws IOException  {
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

        LOG.debug("accessToken {}", accessToken.toJSONString());

        Map<String, Object> customParameters = new HashMap<>();
        if (authCodeMetadata.getLoginSession() != null) {
            customParameters.put("login_session", authCodeMetadata.getLoginSession().getValue());
        }

        ServletUtils.applyHTTPResponse(
                new AccessTokenResponse(new Tokens(accessToken, refreshToken), customParameters).toHTTPResponse(),
                servletResponse);
    }

    private void doResourceOwnerPasswordCredentialFlow(TokenRequest request, HttpServletRequest servletRequest, HttpServletResponse servletResponse) throws IOException {
        UserInfo userInfo = userInfoFactory.createUserInfo(servletRequest);
        LOG.debug(userInfo.toJSONObject().toJSONString());

        RefreshToken refreshToken = new RefreshToken();
        LOG.debug("request.getClientAuthentication() {}", request.getClientAuthentication());
		tokenStore.addRefreshToken(refreshToken, userInfo, request.getClientAuthentication().getClientID(), null, refreshTokenLifetime);

        BearerAccessToken accessToken = new BearerAccessToken(tokenLifetime, request.getScope());

        LOG.debug("resourceOwnerPasswordCredentialFlow {}", accessToken.toJSONString());

        tokenStore.addAccessToken(accessToken, userInfo, request.getClientAuthentication().getClientID(), refreshToken);

        LOG.debug("accessToken {}", accessToken.toJSONString());

        ServletUtils.applyHTTPResponse(
                new AccessTokenResponse(new Tokens(accessToken, refreshToken)).toHTTPResponse(),
                servletResponse);
    }

}
