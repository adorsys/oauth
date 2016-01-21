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
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
        TokenRequest request = TokenRequest.parse(FixedServletUtils.createHTTPRequest(servletRequest));
        LOG.info("tokenRequest {}", request);

        AuthorizationGrant authorizationGrant = request.getAuthorizationGrant();

        if (authorizationGrant.getType() == GrantType.AUTHORIZATION_CODE) {
            doAuthorizationCodeGrantFlow(authorizationGrant);
            return;
        }

        if (authorizationGrant.getType() == GrantType.PASSWORD) {
            doResourceOwnerPasswordCredentialFlow(request);
            return;
        }

         ServletUtils.applyHTTPResponse(
                    new TokenErrorResponse(OAuth2Error.UNSUPPORTED_GRANT_TYPE).toHTTPResponse(), servletResponse);
    }

    private void doAuthorizationCodeGrantFlow(AuthorizationGrant authorizationGrant) throws Exception  {
        AuthorizationCodeGrant authorizationCodeGrant = (AuthorizationCodeGrant) authorizationGrant;

        AccessToken accessToken = tokenStore.load(authorizationCodeGrant.getAuthorizationCode());

        if (accessToken == null) {
            LOG.info("tokenRequest: invalid grant {}", authorizationCodeGrant.getAuthorizationCode());
            ServletUtils.applyHTTPResponse(
                    new TokenErrorResponse(OAuth2Error.INVALID_GRANT).toHTTPResponse(),
                    servletResponse);
            return;
        }

        RefreshToken refreshToken = new RefreshToken();
        UserInfo userInfo = tokenStore.loadUserInfo(accessToken.getValue());

        tokenStore.add(refreshToken, userInfo);

        LOG.info("accessToken {}", accessToken.toJSONString());

        ServletUtils.applyHTTPResponse(
                new AccessTokenResponse(accessToken, refreshToken).toHTTPResponse(),
                servletResponse);
    }

    private void doResourceOwnerPasswordCredentialFlow(TokenRequest request) throws Exception {
        UserInfo userInfo = userInfoFactory.createUserInfo(servletRequest);
        LOG.debug(userInfo.toJSONObject().toJSONString());

        BearerAccessToken accessToken = new BearerAccessToken(tokenLifetime, request.getScope());

        LOG.info("resourceOwnerPasswordCredentialFlow {}", accessToken.toJSONString());

        tokenStore.add(accessToken, userInfo);
        RefreshToken refreshToken = new RefreshToken();
        tokenStore.add(refreshToken, userInfo);

        LOG.info("accessToken {}", accessToken.toJSONString());

        ServletUtils.applyHTTPResponse(
                new AccessTokenResponse(accessToken, refreshToken).toHTTPResponse(),
                servletResponse);
    }

}
