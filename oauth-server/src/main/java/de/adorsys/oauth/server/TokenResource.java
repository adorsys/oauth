package de.adorsys.oauth.server;

import java.security.Principal;

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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;

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
    private Principal principal;

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
            authorizationCodeGrantFlow(authorizationGrant);
        } else if (authorizationGrant.getType() == GrantType.PASSWORD) {
            resourceOwnerPasswordCredentialFlow(request);
        } else {
            FixedServletUtils.applyHTTPResponse(
                    new TokenErrorResponse(OAuth2Error.UNSUPPORTED_GRANT_TYPE).toHTTPResponse(), servletResponse);
        }
    }

    private void authorizationCodeGrantFlow(AuthorizationGrant authorizationGrant) throws Exception  {
        AuthorizationCodeGrant authorizationCodeGrant = (AuthorizationCodeGrant) authorizationGrant;

        AccessToken accessToken = tokenStore.load(authorizationCodeGrant.getAuthorizationCode());

        if (accessToken == null) {
            LOG.info("tokenRequest: invalid grant {}", authorizationCodeGrant.getAuthorizationCode());
            FixedServletUtils.applyHTTPResponse(
                    new TokenErrorResponse(OAuth2Error.INVALID_GRANT).toHTTPResponse(),
                    servletResponse);
            return;
        }

        RefreshToken refreshToken = new RefreshToken();
        UserInfo userInfo = tokenStore.loadUserInfo(accessToken.getValue());

        tokenStore.add(refreshToken, userInfo);

        LOG.info("accessToken {}", accessToken.toJSONString());

        FixedServletUtils.applyHTTPResponse(
                new AccessTokenResponse(accessToken, refreshToken).toHTTPResponse(),
                servletResponse);
    }

    private void resourceOwnerPasswordCredentialFlow(TokenRequest request) throws Exception {
        UserInfo userInfo = createUserInfo(request);
        LOG.debug(userInfo.toJSONObject().toJSONString());

        BearerAccessToken accessToken = new BearerAccessToken(tokenLifetime, request.getScope());

        LOG.info("impliesTokenFlow {}", accessToken.toJSONString());

        tokenStore.add(accessToken, userInfo);
        RefreshToken refreshToken = new RefreshToken();
        tokenStore.add(refreshToken, userInfo);

        LOG.info("accessToken {}", accessToken.toJSONString());

        FixedServletUtils.applyHTTPResponse(
                new AccessTokenResponse(accessToken, refreshToken).toHTTPResponse(),
                servletResponse);
    }

    private UserInfo createUserInfo(TokenRequest request) {
        UserInfo userInfo = userInfoFactory.createUserInfo(servletRequest);

        if (request == null) {
            return userInfo;
        }

        // for what ever ...
        userInfo.setClaim("clientID", request.getClientID());
        if (request.getScope() != null) {
            userInfo.setClaim("scope", request.getScope());
        }

        return userInfo;
    }
}
