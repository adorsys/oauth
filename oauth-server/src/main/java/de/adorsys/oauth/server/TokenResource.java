package de.adorsys.oauth.server;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
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

    @SuppressWarnings("unused")
    @Inject
    private TokenStore tokenStore;

    @POST
    @Consumes("application/x-www-form-urlencoded")
    public void token() throws Exception {

        TokenRequest request = TokenRequest.parse(ServletUtils.createHTTPRequest(servletRequest));
        LOG.info("tokenRequest {}", request);

        AuthorizationGrant authorizationGrant = request.getAuthorizationGrant();
        if (authorizationGrant.getType() != GrantType.AUTHORIZATION_CODE) {
            ServletUtils.applyHTTPResponse(
                    new TokenErrorResponse(OAuth2Error.UNSUPPORTED_GRANT_TYPE).toHTTPResponse(), servletResponse);
            return;
        }

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
}
