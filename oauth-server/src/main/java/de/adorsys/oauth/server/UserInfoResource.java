package de.adorsys.oauth.server;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.core.Context;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import com.nimbusds.openid.connect.sdk.UserInfoErrorResponse;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoSuccessResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;

/**
 * UserInfoResource
 */
@Path("userinfo")
@ApplicationScoped
public class UserInfoResource {

    private static final Logger LOG = LoggerFactory.getLogger(UserInfoResource.class);

    @Context
    private HttpServletRequest servletRequest;

    @Context
    private HttpServletResponse servletResponse;

    @SuppressWarnings("unused")
    @Inject
    private TokenStore tokenStore;

    @GET
    public void userInfo() throws Exception {

        UserInfoRequest userInfoRequest;

        try {
            userInfoRequest = UserInfoRequest.parse(FixedServletUtils.createHTTPRequest(servletRequest));
        } catch (Exception e) {
            FixedServletUtils.applyHTTPResponse(
                    new UserInfoErrorResponse(BearerTokenError.INVALID_REQUEST).toHTTPResponse(),
                    servletResponse);
            return;

        }

        AccessToken accessToken = userInfoRequest.getAccessToken();

        LOG.info("userInfo {}", accessToken.toJSONString());

        UserInfo userInfo = tokenStore.loadUserInfo(accessToken.getValue());
        if (userInfo == null) {
            FixedServletUtils.applyHTTPResponse(
                    new UserInfoErrorResponse(BearerTokenError.INVALID_TOKEN).toHTTPResponse(),
                    servletResponse);
            return;
        }

        long lifeTime = tokenStore.load(accessToken.getValue()).getLifetime();

        HTTPResponse httpResponse = new UserInfoSuccessResponse(userInfo).toHTTPResponse();
        httpResponse.setCacheControl("s-maxage=" + lifeTime);

        FixedServletUtils.applyHTTPResponse(httpResponse, servletResponse);

    }
}
