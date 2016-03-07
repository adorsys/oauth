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

import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import com.nimbusds.openid.connect.sdk.UserInfoErrorResponse;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoSuccessResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.core.Context;

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

    @Context
    private ServletContext servletContext;

    @SuppressWarnings("unused")
    @Inject
    private TokenStore tokenStore;

    private Long cachemaxage;

    @PostConstruct
    public void postConstruct() {
        try {
            cachemaxage = Long.valueOf(servletContext.getInitParameter("cachemaxage"));
            LOG.info("cachemaxage {}", cachemaxage);
        } catch (Exception e) {
        }
    }

    @GET
    public void userInfo() throws Exception {

        UserInfoRequest userInfoRequest;

        try {
            userInfoRequest = UserInfoRequest.parse(FixedServletUtils.createHTTPRequest(servletRequest));
        } catch (Exception e) {
            ServletUtils.applyHTTPResponse(
                    new UserInfoErrorResponse(BearerTokenError.INVALID_REQUEST).toHTTPResponse(),
                    servletResponse);
            return;

        }

        AccessToken accessToken = userInfoRequest.getAccessToken();

        if (!tokenStore.isValid(accessToken.getValue())) {
            LOG.info("expired token {}", accessToken.toJSONString());
            ServletUtils.applyHTTPResponse(
                    new UserInfoErrorResponse(BearerTokenError.INVALID_TOKEN).toHTTPResponse(),
                    servletResponse);
            return;
        }

        UserInfo userInfo = tokenStore.loadUserInfo(accessToken.getValue());

        if (userInfo == null) {
            LOG.info("no userInfo available {}", accessToken.toJSONString());
            ServletUtils.applyHTTPResponse(
                    new UserInfoErrorResponse(BearerTokenError.INVALID_TOKEN).toHTTPResponse(),
                    servletResponse);
            return;
        }

        LOG.info("userInfo {}", accessToken.toJSONString());

        long lifeTime = tokenStore.load(accessToken.getValue()).getLifetime();
        long cacheLiveTime = cachemaxage != null ? cachemaxage : lifeTime;

        HTTPResponse httpResponse = new UserInfoSuccessResponse(userInfo).toHTTPResponse();
        httpResponse.setCacheControl("s-maxage=" + cacheLiveTime);

        ServletUtils.applyHTTPResponse(httpResponse, servletResponse);

    }
}
