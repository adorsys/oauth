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

import java.io.IOException;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import com.nimbusds.openid.connect.sdk.UserInfoErrorResponse;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoSuccessResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;

/**
 * UserInfoResource
 */
@WebServlet("/api/userinfo")
@ApplicationScoped
public class UserInfoResource extends HttpServlet {

    private static final Logger LOG = LoggerFactory.getLogger(UserInfoResource.class);

    @Inject
    private TokenStore tokenStore;

    private Long cachemaxage;
    
    @Override
    public void init(ServletConfig config) throws ServletException {
	   try {
           cachemaxage = Long.valueOf(config.getServletContext().getInitParameter("cachemaxage"));
           LOG.info("cachemaxage {}", cachemaxage);
       } catch (Exception e) {
       }
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
    	userInfo(req, resp);
    }
    
    public void userInfo(HttpServletRequest servletRequest, HttpServletResponse servletResponse) throws IOException {

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

        //TODO mask accesstoken
        LOG.debug("userInfo {}", accessToken.toJSONString());

        long lifeTime = tokenStore.load(accessToken.getValue()).getLifetime();
        long cacheLiveTime = cachemaxage != null ? cachemaxage : lifeTime;

        HTTPResponse httpResponse = new UserInfoSuccessResponse(userInfo).toHTTPResponse();
        httpResponse.setCacheControl("s-maxage=" + cacheLiveTime);

        ServletUtils.applyHTTPResponse(httpResponse, servletResponse);

    }
}
