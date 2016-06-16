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

import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import com.nimbusds.oauth2.sdk.id.ClientID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.mail.internet.ContentType;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;

/**
 * TokenResource
 */
@WebServlet("/api/revoke")
@ApplicationScoped
@SuppressWarnings("unused")
public class RevokeResource extends HttpServlet {

    private static final Logger LOG = LoggerFactory.getLogger(RevokeResource.class);

    @Inject
    private TokenStore tokenStore;

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String token = req.getParameter("token");
        String tokenTypeHint = req.getParameter("token_type_hint");
        revoke(token, tokenTypeHint, req, resp);
    }

    public void revoke(@FormParam("token") String token, @FormParam("token_type_hint") String tokenTypeHint,
            HttpServletRequest servletRequest, HttpServletResponse servletResponse) throws IOException {
        if (token == null) {
            ServletUtils.applyHTTPResponse(new TokenErrorResponse(OAuth2Error.INVALID_GRANT).toHTTPResponse(),
                    servletResponse);
            return;
        }
        ClientID clientId = null;
        try {
            ClientAuthentication clientAuth = ClientAuthentication.parse(FixedServletUtils.createHTTPRequest(servletRequest));
            if (clientAuth != null) {
                clientId = clientAuth.getClientID();
            }
        } catch (ParseException e) {
            // ignore; no clientid given
        }

        if ("login_session".equals(tokenTypeHint)) {
            LoginSessionToken loginSessionToken = new LoginSessionToken(token);
            tokenStore.remove(loginSessionToken);
            tokenStore.invalidateLoginSession(loginSessionToken);
        } else {
            tokenStore.remove(token, clientId);
        }
        HTTPResponse httpResponse = new HTTPResponse(HTTPResponse.SC_OK);
        httpResponse.setHeader("Content-Type", "text/plain");
        httpResponse.setHeader("Pragma", "no-cache");
        httpResponse.setHeader("Cache-Control", "no-store");
        ServletUtils.applyHTTPResponse(httpResponse, servletResponse);
    }

}
