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
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.http.ServletUtils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
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
@Path("revoke")
@ApplicationScoped
@SuppressWarnings("unused")
public class RevokeResource {

    private static final Logger LOG = LoggerFactory.getLogger(RevokeResource.class);

    @Context
    private HttpServletRequest servletRequest;

    @Context
    private HttpServletResponse servletResponse;

    @Inject
    private TokenStore tokenStore;

    @POST
    @Consumes("application/x-www-form-urlencoded")
    public Response revoke(@FormParam("token") String token, @FormParam("token_type_hint") String tokenTypeHint) throws Exception {
    	if (token == null) {
    		ServletUtils.applyHTTPResponse(
                    new TokenErrorResponse(OAuth2Error.INVALID_GRANT).toHTTPResponse(), servletResponse);
    		return null;
    	}
    	ClientAuthentication clientAuthentication = ClientAuthentication.parse(FixedServletUtils.createHTTPRequest(servletRequest));
    	
    	
    	if ("login_session".equals(tokenTypeHint)) {
            LoginSessionToken loginSessionToken = new LoginSessionToken(token);
            tokenStore.remove(loginSessionToken);
            tokenStore.invalidateLoginSession(loginSessionToken);
    	} else {
    		tokenStore.remove(token, clientAuthentication.getClientID());    		
    	}

		return Response.ok("token revoked").header("Pragma", "no-cache").header("Cache-Control", "no-store").build();
    }
   
}
