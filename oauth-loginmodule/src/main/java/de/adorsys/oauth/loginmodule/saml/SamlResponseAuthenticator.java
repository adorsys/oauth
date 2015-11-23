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
package de.adorsys.oauth.loginmodule.saml;

import java.io.IOException;
import java.security.Principal;

import javax.servlet.http.HttpServletResponse;

import org.apache.catalina.Container;
import org.apache.catalina.Realm;
import org.apache.catalina.connector.Request;
import org.apache.catalina.deploy.LoginConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SamlResponseAuthenticator extends SamlRequestAuthenticator {

	private static final Logger LOG = LoggerFactory.getLogger(SamlResponseAuthenticator.class);

	@Override
	public void setContainer(Container container) {
		super.setContainer(container);
	}

	@Override
	protected boolean authenticate(Request request,
			HttpServletResponse response, LoginConfig config)
			throws IOException {
		Principal principal = request.getUserPrincipal();
		if (principal != null) {
			return true;
		}

		// Is this the action request from the client? We expect a get request.
		if ("GET".equals(request.getMethod())){
			response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Expecting post request");
		} if ("POST".equals(request.getMethod())) {
			// Yes -- Validate the response fron the idp server and
			// to the error page if they are not correct
            Principal samlPrincipals = checkSamlRespone(request);
            if (samlPrincipals != null) {
    			String pwd = null;
    			request.setAttribute(SamlConstants.SAML_PRINCIPAL_ATTRIBUTE_KEY, samlPrincipals);
    			Realm realm = context.getRealm();
    			// Associate principal with subjects.
    			Principal authenticatedPrincipal = realm.authenticate(samlPrincipals.getName(), pwd);
    			if(authenticatedPrincipal!=null) {
    				register(request, response, authenticatedPrincipal, "SAML", authenticatedPrincipal.getName(), null);
    				return true;
            	}
            }
		}

		response.sendError(HttpServletResponse.SC_FORBIDDEN);
        return false;
	}	
}
