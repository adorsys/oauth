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
package de.adorsys.oauth.valve.authdispatcher.matcher;

import org.apache.catalina.Realm;
import org.apache.catalina.authenticator.AuthenticatorBase;
import org.apache.catalina.connector.Request;
import org.apache.catalina.deploy.LoginConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.RequestDispatcher;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.security.Principal;

public class StatelessFormAuthenticator extends AuthenticatorBase {
	
	private static final String ORIGIN_PARAM = "origin";

	private static final Logger LOG = LoggerFactory.getLogger(StatelessFormAuthenticator.class);

	// Form based authentication constants
	public static final String FORM_ACTION = "/j_security_check";
	public static final String FORM_PASSWORD = "j_password";
	public static final String FORM_USERNAME = "j_username";
	public static final String EXCEPTION_ATTR = "javax.servlet.error.exception";
	
	protected String characterEncoding = null;

	@Override
	protected boolean authenticate(Request request, HttpServletResponse response, LoginConfig config) throws IOException {

		Principal principal = request.getUserPrincipal();
		if (principal != null) {
			return true;
		}

		// Is this the action request from the login page?
		if ("GET".equals(request.getMethod())){
			showLoginPage(request, response, config);
		}

		if ("POST".equals(request.getMethod())) {
			// Yes -- Validate the specified credentials and redirect
			// to the error page if they are not correct
			if (characterEncoding != null) {
				request.setCharacterEncoding(characterEncoding);
			}

			String username = request.getParameter(FORM_USERNAME);
			String password = request.getParameter(FORM_PASSWORD);

			if (LOG.isDebugEnabled()) {
				LOG.debug("Authenticating username '" + username + "'");
			}

			principal = context.getRealm().authenticate(username, password);

			if (principal != null) {
				register(request, response, principal, "FORM", username, password);
				return true;
			}		

			showErrorPage(request, response, config);
		}

		return false;
	}
	
	private void showLoginPage(Request request, HttpServletResponse response, LoginConfig config) throws IOException {
		RequestDispatcher dispatcher = context.getServletContext().getRequestDispatcher(config.getLoginPage());
		try {
			dispatcher.forward(request.getRequest(), response);
		} catch (Exception e) {
			LOG.warn("formAuthenticator.forwardLoginFail", e);
			request.setAttribute(EXCEPTION_ATTR, e);
			response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "formAuthenticator.forwardErrorFail");
		}
	}
	
	private void showErrorPage(Request request, HttpServletResponse response, LoginConfig config) throws IOException {
		RequestDispatcher dispatcher = context.getServletContext().getRequestDispatcher(config.getErrorPage());
		try {
			dispatcher.forward(request.getRequest(), response);
		} catch (Exception e) {
			LOG.warn("formAuthenticator.forwardLoginFail", e);
			request.setAttribute(EXCEPTION_ATTR, e);
			response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "formAuthenticator.redirectLoginPage");
		}
	}

	public String getCharacterEncoding() {
		return characterEncoding;
	}

	public void setCharacterEncoding(String characterEncoding) {
		this.characterEncoding = characterEncoding;
	}
	
	

}
