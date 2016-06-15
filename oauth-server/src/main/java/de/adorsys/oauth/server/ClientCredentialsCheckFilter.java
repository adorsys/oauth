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

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.servlet.DispatcherType;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.util.Base64;

@WebFilter(urlPatterns = {"/api/token", "/api/revoke"}, dispatcherTypes = { DispatcherType.REQUEST, DispatcherType.FORWARD})
public class ClientCredentialsCheckFilter implements Filter {

	private static final Logger LOG = LoggerFactory.getLogger(ClientCredentialsCheckFilter.class);
	private String clientSecurityDomain = "client-auth";
	private boolean checkClientCredentialsOnTokenRevoke;

	@Override
	public void init(FilterConfig filterConfig) throws ServletException {
		clientSecurityDomain = filterConfig.getServletContext().getInitParameter("clientCredentialsSecurityDomain");
		if (clientSecurityDomain == null) {
			clientSecurityDomain = "client-auth";
		}
		
		checkClientCredentialsOnTokenRevoke = !"false".equals(filterConfig.getServletContext().getInitParameter("checkClientCredentialsOnTokenRevoke"));
	}

	@Override
	public void doFilter(ServletRequest sr, ServletResponse sresp, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) sr;
		HttpServletResponse response = (HttpServletResponse) sresp;
		if (!verifyClientCredentials(request)) {
			response.setStatus(401); // according
										// https://tools.ietf.org/html/rfc6749#section-5.2
										// invalid_client
			response.setHeader("WWW-Authenticate", "Basic realm=\"oauth\"");
			response.getWriter().write("client authentification failed");
			return;
		}
		chain.doFilter(request, response);
	}

	@Override
	public void destroy() {
	}

	/**
	 * Check client credentials We expect the credentials as BASIC-Auth header
	 */
	private boolean verifyClientCredentials(HttpServletRequest httpRequest) {
		if (httpRequest.getRequestURI().endsWith("/api/revoke") && !checkClientCredentialsOnTokenRevoke) {
			return true;
		}

		final String[] namePassword = getNamePassword(httpRequest);
		if (namePassword == null) {
			return false;
		}

		CallbackHandler callbackHandler = new CallbackHandler() {
			@Override
			public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
				for (Callback callback : callbacks) {
					if (callback instanceof NameCallback) {
						((NameCallback) callback).setName(namePassword[0]);
						continue;
					}
					if (callback instanceof PasswordCallback) {
						((PasswordCallback) callback).setPassword(namePassword[1].toCharArray());
					}
				}
			}
		};

		Subject subject = new Subject();
		try {
			LoginContext loginContext = new LoginContext(clientSecurityDomain, subject, callbackHandler);
			loginContext.login();
			loginContext.logout();
		} catch (LoginException e) {
			LOG.error("call securitydomain " + callbackHandler, e);
			return false;
		}

		return true;

	}

	private String[] getNamePassword(HttpServletRequest httpRequest) {
		String authValue = httpRequest.getHeader("Authorization");
		if (authValue != null && authValue.startsWith("Basic ")) {
			String encodedValue = authValue.substring(6);
			String decodedValue = new Base64(encodedValue).decodeToString();
			final String[] namePassword = decodedValue.contains(":") ? decodedValue.split(":")
					: new String[] { decodedValue, "" };
			return namePassword;
		} else if (httpRequest.getContentType().contains("application/x-www-form-urlencoded")) {
			String clientId = httpRequest.getParameter("client_id");
			String clientSecret = httpRequest.getParameter("client_secret");
			if (clientId == null || clientSecret == null) {
				return null;
			}
			return new String[]{clientId, clientSecret};
		} else {
			return null;			
		}
	}

}
