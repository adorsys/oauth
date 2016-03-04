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

import org.apache.commons.lang3.StringUtils;

import javax.servlet.ServletContext;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import io.undertow.security.api.SecurityContext;
import io.undertow.security.idm.Account;
import io.undertow.security.idm.PasswordCredential;
import io.undertow.server.HttpServerExchange;

public class RememberMeMatcher implements AuthenticatorMatcher {

	@Override
	public void initialize(ServletContext servletContext) {

	}

	@Override
	public boolean match(HttpServerExchange exchange, HttpServletRequest request) {

		String clientId = request.getParameter("client_id");
		if (!"/auth".equals(request.getPathInfo()) || clientId == null) {
			return false;
		}

		Cookie cookieToken = getCookieToken(clientId, request);
		return cookieToken != null;
	}


	@Override
	public AuthenticationMechanismOutcome authenticate(HttpServerExchange exchange, SecurityContext securityContext) {
		Account account = securityContext.getIdentityManager().verify("guest", new PasswordCredential("test".toCharArray()));
		if (account == null) {
			return AuthenticationMechanismOutcome.NOT_AUTHENTICATED;
		}

		securityContext.authenticationComplete(account, OAuthServletExtension.MECHANISM_NAME, false);
		return AuthenticationMechanismOutcome.AUTHENTICATED;
	}

	@Override
	public ChallengeResult sendChallenge(HttpServerExchange exchange, SecurityContext securityContext) {
		return new ChallengeResult(false);
	}

	private Cookie getCookieToken(String clientId, HttpServletRequest request) {
		Cookie[] cookies = request.getCookies();
		if (cookies == null) {
			return null;
		}
		for (Cookie cookie : cookies) {
			if (cookie.getName().equals("REMEMBER_" + clientId) && StringUtils.isNotEmpty(cookie.getValue())) {
				return cookie;
			}
		}
		return null;
	}
}
