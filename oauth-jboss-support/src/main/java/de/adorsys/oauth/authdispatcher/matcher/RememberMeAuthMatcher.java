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
package de.adorsys.oauth.authdispatcher.matcher;

import com.nimbusds.oauth2.sdk.AuthorizationRequest;

import org.apache.catalina.authenticator.AuthenticatorBase;
import org.apache.catalina.connector.Request;
import org.apache.catalina.deploy.LoginConfig;
import org.apache.catalina.valves.ValveBase;
import org.apache.commons.lang3.StringUtils;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.security.Principal;

public class RememberMeAuthMatcher extends BaseAuthenticatorMatcher {

	public RememberMeAuthMatcher() {
		valve = new AuthenticatorBase() {
			
			@Override
			protected boolean authenticate(Request request, HttpServletResponse response, LoginConfig lc) throws IOException {
				Principal principal = context.getRealm().authenticate("guest", "test");
				if (principal != null) {
					register(request, response, principal, "FORM", "guest", "test");
					return true;
				}
				return false;
			}
		};
	}


	@Override
	public ValveBase match(HttpServletRequest request, AuthorizationRequest authorizationRequest) {
		if (!"/auth".equals(request.getPathInfo()) || authorizationRequest == null || authorizationRequest.getClientID() == null) {
			return null;
		}
		Cookie cookieToken = getCookieToken(authorizationRequest.getClientID().getValue(), request);
		return cookieToken != null ? valve : null;
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
