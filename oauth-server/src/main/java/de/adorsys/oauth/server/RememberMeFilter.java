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

import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.ClientID;

import org.jboss.security.SecurityContext;
import org.jboss.security.SecurityContextAssociation;
import org.jboss.security.SubjectInfo;
import org.jboss.security.identity.Role;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Web Filter that handles the remember me cookie.
 *
 * If the URL parameter {@code rememberme} is defined as false, the cookie value will not be used to retrieve the login session
 * and the cookie will be removed.
 *
 * @author sso
 */
@WebFilter(filterName = "rememberme")
public class RememberMeFilter implements Filter {

	@Override
	public void init(FilterConfig filterConfig) throws ServletException {
	}

	@Override
	public void doFilter(ServletRequest sr, ServletResponse sresp, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) sr;
		HttpServletResponse response = (HttpServletResponse) sresp;
		AuthorizationRequest authorizationRequest;
		try {
			authorizationRequest = AuthorizationRequest.parse(request.getQueryString());
		} catch (ParseException e) {
			throw new OAuthException("problem extraction clientId", e);
		}
		if (RememberMeTokenUtil.isEnabled() && shouldRememberMe(request)) {
			request.setAttribute("loginSession", getOrCreateLoginSession(request, response, authorizationRequest));
		}
		chain.doFilter(sr, sresp);

		if (request.getAttribute("loginSession") == null) {
			RememberMeCookieUtil.removeCookieToken(request, response, authorizationRequest.getClientID());
		}
	}

	private boolean shouldRememberMe(HttpServletRequest request) {
		// Poor man's way to default to true
		return !"false".equals(request.getParameter("rememberme"));
	}

	private LoginSessionToken getOrCreateLoginSession(HttpServletRequest request, HttpServletResponse response,
			AuthorizationRequest authorizationRequest) {
		Cookie cookieToken = RememberMeCookieUtil.getCookieToken(request, authorizationRequest.getClientID());

		LoginSessionToken loginSession;
		if (cookieToken == null) {
			loginSession = new LoginSessionToken();
			rememberAuthInCookie(request, response, authorizationRequest.getClientID(), loginSession);
		} else {
			loginSession = RememberMeTokenUtil.getLoginSession(cookieToken.getValue());
		}
		return loginSession;
	}

	private void rememberAuthInCookie(HttpServletRequest request, HttpServletResponse response, ClientID clientID, LoginSessionToken loginSessionToken) {

		String callerPrincipal = request.getUserPrincipal().getName();

		SecurityContext context = SecurityContextAssociation.getSecurityContext();
		SubjectInfo subjectInfo = context.getSubjectInfo();
		Collection<Role> roles = new JBossSubjectInfo(subjectInfo).getRoles();
		List<String> roleStrings = new ArrayList<>();
		for (Role role : roles) {
			roleStrings.add(role.getRoleName());
		}

		String encryptedToken = RememberMeTokenUtil.serialize(loginSessionToken, callerPrincipal, roleStrings);

		RememberMeCookieUtil.setLoginSessionCookie(request, response, encryptedToken, clientID);
	}

	@Override
	public void destroy() {

	}

}
