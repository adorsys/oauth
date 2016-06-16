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

import java.security.Principal;
import java.util.Collection;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import javax.security.jacc.PolicyContext;
import javax.security.jacc.PolicyContextException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ParseException;

/**
 * HTTPAuthenticationLoginModule
 */
public class RememberMeLoginModule implements LoginModule {

	private static final Logger LOG = LoggerFactory.getLogger(RememberMeLoginModule.class);

	private Subject subject;
	private CallbackHandler callbackHandler;
	private Map<String, Object> sharedState;

	private Collection<Principal> preparedPrincipals;
	
	HttpServletRequest request;
	HttpServletResponse response;
	
	@SuppressWarnings("unchecked")
	@Override
	public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState, Map<String, ?> options) {
		this.subject = subject;
		this.callbackHandler = callbackHandler;
		this.sharedState = (Map<String, Object>) sharedState;
		try {
			request = (HttpServletRequest) PolicyContext.getContext(HttpServletRequest.class.getName());
		} catch (PolicyContextException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		try {
			response = (HttpServletResponse) PolicyContext.getContext(HttpServletResponse.class.getName());
		} catch (PolicyContextException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		if (request == null) {
			LOG.error("PolicyContext.getContext(HttpServletRequest.class.getName()) null");
		}
		if (response == null) {
			LOG.error("PolicyContext.getContext(HttpServletResponse.class.getName() null");
		}
		
	}

	@Override
	public boolean login() throws LoginException {
		if(!request.getRequestURI().endsWith("/auth")) {
			return false;
		}
		AuthorizationRequest authorizationRequest;
		try {
			authorizationRequest = AuthorizationRequest.parse(request.getQueryString());
		} catch (ParseException e) {
			return false;
		}
		
		Cookie serializedToken = RememberMeCookieUtil.getCookieToken(request, authorizationRequest.getClientID());
		if (serializedToken != null) {
			preparedPrincipals = RememberMeTokenUtil.deserialize(serializedToken.getValue());
			if (preparedPrincipals == null) {
				RememberMeCookieUtil.removeCookieToken(request, response, authorizationRequest.getClientID());
			}
			return true;
		}
		return false;
	}

	@Override
	public boolean commit() throws LoginException {
		if (preparedPrincipals != null) {
			subject.getPrincipals().addAll(preparedPrincipals);
            return true; // sufficient
		}
		return false; // ignore
	}

	@Override
	public boolean abort() throws LoginException {
		return logout();
	}

	@Override
	public boolean logout() throws LoginException {
		this.subject = null;
		preparedPrincipals = null;
		return true;
	}

}
