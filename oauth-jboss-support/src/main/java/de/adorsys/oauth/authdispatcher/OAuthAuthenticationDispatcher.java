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
/**
 * 
 */

package de.adorsys.oauth.authdispatcher;

import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;

import de.adorsys.oauth.authdispatcher.matcher.BasicAuthAuthenticatorMatcher;
import de.adorsys.oauth.authdispatcher.matcher.FormAuthAuthenticatorMatcher;

import org.apache.catalina.Container;
import org.apache.catalina.Valve;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.management.ObjectName;
import javax.security.jacc.PolicyContext;
import javax.security.jacc.PolicyContextException;
import javax.security.jacc.PolicyContextHandler;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;

/**
 * @author sso
 *
 */
public class OAuthAuthenticationDispatcher extends ValveBase implements PolicyContextHandler {

	private static final Logger LOG = LoggerFactory.getLogger(OAuthAuthenticationDispatcher.class);

	private List<AuthenticatorMatcher> matchers;

	private static final String[] SUPPORTED_CONTEXT = {
			HttpServletRequest.class.getName(),
			HttpServletResponse.class.getName(),
			AuthorizationRequest.class.getName(),
			TokenRequest.class.getName()
	};

	private static ThreadLocal<Map<String, Object>> contextData = new ThreadLocal<Map<String, Object>>() {
		@Override
		protected Map<String, Object> initialValue() {
			return new HashMap<>();
		}
	};

	public OAuthAuthenticationDispatcher() {
		matchers = resolveMatcher();

		for (String key : SUPPORTED_CONTEXT) {
			try {
				PolicyContext.registerHandler(key, this, false);
			} catch (Exception e) {
				LOG.debug(e.getClass().getSimpleName() + " " + e.getMessage());
			}
		}
	}

	@Override
	public void setNext(Valve valve) {
		super.setNext(valve);
		for (AuthenticatorMatcher authenticatorMatcher : matchers) {
			for (ValveBase valveBase : authenticatorMatcher.valves()) {
				valveBase.setNext(valve);
			}
		}
	}

	@Override
	public void setContainer(Container container) {
		super.setContainer(container);
		for (AuthenticatorMatcher authenticatorMatcher : matchers) {
			for (ValveBase valveBase : authenticatorMatcher.valves()) {
				valveBase.setContainer(container);
			}
		}
	}

	@Override
	public void setController(ObjectName controller) {
		super.setContainer(container);
		for (AuthenticatorMatcher authenticatorMatcher : matchers) {
			for (ValveBase valveBase : authenticatorMatcher.valves()) {
				valveBase.setController(controller);
			}
		}
	}

	@Override
	public void setObjectName(ObjectName oname) {
		super.setContainer(container);
		for (AuthenticatorMatcher authenticatorMatcher : matchers) {
			for (ValveBase valveBase : authenticatorMatcher.valves()) {
				valveBase.setObjectName(oname);
			}
		}
	}

	@Override
	public void invoke(final Request request, final Response response) throws IOException, ServletException {

		Principal principal = request.getPrincipal();
		if (principal != null) {
			getNext().invoke(request, response);
			return;
		}

		request.setCharacterEncoding("utf-8");

		// force catalina to parse parameters and content now, otherwise sometimes the content is lost ...
		request.getParameterNames();

		HTTPRequest httpRequest = FixedServletUtils.createHTTPRequest(request);
		AuthorizationRequest authorizationRequest = resolveAuthorizationRequest(httpRequest);
		TokenRequest tokenRequest = resolveTokenRequest(httpRequest);


		store(HttpServletRequest.class.getName(), request)
				.store(HttpServletResponse.class.getName(), response)
				.store(AuthorizationRequest.class.getName(), authorizationRequest)
				.store(TokenRequest.class.getName(), tokenRequest);

		String authenticator = null;
		try {
			for (AuthenticatorMatcher authenticatorMatcher : matchers) {
				ValveBase valveBase = authenticatorMatcher.match(request, authorizationRequest);
				if (valveBase != null) {
					authenticator = authenticatorMatcher.getClass().getSimpleName();
					valveBase.invoke(request, response);
					LOG.debug("use {}, principal = {}", authenticator, request.getPrincipal());
					return;
				}
			}
			LOG.debug("no authentificator found for {}", request.getDecodedRequestURI());
		} catch (Exception e) {
			LOG.error("error during calling {}: {} {}", authenticator, e.getClass().getSimpleName(), e.getMessage());
		}
		finally {
			for (String key : SUPPORTED_CONTEXT) {
				contextData.get().remove(key);
			}
		}

		getNext().invoke(request, response);
	}

	private OAuthAuthenticationDispatcher store(String key, Object value) {
		if (value != null) {
			contextData.get().put(key, value);
		}
		return this;
	}

	private List<AuthenticatorMatcher> resolveMatcher() {
		List<AuthenticatorMatcher> list = new ArrayList<>();
		try {
			ServiceLoader<AuthenticatorMatcher> loader = ServiceLoader.load(AuthenticatorMatcher.class);
			for (AuthenticatorMatcher matcher : loader) {
				list.add(matcher);
			}
		} catch (Exception e) {
			LOG.error(e.getClass().getSimpleName() + " " + e.getMessage());
		}

		if (list.isEmpty()) {
			list.add(new FormAuthAuthenticatorMatcher());
			list.add(new BasicAuthAuthenticatorMatcher());
		}
		return list;
	}

	private AuthorizationRequest resolveAuthorizationRequest(HTTPRequest httpRequest)  {
		try {
			return AuthorizationRequest.parse(httpRequest);
		} catch (Exception e) {
			// ignore
		}

		// sometimes during some redirections or idp chaining we get an POST with query string
		try {
			return AuthorizationRequest.parse(httpRequest.getQuery());
		} catch (Exception e) {
			// ignore
		}

		return null;
	}

	private TokenRequest resolveTokenRequest(HTTPRequest httpRequest) {
		try {
			return TokenRequest.parse(httpRequest);
		} catch (Exception e) {
			//
		}
		return null;
	}

	/// PolicyContextHandler

	@Override
	public Object getContext(String key, Object data) throws PolicyContextException {
		return contextData.get().get(key);
	}

	@Override
	public String[] getKeys() throws PolicyContextException {
		return new String[] { HttpServletRequest.class.getName(), HttpServletResponse.class.getName()};
	}

	@Override
	public boolean supports(String key) throws PolicyContextException {
		for (String supported : SUPPORTED_CONTEXT) {
			if (supported.equals(key)) {
				return true;
			}
		}
		return false;
	}
}
