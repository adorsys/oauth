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
package de.adorsys.oauth.loginmodule.authdispatcher.matchers;

import javax.servlet.http.HttpServletRequest;

import org.apache.catalina.valves.ValveBase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.AuthorizationRequest;

import de.adorsys.oauth.loginmodule.authdispatcher.StatelessFormAuthenticator;
import de.adorsys.oauth.loginmodule.clientid.AuthorizationRequestUtil;

public class FormAuthAuthenticatorMatcher extends BaseAuthenticatorMatcher {

	private static final Logger LOG = LoggerFactory.getLogger(FormAuthAuthenticatorMatcher.class);

	public FormAuthAuthenticatorMatcher() {
		super();
		valve = new StatelessFormAuthenticator();
	}

	@Override
	public ValveBase match(HttpServletRequest request) {
		// handle only get requests. So no need to parse.
//		if(!StringUtils.equalsIgnoreCase("GET", request.getMethod())) return null;
		AuthorizationRequest authRequest = AuthorizationRequestUtil.resolveAuthorizationRequest(request);
		if(authRequest != null && request.getParameter("formlogin") != null){
			return valve;
		}
		return null;
	}

}
