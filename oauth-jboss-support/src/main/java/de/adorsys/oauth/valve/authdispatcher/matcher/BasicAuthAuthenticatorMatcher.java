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

import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.TokenRequest;

import de.adorsys.oauth.valve.authdispatcher.FixedServletUtils;

import org.apache.catalina.valves.ValveBase;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;

import java.util.Collections;

public class BasicAuthAuthenticatorMatcher extends BaseAuthenticatorMatcher {

	private static final Logger LOG = LoggerFactory.getLogger(BasicAuthAuthenticatorMatcher.class);

	public BasicAuthAuthenticatorMatcher() {
		try {
			valve = (ValveBase) BasicAuthAuthenticatorMatcher.class.getClassLoader().loadClass("org.apache.catalina.authenticator.BasicAuthenticator").newInstance();
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
	}


	@Override
	public ValveBase match(HttpServletRequest request, AuthorizationRequest authorizationRequest) {
        // Real basic auth header
        if (isBasicAuthentication(request)) {
            return valve;
        }

		// Deals only with POST Requests. So no need to match others.
		// @See com.nimbusds.oauth2.sdk.TokenRequest.parse(HTTPRequest)
		if (!StringUtils.equalsIgnoreCase("POST", request.getMethod())) {
            return null;
        }

        try {
            TokenRequest tokenRequest = TokenRequest.parse(FixedServletUtils.createHTTPRequest(request));
            if (tokenRequest.getAuthorizationGrant().getType() == GrantType.PASSWORD) {
                return valve;
            }
        } catch (Exception e) {
            LOG.warn("Can not load authenticator", e);
        }

        return null;
	}

    private static boolean isBasicAuthentication(HttpServletRequest httpServletRequest) {
        for (String name : Collections.list(httpServletRequest.getHeaderNames())) {
            if ("authorization".equalsIgnoreCase(name)) {
                return httpServletRequest.getHeader(name).substring(0, 5).equalsIgnoreCase("Basic");
            }
        }

        return false;

    }
}
