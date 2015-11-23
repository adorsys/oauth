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
package de.adorsys.oauth.loginmodule.clientid;

import javax.servlet.http.HttpServletRequest;

import com.nimbusds.oauth2.sdk.AuthorizationRequest;

import de.adorsys.oauth.loginmodule.util.FixedServletUtils;

/**
 * @author Sandro Sonntag
 *
 */
public final class AuthorizationRequestUtil {
	private AuthorizationRequestUtil() {
	}
	
	public static AuthorizationRequest resolveAuthorizationRequest(HttpServletRequest servletRequest)  {
        try {
            return AuthorizationRequest.parse(FixedServletUtils.createHTTPRequest(servletRequest));
        } catch (Exception e) {
            // ignore
        }
        // sometimes during some redirections or idp chaining we get an POST with query string
        String query = servletRequest.getQueryString();
        try {
            return AuthorizationRequest.parse(query);
        } catch (Exception e) {
            // ignore
        }
        return null;
    }

}
