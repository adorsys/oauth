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
package de.adorsys.oauth.client.jaas;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author sso
 *
 */
public class HttpContext {
	
	public static final ThreadLocal<HttpServletRequest> SERVLET_REQUEST = new ThreadLocal<>();
	public static final ThreadLocal<HttpServletResponse> SERVLET_RESPONSE = new ThreadLocal<>();
	
	public static void init(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) {
		SERVLET_REQUEST.set(httpServletRequest);
		SERVLET_RESPONSE.set(httpServletResponse);
	}
	
	public static void release() {
		SERVLET_REQUEST.remove();
		SERVLET_RESPONSE.remove();
	}

}
