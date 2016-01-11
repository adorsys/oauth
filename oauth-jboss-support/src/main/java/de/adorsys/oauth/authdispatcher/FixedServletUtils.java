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
package de.adorsys.oauth.authdispatcher;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;

import org.apache.commons.lang3.StringUtils;

import javax.servlet.http.HttpServletRequest;

import java.io.BufferedReader;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Enumeration;
import java.util.Map;
import java.util.Map.Entry;


/**
 * HTTP servlet utilities.
 * Fixed createHTTPRequest from Nimbus ServletUtils
 */
public class FixedServletUtils {

	/**
	 * Reconstructs the request URL string for the specified servlet
	 * request. The host part is always the local IP address. The query
	 * string and fragment is always omitted.
	 *
	 * @param request The servlet request. Must not be {@code null}.
	 *
	 * @return The reconstructed request URL string.
	 */
	private static String reconstructRequestURLString(final HttpServletRequest request) {

		StringBuilder sb = new StringBuilder("http");

		if (request.isSecure())
			sb.append('s');

		sb.append("://");

		String localAddress = request.getLocalAddr();

		if (localAddress.contains(".")) {
			// IPv3 address
			sb.append(localAddress);
		} else if (localAddress.contains(":")) {
			// IPv6 address, see RFC 2732
			sb.append('[');
			sb.append(localAddress);
			sb.append(']');
		} else {
			// Don't know what to do
		}

		if (! request.isSecure() && request.getLocalPort() != 80) {
			// HTTP plain at port other than 80
			sb.append(':');
			sb.append(request.getLocalPort());
		}

		if (request.isSecure() && request.getLocalPort() != 443) {
			// HTTPS at port other than 443 (default TLS)
			sb.append(':');
			sb.append(request.getLocalPort());
		}

		String path = request.getRequestURI();

		if (path != null)
			sb.append(path);

		return sb.toString();
	}

	/**
	 * Creates a new HTTP request from the specified HTTP servlet request.
	 *
	 * @param sr The servlet request. Must not be {@code null}.
	 *
	 * @return The HTTP request.
	 *
	 * @throws IllegalArgumentException The the servlet request method is
	 *                                  not GET, POST, PUT or DELETE or the
	 *                                  content type header value couldn't
	 *                                  be parsed.
	 * @throws IOException              For a POST or PUT body that
	 *                                  couldn't be read due to an I/O
	 *                                  exception.
	 */
	public static HTTPRequest createHTTPRequest(final HttpServletRequest sr)
		throws IOException {

		return createHTTPRequest(sr, -1);
	}


	/**
	 * Creates a new HTTP request from the specified HTTP servlet request.
	 *
	 * @param sr              The servlet request. Must not be
	 *                        {@code null}.
	 * @param maxEntityLength The maximum entity length to accept, -1 for
	 *                        no limit.
	 *
	 * @return The HTTP request.
	 *
	 * @throws IllegalArgumentException The the servlet request method is
	 *                                  not GET, POST, PUT or DELETE or the
	 *                                  content type header value couldn't
	 *                                  be parsed.
	 * @throws IOException              For a POST or PUT body that
	 *                                  couldn't be read due to an I/O
	 *                                  exception.
	 */
	public static HTTPRequest createHTTPRequest(final HttpServletRequest sr, final long maxEntityLength)
		throws IOException {

		HTTPRequest.Method method = HTTPRequest.Method.valueOf(sr.getMethod().toUpperCase());

		String urlString = reconstructRequestURLString(sr);

		URL url;

		try {
			url = new URL(urlString);

		} catch (MalformedURLException e) {

			throw new IllegalArgumentException("Invalid request URL: " + e.getMessage() + ": " + urlString, e);
		}

		HTTPRequest request = new HTTPRequest(method, url);

		try {
			request.setContentType(sr.getContentType());

		} catch (ParseException e) {

			throw new IllegalArgumentException("Invalid Content-Type header value: " + e.getMessage(), e);
		}

		Enumeration<String> headerNames = sr.getHeaderNames();

		while (headerNames.hasMoreElements()) {
			final String headerName = headerNames.nextElement();
			request.setHeader(headerName, sr.getHeader(headerName));
		}

		if (method.equals(HTTPRequest.Method.GET) || method.equals(HTTPRequest.Method.DELETE)) {

			request.setQuery(sr.getQueryString());

		} else if (method.equals(HTTPRequest.Method.POST) || method.equals(HTTPRequest.Method.PUT)) {

			if (maxEntityLength > 0 && sr.getContentLength() > maxEntityLength) {
				throw new IOException("Request entity body is too large, limit is " + maxEntityLength + " chars");
			}
			
			Map<String, String[]> parameterMap = sr.getParameterMap();
			StringBuilder builder = new StringBuilder();

			if (!parameterMap.isEmpty()) {
				for (Entry<String, String[]> entry : parameterMap.entrySet()) {
					String key = entry.getKey();
					String[] value = entry.getValue();
					if (value.length > 0) {
						builder = builder.append(key).append('=').append(value[0]).append('&');
					}
				}
				String queryString = StringUtils.substringBeforeLast(builder.toString(), "&");
				request.setQuery(queryString);

			} else {
				// read body
				StringBuilder body = new StringBuilder(256);
	
				BufferedReader reader = sr.getReader();
	
				char[] cbuf = new char[256];
	
				int readChars;
	
				while ((readChars = reader.read(cbuf)) != -1) {
	
					body.append(cbuf, 0, readChars);
	
					if (maxEntityLength > 0 && body.length() > maxEntityLength) {
						throw new IOException("Request entity body is too large, limit is " + maxEntityLength + " chars");
					}
				}
	
				reader.close();
	
				request.setQuery(body.toString());
			}
		}

		return request;
	}

}
