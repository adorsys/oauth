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
