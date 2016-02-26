package de.adorsys.oauth.server;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.nimbusds.oauth2.sdk.id.ClientID;
import org.apache.commons.lang3.StringUtils;

public class RememberMeCookieUtil {
	
	private static final Integer EXPIRATION = Integer.getInteger("oauth.remembercookie.expiration", 3600);
	
	public static Cookie getCookieToken(HttpServletRequest request, ClientID clientId) {
		Cookie[] cookies = request.getCookies();
		if (cookies == null) {
			return null;
		}
		for (Cookie cookie : cookies) {
			if (cookie.getName().equals("REMEMBER_" + clientId.getValue()) && StringUtils.isNotEmpty(cookie.getValue())) {
				return cookie;
			}
		}
		return null;
	}
	
	public static void setLoginSessionCookie(HttpServletRequest request, HttpServletResponse response, String encryptedToken,
			ClientID clientID) {
		Cookie cookie = new Cookie("REMEMBER_" + clientID.getValue(), encryptedToken);
		cookie.setMaxAge(EXPIRATION);
		cookie.setSecure(request.isSecure());
		response.addCookie(cookie);
	}

	public static void removeCookieToken(HttpServletRequest request, HttpServletResponse response, ClientID clientID) {
		Cookie[] cookies = request.getCookies();
		if (cookies == null) {
			return;
		}
		for (Cookie cookie : cookies) {
			if (cookie.getName().equals("REMEMBER_" + clientID.getValue())) {
                Cookie delete = new Cookie("REMEMBER_" + clientID.getValue(), "");
                delete.setMaxAge(-1);
                response.addCookie(delete);
                return;
            }
		}
	}

}
