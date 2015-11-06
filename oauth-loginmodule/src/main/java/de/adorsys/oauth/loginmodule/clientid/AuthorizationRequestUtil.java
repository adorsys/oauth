/**
 * 
 */
package de.adorsys.oauth.loginmodule.clientid;

import javax.servlet.http.HttpServletRequest;

import com.nimbusds.oauth2.sdk.AuthorizationRequest;

import de.adorsys.oauth.loginmodule.authdispatcher.FixedServletUtils;

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
