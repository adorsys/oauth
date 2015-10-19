/**
 * 
 */
package de.adorsys.oauth.loginmodule.authdispatcher;

import java.io.IOException;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import javax.management.ObjectName;
import javax.security.jacc.PolicyContext;
import javax.security.jacc.PolicyContextException;
import javax.security.jacc.PolicyContextHandler;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.catalina.Container;
import org.apache.catalina.Valve;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;

import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.http.ServletUtils;

import de.adorsys.oauth.loginmodule.clientid.AuthorizationRequestUtil;

/**
 * @author sso
 *
 */
public class OAuthAuthenticationDispatcher extends ValveBase {
	
	private interface AuthenticatorMatcher {
		public boolean match(HttpServletRequest request);
	}
	
	private Map<AuthenticatorMatcher, ValveBase> mapper = new HashMap<>(); 
	
	public OAuthAuthenticationDispatcher() throws InstantiationException, IllegalAccessException, ClassNotFoundException {
		mapper.put(new AuthenticatorMatcher() {

			@Override
			public boolean match(HttpServletRequest request) {
				AuthorizationRequest authRequest = AuthorizationRequestUtil.resolveAuthorizationRequest(request);
				return authRequest != null;
			}
			
		}, (ValveBase)OAuthAuthenticationDispatcher.class.getClassLoader().loadClass("org.apache.catalina.authenticator.FormAuthenticator").newInstance());
		mapper.put(new AuthenticatorMatcher() {

			@Override
			public boolean match(HttpServletRequest request) {
				try {
					TokenRequest tokenRequest = TokenRequest.parse(ServletUtils.createHTTPRequest(request));
					return tokenRequest.getAuthorizationGrant().getType() == GrantType.PASSWORD;
				} catch (ParseException e) {
					return false;
				} catch (IOException e) {
					return false;
				}
			}
			
		}, (ValveBase)OAuthAuthenticationDispatcher.class.getClassLoader().loadClass("org.apache.catalina.authenticator.BasicAuthenticator").newInstance());
	}
	
	@Override
	public void setNext(Valve valve) {
		super.setNext(valve);
		Set<Entry<AuthenticatorMatcher,ValveBase>> entrySet = mapper.entrySet();
		for (Entry<AuthenticatorMatcher, ValveBase> entry : entrySet) {
			entry.getValue().setNext(valve);
		}
	}
	@Override
	public void setContainer(Container container) {
		super.setContainer(container);
		Set<Entry<AuthenticatorMatcher,ValveBase>> entrySet = mapper.entrySet();
		for (Entry<AuthenticatorMatcher, ValveBase> entry : entrySet) {
			entry.getValue().setContainer(container);
		}
	}
	@Override
	public void setController(ObjectName controller) {
		super.setContainer(container);
		Set<Entry<AuthenticatorMatcher,ValveBase>> entrySet = mapper.entrySet();
		for (Entry<AuthenticatorMatcher, ValveBase> entry : entrySet) {
			entry.getValue().setController(controller);
		}
	}
	@Override
	public void setObjectName(ObjectName oname) {
		super.setContainer(container);
		Set<Entry<AuthenticatorMatcher,ValveBase>> entrySet = mapper.entrySet();
		for (Entry<AuthenticatorMatcher, ValveBase> entry : entrySet) {
			entry.getValue().setObjectName(oname);
		}
	}

	/* (non-Javadoc)
	 * @see org.apache.catalina.valves.ValveBase#invoke(org.apache.catalina.connector.Request, org.apache.catalina.connector.Response)
	 */
	@Override
	public void invoke(final Request request, final Response response) throws IOException, ServletException {
		Principal principal = request.getPrincipal();
		if (principal == null) {
			// force catalina to parse parameters and content now, otherwise sometimes the content is lost ...
	        request.getParameterNames();

	        try {
	        	HttpContext.init(request, response);
				
				Set<Entry<AuthenticatorMatcher,ValveBase>> entrySet = mapper.entrySet();
				for (Entry<AuthenticatorMatcher, ValveBase> entry : entrySet) {
					if (entry.getKey().match(request)) {
						entry.getValue().invoke(request, response);
						return;
					}
				}
	        } finally {
	        	HttpContext.release();
	        }
		}
		getNext().invoke(request, response);
	}
}
