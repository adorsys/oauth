/**
 * 
 */
package de.adorsys.oauth.loginmodule.authdispatcher;

import java.io.IOException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;

import javax.management.ObjectName;
import javax.servlet.ServletException;

import org.apache.catalina.Container;
import org.apache.catalina.Valve;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.apache.commons.lang.StringUtils;

import de.adorsys.oauth.loginmodule.authdispatcher.matchers.BasicAuthAuthenticatorMatcher;
import de.adorsys.oauth.loginmodule.authdispatcher.matchers.ClientIdBasedAuthenticatorMatcher;
import de.adorsys.oauth.loginmodule.authdispatcher.matchers.FormAuthAuthenticatorMatcher;
import de.adorsys.oauth.loginmodule.authdispatcher.matchers.SamlResponseAuthenticatorMatcher;
import de.adorsys.oauth.loginmodule.util.EnvUtils;

/**
 * @author sso
 *
 */
public class OAuthAuthenticationDispatcher extends ValveBase {
	
	public static final String AUTH_AUTHENTICATORS = "AUTH_AUTHENTICATORS";
	private List<AuthenticatorMatcher> mapperList = new ArrayList<AuthenticatorMatcher>();
	EnvUtils envUtils = new EnvUtils();
	
	public OAuthAuthenticationDispatcher() {
		// Matcher list can be defined as system properties in standalone.xml
		String authenticators = envUtils.getEnv(AUTH_AUTHENTICATORS, null);
		if(StringUtils.isNotBlank(authenticators)){
			mapperList = toMatcherList(authenticators);
		} else {
			mapperList = defaultMatcherList();
		}
	}
	
	@Override
	public void setNext(Valve valve) {
		super.setNext(valve);
		for (AuthenticatorMatcher authenticatorMatcher : mapperList) {
			List<ValveBase> valves = authenticatorMatcher.valves();
			for (ValveBase valveBase : valves) {
				valveBase.setNext(valve);
			}
		}
	}
	@Override
	public void setContainer(Container container) {
		super.setContainer(container);
		for (AuthenticatorMatcher authenticatorMatcher : mapperList) {
			List<ValveBase> valves = authenticatorMatcher.valves();
			for (ValveBase valveBase : valves) {
				valveBase.setContainer(container);
			}
		}
	}
	@Override
	public void setController(ObjectName controller) {
		super.setContainer(container);
		for (AuthenticatorMatcher authenticatorMatcher : mapperList) {
			List<ValveBase> valves = authenticatorMatcher.valves();
			for (ValveBase valveBase : valves) {
				valveBase.setController(controller);
			}
		}
	}
	
	@Override
	public void setObjectName(ObjectName oname) {
		super.setContainer(container);
		for (AuthenticatorMatcher authenticatorMatcher : mapperList) {
			List<ValveBase> valves = authenticatorMatcher.valves();
			for (ValveBase valveBase : valves) {
				valveBase.setObjectName(oname);
			}
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
	    		for (AuthenticatorMatcher authenticatorMatcher : mapperList) {
	    			ValveBase valveBase = authenticatorMatcher.match(request);
	    			if(valveBase!=null){
	    				valveBase.invoke(request, response);
	    				return;
	    			}
	    		}
	        } finally {
	        	HttpContext.release();
	        }
		}
		// Called by the invoked valve.
		// only invoke next if response still open.
		getNext().invoke(request, response);
	}

	private List<AuthenticatorMatcher> defaultMatcherList(){
		List<AuthenticatorMatcher> list = new ArrayList<AuthenticatorMatcher>();
		list.add(new FormAuthAuthenticatorMatcher());
		list.add(new BasicAuthAuthenticatorMatcher());
		return list;
	}
	
	private List<AuthenticatorMatcher> toMatcherList(String matchers){
		String[] matcherList = StringUtils.split(matchers,',');
		List<AuthenticatorMatcher> list = new ArrayList<AuthenticatorMatcher>();
		for (String matcher : matcherList) {
			if(ClientIdBasedAuthenticatorMatcher.class.getSimpleName().equals(matcher))
				list.add(new ClientIdBasedAuthenticatorMatcher());
			if(SamlResponseAuthenticatorMatcher.class.getSimpleName().equals(matcher))
				list.add(new SamlResponseAuthenticatorMatcher());
			if(FormAuthAuthenticatorMatcher.class.getSimpleName().equals(matcher))
				list.add(new FormAuthAuthenticatorMatcher());
			if(BasicAuthAuthenticatorMatcher.class.getSimpleName().equals(matcher))
				list.add(new BasicAuthAuthenticatorMatcher());
		}
		return list;
	}
}
