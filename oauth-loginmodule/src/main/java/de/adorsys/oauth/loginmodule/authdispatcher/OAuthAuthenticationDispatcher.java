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

import de.adorsys.oauth.loginmodule.authdispatcher.matchers.BasicAuthAuthenticatorMatcher;
import de.adorsys.oauth.loginmodule.authdispatcher.matchers.ClientIdBasedAuthenticatorMatcher;
import de.adorsys.oauth.loginmodule.authdispatcher.matchers.FormAuthAuthenticatorMatcher;

/**
 * @author sso
 *
 */
public class OAuthAuthenticationDispatcher extends ValveBase {
	
	private List<AuthenticatorMatcher> mapperList = new ArrayList<AuthenticatorMatcher>();
	
	public OAuthAuthenticationDispatcher() throws InstantiationException, IllegalAccessException, ClassNotFoundException {
		mapperList.add(new ClientIdBasedAuthenticatorMatcher());
		mapperList.add(new FormAuthAuthenticatorMatcher());
		mapperList.add(new BasicAuthAuthenticatorMatcher());
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
	    				break;
	    			}
	    		}
	        } finally {
	        	HttpContext.release();
	        }
		}
		getNext().invoke(request, response);
	}
}
