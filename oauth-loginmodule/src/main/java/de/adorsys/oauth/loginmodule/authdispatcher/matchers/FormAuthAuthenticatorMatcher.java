package de.adorsys.oauth.loginmodule.authdispatcher.matchers;

import javax.servlet.http.HttpServletRequest;

import org.apache.catalina.valves.ValveBase;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.AuthorizationRequest;

import de.adorsys.oauth.loginmodule.authdispatcher.StatelessFormAuthenticator;
import de.adorsys.oauth.loginmodule.clientid.AuthorizationRequestUtil;

public class FormAuthAuthenticatorMatcher extends BaseAuthenticatorMatcher {

	private static final Logger LOG = LoggerFactory.getLogger(FormAuthAuthenticatorMatcher.class);

	public FormAuthAuthenticatorMatcher() {
		super();
		valve = new StatelessFormAuthenticator();
	}

	@Override
	public ValveBase match(HttpServletRequest request) {
		// handle only get requests. So no need to parse.
		if(!StringUtils.equalsIgnoreCase("GET", request.getMethod())) return null;
		AuthorizationRequest authRequest = AuthorizationRequestUtil.resolveAuthorizationRequest(request);
		if(authRequest != null && request.getParameter("formlogin") != null){
			return valve;
		}
		return null;
	}

}
