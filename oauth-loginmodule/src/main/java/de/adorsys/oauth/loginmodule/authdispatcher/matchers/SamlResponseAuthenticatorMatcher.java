package de.adorsys.oauth.loginmodule.authdispatcher.matchers;

import javax.servlet.http.HttpServletRequest;

import org.apache.catalina.valves.ValveBase;
import org.apache.commons.lang3.StringUtils;

import de.adorsys.oauth.loginmodule.saml.SamlResponseAuthenticator;

/**
 * Check if the request matches a SAMLResponse and return the corresponding authenticator.
 * @author francis
 *
 */
public class SamlResponseAuthenticatorMatcher extends BaseAuthenticatorMatcher {

	public SamlResponseAuthenticatorMatcher() {
		super();
		valve = new SamlResponseAuthenticator();
	}

	@Override
	public ValveBase match(HttpServletRequest request) {
		// handle only POST requests. So no need to parse.
		if(!StringUtils.equalsIgnoreCase("POST", request.getMethod())) return null;
        String samlResponse = request.getParameter("SAMLResponse");
        if(StringUtils.isNoneBlank(samlResponse)) return valve;
		return null;
	}

}
