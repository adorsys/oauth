package de.adorsys.oauth.loginmodule.authdispatcher.matchers;

import javax.servlet.http.HttpServletRequest;

import org.apache.catalina.valves.ValveBase;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.TokenRequest;

import de.adorsys.oauth.loginmodule.authdispatcher.FixedServletUtils;

public class BasicAuthAuthenticatorMatcher extends BaseAuthenticatorMatcher {
	private static final Logger LOG = LoggerFactory.getLogger(BasicAuthAuthenticatorMatcher.class);

	public BasicAuthAuthenticatorMatcher() {
		try {
			valve = (ValveBase)BasicAuthAuthenticatorMatcher.class.getClassLoader().loadClass("org.apache.catalina.authenticator.BasicAuthenticator").newInstance();
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
	}


	@Override
	public ValveBase match(HttpServletRequest request) {
		// Deals only with POST Requests. So no need to match others.
		// @See com.nimbusds.oauth2.sdk.TokenRequest.parse(HTTPRequest)
		if(!StringUtils.equalsIgnoreCase("POST", request.getMethod())) return null;
		try {
			TokenRequest tokenRequest = TokenRequest.parse(FixedServletUtils.createHTTPRequest(request));
			if(tokenRequest.getAuthorizationGrant().getType() == GrantType.PASSWORD){
				return valve;
			}
			return null;
		} catch (Exception e) {
			LOG.warn("Can not load authenticator", e);
			return null;
		}
	}
}
