package de.adorsys.oauth.loginmodule.authdispatcher.matchers;

import javax.servlet.http.HttpServletRequest;

import org.apache.catalina.valves.ValveBase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.AuthorizationRequest;

import de.adorsys.oauth.loginmodule.authdispatcher.OAuthAuthenticationDispatcher;
import de.adorsys.oauth.loginmodule.clientid.AuthorizationRequestUtil;

public class FormAuthAuthenticatorMatcher extends BaseAuthenticatorMatcher {

	private static final Logger LOG = LoggerFactory.getLogger(FormAuthAuthenticatorMatcher.class);

	public FormAuthAuthenticatorMatcher() {
		super();
		try {
			valve = (ValveBase)OAuthAuthenticationDispatcher.class.getClassLoader().loadClass("de.adorsys.oauth.loginmodule.authdispatcher.StatelessFormAuthenticator").newInstance();
		} catch (Exception e) {
			LOG.error("Can not load authenticator", e);
			throw new IllegalStateException(e);
		}
	}

	@Override
	public ValveBase match(HttpServletRequest request) {
		AuthorizationRequest authRequest = AuthorizationRequestUtil.resolveAuthorizationRequest(request);
		if(authRequest != null && request.getParameter("formlogin") != null){
			return valve;
		}
		return null;
	}

}
