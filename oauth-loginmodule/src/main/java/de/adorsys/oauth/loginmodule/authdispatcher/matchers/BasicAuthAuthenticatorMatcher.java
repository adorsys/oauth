package de.adorsys.oauth.loginmodule.authdispatcher.matchers;

import javax.servlet.http.HttpServletRequest;

import org.apache.catalina.valves.ValveBase;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.TokenRequest;

import de.adorsys.oauth.loginmodule.util.FixedServletUtils;

import java.util.Collections;

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
        // Real basic auth header
        if (isBasicAuthentication(request)) {
            return valve;
        }

		// Deals only with POST Requests. So no need to match others.
		// @See com.nimbusds.oauth2.sdk.TokenRequest.parse(HTTPRequest)
		if(StringUtils.equalsIgnoreCase("POST", request.getMethod())) {
            try {
                TokenRequest tokenRequest = TokenRequest.parse(FixedServletUtils.createHTTPRequest(request));
                if (tokenRequest.getAuthorizationGrant().getType() == GrantType.PASSWORD) {
                    return valve;
                }
                return null;
            } catch (Exception e) {
                LOG.warn("Can not load authenticator", e);
                return null;
            }
        }

        return null;
	}

    private static boolean isBasicAuthentication(HttpServletRequest httpServletRequest) {
        String authHeader = null;

        for (String name : Collections.list(httpServletRequest.getHeaderNames())) {
            if ("authorization".equalsIgnoreCase(name)) {
                authHeader = httpServletRequest.getHeader(name);
                break;
            }
        }

        if (StringUtils.isNotEmpty(authHeader) && authHeader.substring(0,5).equalsIgnoreCase("Basic")) {
            return true;
        }

        return false;
    }
}
