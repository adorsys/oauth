package de.adorsys.oauth.loginmodule.authdispatcher;

import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.apache.catalina.valves.ValveBase;

public interface AuthenticatorMatcher {
	public ValveBase match(HttpServletRequest request);
	public List<ValveBase> valves();
}
