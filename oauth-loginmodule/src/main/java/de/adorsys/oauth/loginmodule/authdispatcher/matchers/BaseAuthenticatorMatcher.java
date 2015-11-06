package de.adorsys.oauth.loginmodule.authdispatcher.matchers;

import java.util.Arrays;
import java.util.List;

import org.apache.catalina.valves.ValveBase;

import de.adorsys.oauth.loginmodule.authdispatcher.AuthenticatorMatcher;

public abstract class BaseAuthenticatorMatcher implements AuthenticatorMatcher {

	protected ValveBase valve = null;

	@Override
	public List<ValveBase> valves() {
		return Arrays.asList(valve);
	}
	
}
