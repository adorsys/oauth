package de.adorsys.oauth.loginmodule.authdispatcher.matchers;

/**
 * Format client id in a way displayable in env property keys. 
 * 
 * @author francis
 *
 */
public class ClientIdKeyFormater {
	private static final String AUTHENTICATOR_PREFIX = "authenticator_";

	public String format(String clientId){
		return AUTHENTICATOR_PREFIX + clientId.replace('.', '_');
	}
}
