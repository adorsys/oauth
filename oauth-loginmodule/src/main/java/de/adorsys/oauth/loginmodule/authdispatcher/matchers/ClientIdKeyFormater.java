package de.adorsys.oauth.loginmodule.authdispatcher.matchers;

/**
 * Format client id in a way displayable in env property keys. 
 * 
 * @author francis
 *
 */
public class ClientIdKeyFormater {
	private static final String AUTHENTICATOR_SUFFIX = "_AUTH";

	public String format(String clientId){
		return clientId.replace('.', '_') + AUTHENTICATOR_SUFFIX;
	}
}
