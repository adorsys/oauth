package de.adorsys.oauth.loginmodule.authdispatcher.matchers;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.apache.catalina.valves.ValveBase;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;

import de.adorsys.oauth.loginmodule.authdispatcher.AuthenticatorMatcher;
import de.adorsys.oauth.loginmodule.clientid.AuthorizationRequestUtil;
import de.adorsys.oauth.loginmodule.saml.SamlRequestAuthenticator;
import de.adorsys.oauth.loginmodule.util.EnvUtils;

/**
 * Registers authenticators to match request based on the client id.
 * 
 * @author francis pouatcha
 *
 */
public class ClientIdBasedAuthenticatorMatcher implements AuthenticatorMatcher {
	
	private static final String AUTH_CLIENTID_AUTHENTICATORS = "AUTH_CLIENTID_AUTHENTICATORS";
	private static final String AUTH_CLIENTID_FORMATER = "AUTH_CLIENTID_FORMATER";
	private static final Logger LOG = LoggerFactory.getLogger(BasicAuthAuthenticatorMatcher.class);
	Map<String, ValveBase> configuredAuthenticators = new HashMap<String, ValveBase>();
	private ClientIdKeyFormater keyFormater;
	
	private EnvUtils envUtils = new EnvUtils();
	
	public ClientIdBasedAuthenticatorMatcher() {
		super();
		initAuthenticators();
		setupClientIdKeyFormater();
		setupClientIdAuthenticators();
	}
	
	@Override
	public ValveBase match(HttpServletRequest request) {
		AuthorizationRequest authorizationRequest = AuthorizationRequestUtil.resolveAuthorizationRequest(request);
		if(authorizationRequest==null) return null;
		ClientID clientID = authorizationRequest.getClientID();
		String clientIdStr = clientID.getValue();
		String formatedClientIdKey = keyFormater.format(clientIdStr);
		return configuredAuthenticators.get(formatedClientIdKey);
	}
	@Override
	public List<ValveBase> valves() {
		return new ArrayList<ValveBase>(configuredAuthenticators.values());
	}

	private void setupClientIdKeyFormater(){
		String formaterClassName = envUtils.getEnv(AUTH_CLIENTID_FORMATER, null);
		if(StringUtils.isNotBlank(formaterClassName)){
			try {
				Class<?> loadClass = ClientIdBasedAuthenticatorMatcher.class.getClassLoader().loadClass(formaterClassName);
				keyFormater = (ClientIdKeyFormater) loadClass.newInstance();
			} catch (Exception e) {
				LOG.error("Can not instantiate specified clientId key formater : " + formaterClassName, e);
				throw new IllegalStateException(e);
			}
		} else {
			keyFormater = new ClientIdKeyFormater();
		}		
	}
	
	private void setupClientIdAuthenticators(){
		String clientIds = envUtils.getEnv(AUTH_CLIENTID_AUTHENTICATORS, null);
		String[] split = StringUtils.split(clientIds, ',');
		if(split==null)return;
		for (String formatedClientIdStr : split) {
			String clientIdAuthClass = envUtils.getEnv(formatedClientIdStr, null);
			if(StringUtils.isBlank(clientIdAuthClass)){
				throw new IllegalStateException("Missing property: " + clientIdAuthClass); 
			}
			ValveBase valveBase = registeredAuthenticators.get(clientIdAuthClass);
			if(valveBase==null){
				LOG.error("Can not load authenticator class");
				throw new IllegalStateException("Unknown valve: " + clientIdAuthClass); 
			}
			configuredAuthenticators.put(formatedClientIdStr, valveBase);
		}
	}
	
	private Map<String, ValveBase> registeredAuthenticators = new HashMap<String, ValveBase>();
	private void initAuthenticators() {
		registeredAuthenticators.put(SamlRequestAuthenticator.class.getName(), new SamlRequestAuthenticator());
	}	
}
