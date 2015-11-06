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

public class ClientIdBasedAuthenticatorMatcher implements AuthenticatorMatcher {
	private static final String AUTH_CLIENTID_AUTHENTICATORS = "AUTH_CLIENTID_AUTHENTICATORS";
	private static final String AUTH_CLIENTID_FORMATER = "AUTH_CLIENTID_FORMATER";
	private static final Logger LOG = LoggerFactory.getLogger(BasicAuthAuthenticatorMatcher.class);
	Map<String, ValveBase> authenticator = new HashMap<String, ValveBase>();
	private ClientIdKeyFormater keyFormater;
	public ClientIdBasedAuthenticatorMatcher() {
		super();
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
		return authenticator.get(formatedClientIdKey);
	}
	@Override
	public List<ValveBase> valves() {
		return new ArrayList<ValveBase>(authenticator.values());
	}

	private String getEnv(String propertyKey){
		String property = System.getProperty(propertyKey);
		if(StringUtils.isBlank(property)){
			property = System.getenv(propertyKey);
		}		
		return property;
	}
	
	private void setupClientIdKeyFormater(){
		String formaterClassName = getEnv(AUTH_CLIENTID_FORMATER);
		if(StringUtils.isNotBlank(formaterClassName)){
			try {
				Class<?> loadClass = Thread.currentThread().getContextClassLoader().loadClass(formaterClassName);
//				Class<?> loadClass = ClientIdBasedAuthenticatorMatcher.class.getClassLoader().loadClass(formaterClassName);
				keyFormater = (ClientIdKeyFormater) loadClass.newInstance();
			} catch (Exception e) {
				LOG.error("Can not instantiate specified clientId key formater : " + formaterClassName, e);
				throw new IllegalStateException(e);
			}
		} else {
			keyFormater = new ClientIdKeyFormater();
		}		
	}
	
	@SuppressWarnings("unchecked")
	private void setupClientIdAuthenticators(){
		String clientIds = getEnv(AUTH_CLIENTID_AUTHENTICATORS);
		String[] split = StringUtils.split(clientIds, ',');
		if(split==null)return;
		for (String formatedClientIdStr : split) {
			String clientIdAuthClass = getEnv(formatedClientIdStr);
			if(StringUtils.isBlank(clientIdAuthClass)){
				throw new IllegalStateException("Missing property: " + clientIdAuthClass); 
			}
			Class<? extends ValveBase> klass;
			try {
				 klass = (Class<? extends ValveBase>) ClientIdBasedAuthenticatorMatcher.class.getClassLoader().loadClass(clientIdAuthClass);
			} catch(Exception ex){
				LOG.error("Can not load authenticator class", ex);
				throw new IllegalStateException("Can not load class: " + clientIdAuthClass, ex); 
			}
			try {
				authenticator.put(formatedClientIdStr, klass.newInstance());
			} catch (Exception e) {
				LOG.warn("Can not instantiate object.", e);
			}
		}
	}
}
