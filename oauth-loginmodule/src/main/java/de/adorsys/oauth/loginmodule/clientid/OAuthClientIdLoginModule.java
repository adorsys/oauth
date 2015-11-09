package de.adorsys.oauth.loginmodule.clientid;

import java.security.Principal;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;

import de.adorsys.oauth.loginmodule.authdispatcher.HttpContext;

/**
 * 
 * @author Sandro SOnntag
 *
 */
@SuppressWarnings({"MismatchedQueryAndUpdateOfCollection", "unchecked"})
public class OAuthClientIdLoginModule implements LoginModule {

    private static final Logger LOG = LoggerFactory.getLogger(OAuthClientIdLoginModule.class);

    private Map sharedState;
    private Subject subject;
    private boolean success;

    @Override
    public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState, Map<String, ?> options) {
        this.sharedState = sharedState;
        this.subject = subject;
    }

    @Override
    public boolean login() throws LoginException {
        validateRequest();
        return true;
    }

    @Override
    public boolean commit() throws LoginException {
        return true;
    }

    @Override
    public boolean abort() throws LoginException {
        return true;
    }

    @Override
    public boolean logout() throws LoginException {
        return true;
    }


    private boolean validateRequest() throws LoginException {
    	HttpServletRequest request = HttpContext.SERVLET_REQUEST.get();
    	Principal principal = request.getUserPrincipal();
        if (principal != null) {
            return false;
        }

        AuthorizationRequest authorizationRequest = AuthorizationRequestUtil.resolveAuthorizationRequest(request);
        if (authorizationRequest == null) {
        	return false;
        }
        
        ClientID clientID = authorizationRequest.getClientID();
        Properties properties = System.getProperties();
        String redirectionURIs = properties.getProperty("oauth.clients." + clientID + ".redirectionURIs");
        if (redirectionURIs == null) {
        	LOG.warn("Unknow OAUTH ClientID {} requested a token. Please define system property 'oauth.clients.{}.redirectionURIs'.", clientID, clientID);
        	throw new LoginException("Unknow OAUTH ClientID {} requested a token. Please define system property 'oauth.clients.{}.redirectionURIs'.");
        	
        }
        List<String>allowedUris = Arrays.asList(redirectionURIs.split(","));
        if (allowedUris.contains(authorizationRequest.getRedirectionURI().toString())) {
        	return true;
        } else {
        	LOG.warn("OAUTH ClientID {} requested a token but the redirect urls does not match. Actual redirectionurl {} is not defined in {}.", clientID, authorizationRequest.getRedirectionURI(), allowedUris);
        	throw new LoginException("OAUTH ClientID {} requested a token but the redirect urls does not match. Actual redirectionurl {} is not defined in {}.");
        }
    }
    
    
    

}
