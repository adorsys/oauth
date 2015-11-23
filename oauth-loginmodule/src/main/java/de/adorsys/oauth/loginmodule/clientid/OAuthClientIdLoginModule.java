/**
 * Copyright (C) 2015 Daniel Straub, Sandro Sonntag, Christian Brandenstein, Francis Pouatcha (sso@adorsys.de, dst@adorsys.de, cbr@adorsys.de, fpo@adorsys.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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

import org.apache.commons.lang3.StringUtils;
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
        for (String allowedUri : allowedUris) {
        	String redirectUri = authorizationRequest.getRedirectionURI().toString();
        	if(StringUtils.startsWithIgnoreCase(redirectUri, allowedUri)) return true;
		}

    	LOG.warn("OAUTH ClientID {} requested a token but the redirect urls does not match. Actual redirectionurl {} is not defined in {}.", clientID, authorizationRequest.getRedirectionURI(), allowedUris);
    	throw new LoginException("OAUTH ClientID {} requested a token but the redirect urls does not match. Actual redirectionurl {} is not defined in {}.");
    }
    
    
    

}
