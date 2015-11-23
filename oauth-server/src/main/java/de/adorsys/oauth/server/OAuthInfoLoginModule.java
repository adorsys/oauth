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
package de.adorsys.oauth.server;

import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import javax.security.jacc.PolicyContext;
import javax.security.jacc.PolicyContextException;
import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.AuthorizationRequest;

/**
 * OAuthInfoLoginModule
 * Purpose of this module is to provide oauth informations for the following login modules
 */
@SuppressWarnings("unchecked")
public class OAuthInfoLoginModule implements LoginModule {

    private static final Logger LOG = LoggerFactory.getLogger(OAuthInfoLoginModule.class);

    private Subject subject;
    private CallbackHandler callbackHandler;
    private Map sharedState;

    @Override
    public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState, Map<String, ?> options) {
        this.subject = subject;
        this.callbackHandler = callbackHandler;
        this.sharedState = sharedState;
        readOAuthParameter();
    }

    @Override
    public boolean login() throws LoginException {
        return true;
    }

    @Override
    public boolean commit() throws LoginException {
        logSharedState();
        return true;
    }

    @Override
    public boolean abort() throws LoginException {
        return false;
    }

    @Override
    public boolean logout() throws LoginException {
        return false;
    }

    private void logSharedState() {
        if (sharedState.isEmpty()) {
            return;
        }
        int maxLength = 0;
        for (Object key : sharedState.keySet()) {
            if (maxLength < key.toString().length()) {
                maxLength = key.toString().length();
            }
        }
        StringBuilder sb = new StringBuilder("Shared State");
        for (Object key : sharedState.keySet()) {
            if (sharedState.get(key) == null) {
                continue;
            }
            Object value  = sharedState.get(key);
            if (key.equals("javax.security.auth.login.password")) {
                value = new String((char[]) value).replaceAll(".", "x");
            }
            sb.append('\n').append(key).append(" = ").append(value);
        }
        LOG.info(sb.toString());
    }

    private void readOAuthParameter() {
        HttpServletRequest servletRequest = null;
        try {
            servletRequest = (HttpServletRequest) PolicyContext.getContext(HttpServletRequest.class.getName());
        } catch (PolicyContextException e) {
            LOG.error("unable to retrieve PolicyContext.getContext(HttpServletRequest): {}", e.getMessage());
        }

        if (servletRequest == null) {
            return;
        }

        // check for AuthRequest
        AuthorizationRequest authRequest = resolveAuthorizationRequest(servletRequest);
        if (authRequest != null) {
            sharedState.put("client_id", authRequest.getClientID());
            sharedState.put("redirect_uri", authRequest.getRedirectionURI());
            sharedState.put("state", authRequest.getState());
            sharedState.put("scope", authRequest.getScope());
            sharedState.put("response_type", authRequest.getResponseType());
            sharedState.put("response_mode", authRequest.getResponseMode());
        }

        // todo: Token Request doesn't support 4.3.2 username / password
    }

    private AuthorizationRequest resolveAuthorizationRequest(HttpServletRequest servletRequest)  {
        try {
            return AuthorizationRequest.parse(FixedServletUtils.createHTTPRequest(servletRequest));
        } catch (Exception e) {
            // ignore
        }
        // sometimes during some redirections or idp chaining we get an POST with query string
        String query = servletRequest.getQueryString();
        try {
            return AuthorizationRequest.parse(query);
        } catch (Exception e) {
            // ignore
        }

        return null;
    }


}
