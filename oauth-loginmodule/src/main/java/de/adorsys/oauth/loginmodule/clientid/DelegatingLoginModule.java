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

import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;

import de.adorsys.oauth.loginmodule.authdispatcher.HttpContext;

import de.adorsys.oauth.loginmodule.util.FixedServletUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import javax.servlet.http.HttpServletRequest;

import java.io.IOException;
import java.util.Arrays;
import java.util.Map;

/**
 * Master LoginModule for main security domain
 *
 * Reads client_id from request and delegates to security domain with the same name
 *
 * Usage:
 * {@code
    <security-domain name="oauth">
        <authentication>
            <login-module code="de.adorsys.oauth.loginmodule.clientid.DelegatingLoginModule" flag="required">
                <module-option name="de.adorsys.oauth.loginmodule.clientid.list" value="clientida,clientidb,clientidc"/>
            </login-module>
        </authentication>
    </security-domain>
    <security-domain name="clientida".../>
    <security-domain name="clientidb".../>
    <security-domain name="clientidc".../>
    }
 *
 * auth request and token request supported
 *
 * CAUTION: Credentials cache must not be enabled, when using this module
 *
 * @author Christian Brandenstein
 */
public class DelegatingLoginModule implements LoginModule {

    private static final Logger log = LoggerFactory.getLogger(DelegatingLoginModule.class);
    private static final String CLIENT_ID_LIST = "de.adorsys.oauth.loginmodule.clientid.list";

    private Subject subject;
    private CallbackHandler callbackHandler;
    private String clientIdList;

    private LoginContext loginContext;
    private boolean loginSucceded = false;

    @Override
    public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState, Map<String, ?> options) {
        this.subject = subject;
        this.callbackHandler = callbackHandler;
        this.clientIdList = (String) options.get(CLIENT_ID_LIST);

        if (StringUtils.isEmpty(clientIdList)) {
            log.error("No client_ids for delegation configured");
            throw new IllegalStateException("No client_ids for delegation configured");
        }
    }

    @Override
    public boolean login() throws LoginException {
        HttpServletRequest request = HttpContext.SERVLET_REQUEST.get();
        HTTPRequest nimbusRequest = null;

        try {
            nimbusRequest = FixedServletUtils.createHTTPRequest(request);
        } catch (IOException e) {
            log.error("Error parsing Request", e);
            throw new LoginException("Error parsing Request");
        }

        ClientID clientID = null;

        //auth request
        try {
            AuthorizationRequest authorizationRequest = AuthorizationRequest.parse(nimbusRequest);
            clientID = authorizationRequest != null ? authorizationRequest.getClientID() : null;
        } catch (Exception e) {
            log.trace("Exception parsing auth request", e);
        }

        //token request
        if (clientID == null) {
            try {
                TokenRequest tokenRequest = TokenRequest.parse(nimbusRequest);
                if (tokenRequest != null) {
                    clientID = tokenRequest.getClientID();

                    if (clientID == null && tokenRequest.getClientAuthentication() != null) {
                        clientID = tokenRequest.getClientAuthentication().getClientID();
                    }
                }
            } catch (Exception e) {
                log.trace("Exception parsing token request", e);
            }
        }

        if (clientID == null) {
            log.error("Client Id Extraction failed");
            throw new LoginException("Client Id Extraction failed");
        }


        verifyClientID(clientID);

        loginContext = new LoginContext(clientID.getValue(), subject, callbackHandler);
        loginContext.login(); //throws LoginException
        loginSucceded = true;
        return true;
    }

    private void verifyClientID(ClientID clientID) throws LoginException {
        if (clientID == null || StringUtils.isEmpty(clientID.toString())) {
            log.warn("Received call with invalid client_id: " + clientID);
            throw new LoginException("Invalid client_id");
        }

        String[] clientIDs = clientIdList.split(",");

        if (! Arrays.asList(clientIDs).contains(clientID.getValue())) {
            log.warn("Received call with unkown client_id: " + clientID);
            throw new LoginException("Unkown client_id");
        }
    }

    @Override
    public boolean commit() throws LoginException {
         return loginSucceded;
    }

    @Override
    public boolean abort() throws LoginException {
        return false;
    }

    @Override
    public boolean logout() throws LoginException {
        if (loginContext != null) {
            loginContext.logout();
            return true;
        }
        return false;
    }
}
