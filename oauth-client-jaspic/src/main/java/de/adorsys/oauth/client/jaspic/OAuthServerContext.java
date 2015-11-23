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
package de.adorsys.oauth.client.jaspic;

import java.util.Map;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.config.ServerAuthContext;

/**
 * OAuthServerContext
 */
@SuppressWarnings({"unused", "UnusedParameters", "rawtypes"})
public class OAuthServerContext implements ServerAuthContext {

    private OAuthServerAuthModule authServerAuthModule;

    public OAuthServerContext(String layer, Subject serviceSubject, CallbackHandler callbackHandler, Map properties) throws AuthException {
        authServerAuthModule = new OAuthServerAuthModule();
        authServerAuthModule.initialize(null, null, callbackHandler, properties);
    }

    @Override
    public void cleanSubject(MessageInfo messageInfo, Subject subject) throws AuthException {
        authServerAuthModule.cleanSubject(messageInfo, subject);
    }

    @Override
    public AuthStatus secureResponse(MessageInfo messageInfo, Subject subject) throws AuthException {
        return authServerAuthModule.secureResponse(messageInfo, subject);
    }

    @Override
    public AuthStatus validateRequest(MessageInfo messageInfo, Subject clientSubject, Subject serviceSubject) throws AuthException {
        return authServerAuthModule.validateRequest(messageInfo, clientSubject, serviceSubject);
    }
}
