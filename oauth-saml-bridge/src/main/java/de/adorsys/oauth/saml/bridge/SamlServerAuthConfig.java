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
package de.adorsys.oauth.saml.bridge;

import java.util.Map;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.config.ServerAuthConfig;
import javax.security.auth.message.config.ServerAuthContext;

/**
 * SamlServerAuthConfig
 */
@SuppressWarnings({"unused", "UnusedParameters", "FieldCanBeLocal", "rawtypes"})
public class SamlServerAuthConfig implements ServerAuthConfig {

    private final CallbackHandler callbackHandler;
    private final String appContext;
    private final Map<String, String> properties;
    private final String layer;

    public SamlServerAuthConfig(String layer, String appContext, CallbackHandler callbackHandler, Map<String, String> properties) {
        this.layer = layer;
        this.appContext = appContext;
        this.callbackHandler = callbackHandler;
        this.properties = properties;
    }

    @Override
    public ServerAuthContext getAuthContext(String layer, Subject serviceSubject, Map properties) throws AuthException {
        return new SamlServerContext(layer, serviceSubject, callbackHandler, this.properties);
    }

    @Override
    public String getAppContext() {
        return appContext;
    }

    @Override
    public String getAuthContextID(MessageInfo messageInfo) {
        return appContext;
    }

    @Override
    public String getMessageLayer() {
        return layer;
    }

    @Override
    public boolean isProtected() {
        return false;
    }

    @Override
    public void refresh() {

    }
}
