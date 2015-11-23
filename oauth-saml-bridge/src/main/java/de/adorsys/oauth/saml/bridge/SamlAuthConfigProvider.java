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
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.config.AuthConfigFactory;
import javax.security.auth.message.config.AuthConfigProvider;
import javax.security.auth.message.config.ClientAuthConfig;
import javax.security.auth.message.config.ServerAuthConfig;

/**
 * SamlAuthConfigProvider
 */
@SuppressWarnings({"unused", "UnusedParameters"})
public class SamlAuthConfigProvider implements AuthConfigProvider {

    private final Map<String, String> properties;
    private final String registrationId;
   // private final String contextPath;

    public SamlAuthConfigProvider(Map<String, String> properties, AuthConfigFactory factory, String contextPath) {
        this.registrationId = factory.registerConfigProvider(this, "HttpServlet", "localhost " + contextPath, "oauth");
        this.properties = properties;
 //       this.contextPath = contextPath;
    }

    @Override
    public ClientAuthConfig getClientAuthConfig(String layer, String appContext, CallbackHandler callbackHandler) throws AuthException, SecurityException {
        return null;
    }

    @Override
    public ServerAuthConfig getServerAuthConfig(String layer, String appContext, CallbackHandler callbackHandler) throws AuthException, SecurityException {
        return new SamlServerAuthConfig(layer, appContext, callbackHandler, properties);
    }

    @Override
    public void refresh() {
    }

    public String getRegistrationId() {
        return registrationId;
    }
}
