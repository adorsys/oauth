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

    private Map<String, String> properties;
    private String registrationId;

    public SamlAuthConfigProvider(Map<String, String> properties, AuthConfigFactory factory) {
        if (factory != null) {
            registrationId = factory.registerConfigProvider(this, "HttpServlet", null, "oauth");
        }
        this.properties = properties;
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
