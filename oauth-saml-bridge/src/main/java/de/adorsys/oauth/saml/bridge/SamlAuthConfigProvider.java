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