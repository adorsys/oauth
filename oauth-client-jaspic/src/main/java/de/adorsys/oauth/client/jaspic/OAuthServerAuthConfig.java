package de.adorsys.oauth.client.jaspic;

import java.util.Map;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.config.ServerAuthConfig;
import javax.security.auth.message.config.ServerAuthContext;

/**
 * OAuthServerAuthConfig
 */
@SuppressWarnings({"unused", "UnusedParameters", "FieldCanBeLocal", "rawtypes"})
public class OAuthServerAuthConfig implements ServerAuthConfig {

    private final CallbackHandler callbackHandler;
    private final String appContext;
    private final Map<String, String> properties;
    private final String layer;

    public OAuthServerAuthConfig(String layer, String appContext, CallbackHandler callbackHandler, Map<String, String> properties) {
        this.layer = layer;
        this.appContext = appContext;
        this.callbackHandler = callbackHandler;
        this.properties = properties;
    }

    @Override
    public ServerAuthContext getAuthContext(String layer, Subject serviceSubject, Map properties) throws AuthException {
        return new OAuthServerContext(layer, serviceSubject, callbackHandler, this.properties);
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
