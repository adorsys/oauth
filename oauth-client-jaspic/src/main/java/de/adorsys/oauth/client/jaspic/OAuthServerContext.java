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
