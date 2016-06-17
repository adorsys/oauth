package de.adorsys.oauth.server;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationSuccessResponse;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.AccessToken;

public class LoginSessionAuthorizationSuccessResponse extends AuthorizationSuccessResponse {

    private LoginSessionToken loginSession;
    
    private String originalFragment;

    public LoginSessionAuthorizationSuccessResponse(URI redirectURI, AuthorizationCode code, AccessToken accessToken,
            State state, ResponseMode rm, LoginSessionToken loginSession, String originalFragment) {
        super(redirectURI, code, accessToken, state, rm);
        this.loginSession = loginSession;
        this.originalFragment = originalFragment;
    }

    @Override
    public Map<String, String> toParameters() {
        Map<String, String> parameters = super.toParameters();
        if (loginSession != null) {
            parameters.put("login_session", loginSession.getValue());
        }
        return parameters;
    }
    
    @Override
    public URI toURI() {
        if (originalFragment == null) {
            return super.toURI();
        }
        String uri = super.toURI().toString();
        uri = uri.replace("#", "#" + originalFragment + "?");
        try {
            return new URI(uri);
        } catch (URISyntaxException e) {
            throw new OAuthException("failed to construct new redirect url", e);
        }
    }
}
