package de.adorsys.oauth.server;

import java.net.URI;
import java.util.Map;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationSuccessResponse;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.AccessToken;

public class LoginSessionAuthorizationSuccessResponse extends AuthorizationSuccessResponse {

    private LoginSessionToken loginSession;

    public LoginSessionAuthorizationSuccessResponse(URI redirectURI, AuthorizationCode code, AccessToken accessToken,
            State state, ResponseMode rm, LoginSessionToken loginSession) {
        super(redirectURI, code, accessToken, state, rm);
        this.loginSession = loginSession;
    }

    @Override
    public Map<String, String> toParameters() {
        Map<String, String> parameters = super.toParameters();
        if (loginSession != null) {
            parameters.put("login_session", loginSession.getValue());
        }
        return parameters;
    }
}
