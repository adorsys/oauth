package de.adorsys.oauth.server;

import java.io.IOException;
import java.security.Principal;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.servlet.ServletException;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ResourceOwnerPasswordCredentialsGrant;
import com.nimbusds.oauth2.sdk.TokenRequest;

import de.adorsys.oauth.authdispatcher.FixedServletUtils;

/**
 * ResourceOwnerPasswordCredentialFlowValve
 */
public class ResourceOwnerPasswordCredentialFlowValve extends ValveBase {

    private static final Logger LOG = LoggerFactory.getLogger(ResourceOwnerPasswordCredentialFlowValve.class);

    private String clientSecurityDomain;

    @SuppressWarnings("ReplaceAllDot")
    @Override
    public void invoke(Request request, Response response) throws IOException, ServletException {

        TokenRequest tokenRequest = resolveTokenRequest(request);
        if (tokenRequest == null) {
            getNext().invoke(request, response);
            return;
        }

        AuthorizationGrant authorizationGrant = tokenRequest.getAuthorizationGrant();
        if (authorizationGrant.getType() != GrantType.PASSWORD) {
            getNext().invoke(request, response);
            return;
        }

        ResourceOwnerPasswordCredentialsGrant grant = (ResourceOwnerPasswordCredentialsGrant) authorizationGrant;
        String userName = grant.getUsername();
        String password = grant.getPassword().getValue();

        LOG.debug("ResourceOwnerPasswordCredentialFlow - login {} {}", userName, password.replaceAll(".", "x"));

        Principal principal = getContainer().getRealm().authenticate(userName, password);
        request.setUserPrincipal(principal);

        getNext().invoke(request, response);
    }

    /**
     * resolveTokenRequest
     */
    private TokenRequest resolveTokenRequest(Request httpRequest) {
        try {
            return TokenRequest.parse(FixedServletUtils.createHTTPRequest(httpRequest));
        } catch (Exception e) {
            //
        }
        return null;
    }

}
