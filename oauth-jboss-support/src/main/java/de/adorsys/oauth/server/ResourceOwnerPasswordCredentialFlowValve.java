package de.adorsys.oauth.server;

import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ResourceOwnerPasswordCredentialsGrant;
import com.nimbusds.oauth2.sdk.TokenRequest;

import de.adorsys.oauth.authdispatcher.FixedServletUtils;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.servlet.ServletException;

import java.io.IOException;
import java.security.Principal;

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

        if (!verifyClientCredentials(request)) {
            response.setStatus(403);
            response.getWriter().write("client authentification failed");
            response.finishResponse();
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
     * Check client credentials
     * We expect the credentials as BASIC-Auth header
     */
    private boolean verifyClientCredentials(Request httpRequest) {

        if (clientSecurityDomain == null) {
            // ignore auth if no security domain is configured
            return true;
        }

        String authValue = httpRequest.getHeader("Authorization");
        if (authValue == null || !authValue.startsWith("Basic ")) {
            return false;
        }

        String encodedValue = authValue.substring(6);
        String decodedValue= new String(Base64.decodeBase64(encodedValue));
        final String[] namePassword = decodedValue.contains(":") ? decodedValue.split(":") : new String[] { decodedValue, "" };

        CallbackHandler callbackHandler = new CallbackHandler() {
            @Override
            public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                for (Callback callback : callbacks) {
                    if (callback instanceof NameCallback) {
                        ((NameCallback) callback).setName(namePassword[0]);
                        continue;
                    }
                    if (callback instanceof PasswordCallback) {
                        ((PasswordCallback) callback).setPassword(namePassword[1].toCharArray());
                    }
                }
            }
        };

        Subject subject = new Subject();
        try {
            LoginContext loginContext = new LoginContext(clientSecurityDomain, subject, callbackHandler);
            loginContext.login();
            loginContext.logout();
        } catch (LoginException e) {
            LOG.error("call securitydomain " + callbackHandler, e);
            return false;
        }

        return true;

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

    public void setClientSecurityDomain(String clientSecurityDomain) {
        this.clientSecurityDomain = clientSecurityDomain;
    }

}
