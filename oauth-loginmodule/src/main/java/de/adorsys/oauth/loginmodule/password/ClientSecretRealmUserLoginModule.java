package de.adorsys.oauth.loginmodule.password;

import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ResourceOwnerPasswordCredentialsGrant;
import com.nimbusds.oauth2.sdk.TokenRequest;
import de.adorsys.oauth.loginmodule.authdispatcher.HttpContext;
import de.adorsys.oauth.loginmodule.util.FixedServletUtils;
import org.jboss.as.security.RealmUsersRolesLoginModule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import javax.servlet.http.HttpServletRequest;
import java.util.Map;

/**
 * Same behavior as JBoss RealmUserRolesLoginModule
 * In case of grant type "password" resource owner credentials will be used in next LoginModule
 *
 * @author Christian Brandenstein
 */
public class ClientSecretRealmUserLoginModule extends RealmUsersRolesLoginModule {

    private Map sharedState;
    private boolean abort = false;

    @Override
    public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState, Map<String, ?> options) {
        this.sharedState = sharedState;
        super.initialize(subject, callbackHandler, sharedState, options);
    }

    @Override
    public boolean login() throws LoginException {
        boolean returnValue = super.login(); // client secret wrong => login exception

        // map resource owner password credentials to shared state in case of grant type "password"
        HttpServletRequest httpServletRequest = HttpContext.SERVLET_REQUEST.get();
        try {
            TokenRequest tokenRequest = TokenRequest.parse(FixedServletUtils.createHTTPRequest(httpServletRequest));
            AuthorizationGrant authorizationGrant = tokenRequest.getAuthorizationGrant();

            if(authorizationGrant.getType() == GrantType.PASSWORD){
                ResourceOwnerPasswordCredentialsGrant ropcg = (ResourceOwnerPasswordCredentialsGrant) authorizationGrant;
                sharedState.put("javax.security.auth.login.name", ropcg.getUsername());
                sharedState.put("javax.security.auth.login.password", ropcg.getPassword().getValue());
                abort = true;
                return false; // ignore client credentials
            }
        } catch (Exception e) {
            // ignore
        }

        return returnValue;
    }

    @Override
    public boolean commit() throws LoginException {
        if (abort) {
            super.abort();
        } else {
            return super.commit();
        }
        return false;
    }

    @Override
    public boolean abort() throws LoginException {
        return super.abort();
    }

    @Override
    public boolean logout() throws LoginException {
        return super.logout();
    }
}
