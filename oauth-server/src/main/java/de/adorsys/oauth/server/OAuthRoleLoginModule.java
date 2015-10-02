package de.adorsys.oauth.server;

import java.security.Principal;
import java.security.acl.Group;
import java.util.Map;
import javax.enterprise.inject.Alternative;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

/**
 * OAuthRoleLoginModule
 */
public class OAuthRoleLoginModule implements LoginModule {

    private Subject subject;
    private static final Principal OAUTH_ROLE = new OAuthRole();
    
    @Override
    public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState, Map<String, ?> options) {
        this.subject = subject;
    }

    @Override
    public boolean login() throws LoginException {
        return true;
    }

    @Override
    public boolean commit() throws LoginException {
        for (Principal principal : subject.getPrincipals()) {
            if (principal.getName().equals("Roles")) {
                ((Group) principal).addMember(OAUTH_ROLE);
                break;
            }
        }
        return true;
    }

    @Override
    public boolean abort() throws LoginException {
        return logout();
    }

    @Override
    public boolean logout() throws LoginException {
        this.subject = null;
        return true;
    }

    @Alternative
    private static class OAuthRole implements Principal {
               
        private static String ROLE = "oauth";
        @Override
        public String getName() {
            return ROLE;
        }
        public String toString() {
            return ROLE;
        }
    }
}
