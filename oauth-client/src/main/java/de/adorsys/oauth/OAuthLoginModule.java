package de.adorsys.oauth;

import org.jboss.security.SimpleGroup;
import org.jboss.security.SimplePrincipal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.openid.connect.sdk.claims.UserInfo;

import java.security.acl.Group;
import java.util.List;
import java.util.Map;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

/**
 * OAuthRoleLoginModule
 */
public class OAuthLoginModule implements LoginModule {

    private static final Logger LOG = LoggerFactory.getLogger(OAuthLoginModule.class);

    private Subject subject;
    private CallbackHandler callbackHandler;
    
    static final ThreadLocal<UserInfo> USER_INFO = new ThreadLocal<>();

    @Override
    public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState, Map<String, ?> options) {
        this.subject = subject;
        this.callbackHandler = callbackHandler;
    }

    @Override
    @SuppressWarnings("unchecked")
    public boolean login() throws LoginException {

        NameCallback nameCallback = new NameCallback("name");
        PasswordCallback password = new PasswordCallback("password", false);
        try {
            callbackHandler.handle(new Callback[] { nameCallback, password });
        } catch (Exception x) {
            throw new LoginException(x.getMessage());
        }

        String name = nameCallback.getName();
        String bearer = new String(password.getPassword());

        LOG.info("login {}:{}", name, bearer);

        try {

            SimplePrincipal principal = new SimplePrincipal(name);
            subject.getPrincipals().add(principal);

            Group callerGroup = new SimpleGroup("CallerPrincipal");
            subject.getPrincipals().add(callerGroup);
            callerGroup.addMember(principal);

            Group bearerGroup = new SimpleGroup("Bearer");
            subject.getPrincipals().add(bearerGroup);
            bearerGroup.addMember(new SimplePrincipal(bearer));

            UserInfo userInfo = USER_INFO.get();
            if (userInfo != null && userInfo.getSubject().getValue().equals(name)) {
                LOG.info("UserInfo: {} {}", userInfo.getSubject().getValue(), userInfo.getClaim("groups"));
                Group rolesGroup = new SimpleGroup("Roles");
                subject.getPrincipals().add(rolesGroup);
                for (String group : (List<String>) userInfo.getClaim("groups")) {
                    rolesGroup.addMember(new SimplePrincipal(group));
                }
            }           
            
            return true;
            
        } catch (Exception e) {
            throw  new LoginException(e.getMessage());
        } finally {
            USER_INFO.remove();
        }
    }

    @Override
    public boolean commit() throws LoginException {
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
    
}
