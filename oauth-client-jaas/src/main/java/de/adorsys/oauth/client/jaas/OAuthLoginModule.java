package de.adorsys.oauth.client.jaas;

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
import javax.security.jacc.PolicyContext;
import javax.servlet.http.HttpServletRequest;

/**
 * OAuthRoleLoginModule
 */
public class OAuthLoginModule implements LoginModule {

    private static final Logger LOG = LoggerFactory.getLogger(OAuthLoginModule.class);

    private Subject subject;
    private CallbackHandler callbackHandler;
    private Map sharedState;

    @Override
    public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState, Map<String, ?> options) {
        this.subject = subject;
        this.callbackHandler = callbackHandler;
        this.sharedState = sharedState;
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
        try {

        	HttpServletRequest request = (HttpServletRequest) PolicyContext.getContext(HttpServletRequest.class.getName());
        	UserInfo userInfo = (UserInfo) request.getAttribute(UserInfo.class.getName());
        	if (userInfo == null) {
        		//no userinfo - no oauth login
        		return false;
        	}
        	
        	LOG.info("login {}:{}", name, bearer);

            SimplePrincipal principal = new SimplePrincipal(name);
            subject.getPrincipals().add(principal);

            Group callerGroup = new SimpleGroup("CallerPrincipal");
            subject.getPrincipals().add(callerGroup);
            callerGroup.addMember(principal);

            Group bearerGroup = new SimpleGroup("Bearer");
            subject.getPrincipals().add(bearerGroup);
            bearerGroup.addMember(new SimplePrincipal(bearer));


            if (userInfo != null && userInfo.getSubject().getValue().equals(name)) {
                Object claims = userInfo.getClaim("groups");
				LOG.info("UserInfo: {} {}", userInfo.getSubject().getValue(), claims);
                Group rolesGroup = new SimpleGroup("Roles");
                subject.getPrincipals().add(rolesGroup);
                if (claims != null) {
	                for (String group : (List<String>) claims) {
	                    rolesGroup.addMember(new SimplePrincipal(group));
	                }
                }

                if (sharedState != null) {
                    sharedState.put("userInfo", userInfo);
                }
            }           
            
            return true;
            
        } catch (Exception e) {
            throw  new LoginException(e.getMessage());
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
