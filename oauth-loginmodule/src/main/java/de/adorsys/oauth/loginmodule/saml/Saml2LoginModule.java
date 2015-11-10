package de.adorsys.oauth.loginmodule.saml;

import java.security.Principal;
import java.security.acl.Group;
import java.util.Enumeration;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import javax.security.jacc.PolicyContext;
import javax.security.jacc.PolicyContextException;
import javax.servlet.http.HttpServletRequest;

import org.jboss.security.PicketBoxLogger;
import org.jboss.security.SimpleGroup;
import org.jboss.security.auth.spi.AbstractServerLoginModule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Procsses sucessfull SAML Response.
 *  
 * @author Francis Pouatcha
 */
public class Saml2LoginModule extends AbstractServerLoginModule {

	private static final Logger LOG = LoggerFactory.getLogger(Saml2LoginModule.class);
	private static final String DEFAULT_ROLE = "defaultRole";
	private transient SimpleGroup userRoles = new SimpleGroup("Roles");
   /** The login identity */
   private Principal identity;

   HttpServletRequest servletRequest = null;
	@Override
	public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState,
			Map<String, ?> options) {
		addValidOptions(new String[]{DEFAULT_ROLE});
		super.initialize(subject, callbackHandler, sharedState, options);
		try {
			servletRequest = (HttpServletRequest) PolicyContext
					.getContext(HttpServletRequest.class.getName());
		} catch (PolicyContextException e) {
			LOG.error(
					"unable to retrieve PolicyContext.getContext(HttpServletRequest): {}",
					e.getMessage());
		}
	}

	@Override
	public boolean login() throws LoginException {
		SimpleGroup samlPrincipal = (SimpleGroup) servletRequest.getAttribute(SamlConstants.SAML_PRINCIPAL_ATTRIBUTE_KEY);
		if(samlPrincipal==null) return false;
		try {
			identity = super.createIdentity(samlPrincipal.getName());
			Enumeration<Principal> members = samlPrincipal.members();
			while (members.hasMoreElements()) {
				Principal role = super.createIdentity(members.nextElement().getName());
				PicketBoxLogger.LOGGER.traceAssignUserToRole(role.getName());
				userRoles.addMember(role);
			}
		} catch (Exception e) {
			throw new LoginException(e.getMessage());
		}
		defaultRole();
		super.loginOk = true;
		return true;
	}

	private void defaultRole() {
		String defaultRole = (String) options.get(DEFAULT_ROLE);
		try {
			if (defaultRole == null || defaultRole.equals("")) {
				return;
			}
			Principal p = super.createIdentity(defaultRole);
			PicketBoxLogger.LOGGER.traceAssignUserToRole(defaultRole);
			userRoles.addMember(p);
		} catch (Exception e) {
			PicketBoxLogger.LOGGER.debugFailureToCreatePrincipal(defaultRole, e);
		}
	}

	protected Group[] getRoleSets() throws LoginException {
		Group[] roleSets = { userRoles };
		return roleSets;
	}

	@Override
	protected Principal getIdentity() {
		return identity;
	}
}
