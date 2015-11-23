/**
 * Copyright (C) 2015 Daniel Straub, Sandro Sonntag, Christian Brandenstein, Francis Pouatcha (sso@adorsys.de, dst@adorsys.de, cbr@adorsys.de, fpo@adorsys.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.adorsys.oauth.loginmodule.ldap;

import java.security.Principal;
import java.security.acl.Group;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;

import org.jboss.security.PicketBoxLogger;
import org.jboss.security.SimpleGroup;
import org.jboss.security.auth.spi.LdapUsersLoginModule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This login module checks the password by an ldap bind. The default
 * LdapExtLoginModule does not check javax.security.auth.login.password again.
 * We force that by this class.
 * 
 * @author Sandro Sonntag
 */
public class LdapPwCheckLoginModule extends LdapUsersLoginModule {

	private static final Logger LOG = LoggerFactory.getLogger(LdapPwCheckLoginModule.class);
	private static final String DEFAULT_ROLE = "defaultRole";
	private transient SimpleGroup userRoles = new SimpleGroup("Roles");
	
	@Override
	public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState,
			Map<String, ?> options) {
		addValidOptions(new String[]{DEFAULT_ROLE});
		super.initialize(subject, callbackHandler, sharedState, options);
	}

	@Override
	@SuppressWarnings("unchecked")
	public boolean login() throws LoginException {
		if (super.login()) {
			String password = (String) sharedState.get("javax.security.auth.login.password");
			boolean success = validatePassword(password, null);
			if (success) {
				defaultRole();
				return true;
			} else {
				LOG.error("LDAP error {}", getValidateError());
				throw new LoginException(getValidateError().getMessage());
			}
		}
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
}
