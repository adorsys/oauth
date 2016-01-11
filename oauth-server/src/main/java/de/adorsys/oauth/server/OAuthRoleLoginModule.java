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
 * Deprecated: use Jboss IdentyLoginModule
 */
@Deprecated
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
